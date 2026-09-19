// Self-audit regression tests: pin three semantics that were (or nearly were) missed -- prepare
// signature-verification negative path, outbox republish wiring, per-kind inbound participant type check.
package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	wirebus "github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// prepare signature-verification negative path: bad signature, expired, chain_id mismatch, unknown
// field, non-Builder submitter are all rejected; the control group must pass.
func TestBuilderPrepareDecodeRejections(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keys := newTestServiceKeys()
	self := testBuilderSelf
	codec := &prepareCodec{
		log: log, chainID: testChainID, addressPrefix: "trueopen",
		self: self, signer: keys.signerFor(servicekey.ParticipantBuilder, self),
		authority: keys,
	}
	now := uint64(nowMS())
	good, err := codec.encode("session-1", testTaskID("prepare-audit"), now)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := codec.decode(context.Background(), good, now); err != nil {
		t.Fatalf("conforming prepare rejected: %v", err)
	}

	mutate := func(change func(*builderPrepare)) []byte {
		var p builderPrepare
		if err := json.Unmarshal(good, &p); err != nil {
			t.Fatal(err)
		}
		change(&p)
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string][]byte{
		"tampered task after signing": mutate(func(p *builderPrepare) { p.TaskID = testTaskID("other") }),
		"foreign chain":               mutate(func(p *builderPrepare) { p.ChainID = "trueopen-other" }),
		"expired":                     mutate(func(p *builderPrepare) { p.ExpiresAtUnixMS = now - 1; p.IssuedAtUnixMS = now - 2 }),
		"truncated signature":         mutate(func(p *builderPrepare) { p.Signature = p.Signature[:64] }),
		"unknown field":               []byte(strings.Replace(string(good), `"chain_id"`, `"extra":1,"chain_id"`, 1)),
		"unknown stage":               mutate(func(p *builderPrepare) { p.Stage = "ASSIGN" }),
	}
	for name, raw := range cases {
		if _, err := codec.decode(context.Background(), raw, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Non-Builder submitter: no Builder binding for this operator is found on-chain.
	imposter := mutate(func(p *builderPrepare) { p.Submitter = testOperator("not-a-builder") })
	if _, err := codec.decode(context.Background(), imposter, now); err == nil {
		t.Fatal("prepare from a non-builder submitter accepted")
	}
}

// republishOutbox must re-send unexpired outbox entries verbatim. This wiring was last fixed only
// via manual review (Start missed calling Republish); pin it with a test.
func TestRepublishOutboxResendsPending(t *testing.T) {
	backing := kv.NewMemStore()
	outbox := busadapter.NewOutbox(backing)
	wire := []byte{0x0a, 0x01, 0x02}
	if err := outbox.Put(busadapter.OutboxEntry{
		MessageID: "m-1", Subject: "trueopen.task.open.model-a", Tier: busadapter.TierCore,
		Wire: wire, ExpiresAtUnixMS: uint64(nowMS()) + 60_000,
	}); err != nil {
		t.Fatal(err)
	}
	bus := &republishCaptureBus{}
	c := &Coordinator{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		busPublisher: busadapter.NewPublisher(busadapter.PublisherConfig{
			ChainID: testChainID, OperatorAddress: testBuilderSelf,
			ParticipantType: wirebus.ParticipantBuilder,
			Outbox:          outbox, Bus: bus, TTLMS: 30_000,
			Now: func() uint64 { return uint64(nowMS()) },
		}),
	}
	c.republishOutbox(context.Background())
	if len(bus.published) != 1 || !bytes.Equal(bus.published[0], wire) {
		t.Fatalf("republish did not resend the stored bytes: %+v", bus.published)
	}
}

type republishCaptureBus struct{ published [][]byte }

func (b *republishCaptureBus) Publish(_ string, data []byte) error {
	b.published = append(b.published, append([]byte(nil), data...))
	return nil
}

func (b *republishCaptureBus) JSPublish(_ string, data []byte, _ string) error {
	return b.Publish("", data)
}

// Per-kind inbound participant type check: a Builder impersonating Cortex to send hand-raises /
// verification result receipts is always rejected. The old envelope's AllowedSender matrix test covered all
// kinds; this is the V2-path equivalent.
func TestReceiveRejectsWrongParticipantPerKind(t *testing.T) {
	c, _, keys, _, session, task, _ := busEnvelopeRejectionFixture(t)
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing")
	}
	cases := []struct {
		name    string
		subject string
		kind    int32
		payload func() []byte
	}{
		{"verifier handraise", msgbus.SubjectVerifierHandraiseV1(task), wirebus.KindVerifierHandraise, nil},
		{"verify result", msgbus.SubjectVerifyResultV1(task), wirebus.KindVerifyResult, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var wire []byte
			switch tc.kind {
			case wirebus.KindVerifierHandraise:
				wire = signTestEnvelope(t, keys, wirebus.ParticipantBuilder, testBuilderSelf,
					tc.subject, tc.kind,
					testVerifierHandraise(session, task, testBuilderSelf,
						[]byte("output-root-hash"), []byte("infer-receipt")), nil)
			case wirebus.KindVerifyResult:
				wire = signTestEnvelope(t, keys, wirebus.ParticipantBuilder, testBuilderSelf,
					tc.subject, tc.kind, testVerifyResult(task, testBuilderSelf, [][]byte{[]byte("v")}), nil)
			}
			inbound, err := fsm.receive(tc.subject, tc.kind,
				sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, wire)
			if err == nil {
				t.Fatalf("builder-signed %s accepted as cortex: %+v", tc.name, inbound)
			}
		})
	}
}
