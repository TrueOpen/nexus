package coordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	wirebus "github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// busEnvelopeRejectionFixture starts a task that is already receiving Worker hand-raises and
// returns its bus, service key base and subject. The gh #45 acceptance-3 counterexamples start here.
func busEnvelopeRejectionFixture(t *testing.T) (
	*Coordinator, msgbus.Bus, *testServiceKeys, *fakeSubmitter, string, string, string,
) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	submitter := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log),
		kv.NewMemStore(), testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = submitter

	session := "sess-envelope-reject"
	task := testTaskID("envelope-reject")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	return c, bus, keys, submitter, session, task, msgbus.SubjectWorkerHandraiseV1(task)
}

func handraiseCount(t *testing.T, c *Coordinator, session, task string) int {
	t.Helper()
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing")
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return len(fsm.workerHR)
}

// TestInboundEnvelopeMustVerify is gh #45 acceptance 3: inbound frames must pass the wire
// bus 7-step verification. Each subcase builds a frame that is non-conforming in exactly
// one place and asserts it is neither accepted nor advances the FSM. The byte-level step-by-step
// counterexamples are frozen by the wire and busadapter tests; what is tested here is that
// "coordinator really wires inbound onto that verification order".
func TestInboundEnvelopeMustVerify(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*busv1.BusEnvelopeV1)
		// resign=false means no re-signing after the change, simulating "signature does not match content".
		resign bool
	}{
		{name: "tampered payload after signing", mutate: func(e *busv1.BusEnvelopeV1) {
			// Modify payload after signing: payload_digest mismatches and the signature does not cover the new content.
			e.Payload = []byte{0xde, 0xad}
		}},
		{name: "foreign chain id", mutate: func(e *busv1.BusEnvelopeV1) {
			e.ChainId = "trueopen-other-chain"
		}, resign: true},
		{name: "subject does not match envelope", mutate: func(e *busv1.BusEnvelopeV1) {
			e.Subject = msgbus.SubjectWorkerHandraiseV1(testTaskID("another-task"))
		}, resign: true},
		{name: "payload type does not match kind", mutate: func(e *busv1.BusEnvelopeV1) {
			e.PayloadType = busv1.BusPayloadType_BUS_PAYLOAD_TYPE_VERIFY_RESULT_V1
		}, resign: true},
		{name: "builder claims a worker handraise", mutate: func(e *busv1.BusEnvelopeV1) {
			e.SenderParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER
			e.SenderOperatorAddress = testBuilderSelf
		}, resign: true},
		{name: "already expired", mutate: func(e *busv1.BusEnvelopeV1) {
			e.IssuedAtUnixMs = uint64(nowMS() - 120_000)
			e.ExpiresAtUnixMs = uint64(nowMS() - 60_000)
		}, resign: true},
		{name: "authorization nonce does not match the current binding", mutate: func(e *busv1.BusEnvelopeV1) {
			e.ServiceAuthorizationNonce = testAuthorizationNo + 1
		}, resign: true},
		{name: "short signature", mutate: func(e *busv1.BusEnvelopeV1) {
			e.ServiceSignature = e.ServiceSignature[:32]
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			c, bus, keys, submitter, session, task, subject := busEnvelopeRejectionFixture(t)
			candidate := testOperator("worker-1")
			payload := testWorkerHandraise(session, task, candidate)

			var wire []byte
			if testCase.resign {
				wire = signTestEnvelope(t, keys, wirebus.ParticipantCortex, candidate, subject,
					wirebus.KindWorkerHandraise, payload, testCase.mutate)
			} else {
				wire = signTestEnvelope(t, keys, wirebus.ParticipantCortex, candidate, subject,
					wirebus.KindWorkerHandraise, payload, nil)
				var envelope busv1.BusEnvelopeV1
				if err := proto.Unmarshal(wire, &envelope); err != nil {
					t.Fatalf("decode: %v", err)
				}
				testCase.mutate(&envelope)
				var err error
				if wire, err = proto.Marshal(&envelope); err != nil {
					t.Fatalf("re-encode: %v", err)
				}
			}
			if err := bus.Publish(subject, wire); err != nil {
				t.Fatalf("publish: %v", err)
			}
			if got := handraiseCount(t, c, session, task); got != 0 {
				t.Fatalf("a non-conforming envelope advanced the FSM: handraises=%d", got)
			}
			if len(submitter.assign) != 0 {
				t.Fatalf("a non-conforming envelope produced %d AssignTx", len(submitter.assign))
			}
		})
	}
}

// TestInboundEnvelopeAcceptsAConformingFrame is the control for the counterexamples above: a fully
// conforming frame on the same pipeline must be accepted, otherwise "all rejected" does not prove
// the rejections were due to non-conformance.
func TestInboundEnvelopeAcceptsAConformingFrame(t *testing.T) {
	c, bus, keys, _, session, task, subject := busEnvelopeRejectionFixture(t)
	candidate := testOperator("worker-1")
	publishEnvelope(t, bus, keys, candidate, subject, wirebus.KindWorkerHandraise,
		testWorkerHandraise(session, task, candidate))
	if got := handraiseCount(t, c, session, task); got != 1 {
		t.Fatalf("a conforming envelope was not accepted: handraises=%d", got)
	}
}

// TestInboundEnvelopeRejectsReplay is the replay store part of acceptance 3: the same
// (chain_id, sender_operator, authorization_nonce, message_id / nonce) re-sent with different
// content must be rejected (verification step 7, StoreOnce).
func TestInboundEnvelopeRejectsReplay(t *testing.T) {
	c, bus, keys, _, session, task, subject := busEnvelopeRejectionFixture(t)
	candidate := testOperator("worker-1")

	first := signTestEnvelope(t, keys, wirebus.ParticipantCortex, candidate, subject,
		wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, candidate), nil)
	if err := bus.Publish(subject, first); err != nil {
		t.Fatalf("publish first: %v", err)
	}
	if got := handraiseCount(t, c, session, task); got != 1 {
		t.Fatalf("first frame was not accepted: handraises=%d", got)
	}

	// Same message_id + same nonce but different content -> same key, different signature digest = replay/conflict.
	var original busv1.BusEnvelopeV1
	if err := proto.Unmarshal(first, &original); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	conflicting := signTestEnvelope(t, keys, wirebus.ParticipantCortex, candidate, subject,
		wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, testOperator("worker-2")),
		func(e *busv1.BusEnvelopeV1) {
			e.MessageId = original.GetMessageId()
			e.Nonce = original.GetNonce()
		})
	if err := bus.Publish(subject, conflicting); err != nil {
		t.Fatalf("publish conflicting: %v", err)
	}
	if got := handraiseCount(t, c, session, task); got != 1 {
		t.Fatalf("a replayed key with a different signing digest advanced the FSM: handraises=%d", got)
	}

	// A byte-identical redelivery is a legitimate retry: the replay store must not reject it (JetStream redelivers).
	if err := bus.Publish(subject, first); err != nil {
		t.Fatalf("publish exact retry: %v", err)
	}
	if got := handraiseCount(t, c, session, task); got != 1 {
		t.Fatalf("an exact retry changed the FSM: handraises=%d", got)
	}
}

// TestInboundEnvelopeFailsClosedWhenBindingUnavailable locks in "cannot query != determined invalid":
// when the on-chain binding lookup fails, reject and let the caller tell it apart as a chain lookup failure.
func TestInboundEnvelopeFailsClosedWhenBindingUnavailable(t *testing.T) {
	c, bus, keys, _, session, task, subject := busEnvelopeRejectionFixture(t)
	candidate := testOperator("worker-1")
	wire := signTestEnvelope(t, keys, wirebus.ParticipantCortex, candidate, subject,
		wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, candidate), nil)
	keys.revoke(servicekey.ParticipantCortex, candidate)

	if err := bus.Publish(subject, wire); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := handraiseCount(t, c, session, task); got != 0 {
		t.Fatalf("a frame without a current service binding advanced the FSM: handraises=%d", got)
	}
}
