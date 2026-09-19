package busadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	wirebus "github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	testChainID  = "trueopen-localnet-1"
	testOperator = "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"
	testSubject  = "trueopen.handraise.worker.task-1"
)

type capturedPublish struct {
	subject string
	data    []byte
	msgID   string
	tier    string
}

type captureBus struct {
	published []capturedPublish
	fail      error
}

func (b *captureBus) Publish(subject string, data []byte) error {
	if b.fail != nil {
		return b.fail
	}
	b.published = append(b.published, capturedPublish{subject: subject, data: append([]byte(nil), data...), tier: "core"})
	return nil
}

func (b *captureBus) JSPublish(subject string, data []byte, msgID string) error {
	if b.fail != nil {
		return b.fail
	}
	b.published = append(b.published, capturedPublish{subject: subject, data: append([]byte(nil), data...), msgID: msgID, tier: "js"})
	return nil
}

func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	seed := sha256.Sum256([]byte("busadapter roundtrip key"))
	s, err := signer.NewFromBytes(seed[:], "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fixture struct {
	publisher *Publisher
	receiver  *Receiver
	bus       *captureBus
	outbox    *Outbox
	signer    signer.Signer
	nowMS     uint64
}

func newRoundtripFixture(t *testing.T) *fixture {
	t.Helper()
	serviceSigner := testSigner(t)
	bus := &captureBus{}
	outbox := NewOutbox(kv.NewMemStore())
	nowMS := uint64(1_700_000_000_000)
	now := func() uint64 { return nowMS }

	publisher := NewPublisher(PublisherConfig{
		ChainID:         testChainID,
		OperatorAddress: testOperator,
		ParticipantType: wirebus.ParticipantBuilder,
		Signer:          serviceSigner,
		AuthorizationNonce: func(context.Context) (uint64, error) {
			return 7, nil
		},
		Outbox: outbox,
		Bus:    bus,
		TTLMS:  30_000,
		Now:    now,
	})
	receiver := NewReceiver(ReceiverConfig{
		ChainID: testChainID,
		LookupBinding: func(_ context.Context, participantType int32, operator string) (wirebus.KeyBinding, error) {
			if participantType != wirebus.ParticipantBuilder || operator != testOperator {
				return wirebus.KeyBinding{}, errors.New("unknown operator")
			}
			return wirebus.KeyBinding{
				PubKeyCompressed:   serviceSigner.PubKeyCompressed(),
				AuthorizationNonce: 7,
				Active:             true,
			}, nil
		},
		Replay:               NewKVReplayStore(kv.NewMemStore()),
		MaxEnvelopeBytes:     1 << 20,
		ReplaySafetyMarginMS: 60_000,
		Now:                  now,
	})
	return &fixture{publisher: publisher, receiver: receiver, bus: bus, outbox: outbox, signer: serviceSigner, nowMS: nowMS}
}

func testHandraise() *taskv1.WorkerHandraiseV1 {
	return &taskv1.WorkerHandraiseV1{
		SchemaVersion: 1,
		ChainId:       testChainID,
		TaskId:        bytes.Repeat([]byte{0xAB}, 32),
		TaskHash:      bytes.Repeat([]byte{0xCD}, 32),
	}
}

// Full publish -> receive path: the envelope verifies, the payload decodes back to the same message, and
// the outbox holds bytes identical to what went onto the bus.
func TestPublishReceiveRoundtrip(t *testing.T) {
	fx := newRoundtripFixture(t)
	payload := testHandraise()

	messageID, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, payload, TierJetStream)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(fx.bus.published) != 1 {
		t.Fatalf("published %d messages, want 1", len(fx.bus.published))
	}
	sent := fx.bus.published[0]
	if sent.subject != testSubject || sent.msgID != messageID {
		t.Fatalf("published subject/msgID mismatch: %+v", sent)
	}

	pending, err := fx.outbox.Pending(fx.nowMS)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !bytes.Equal(pending[0].Wire, sent.data) {
		t.Fatalf("outbox does not hold the exact published bytes")
	}

	inbound, err := fx.receiver.Receive(context.Background(), testSubject, sent.data)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	got, ok := inbound.Payload.(*taskv1.WorkerHandraiseV1)
	if !ok {
		t.Fatalf("payload type = %T, want WorkerHandraiseV1", inbound.Payload)
	}
	if !proto.Equal(got, payload) {
		t.Fatalf("payload round-trip mismatch")
	}
	if inbound.Envelope.GetKind() != busv1.BusMessageKind_BUS_MESSAGE_KIND_WORKER_HANDRAISE {
		t.Fatalf("kind = %v", inbound.Envelope.GetKind())
	}

	// Redelivering the same bytes is a legitimate retry.
	if _, err := fx.receiver.Receive(context.Background(), testSubject, sent.data); err != nil {
		t.Fatalf("legal redelivery rejected: %v", err)
	}
}

// Tampering with a single payload byte makes the digest mismatch, and verification step 4 rejects it.
func TestReceiveRejectsTamperedPayload(t *testing.T) {
	fx := newRoundtripFixture(t)
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, testHandraise(), TierJetStream); err != nil {
		t.Fatal(err)
	}
	sent := fx.bus.published[0].data

	var envelope busv1.BusEnvelopeV1
	if err := proto.Unmarshal(sent, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload[0] ^= 0x01
	tampered, err := proto.Marshal(&envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.receiver.Receive(context.Background(), testSubject, tampered); !errors.Is(err, wirebus.ErrPayload) {
		t.Fatalf("err = %v, want payload digest failure", err)
	}
}

// Publishing with a kind that does not match payload_type must be rejected locally and never go out.
func TestPublishRejectsWrongPayloadType(t *testing.T) {
	fx := newRoundtripFixture(t)
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindOrderBroadcast, testHandraise(), TierCore); err == nil {
		t.Fatal("kind/payload mismatch accepted")
	}
	if len(fx.bus.published) != 0 {
		t.Fatal("mismatched message was published")
	}
}

// A failed chain query (chain lookup unavailable) must be distinguishable from "the binding is invalid": the
// former is Nak'd and awaits redelivery, the latter is acked and discarded.
func TestReceiveDistinguishesAuthorityUnavailable(t *testing.T) {
	fx := newRoundtripFixture(t)
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, testHandraise(), TierJetStream); err != nil {
		t.Fatal(err)
	}
	sent := fx.bus.published[0].data

	down := NewReceiver(ReceiverConfig{
		ChainID: testChainID,
		LookupBinding: func(context.Context, int32, string) (wirebus.KeyBinding, error) {
			return wirebus.KeyBinding{}, ErrAuthorityUnavailable
		},
		Replay:               NewKVReplayStore(kv.NewMemStore()),
		MaxEnvelopeBytes:     1 << 20,
		ReplaySafetyMarginMS: 60_000,
		Now:                  func() uint64 { return fx.nowMS },
	})
	if _, err := down.Receive(context.Background(), testSubject, sent); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("err = %v, want authority-unavailable", err)
	}

	inactive := NewReceiver(ReceiverConfig{
		ChainID: testChainID,
		LookupBinding: func(context.Context, int32, string) (wirebus.KeyBinding, error) {
			return wirebus.KeyBinding{
				PubKeyCompressed:   fx.signer.PubKeyCompressed(),
				AuthorizationNonce: 7,
				Active:             false,
			}, nil
		},
		Replay:               NewKVReplayStore(kv.NewMemStore()),
		MaxEnvelopeBytes:     1 << 20,
		ReplaySafetyMarginMS: 60_000,
		Now:                  func() uint64 { return fx.nowMS },
	})
	_, err := inactive.Receive(context.Background(), testSubject, sent)
	if !errors.Is(err, wirebus.ErrKeyBinding) || errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("err = %v, want plain key-binding rejection", err)
	}
}

// Core-tier publishing goes through the ordinary Publish; Republish must also resend at the stored tier.
func TestPublishCoreTierRouting(t *testing.T) {
	fx := newRoundtripFixture(t)
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, testHandraise(), TierCore); err != nil {
		t.Fatal(err)
	}
	if len(fx.bus.published) != 1 || fx.bus.published[0].tier != "core" {
		t.Fatalf("published = %+v, want one core-tier publish", fx.bus.published)
	}
	fx.bus.published = nil
	if err := fx.publisher.Republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fx.bus.published) != 1 || fx.bus.published[0].tier != "core" {
		t.Fatalf("republished = %+v, want one core-tier publish", fx.bus.published)
	}
}

// A failed publish keeps the outbox entry (so it can be resent verbatim after a restart); Republish resends it verbatim.
func TestRepublishResendsExactBytes(t *testing.T) {
	fx := newRoundtripFixture(t)
	fx.bus.fail = errors.New("nats down")
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, testHandraise(), TierJetStream); err == nil {
		t.Fatal("publish should surface bus error")
	}
	pending, err := fx.outbox.Pending(fx.nowMS)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1 (entry persisted before publish)", len(pending))
	}

	fx.bus.fail = nil
	if err := fx.publisher.Republish(context.Background()); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if len(fx.bus.published) != 1 {
		t.Fatalf("republished %d messages, want 1", len(fx.bus.published))
	}
	if !bytes.Equal(fx.bus.published[0].data, pending[0].Wire) {
		t.Fatal("republish did not reuse the exact stored bytes")
	}
	if fx.bus.published[0].msgID != pending[0].MessageID {
		t.Fatal("republish did not reuse the stored message_id")
	}
}

type failingStore struct {
	kv.Store
	fail bool
}

func (s *failingStore) Set(ns kv.Namespace, key string, val []byte) error {
	if s.fail && ns == kv.NSBusReplay {
		return errors.New("disk full")
	}
	return s.Store.Set(ns, key, val)
}

// An infrastructure failure of the replay store must surface as the wirebus.ErrStoreFailure class (so the
// JetStream consumer Naks for redelivery), and the same frame must be accepted normally once it recovers.
func TestReceiveSurfacesReplayStoreFailure(t *testing.T) {
	fx := newRoundtripFixture(t)
	if _, err := fx.publisher.Publish(
		context.Background(), testSubject, wirebus.KindWorkerHandraise, testHandraise(), TierJetStream); err != nil {
		t.Fatal(err)
	}
	sent := fx.bus.published[0].data

	backing := &failingStore{Store: kv.NewMemStore(), fail: true}
	receiver := NewReceiver(ReceiverConfig{
		ChainID: testChainID,
		LookupBinding: func(context.Context, int32, string) (wirebus.KeyBinding, error) {
			return wirebus.KeyBinding{
				PubKeyCompressed:   fx.signer.PubKeyCompressed(),
				AuthorizationNonce: 7,
				Active:             true,
			}, nil
		},
		Replay:               NewKVReplayStore(backing),
		MaxEnvelopeBytes:     1 << 20,
		ReplaySafetyMarginMS: 60_000,
		Now:                  func() uint64 { return fx.nowMS },
	})
	if _, err := receiver.Receive(context.Background(), testSubject, sent); !errors.Is(err, wirebus.ErrStoreFailure) {
		t.Fatalf("err = %v, want store-failure class", err)
	}
	backing.fail = false
	if _, err := receiver.Receive(context.Background(), testSubject, sent); err != nil {
		t.Fatalf("receive after store recovery: %v", err)
	}
}

// Republish must attempt every entry: one persistently failing entry must not block the others, or those
// would be dropped within the TTL without ever being attempted.
func TestRepublishAttemptsEveryEntry(t *testing.T) {
	backing := kv.NewMemStore()
	outbox := NewOutbox(backing)
	for _, id := range []string{"m-1", "m-2", "m-3"} {
		if err := outbox.Put(OutboxEntry{
			MessageID: id, Subject: "s-" + id, Tier: TierJetStream,
			Wire: []byte(id), ExpiresAtUnixMS: 9_000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	bus := &selectiveFailBus{failSubject: "s-m-1"}
	publisher := NewPublisher(PublisherConfig{
		Outbox: outbox, Bus: bus, Now: func() uint64 { return 1_000 },
	})
	err := publisher.Republish(context.Background())
	if err == nil {
		t.Fatal("republish must report the failing entry")
	}
	if len(bus.attempted) != 3 {
		t.Fatalf("attempted %v, want all three entries tried", bus.attempted)
	}
}

type selectiveFailBus struct {
	failSubject string
	attempted   []string
}

func (b *selectiveFailBus) Publish(subject string, _ []byte) error {
	b.attempted = append(b.attempted, subject)
	if subject == b.failSubject {
		return errors.New("still down")
	}
	return nil
}

func (b *selectiveFailBus) JSPublish(subject string, data []byte, _ string) error {
	return b.Publish(subject, data)
}
