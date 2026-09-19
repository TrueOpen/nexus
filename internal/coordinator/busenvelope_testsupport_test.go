package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Test harness for TRUEOPEN_BUS_ENVELOPE_V2: every frame is signed by a current service key and
// verified inbound in the 7-step order of wire bus, so the tests too need a real private key
// and a queryable on-chain binding -- there is no such thing as "signature-free test mode", which
// would reintroduce the unsigned-frame bug.

const (
	testAddressPrefix   = "trueopen"
	testSnapshotHeight  = uint64(120_000)
	testAuthorizationNo = uint64(23)
)

// testOperator derives a canonical bech32 operator address from a logical name: the V2 envelope's
// signing projection decodes sender_operator_address into codec bytes, so a non-bech32 placeholder
// name cannot form a frame. The same logical name yields the same address in every test.
func testOperator(name string) string {
	seed := sha256.Sum256([]byte("test-operator|" + name))
	sg, err := signer.NewFromBytes(seed[:], testAddressPrefix)
	if err != nil {
		panic(err)
	}
	return sg.Address()
}

// testBuilderSelf is the test identity of this node's own Builder.
var testBuilderSelf = testOperator("builder-self")

// testBuilderSetRef holds the same values as the SignedOrderV2 fixture in submitter_test.
var testBuilderSetRef = builderSetRef{
	ID:   "term-1",
	Hash: "0x4444444444444444444444444444444444444444444444444444444444444444",
}

// testServiceKeys is an in-memory implementation of QueryCurrentServiceKey: every
// (participant, operator) has a deterministically derived service key, so sender and receiver line
// up naturally in tests.
type testServiceKeys struct {
	mu      sync.Mutex
	signers map[string]signer.Signer
	// A (participant|operator) listed in revoked returns ErrNotFound from the query; it is used to
	// build the "no usable current key on chain" counterexamples.
	revoked map[string]bool
}

func newTestServiceKeys() *testServiceKeys {
	return &testServiceKeys{signers: map[string]signer.Signer{}, revoked: map[string]bool{}}
}

func testServiceKeyKey(participantType, operator string) string {
	return participantType + "|" + operator
}

// signerFor returns the service key private key for (participant, operator). The key is derived
// deterministically from the pair, so it is reproducible across tests and is not any real key.
func (k *testServiceKeys) signerFor(participantType, operator string) signer.Signer {
	key := testServiceKeyKey(participantType, operator)
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing, ok := k.signers[key]; ok {
		return existing
	}
	seed := sha256.Sum256([]byte("test-service-key|" + key))
	sg, err := signer.NewFromBytes(seed[:], testAddressPrefix)
	if err != nil {
		panic(err)
	}
	k.signers[key] = sg
	return sg
}

func (k *testServiceKeys) revoke(participantType, operator string) {
	k.mu.Lock()
	k.revoked[testServiceKeyKey(participantType, operator)] = true
	k.mu.Unlock()
}

func (k *testServiceKeys) QueryCurrentServiceKey(
	_ context.Context, participantType, operator string,
) (chaincli.ServiceKeyState, error) {
	k.mu.Lock()
	revoked := k.revoked[testServiceKeyKey(participantType, operator)]
	k.mu.Unlock()
	if revoked {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	sg := k.signerFor(participantType, operator)
	return chaincli.ServiceKeyState{
		ParticipantType:    participantType,
		OperatorAddress:    operator,
		ServiceAddress:     sg.Address(),
		ServicePubKey:      hex.EncodeToString(sg.PubKeyCompressed()),
		AuthorizationNonce: testAuthorizationNo,
		UpdatedHeight:      testSnapshotHeight,
		Status:             servicekey.StatusActive,
	}, nil
}

// enableTestBusEnvelopes attaches a service key to a Coordinator built with New(). In production
// identity.LoadServiceSigner does this; the tests do not run the full assembly, so it is filled in
// here and the shared Publisher/Receiver/prepare harness is rebuilt.
func enableTestBusEnvelopes(c *Coordinator) *testServiceKeys {
	keys := newTestServiceKeys()
	c.serviceSigner = keys.signerFor(servicekey.ParticipantBuilder, c.active.self)
	c.serviceKeys = keys
	c.addressPrefix = testAddressPrefix
	c.busPublisher, c.busReceiver = c.buildBusAdapters()
	c.prepares = &prepareCodec{
		log: c.log, chainID: c.chainID, addressPrefix: testAddressPrefix,
		self: c.active.self, signer: c.serviceSigner, authority: keys,
	}
	c.mu.RLock()
	tasks := make([]*taskFSM, 0, len(c.tasks))
	for _, fsm := range c.tasks {
		tasks = append(tasks, fsm)
	}
	c.mu.RUnlock()
	for _, fsm := range tasks {
		fsm.publisher = c.busPublisher
		fsm.receiver = c.busReceiver
		fsm.prepares = c.prepares
	}
	return keys
}

// participantForKind returns the default sender domain for the given kind.
func participantForKind(kind int32) int32 {
	switch kind {
	case bus.KindWorkerHandraise, bus.KindVerifierHandraise,
		bus.KindVerifyResult, bus.KindOutputAvailable:
		return bus.ParticipantCortex
	default:
		return bus.ParticipantBuilder
	}
}

// publishEnvelope signs a V2 frame with the operator's current service key and publishes it to the
// subject, simulating a peer (a Cortex Worker/Verifier) sending a message.
func publishEnvelope(
	t *testing.T, bus msgbus.Bus, keys *testServiceKeys, operator, subject string,
	kind int32, payload proto.Message,
) {
	t.Helper()
	wire := signTestEnvelope(t, keys, participantForKind(kind), operator, subject, kind, payload, nil)
	if err := bus.Publish(subject, wire); err != nil {
		t.Fatalf("publish %s: %v", subject, err)
	}
}

// signTestEnvelope assembles a signed V2 frame; mutate can change fields before signing, which is
// how the "invalid content but valid signature" counterexamples are built. When mutate changes the
// payload the digest is recomputed with it, so a counterexample that needs a mismatched digest must
// set PayloadDigest directly.
func signTestEnvelope(
	t *testing.T, keys *testServiceKeys, participantType int32, operator string,
	subject string, kind int32, payload proto.Message,
	mutate func(*busv1.BusEnvelopeV1),
) []byte {
	t.Helper()
	payloadType, ok := bus.PayloadTypeForKind(kind)
	if !ok {
		t.Fatalf("unknown kind %d", kind)
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	now := uint64(nowMS())
	// message_id/nonce are derived deterministically from (subject, operator, payload): a resend of
	// the same message gets the same pair (a legitimate retry), and different messages get different
	// pairs (no collision on the replay key).
	nonce := make([]byte, bus.NonceSize)
	seed := sha256.Sum256(append([]byte(subject+operator+"|nonce|"), payloadBytes...))
	copy(nonce, seed[:])
	digest := bus.PayloadDigest(payloadBytes)
	envelope := &busv1.BusEnvelopeV1{
		SchemaVersion:             1,
		ChainId:                   testChainID,
		Subject:                   subject,
		Kind:                      busv1.BusMessageKind(kind),
		SenderParticipantType:     sharedv1.ParticipantType(participantType),
		SenderOperatorAddress:     operator,
		ServiceAuthorizationNonce: testAuthorizationNo,
		MessageId:                 "01890000-0000-7000-8000-" + hex.EncodeToString(seed[:6]),
		Nonce:                     nonce,
		IssuedAtUnixMs:            now,
		ExpiresAtUnixMs:           now + 60_000,
		PayloadType:               busv1.BusPayloadType(payloadType),
		Payload:                   payloadBytes,
		PayloadDigest:             digest[:],
	}
	if mutate != nil {
		before := append([]byte(nil), envelope.Payload...)
		mutate(envelope)
		if !equalBytes(before, envelope.Payload) {
			refreshed := bus.PayloadDigest(envelope.Payload)
			envelope.PayloadDigest = refreshed[:]
		}
	}
	fields := bus.Fields{
		SchemaVersion:             envelope.GetSchemaVersion(),
		ChainID:                   envelope.GetChainId(),
		Subject:                   envelope.GetSubject(),
		Kind:                      int32(envelope.GetKind()),
		SenderParticipantType:     int32(envelope.GetSenderParticipantType()),
		SenderOperatorAddress:     envelope.GetSenderOperatorAddress(),
		ServiceAuthorizationNonce: envelope.GetServiceAuthorizationNonce(),
		MessageID:                 envelope.GetMessageId(),
		Nonce:                     envelope.GetNonce(),
		IssuedAtUnixMS:            envelope.GetIssuedAtUnixMs(),
		ExpiresAtUnixMS:           envelope.GetExpiresAtUnixMs(),
		PayloadType:               int32(envelope.GetPayloadType()),
		PayloadDigest:             envelope.GetPayloadDigest(),
	}
	preimage, err := bus.SigningPreimage(fields)
	if err != nil {
		t.Fatalf("signing preimage: %v", err)
	}
	participantName := servicekey.ParticipantBuilder
	if participantType == bus.ParticipantCortex {
		participantName = servicekey.ParticipantCortex
	}
	signature, err := keys.signerFor(participantName, operator).Sign(preimage)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope.ServiceSignature = signature
	wire, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return wire
}

// decodeTestEnvelope decodes a frame captured by a test (no signature verification, structure only).
func decodeTestEnvelope(t *testing.T, data []byte) *busv1.BusEnvelopeV1 {
	t.Helper()
	var envelope busv1.BusEnvelopeV1
	if err := proto.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return &envelope
}

// assertContractEnvelope checks one by one that all 15 fields of the V2 envelope are filled per the
// contract, and that the signature really was produced by the sender's current service key over the
// TRUEOPEN_BUS_ENVELOPE_V2 digest.
func assertContractEnvelope(
	t *testing.T, envelope *busv1.BusEnvelopeV1, subject string, kind int32,
) {
	t.Helper()
	payloadType, _ := bus.PayloadTypeForKind(kind)
	digest := bus.PayloadDigest(envelope.GetPayload())
	checks := []struct {
		field string
		bad   bool
	}{
		{"1 schema_version", envelope.GetSchemaVersion() != 1},
		{"2 chain_id", envelope.GetChainId() != testChainID},
		{"3 subject", envelope.GetSubject() != subject},
		{"4 kind", int32(envelope.GetKind()) != kind},
		{"5 sender_participant_type", int32(envelope.GetSenderParticipantType()) != bus.ParticipantBuilder},
		{"6 sender_operator_address", envelope.GetSenderOperatorAddress() == ""},
		{"7 service_authorization_nonce", envelope.GetServiceAuthorizationNonce() != testAuthorizationNo},
		{"8 message_id", envelope.GetMessageId() == ""},
		{"9 nonce", len(envelope.GetNonce()) != bus.NonceSize},
		{"10 issued_at_unix_ms", envelope.GetIssuedAtUnixMs() == 0},
		{"11 expires_at_unix_ms", envelope.GetExpiresAtUnixMs() <= envelope.GetIssuedAtUnixMs()},
		{"12 payload_type", int32(envelope.GetPayloadType()) != payloadType},
		{"13 payload", len(envelope.GetPayload()) == 0},
		{"14 payload_digest", !equalBytes(envelope.GetPayloadDigest(), digest[:])},
		{"15 service_signature", len(envelope.GetServiceSignature()) != bus.SignatureSize},
	}
	for _, check := range checks {
		if check.bad {
			t.Fatalf("envelope field %s is not contract-conforming: %+v", check.field, envelope)
		}
	}
	fields := bus.Fields{
		SchemaVersion:             envelope.GetSchemaVersion(),
		ChainID:                   envelope.GetChainId(),
		Subject:                   envelope.GetSubject(),
		Kind:                      int32(envelope.GetKind()),
		SenderParticipantType:     int32(envelope.GetSenderParticipantType()),
		SenderOperatorAddress:     envelope.GetSenderOperatorAddress(),
		ServiceAuthorizationNonce: envelope.GetServiceAuthorizationNonce(),
		MessageID:                 envelope.GetMessageId(),
		Nonce:                     envelope.GetNonce(),
		IssuedAtUnixMS:            envelope.GetIssuedAtUnixMs(),
		ExpiresAtUnixMS:           envelope.GetExpiresAtUnixMs(),
		PayloadType:               int32(envelope.GetPayloadType()),
		PayloadDigest:             envelope.GetPayloadDigest(),
	}
	signingDigest, err := bus.SigningDigest(fields)
	if err != nil {
		t.Fatalf("signing digest: %v", err)
	}
	keys := newTestServiceKeys()
	pubKey := keys.signerFor(servicekey.ParticipantBuilder, envelope.GetSenderOperatorAddress()).PubKeyCompressed()
	if err := bus.VerifyDigestSignature(pubKey, signingDigest[:], envelope.GetServiceSignature()); err != nil {
		t.Fatalf("envelope signature does not verify under the sender's current service key: %v", err)
	}
}

// decodeTestPayload decodes the payload of a frame captured by a test (no signature verification).
func decodeTestPayload[T any, P interface {
	*T
	proto.Message
}](t *testing.T, data []byte) P {
	t.Helper()
	envelope := decodeTestEnvelope(t, data)
	out := P(new(T))
	if err := proto.Unmarshal(envelope.GetPayload(), out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return out
}
