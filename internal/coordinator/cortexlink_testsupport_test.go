package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// Test harness for Builder messages to Cortex: every OpenVerify and VerifierAssignmentNotify is
// signed by the Builder's current service key, so the tests too need a real private key and a
// queryable on-chain binding; there is no signature-free test mode.

const (
	testAddressPrefix   = "trueopen"
	testSnapshotHeight  = uint64(120_000)
	testAuthorizationNo = uint64(23)
)

// testOperator derives a canonical bech32 operator address from a logical name: the wire signing
// projection decodes addresses into codec bytes, so a non-bech32 placeholder name cannot be signed.
// The same logical name yields the same address in every test.
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
	// pending holds the registered replacement of a (participant|operator) key.
	pending map[string]*chaincli.PendingServiceKeyRotation
}

func newTestServiceKeys() *testServiceKeys {
	return &testServiceKeys{signers: map[string]signer.Signer{}, revoked: map[string]bool{},
		pending: map[string]*chaincli.PendingServiceKeyRotation{}}
}

func (k *testServiceKeys) setPending(participantType, operator string, p *chaincli.PendingServiceKeyRotation) {
	k.mu.Lock()
	k.pending[testServiceKeyKey(participantType, operator)] = p
	k.mu.Unlock()
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
	pending := k.pending[testServiceKeyKey(participantType, operator)]
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
		PendingRotation:    pending,
	}, nil
}

// fakeCortexLink is the in-memory CortexLink of the tests: it keeps every broadcast frame.
type fakeCortexLink struct {
	mu      sync.Mutex
	frames  []*nexusv1.DispatchStreamFrameV1
	err     error
	retired []string // "<task_id hex>/<verify_round>"
}

func (l *fakeCortexLink) Retire(taskID []byte, verifyRound uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.retired = append(l.retired, fmt.Sprintf("%x/%d", taskID, verifyRound))
}

func (l *fakeCortexLink) retiredRounds() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.retired...)
}

func (l *fakeCortexLink) Broadcast(_ context.Context, frame *nexusv1.DispatchStreamFrameV1) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.frames = append(l.frames, proto.Clone(frame).(*nexusv1.DispatchStreamFrameV1))
	return nil
}

func (l *fakeCortexLink) setErr(err error) {
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
}

// openVerifies returns the OpenVerify messages broadcast so far.
func (l *fakeCortexLink) openVerifies() []*nexusv1.OpenVerifyV1 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*nexusv1.OpenVerifyV1
	for _, frame := range l.frames {
		if msg := frame.GetOpenVerify(); msg != nil {
			out = append(out, msg)
		}
	}
	return out
}

// verifierAssignments returns the VerifierAssignmentNotify messages broadcast so far.
func (l *fakeCortexLink) verifierAssignments() []*nexusv1.VerifierAssignmentNotifyV1 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*nexusv1.VerifierAssignmentNotifyV1
	for _, frame := range l.frames {
		if msg := frame.GetVerifierAssignment(); msg != nil {
			out = append(out, msg)
		}
	}
	return out
}

// openVerifyCounter counts the OPEN_VERIFY messages sent to the Cortex streams.
type openVerifyCounter struct{ link *fakeCortexLink }

func (o openVerifyCounter) count() int { return len(o.link.openVerifies()) }

// assignmentCounter counts the VERIFIER_ASSIGNMENT_NOTIFY messages sent to the Cortex streams.
type assignmentCounter struct{ link *fakeCortexLink }

func (o assignmentCounter) count() int { return len(o.link.verifierAssignments()) }

// enableTestBuilderMessages attaches a service key and a fake CortexLink to a Coordinator built with
// New(). In production identity.LoadServiceSigner and the app wiring do this.
func enableTestBuilderMessages(c *Coordinator) (*testServiceKeys, *fakeCortexLink) {
	keys := newTestServiceKeys()
	link := &fakeCortexLink{}
	c.serviceSigner = keys.signerFor(servicekey.ParticipantBuilder, c.active.self)
	c.serviceKeys = keys
	c.addressPrefix = testAddressPrefix
	c.cortex = link
	return keys, link
}

// assertBuilderSigned checks that a Builder message carries this Builder's binding and that its
// builder_service_signature verifies, under the Builder's current service key, over the wire
// signing digest of the message.
func assertBuilderSigned(t *testing.T, c *Coordinator, name string, msg proto.Message, binding *nexusv1.BuilderMessageBindingV1, signature []byte) {
	t.Helper()
	if binding.GetChainId() != c.chainID || binding.GetBuilderAddress() != c.active.self ||
		binding.GetServiceAuthorizationNonce() != testAuthorizationNo {
		t.Fatalf("%s binding = %+v", name, binding)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		t.Fatalf("%s signing digest: %v", name, err)
	}
	keys := newTestServiceKeys()
	pub := keys.signerFor(servicekey.ParticipantBuilder, c.active.self).PubKeyCompressed()
	if err := dispatch.VerifyDigestSignature(pub, digest[:], signature); err != nil {
		t.Fatalf("%s builder_service_signature does not verify: %v", name, err)
	}
}

// trackTestOrder starts tracking an order as a Pending task, as OnOrder does, without a
// dispatcher.
func trackTestOrder(c *Coordinator, o types.Order) error {
	key := taskKey(o.SessionID, o.TaskID)
	_, terminal, err := c.terminalMarker(key)
	if err != nil || terminal {
		return err
	}
	o.Payload = nil
	c.mu.Lock()
	if _, terminal := c.terminalTasks[key]; terminal {
		c.mu.Unlock()
		return nil
	}
	if _, exists := c.tasks[key]; exists {
		c.mu.Unlock()
		return nil
	}
	fsm := c.newFSM(o)
	c.tasks[key] = fsm
	c.mu.Unlock()
	if err := c.trackTaskEvents(key, fsm); err != nil {
		c.abandonTask(key, fsm)
		return err
	}
	fsm.mu.Lock()
	fsm.emit(EvOrderReceived, 0)
	err = fsm.save()
	fsm.mu.Unlock()
	return err
}

// recordTestWinner moves a tracked Pending task to Assigned, as the chain's dispatch record does.
func recordTestWinner(c *Coordinator, sessionID, taskID, winner string, height int64) {
	if fsm, ok := c.getFSM(sessionID, taskID); ok {
		fsm.onWinnerRecorded(winner, nil, height, 0)
	}
}

// relayTestVerifyResult relays a Verifier's result receipt as Ingress does.
func relayTestVerifyResult(t *testing.T, c *Coordinator, sessionID, taskID string, receipt *taskv1.ResultReceiptV3) {
	t.Helper()
	if _, err := c.OnVerifyResult(context.Background(), sessionID, taskID, receipt); err != nil {
		t.Fatalf("relay verify result from %s: %v", receipt.GetVerifierOperatorAddress(), err)
	}
}
