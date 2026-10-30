package dispatchstream

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	testChainID = "trueopen-stream-test-1"
	testPrefix  = "trueopen"
	testNonce   = uint64(7)
	waitFor     = 2 * time.Second
)

// testAccount derives a canonical trueopen account from a logical name.
func testAccount(name string) signer.Signer {
	seed := sha256.Sum256([]byte("dispatchstream-test|" + name))
	sg, err := signer.NewFromBytes(seed[:], testPrefix)
	if err != nil {
		panic(err)
	}
	return sg
}

var (
	testBuilder = testAccount("builder").Address()
	cortexA     = testAccount("cortex-a").Address()
	cortexB     = testAccount("cortex-b").Address()
)

// testKeys is the chain's current CORTEX key table: one deterministic key per operator, and the
// previous generation a cutover retained for some.
type testKeys struct {
	mu        sync.Mutex
	nonce     map[string]uint64
	missing   map[string]bool
	revoked   map[string]bool
	previous  map[string]previousKey
	transient bool
	lookups   int
}

// previousKey is a retired generation: its key, nonce and retirement height.
type previousKey struct {
	key     signer.Signer
	nonce   uint64
	retired uint64
}

func newTestKeys() *testKeys {
	return &testKeys{nonce: map[string]uint64{}, missing: map[string]bool{}, revoked: map[string]bool{}, previous: map[string]previousKey{}}
}

// ProofOptions resolves the current generation (REVOKED when revoked), or the previous one of a
// cutover, by nonce.
func (k *testKeys) ProofOptions(_ context.Context, earliestSubmitHeight *uint64) dispatch.ProofKeyOptions {
	return dispatch.ProofKeyOptions{OrderEarliestSubmitHeight: earliestSubmitHeight, LookupProofKey: func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		k.mu.Lock()
		revoked := k.revoked[s.OperatorAddress]
		p, ok := k.previous[s.OperatorAddress]
		k.mu.Unlock()
		if revoked {
			nonce := testNonce
			if n, ok := k.nonce[s.OperatorAddress]; ok {
				nonce = n
			}
			if s.ServiceAuthorizationNonce == nonce {
				return dispatch.ProofKeyBinding{PublicKey: k.signer(s.OperatorAddress).PubKeyCompressed(), ServiceAuthorizationNonce: nonce, Status: dispatch.ProofKeyRevoked}, nil
			}
		}
		current, err := k.CurrentCortexKey(context.Background(), s.OperatorAddress)
		if err != nil {
			return dispatch.ProofKeyBinding{}, err
		}
		if s.ServiceAuthorizationNonce == current.AuthorizationNonce {
			return dispatch.ProofKeyBinding{PublicKey: current.PubKey, ServiceAuthorizationNonce: current.AuthorizationNonce, Status: dispatch.ProofKeyActive}, nil
		}
		if ok && s.ServiceAuthorizationNonce == p.nonce {
			return dispatch.ProofKeyBinding{PublicKey: p.key.PubKeyCompressed(), ServiceAuthorizationNonce: p.nonce, Status: dispatch.ProofKeyPrevious,
				PreviousRetiredHeight: p.retired}, nil
		}
		return dispatch.ProofKeyBinding{}, errors.New("unknown generation")
	}}
}

func (k *testKeys) signer(operator string) signer.Signer { return testAccount("service|" + operator) }

func (k *testKeys) CurrentCortexKey(_ context.Context, operator string) (CortexKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lookups++
	if k.transient {
		return CortexKey{}, fmt.Errorf("%w: node down", ErrTransient)
	}
	if k.missing[operator] {
		return CortexKey{}, errors.New("no current key")
	}
	if k.revoked[operator] {
		return CortexKey{}, errors.New("current key revoked")
	}
	nonce := testNonce
	if n, ok := k.nonce[operator]; ok {
		nonce = n
	}
	return CortexKey{PubKey: k.signer(operator).PubKeyCompressed(), AuthorizationNonce: nonce}, nil
}

func (k *testKeys) setTransient(v bool) {
	k.mu.Lock()
	k.transient = v
	k.mu.Unlock()
}

// sign fills the service signature of msg (via set) over its wire signing digest.
func sign(t *testing.T, sg signer.Signer, name string, msg proto.Message, set func([]byte)) {
	t.Helper()
	set(nil)
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		t.Fatalf("%s digest: %v", name, err)
	}
	signature, err := sg.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	set(signature)
}

func hash32(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

func member(operator string) *taskv1.CandidateMemberRefV1 {
	return &taskv1.CandidateMemberRefV1{
		CandidatePoolSnapshotId: hash32("snapshot"), Slot: 3, SlotVersion: 2, OperatorAddress: operator,
	}
}

func (k *testKeys) binding(t *testing.T, operator string, streamNonce []byte) *nexusv1.DispatchStreamBindingV1 {
	t.Helper()
	b := &nexusv1.DispatchStreamBindingV1{
		SchemaVersion: 1, ChainId: testChainID, BuilderOperator: testBuilder, CortexOperator: operator,
		ServiceAuthorizationNonce: testNonce, StreamNonce: streamNonce,
	}
	k.signBinding(t, b)
	return b
}

func (k *testKeys) signBinding(t *testing.T, b *nexusv1.DispatchStreamBindingV1) {
	t.Helper()
	sign(t, k.signer(b.GetCortexOperator()), bindingMessage, b, func(s []byte) { b.ServiceSignature = s })
}

func (k *testKeys) accept(t *testing.T, operator, label string) *taskv1.DispatchAcceptV1 {
	t.Helper()
	m := &taskv1.DispatchAcceptV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: hash32("task|" + label), TaskHash: hash32("hash|" + label),
		DispatchTicketHash: hash32("ticket|" + label), Member: member(operator), ServiceAuthorizationNonce: testNonce,
	}
	sign(t, k.signer(operator), "task.v1.DispatchAcceptV1", m, func(s []byte) { m.ServiceSignature = s })
	return m
}

func (k *testKeys) reject(t *testing.T, operator, label string) *taskv1.DispatchRejectV1 {
	t.Helper()
	m := &taskv1.DispatchRejectV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: hash32("task|" + label), TaskHash: hash32("hash|" + label),
		DispatchTicketHash: hash32("ticket|" + label), Member: member(operator), ServiceAuthorizationNonce: testNonce,
		RejectReason: taskv1.DispatchRejectReasonV1(1),
	}
	sign(t, k.signer(operator), "task.v1.DispatchRejectV1", m, func(s []byte) { m.ServiceSignature = s })
	return m
}

func (k *testKeys) inputRequest(t *testing.T, operator, label string) *nexusv1.DispatchInputRequestV1 {
	t.Helper()
	m := &nexusv1.DispatchInputRequestV1{
		TaskId: hash32("task|" + label), DispatchTicketHash: hash32("ticket|" + label), Member: member(operator),
		ServiceAuthorizationNonce: testNonce, DispatchAcceptDigest: hash32("accept|" + label),
	}
	sign(t, k.signer(operator), "nexus.v1.DispatchInputRequestV1", m, func(s []byte) { m.ServiceSignature = s })
	return m
}

func (k *testKeys) standing(t *testing.T, operator string) *taskv1.StandingHandraiseV1 {
	t.Helper()
	m := &taskv1.StandingHandraiseV1{
		SchemaVersion: 1, ChainId: testChainID, BuilderAddress: testBuilder, Member: member(operator),
		Profiles:      []*taskv1.DispatchProfileV1{{ModelId: hash32("model"), ProfileVersion: 1}},
		FreeSlotCount: 2, IssuedHeight: 100, ExpiryHeight: 200, HandraiseNonce: 1, ServiceAuthorizationNonce: testNonce,
	}
	sign(t, k.signer(operator), "task.v1.StandingHandraiseV1", m, func(s []byte) { m.ServiceSignature = s })
	return m
}

func (k *testKeys) verifyNotice(t *testing.T, operator, label string) *nexusv1.VerifyResultSubmittedNoticeV1 {
	t.Helper()
	m := &nexusv1.VerifyResultSubmittedNoticeV1{
		TaskId: hash32("task|" + label), TaskHash: hash32("hash|" + label), VerifyRound: 1,
		CommitKey: hash32("commit|" + label), OperatorAddress: operator, ServiceAuthorizationNonce: testNonce,
	}
	sign(t, k.signer(operator), "nexus.v1.VerifyResultSubmittedNoticeV1", m, func(s []byte) { m.ServiceSignature = s })
	return m
}

func (k *testKeys) verifierHandraise(t *testing.T, operator string) *taskv1.VerifierHandraiseV1 {
	t.Helper()
	m := &taskv1.VerifierHandraiseV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: hash32("task|vh"), VerifyRound: 1,
		InferReceiptHash: hash32("receipt"), OutputHash: hash32("output"), ModelId: hash32("model"), ProfileVersion: 1,
		Member: member(operator), Duty: 2, ServiceAuthorizationNonce: testNonce, ExpiryHeight: 500,
	}
	sign(t, k.signer(operator), verifierHandraiseMessage, m, func(s []byte) { m.ServiceSignature = s })
	return m
}

// memStream is an in-memory FrameStream: the test plays the Cortex.
type memStream struct {
	in     chan *nexusv1.DispatchStreamFrameV1 // Cortex -> Builder
	out    chan *nexusv1.DispatchStreamFrameV1 // Builder -> Cortex
	closed chan struct{}
	once   sync.Once
}

func newMemStream() *memStream {
	return &memStream{
		in: make(chan *nexusv1.DispatchStreamFrameV1, 64), out: make(chan *nexusv1.DispatchStreamFrameV1, 256),
		closed: make(chan struct{}),
	}
}

func (m *memStream) Receive() (*nexusv1.DispatchStreamFrameV1, error) {
	select {
	case f := <-m.in:
		return f, nil
	case <-m.closed:
		return nil, io.EOF
	}
}

func (m *memStream) Send(f *nexusv1.DispatchStreamFrameV1) error {
	select {
	case <-m.closed:
		return io.ErrClosedPipe
	default:
	}
	select {
	case m.out <- proto.Clone(f).(*nexusv1.DispatchStreamFrameV1):
		return nil
	case <-m.closed:
		return io.ErrClosedPipe
	}
}

func (m *memStream) close() { m.once.Do(func() { close(m.closed) }) }

// next returns the next frame the Builder sent, failing after waitFor.
func (m *memStream) next(t *testing.T) *nexusv1.DispatchStreamFrameV1 {
	t.Helper()
	select {
	case f := <-m.out:
		return f
	case <-time.After(waitFor):
		t.Fatal("no frame from the Builder")
		return nil
	}
}

// nextBusiness skips transport frames.
func (m *memStream) nextBusiness(t *testing.T) *nexusv1.DispatchStreamFrameV1 {
	t.Helper()
	for {
		f := m.next(t)
		switch f.GetMessage().(type) {
		case *nexusv1.DispatchStreamFrameV1_Ack, *nexusv1.DispatchStreamFrameV1_Keepalive:
			continue
		}
		return f
	}
}

// nextAck skips everything but acks.
func (m *memStream) nextAck(t *testing.T) uint64 {
	t.Helper()
	for {
		if a := m.next(t).GetAck(); a != nil {
			return a.GetAckedCursor()
		}
	}
}

// quiet asserts the Builder sends nothing for a short while.
func (m *memStream) quiet(t *testing.T) {
	t.Helper()
	select {
	case f := <-m.out:
		t.Fatalf("unexpected frame from the Builder: %v", f)
	case <-time.After(50 * time.Millisecond):
	}
}

// harness runs a hub with fake keys over the in-memory store.
type harness struct {
	t     *testing.T
	hub   *Hub
	keys  *testKeys
	store kv.Store
	ticks chan time.Time
	clock *fakeClock
	conn  chan connEvent
	sinks *recordingSinks
}

type connEvent struct {
	operator  string
	connected bool
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()
	return newHarnessOn(t, kv.NewMemStore(), newTestKeys(), opts...)
}

func newHarnessOn(t *testing.T, store kv.Store, keys *testKeys, opts ...Option) *harness {
	t.Helper()
	h := &harness{t: t, keys: keys, store: store, ticks: make(chan time.Time), conn: make(chan connEvent, 32),
		clock: &fakeClock{now: time.UnixMilli(1_700_000_000_000)}, sinks: &recordingSinks{}}
	opts = append([]Option{WithConnectionObserver(func(op string, c bool) { h.conn <- connEvent{op, c} })}, opts...)
	hub, err := New(nil, Config{ChainID: testChainID, BuilderOperator: testBuilder, MaxPending: 8}, keys, store, opts...)
	if err != nil {
		t.Fatal(err)
	}
	hub.now = h.clock.Now
	hub.keepaliveTicks = func(time.Duration) (<-chan time.Time, func()) { return h.ticks, func() {} }
	hub.SetSinks(Sinks{Handraise: h.sinks, Dispatch: h.sinks, Verifier: h.sinks})
	h.hub = hub
	return h
}

// served is one running Serve call.
type served struct {
	stream *memStream
	nonce  []byte
	cursor uint64
	result chan error
}

// open starts Serve on a fresh stream and sends frame first.
func (h *harness) open(first *nexusv1.DispatchStreamFrameV1) *served {
	s := &served{stream: newMemStream(), nonce: first.GetStreamNonce(), result: make(chan error, 1)}
	s.stream.in <- first
	go func() { s.result <- h.hub.Serve(context.Background(), s.stream) }()
	return s
}

// connect binds operator with a fresh stream nonce and waits until the hub reports it connected.
func (h *harness) connect(operator, nonceLabel string) *served {
	h.t.Helper()
	nonce := hash32("stream|" + nonceLabel)
	s := h.open(&nexusv1.DispatchStreamFrameV1{
		StreamNonce: nonce,
		Message:     &nexusv1.DispatchStreamFrameV1_Binding{Binding: h.keys.binding(h.t, operator, nonce)},
	})
	h.waitConn(operator, true)
	return s
}

func (h *harness) waitConn(operator string, connected bool) {
	h.t.Helper()
	for {
		select {
		case ev := <-h.conn:
			if ev.operator == operator && ev.connected == connected {
				return
			}
		case <-time.After(waitFor):
			h.t.Fatalf("no connection event %s=%v", operator, connected)
		}
	}
}

// send delivers one uplink business frame (only its message is used) with the next cursor.
func (s *served) send(f *nexusv1.DispatchStreamFrameV1) uint64 {
	s.cursor++
	s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce, Cursor: s.cursor, Message: f.GetMessage()}
	return s.cursor
}

func (s *served) ack(cursor uint64) {
	s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
		Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{AckedCursor: cursor}}}
}

func (s *served) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.result:
		return err
	case <-time.After(waitFor):
		t.Fatal("Serve did not return")
		return nil
	}
}

// recordingSinks records every routed message.
type recordingSinks struct {
	mu        sync.Mutex
	routed    []string
	origins   []Origin
	err       error
	operators []string
	// heights are the earliest_submit_height of the orders of known tickets.
	heights map[string]uint64
}

func (r *recordingSinks) OrderEarliestSubmitHeight(ticketHash []byte) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.heights[string(ticketHash)]
	return h, ok
}

func (r *recordingSinks) record(kind string, from Origin, operator string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routed = append(r.routed, kind)
	r.origins = append(r.origins, from)
	r.operators = append(r.operators, operator)
	return r.err
}

func (r *recordingSinks) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.routed...)
}

func (r *recordingSinks) setErr(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

func (r *recordingSinks) HandleStandingHandraise(_ context.Context, from Origin, _ *taskv1.StandingHandraiseV1) error {
	return r.record("handraise", from, from.Operator)
}
func (r *recordingSinks) HandleDispatchAccept(_ context.Context, from Origin, _ *taskv1.DispatchAcceptV1) error {
	return r.record("accept", from, from.Operator)
}
func (r *recordingSinks) HandleDispatchReject(_ context.Context, from Origin, _ *taskv1.DispatchRejectV1) error {
	return r.record("reject", from, from.Operator)
}
func (r *recordingSinks) HandleDispatchInputRequest(_ context.Context, from Origin, _ *nexusv1.DispatchInputRequestV1) error {
	return r.record("input_request", from, from.Operator)
}
func (r *recordingSinks) HandleVerifierHandraise(_ context.Context, operator string, _ *taskv1.VerifierHandraiseV1) error {
	return r.record("verifier_handraise", Origin{}, operator)
}
func (r *recordingSinks) HandleVerifyResultSubmitted(_ context.Context, operator string, _ *nexusv1.VerifyResultSubmittedNoticeV1) error {
	return r.record("verify_result_submitted", Origin{}, operator)
}

// offer is a downlink message carrying a recognisable ticket hash.
func offer(label string) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{
		Ticket: &taskv1.DispatchTicketV1{TaskId: hash32("task|" + label), BuilderServiceSignature: []byte("sig|" + label)},
	}}}
}

func offerLabelOf(t *testing.T, f *nexusv1.DispatchStreamFrameV1) string {
	t.Helper()
	sig := string(f.GetOffer().GetTicket().GetBuilderServiceSignature())
	if len(sig) < 4 {
		t.Fatalf("frame is not a test offer: %v", f)
	}
	return sig[4:]
}
