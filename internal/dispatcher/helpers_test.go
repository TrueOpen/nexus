package dispatcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	testChainID = "trueopen-phase1-vector-1"
	testPrefix  = "trueopen"
	// Pool members of the tests (the wire vector operators): slot 1, 3 and 7.
	op1 = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8"
	op3 = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3"
	op7 = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

	testESH       = 100
	testBound     = 40
	testDeadline  = testESH + 20 // max(esh, bound_change_height) + record_deadline_blocks
	testUser      = "trueopen1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"
	testMaxSkips  = 2
	testRosterCap = 1 << 20
)

var (
	testSnapshot = fill32(0x66)
	testModel    = fill32(0x77)
	testEpoch    = dispatchdraw.Epoch{Number: 1, ReferenceHeight: 90, Seed: fill32(0x5e), SnapshotID: testSnapshot}
	testProfile  = dispatchdraw.Profile{ModelID: testModel, Version: 1}
	poolMembers  = []dispatch.RosterMember{
		{Slot: 1, SlotVersion: 1, OperatorAddress: op1, CandidateWeight: 1},
		{Slot: 3, SlotVersion: 1, OperatorAddress: op3, CandidateWeight: 5},
		{Slot: 7, SlotVersion: 1, OperatorAddress: op7, CandidateWeight: 2},
	}
	testTiers = []config.RTTTierConfig{{MaxRTTMs: 50, AcceptTimeoutMs: 300}, {MaxRTTMs: 150, AcceptTimeoutMs: 500}}
)

func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func member(op string) dispatch.RosterMember {
	for _, m := range poolMembers {
		if m.OperatorAddress == op {
			return m
		}
	}
	panic("unknown test operator " + op)
}

// testBuilderNonce is the authorization nonce of the test Builder's service key.
const testBuilderNonce = 3

func newTestSigner(t testing.TB, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{seed}, 32), testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---- fakes ----

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool { was := !t.stopped; t.stopped = true; return was }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return t
}

// advance moves the clock and fires the due timers in order, outside the clock's lock.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].at.Before(c.timers[j].at) })
		var due *fakeTimer
		for i, t := range c.timers {
			if !t.stopped && !t.at.After(c.now) {
				due = t
				c.timers = append(c.timers[:i:i], c.timers[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
		if due == nil {
			return
		}
		due.stopped = true
		due.f()
	}
}

type sent struct {
	operator string
	frame    *nexusv1.DispatchStreamFrameV1
}

type fakeStreams struct {
	mu           sync.Mutex
	disconnected map[string]bool
	rtt          map[string]time.Duration
	sent         []sent
	sendErr      error
}

func (s *fakeStreams) Send(_ context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	if s.disconnected[operator] {
		return dispatchstream.ErrNotConnected
	}
	s.sent = append(s.sent, sent{operator, proto.Clone(frame).(*nexusv1.DispatchStreamFrameV1)})
	return nil
}

func (s *fakeStreams) Connected(operator string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.disconnected[operator]
}

func (s *fakeStreams) RTT(operator string) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.rtt[operator]
	return d, ok
}

func (s *fakeStreams) offers() []sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sent
	for _, m := range s.sent {
		if m.frame.GetOffer() != nil {
			out = append(out, m)
		}
	}
	return out
}

func (s *fakeStreams) inputResponses() []*nexusv1.DispatchInputResponseV1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*nexusv1.DispatchInputResponseV1
	for _, m := range s.sent {
		if r := m.frame.GetInputResponse(); r != nil {
			out = append(out, r)
		}
	}
	return out
}

type outcomeCall struct {
	operator string
	rejected bool
}

type fakeHandraises struct {
	mu       sync.Mutex
	root     *handraise.IssuedRoot
	current  map[string]*taskv1.StandingHandraiseV1
	outcomes []outcomeCall
}

func (h *fakeHandraises) LatestRoot() (*handraise.IssuedRoot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.root, h.root != nil
}

func (h *fakeHandraises) Current(operator string) (*taskv1.StandingHandraiseV1, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.current[operator]
	return c, ok
}

func (h *fakeHandraises) RecordOutcome(operator string, _ uint64, rejected bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.outcomes = append(h.outcomes, outcomeCall{operator, rejected})
	return nil
}

// setRoot issues a root whose admitted leaves are the given operators, each with free slots.
func (h *fakeHandraises) setRoot(digest byte, free uint32, operators ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	root := &handraise.IssuedRoot{Root: &taskv1.SignedHandraiseRootV1{ChainId: testChainID, RootHeight: uint64(digest)}, Digest: fill32(digest)}
	for _, op := range operators {
		m := member(op)
		hr := &taskv1.StandingHandraiseV1{
			SchemaVersion: 1, ChainId: testChainID,
			Member:        &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: testSnapshot[:], Slot: m.Slot, SlotVersion: m.SlotVersion, OperatorAddress: op},
			Profiles:      []*taskv1.DispatchProfileV1{{ModelId: testModel[:], ProfileVersion: 1}},
			FreeSlotCount: free, IssuedHeight: 95, ExpiryHeight: 1000, HandraiseNonce: uint64(digest),
		}
		root.Leaves = append(root.Leaves, &taskv1.HandraiseRootLeafV1{Handraise: hr, Admitted: true})
		h.current[op] = hr
	}
	h.root = root
}

func (h *fakeHandraises) outcomeCalls() []outcomeCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]outcomeCall(nil), h.outcomes...)
}

type fakeDrawer struct {
	mu    sync.Mutex
	epoch dispatchdraw.Epoch
	drawn []dispatch.RosterMember
	err   error
	calls int
	// epochErr fails EpochOf.
	epochErr error
}

func (d *fakeDrawer) EpochOf(context.Context, uint64) (dispatchdraw.Epoch, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.epochErr != nil {
		return dispatchdraw.Epoch{}, d.epochErr
	}
	return d.epoch, nil
}

func (d *fakeDrawer) Draw(_ context.Context, sessionID [32]byte, sequence, esh uint64, profile dispatchdraw.Profile, _ uint32) (*dispatchdraw.Draw, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	if profile != testProfile {
		return nil, fmt.Errorf("unexpected profile %v", profile)
	}
	output := fill32(byte(sequence))
	return &dispatchdraw.Draw{
		Epoch: d.epoch,
		VRF:   dispatchdraw.VRFProof{Epoch: d.epoch.Number, Proof: bytes.Repeat([]byte{0x0f}, 80), Output: output},
		Pool:  dispatchdraw.NewPool(d.epoch, profile, poolMembers),
		Drawn: append([]dispatch.RosterMember(nil), d.drawn...),
	}, nil
}

type fakeKeys struct {
	mu           sync.Mutex
	builderErr   error
	cortexPended map[string]bool
}

func (k *fakeKeys) CheckBuilderKey(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.builderErr
}

func (k *fakeKeys) CortexRotationPending(_ context.Context, operator string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.cortexPended[operator], nil
}

type fakeInputs struct{ data map[string][]byte }

func (f fakeInputs) OpenInput(_ context.Context, sessionID, taskID, taskHash string) (io.ReadCloser, uint64, error) {
	b, ok := f.data[taskHash]
	if !ok {
		return nil, 0, errors.New("no input")
	}
	return io.NopCloser(bytes.NewReader(b)), uint64(len(b)), nil
}

type observed struct {
	accepted []string // worker per accepted order
	tickets  [][32]byte
	failed   []error
}

type fakeObserver struct {
	mu sync.Mutex
	observed
}

func (f *fakeObserver) DispatchAccepted(_, _ string, ticket [32]byte, worker string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted = append(f.accepted, worker)
	f.tickets = append(f.tickets, ticket)
}

func (f *fakeObserver) DispatchFailed(_, _ string, reason error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, reason)
}

func (f *fakeObserver) snapshot() observed {
	f.mu.Lock()
	defer f.mu.Unlock()
	return observed{append([]string(nil), f.accepted...), append([][32]byte(nil), f.tickets...), append([]error(nil), f.failed...)}
}

type fakeRecorder struct {
	mu        sync.Mutex
	bundles   []*Bundle
	withdrawn [][32]byte
	// onWithdraw runs inside Withdraw.
	onWithdraw func()
}

func (r *fakeRecorder) Record(_ context.Context, b *Bundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundles = append(r.bundles, b)
	return nil
}

func (r *fakeRecorder) Withdraw(_ context.Context, _ string, _ uint64, hash [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawn = append(r.withdrawn, hash)
	if r.onWithdraw != nil {
		r.onWithdraw()
	}
}

func (r *fakeRecorder) recorded() []*Bundle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Bundle(nil), r.bundles...)
}

// ---- environment ----

type env struct {
	t          *testing.T
	store      kv.Store
	ledger     *inflight.Ledger
	sessions   *inflight.SessionCache
	precheck   *inflight.Prechecker
	chain      *fakeChain
	streams    *fakeStreams
	handraises *fakeHandraises
	drawer     *fakeDrawer
	keys       *fakeKeys
	inputs     fakeInputs
	observer   *fakeObserver
	recorder   *fakeRecorder
	attempts   *attempt.Book
	evidence   *dispatchevidence.Store
	clock      *fakeClock
	syncer     *fakeSync
	metrics    *opsmetrics.Registry
	draining   atomic.Bool
	// takeoverOrders reserves the orders as a takeover's order, as the takeover's activation does.
	takeoverOrders bool
	signer         servicekey.Signer
	builder        string
	d              *Dispatcher
	params         Params
}

// fakeChain holds the session states the session cache reads.
type fakeChain struct {
	mu       sync.Mutex
	sessions map[string]chaincli.SessionState
}

func (c *fakeChain) read(_ context.Context, sessionID string) (chaincli.SessionState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[sessionID]
	if !ok {
		return chaincli.SessionState{}, chaincli.ErrNotFound
	}
	return s, nil
}

func (c *fakeChain) update(sessionID string, f func(*chaincli.SessionState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[sessionID]
	f(&s)
	c.sessions[sessionID] = s
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, store: kv.NewMemStore(), chain: &fakeChain{sessions: map[string]chaincli.SessionState{}},
		streams:    &fakeStreams{disconnected: map[string]bool{}, rtt: map[string]time.Duration{}},
		handraises: &fakeHandraises{current: map[string]*taskv1.StandingHandraiseV1{}},
		drawer:     &fakeDrawer{epoch: testEpoch, drawn: []dispatch.RosterMember{member(op7), member(op1), member(op3)}},
		keys:       &fakeKeys{cortexPended: map[string]bool{}},
		inputs:     fakeInputs{data: map[string][]byte{}},
		observer:   &fakeObserver{}, recorder: &fakeRecorder{},
		clock:  &fakeClock{now: time.UnixMilli(1_800_000_000_000)},
		signer: servicekey.Static(newTestSigner(t, 0x01), testBuilderNonce),
		params: Params{MaxSkips: testMaxSkips, Sticky: dispatchdraw.StickyParams{MaxOrders: 3, WindowBlocks: 50}, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64,
			RecordDeadlineBlocks: 20},
	}
	e.builder = newTestSigner(t, 0x09).Address()
	e.handraises.setRoot(0xd1, 2, op1, op3, op7)
	e.open(e.store)
	return e
}

// open builds the ledger, session cache, precheck and dispatcher over store, as after a start.
func (e *env) open(store kv.Store) {
	e.t.Helper()
	var err error
	e.ledger, err = inflight.NewLedger(store)
	if err != nil {
		e.t.Fatal(err)
	}
	e.sessions, err = inflight.NewSessionCache(inflight.SessionCacheConfig{
		Read: e.chain.read, LatestHeight: func(context.Context) (uint64, error) { return testESH, nil },
		Ledger: e.ledger, LookupsPerSecond: 1_000_000,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.sessions.ObserveHeight(testESH)
	e.precheck, err = inflight.NewPrechecker(inflight.PrecheckConfig{
		Builder: e.builder, Sessions: e.sessions, Ledger: e.ledger,
		Params: inflight.Params{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, BuilderMaxInflightPerSession: 8, MaxPendingPerSession: 8},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.attempts, err = attempt.New(store, e.signer, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.evidence = dispatchevidence.New(store, dispatchevidence.Params{RecordDeadlineBlocks: 20, ClaimWindowBlocks: 30, RebuttalBlocks: 10})
	cfg := Config{
		ChainID: testChainID, Builder: e.builder,
		Dispatch:        config.DispatchConfig{AcceptTimeoutMsByRTTTier: testTiers},
		InputChunkBytes: 4, Signer: e.signer, Store: store, Ledger: e.ledger, Sessions: e.sessions,
		Streams: e.streams, Handraises: e.handraises, Drawer: e.drawer, Keys: e.keys, Inputs: e.inputs,
		Recorder: e.recorder, Observer: e.observer, Attempts: e.attempts, Evidence: e.evidence, Clock: e.clock,
		Background: func(f func()) { f() }, Metrics: e.metrics, Draining: e.draining.Load,
	}
	if e.syncer != nil {
		cfg.Sync = e.syncer
	}
	e.d, err = New(cfg, e.params)
	if err != nil {
		e.t.Fatal(err)
	}
}

// session registers a session bound to this Builder with next expected sequence next.
func (e *env) session(id byte, next uint64) string {
	sessionID := hex.EncodeToString(bytes.Repeat([]byte{id}, 32))
	e.chain.update(sessionID, func(s *chaincli.SessionState) {
		*s = chaincli.SessionState{
			SessionID: sessionID, Owner: testUser, NextExpectedSequence: next, Balance: "1000000", FrozenTotal: "0",
			PendingWithdrawAmount: "0", BoundBuilder: e.builder, BoundChangeHeight: testBound, SpendCap: "0", Spent: "0",
		}
	})
	return sessionID
}

// order builds an order of the session and reserves it as the OpenTask precheck does.
func (e *env) order(sessionID string, seq uint64, version byte) types.Order {
	e.t.Helper()
	return e.orderAt(sessionID, seq, version, testESH)
}

// orderAt is order with the given earliest_submit_height.
func (e *env) orderAt(sessionID string, seq uint64, version byte, esh uint64) types.Order {
	e.t.Helper()
	sid, _ := hex.DecodeString(sessionID)
	inputHash := fill32(0x40 + version)
	signed := &taskv1.SignedOrderV2{
		Order: &taskv1.TaskOrderV3{
			ChainId: testChainID, UserAddress: testUser, SessionId: sid, OrderSequence: seq,
			ModelId: testModel[:], ProfileVersion: 1, InputHash: inputHash[:], EarliestSubmitHeight: esh,
			OrderExpireHeight: 10_000,
		},
		UserSignature: bytes.Repeat([]byte{version}, 65),
	}
	raw, err := proto.Marshal(signed)
	if err != nil {
		e.t.Fatal(err)
	}
	taskID := fmt.Sprintf("%064x", uint64(seq)+uint64(sid[0])<<56)
	o := types.Order{
		SessionID: sessionID, TaskID: taskID, OrderSequence: seq,
		TaskHash: hex.EncodeToString(bytes.Repeat([]byte{version, byte(seq)}, 16)), SignedOrder: raw,
	}
	e.inputs.data[o.TaskHash] = []byte("hello world")
	res, err := e.precheck.Reserve(context.Background(), inflight.Order{
		SessionID: sessionID, Sequence: seq, TaskID: taskID, TaskHash: o.TaskHash, User: testUser, MaxFee: 10,
		EarliestSubmitHeight: esh, ExpireHeight: 10_000, Takeover: e.takeoverOrders,
	})
	if err != nil {
		e.t.Fatalf("reserve %s/%d: %v", sessionID, seq, err)
	}
	if res.Reservation == nil {
		e.t.Fatalf("reserve %s/%d: no reservation (%+v)", sessionID, seq, res)
	}
	return o
}

func (e *env) dispatch(o types.Order) {
	e.t.Helper()
	if err := e.d.Dispatch(context.Background(), o); err != nil {
		e.t.Fatalf("dispatch: %v", err)
	}
}

// lastOffer returns the latest offer and its ticket hash.
func (e *env) lastOffer() (string, *taskv1.DispatchTicketV1, [32]byte) {
	e.t.Helper()
	offers := e.streams.offers()
	if len(offers) == 0 {
		e.t.Fatal("no offer sent")
	}
	m := offers[len(offers)-1]
	ticket := m.frame.GetOffer().GetTicket()
	raw, err := marshal(ticket)
	if err != nil {
		e.t.Fatal(err)
	}
	hash, err := dispatch.SigningDigest(ticketName, raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return m.operator, ticket, hash
}

// cortex is a Worker's service key; answers are signed with it as the stream would verify.
func cortexKey(t testing.TB) signer.Signer { return newTestSigner(t, 0x05) }

func (e *env) acceptMsg(ticket *taskv1.DispatchTicketV1, hash [32]byte) (*taskv1.DispatchAcceptV1, dispatchstream.Origin) {
	e.t.Helper()
	m := &taskv1.DispatchAcceptV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: ticket.GetTaskId(), TaskHash: ticket.GetTaskHash(),
		DispatchTicketHash: hash[:], Member: proto.Clone(ticket.GetTarget()).(*taskv1.CandidateMemberRefV1), ServiceAuthorizationNonce: 3,
	}
	raw, digest, err := signMessage(cortexKey(e.t), acceptName, m, func(sig []byte) { m.ServiceSignature = sig })
	if err != nil {
		e.t.Fatal(err)
	}
	return m, dispatchstream.Origin{Operator: ticket.GetTarget().GetOperatorAddress(), Raw: raw, Digest: digest}
}

func (e *env) rejectMsg(ticket *taskv1.DispatchTicketV1, hash [32]byte) (*taskv1.DispatchRejectV1, dispatchstream.Origin) {
	e.t.Helper()
	m := &taskv1.DispatchRejectV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: ticket.GetTaskId(), TaskHash: ticket.GetTaskHash(),
		DispatchTicketHash: hash[:], Member: proto.Clone(ticket.GetTarget()).(*taskv1.CandidateMemberRefV1), ServiceAuthorizationNonce: 3,
		RejectReason: taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY,
	}
	raw, digest, err := signMessage(cortexKey(e.t), "task.v1.DispatchRejectV1", m, func(sig []byte) { m.ServiceSignature = sig })
	if err != nil {
		e.t.Fatal(err)
	}
	return m, dispatchstream.Origin{Operator: ticket.GetTarget().GetOperatorAddress(), Raw: raw, Digest: digest}
}

func (e *env) accept() (string, [32]byte) {
	e.t.Helper()
	op, ticket, hash := e.lastOffer()
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); err != nil {
		e.t.Fatalf("accept: %v", err)
	}
	return op, hash
}

func (e *env) reject() string {
	e.t.Helper()
	op, ticket, hash := e.lastOffer()
	m, from := e.rejectMsg(ticket, hash)
	if err := e.d.HandleDispatchReject(context.Background(), from, m); err != nil {
		e.t.Fatalf("reject: %v", err)
	}
	return op
}

func (e *env) ledgerState(o types.Order) inflight.State {
	e.t.Helper()
	entry, ok := e.ledger.Get(o.SessionID, o.OrderSequence)
	if !ok {
		e.t.Fatal("ledger entry missing")
	}
	return entry.State
}

// recordOf decodes the record of the only recorded bundle.
func (e *env) onlyBundle() *Bundle {
	e.t.Helper()
	bundles := e.recorder.recorded()
	if len(bundles) != 1 {
		e.t.Fatalf("recorded %d bundles, want 1", len(bundles))
	}
	return bundles[0]
}

func operatorsOf(offers []sent) []string {
	out := make([]string, len(offers))
	for i, m := range offers {
		out[i] = m.operator
	}
	return out
}
