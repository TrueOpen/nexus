package takeover

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/recorder"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	self      = "trueopen1self"
	bound     = "trueopen1bound"
	other     = "trueopen1other"
	session   = "aa00000000000000000000000000000000000000000000000000000000000000"
	expiresAt = 200
)

type fakeChain struct {
	mu        sync.Mutex
	state     chaincli.SessionState
	stateErr  error
	records   map[uint64]*taskv1.DispatchRecordState
	recordErr error
	reads     int
}

func (c *fakeChain) QuerySession(context.Context, string) (chaincli.SessionState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return c.state, c.stateErr
}

func (c *fakeChain) QueryDispatchRecordByOrder(_ context.Context, _ string, seq uint64) (*taskv1.DispatchRecordState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recordErr != nil {
		return nil, c.recordErr
	}
	if rec, ok := c.records[seq]; ok {
		return rec, nil
	}
	return nil, fmt.Errorf("query dispatch record: %w", chaincli.ErrNotFound)
}

func (c *fakeChain) set(edit func(*chaincli.SessionState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	edit(&c.state)
}

type fakeRecorder struct {
	mu        sync.Mutex
	bundles   []*recorder.TakeoverBundle
	err       error
	withdrawn int
	// sent marks the sessions whose takeover entry went out in a transaction; resolved those
	// whose entry the recorder no longer holds (the chain refused it, or it was unsettled).
	sent, resolved map[string]bool
}

func (r *fakeRecorder) WithdrawUnsentTakeover(sessionID string, _ uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bundles) == 0 || r.sent[sessionID] || r.resolved[sessionID] {
		return false
	}
	r.withdrawn++
	return true
}

func (r *fakeRecorder) WithdrawTakeoverUnlessSent(sessionID string, _ uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bundles) == 0 || r.resolved[sessionID] {
		return true
	}
	if r.sent[sessionID] {
		return false
	}
	r.withdrawn++
	return true
}

func (r *fakeRecorder) WithdrawTakeover(context.Context, string, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawn++
}

type fakeKeys struct{ err error }

func (k *fakeKeys) CheckBuilderKey(context.Context) error { return k.err }

func (r *fakeRecorder) RecordTakeover(_ context.Context, b *recorder.TakeoverBundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.bundles = append(r.bundles, b)
	return nil
}

type fakePrecheck struct {
	mu       sync.Mutex
	results  []inflight.Result
	errs     []error
	orders   []inflight.Order
	released int
}

func (p *fakePrecheck) Reserve(_ context.Context, o inflight.Order) (inflight.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.orders = append(p.orders, o)
	res := inflight.Result{Binding: inflight.BoundHere, Reservation: &inflight.Reservation{SessionID: o.SessionID, Sequence: o.Sequence}}
	var err error
	if len(p.results) > 0 {
		res, p.results = p.results[0], p.results[1:]
	}
	if len(p.errs) > 0 {
		err, p.errs = p.errs[0], p.errs[1:]
	}
	return res, err
}

func (p *fakePrecheck) Release(*inflight.Reservation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.released++
	return nil
}

// fakeTasks logs every call as a string.
type fakeTasks struct {
	mu       sync.Mutex
	log      []string
	orderErr error
}

func (f *fakeTasks) add(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, fmt.Sprintf(format, args...))
}

func (f *fakeTasks) OnTakeover(_ context.Context, o types.Order) error {
	f.add("held %s", o.TaskID)
	return nil
}
func (f *fakeTasks) TakeoverRegistered(_, taskID string, activation uint64) {
	f.add("registered %s %d", taskID, activation)
}
func (f *fakeTasks) TakeoverActivated(_, taskID string, height uint64) {
	f.add("activated %s %d", taskID, height)
}
func (f *fakeTasks) TakeoverEnded(_, taskID, code string, _ uint64, dropInput bool, d *types.TaskEventDetail) {
	switch {
	case d == nil:
		f.add("ended %s %s drop=%t", taskID, code, dropInput)
	case d.RecordingBuilder != "":
		f.add("ended %s %s drop=%t where=recorded:%s/%s", taskID, code, dropInput, d.RecordingBuilder, d.RecordedTaskID)
	case d.CandidateBuilder != "":
		f.add("ended %s %s drop=%t where=candidate:%s@%d", taskID, code, dropInput, d.CandidateBuilder, d.TakeoverActivationHeight)
	case d.BoundBuilder != "":
		f.add("ended %s %s drop=%t where=bound:%s", taskID, code, dropInput, d.BoundBuilder)
	default:
		f.add("ended %s %s drop=%t reject=%s", taskID, code, dropInput, taskv1.DispatchRejectCodeV1(d.RejectCode))
	}
}
func (f *fakeTasks) OnOrder(_ context.Context, o types.Order) error {
	f.add("dispatch %s", o.TaskID)
	return f.orderErr
}

func (f *fakeTasks) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

type env struct {
	t        *testing.T
	store    kv.Store
	chain    *fakeChain
	rec      *fakeRecorder
	precheck *fakePrecheck
	tasks    *fakeTasks
	keys     *fakeKeys
	tracked  []string
	m        *Manager
	metrics  *opsmetrics.Registry
	draining atomic.Bool
}

// newEnv: the session is bound to "bound" at 40, next sequence 5, balance 1000 of which 100 is
// frozen.
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, store: kv.NewMemStore(),
		chain: &fakeChain{state: chaincli.SessionState{
			Owner: "owner", NextExpectedSequence: 5, Balance: "1000", FrozenTotal: "100", PendingWithdrawAmount: "0",
			BoundBuilder: bound, BoundChangeHeight: 40, FrozenDispatch: &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 20, MaxOrderLifetimeBlocks: 240},
		}, records: map[uint64]*taskv1.DispatchRecordState{}},
		rec: &fakeRecorder{}, precheck: &fakePrecheck{}, tasks: &fakeTasks{}, keys: &fakeKeys{},
	}
	e.open()
	return e
}

// open builds the manager over the env's store, as after a start.
func (e *env) open() {
	e.t.Helper()
	m, err := New(Config{
		Builder: self, Store: e.store, Chain: e.chain, Recorder: e.rec, Precheck: e.precheck, Tasks: e.tasks, Keys: e.keys,
		Track:      func(s string) error { e.tracked = append(e.tracked, s); return nil },
		Background: func(f func()) { f() }, Metrics: e.metrics, Draining: e.draining.Load,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.m = m
}

func takeoverOrder(seq uint64, version byte) (types.Order, inflight.Order) {
	signed, _ := proto.Marshal(&taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{
		SessionId: bytes.Repeat([]byte{0xaa}, 32), OrderSequence: seq, OrderExpireHeight: expiresAt, EarliestSubmitHeight: 30,
	}, UserSignature: []byte{version}})
	taskID := fmt.Sprintf("task%d", seq)
	hash := fmt.Sprintf("hash%d-%d", seq, version)
	o := types.Order{SessionID: session, TaskID: taskID, OrderSequence: seq, TaskHash: hash, SignedOrder: signed}
	pre := inflight.Order{SessionID: session, Sequence: seq, TaskID: taskID, TaskHash: hash, User: "owner", MaxFee: 100,
		EarliestSubmitHeight: 30, ExpireHeight: expiresAt}
	return o, pre
}

// submit admits and submits order seq.
func (e *env) submit(seq uint64) types.Order {
	e.t.Helper()
	o, pre := takeoverOrder(seq, 1)
	if adm, err := e.m.Admit(context.Background(), o, pre); err != nil || adm.Existing {
		e.t.Fatalf("Admit = %+v, %v", adm, err)
	}
	if err := e.m.Submit(context.Background(), o); err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) wantCalls(want ...string) {
	e.t.Helper()
	if got := e.tasks.calls(); !reflect.DeepEqual(got, want) {
		e.t.Fatalf("task calls = %q, want %q", got, want)
	}
}

func (e *env) stored() int {
	n := 0
	_ = e.store.Scan(kv.NSTakeover, func(string, []byte) bool { n++; return true })
	return n
}

// registerAt makes the chain hold this Builder's takeover of sequence 5, activating at height.
func (e *env) registerAt(height uint64) {
	e.chain.set(func(s *chaincli.SessionState) {
		s.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: self, OrderSequence: 5, ActivationHeight: height}
	})
}

// bindHere makes the chain bind the session here at height.
func (e *env) bindHere(height uint64) {
	e.chain.set(func(s *chaincli.SessionState) {
		s.BoundBuilder, s.BoundChangeHeight, s.PendingTakeover = self, height, nil
	})
}

// The bound Builder already recorded the sequence: the SDK is sent there with the task.
func TestAdmitSendsTheSDKToTheBuilderThatRecorded(t *testing.T) {
	e := newEnv(t)
	e.chain.records[5] = &taskv1.DispatchRecordState{BuilderAddress: bound, TaskId: bytes.Repeat([]byte{0x05}, 32)}
	o, pre := takeoverOrder(5, 1)
	_, err := e.m.Admit(context.Background(), o, pre)
	var elsewhere *inflight.SessionBoundElsewhereError
	if !errors.As(err, &elsewhere) || elsewhere.Builder != bound || elsewhere.TaskID != hex.EncodeToString(bytes.Repeat([]byte{0x05}, 32)) {
		t.Fatalf("Admit = %v", err)
	}
	if !errors.Is(err, inflight.ErrSessionBoundElsewhere) {
		t.Fatal("not SESSION_BOUND_ELSEWHERE")
	}
	if _, held := e.m.Held(session, 5, o.TaskHash); held || len(e.m.records) != 0 {
		t.Fatal("a refused order is held")
	}
}

// Another Builder's takeover is registered: the SDK waits for it; nothing is registered here.
func TestAdmitWaitsForAnotherTakeover(t *testing.T) {
	e := newEnv(t)
	e.chain.set(func(s *chaincli.SessionState) {
		s.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: other, OrderSequence: 5, ActivationHeight: 70}
	})
	o, pre := takeoverOrder(5, 1)
	_, err := e.m.Admit(context.Background(), o, pre)
	var pending *inflight.TakeoverPendingError
	if !errors.As(err, &pending) || pending.Candidate != other || pending.ActivationHeight != 70 {
		t.Fatalf("Admit = %v", err)
	}
}

// The sequence must be the chain's next one and the funds must cover the order; an unreadable
// chain or a session bound here meanwhile is retryable, never a verdict.
func TestAdmitChecksSequenceAndFunds(t *testing.T) {
	cases := []struct {
		name string
		edit func(*env)
		seq  uint64
		want error
	}{
		{"sequence ahead", nil, 6, inflight.ErrOrderSequenceConflict},
		{"sequence consumed by a cancellation", nil, 4, inflight.ErrOrderSequenceConflict},
		{"funds", func(e *env) { e.chain.set(func(s *chaincli.SessionState) { s.FrozenTotal = "901" }) }, 5, inflight.ErrSessionBalanceInsufficient},
		{"closing", func(e *env) {
			e.chain.set(func(s *chaincli.SessionState) {
				s.PendingWithdrawKind = taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE
			})
		}, 5, inflight.ErrSessionClosing},
		{"record unreadable", func(e *env) { e.chain.recordErr = errors.New("down") }, 5, inflight.ErrUnavailable},
		{"session unreadable", func(e *env) { e.chain.stateErr = errors.New("down") }, 5, inflight.ErrUnavailable},
		{"bound here meanwhile", func(e *env) { e.bindHere(60) }, 5, inflight.ErrUnavailable},
		// Expiry 200 is 170 blocks after earliest_submit_height 30.
		{"lifetime past the session's", func(e *env) {
			e.chain.set(func(s *chaincli.SessionState) {
				s.FrozenDispatch = &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 20, MaxOrderLifetimeBlocks: 169}
			})
		}, 5, inflight.ErrOrderExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.edit != nil {
				tc.edit(e)
			}
			o, pre := takeoverOrder(tc.seq, 1)
			if _, err := e.m.Admit(context.Background(), o, pre); !errors.Is(err, tc.want) {
				t.Fatalf("Admit = %v, want %v", err, tc.want)
			}
			if len(e.m.records) != 0 {
				t.Fatal("a refused order is held")
			}
		})
	}
}

// One takeover per session: while the order uploads its resend is told to retry; once
// submitted it is the existing order; any other order of the session waits for it. Release drops
// only an unsubmitted reservation.
// The chain registers a takeover only for an order whose expiry follows earliest_submit_height
// strictly and by at least the record_deadline_blocks the session froze.
func TestAdmitChecksTheOrderLifetime(t *testing.T) {
	// Expiry 200 is 170 blocks after earliest_submit_height 30.
	cases := []struct {
		name           string
		recordDeadline uint64
		expiry         uint64
		want           error
	}{
		{"expiry at earliest_submit_height", 0, 30, inflight.ErrOrderExpired},
		{"lifetime one block short of the recording span", 171, expiresAt, inflight.ErrOrderExpired},
		{"lifetime of the recording span", 170, expiresAt, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.chain.set(func(s *chaincli.SessionState) {
				s.FrozenDispatch = &taskv1.DispatchParamsV1{RecordDeadlineBlocks: tc.recordDeadline, MaxOrderLifetimeBlocks: 240}
			})
			o, pre := takeoverOrder(5, 1)
			pre.ExpireHeight = tc.expiry
			if _, err := e.m.Admit(context.Background(), o, pre); !errors.Is(err, tc.want) {
				t.Fatalf("Admit = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOneTakeoverPerSession(t *testing.T) {
	e := newEnv(t)
	o, pre := takeoverOrder(5, 1)
	if _, err := e.m.Admit(context.Background(), o, pre); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Admit(context.Background(), o, pre); !errors.Is(err, inflight.ErrOrderUploading) {
		t.Fatalf("resend while uploading = %v", err)
	}
	if _, held := e.m.Held(session, 5, o.TaskHash); held {
		t.Fatal("an uploading order is held")
	}
	another, anotherPre := takeoverOrder(5, 2)
	var pending *inflight.TakeoverPendingError
	if _, err := e.m.Admit(context.Background(), another, anotherPre); !errors.As(err, &pending) || pending.Candidate != self {
		t.Fatalf("another order = %v", err)
	}
	e.m.Release(session, another.TaskHash)
	if err := e.m.Submit(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	e.m.Release(session, o.TaskHash)
	if adm, held := e.m.Held(session, 5, o.TaskHash); !held || !adm.Existing {
		t.Fatalf("Held = %+v, %t", adm, held)
	}
	if adm, err := e.m.Admit(context.Background(), o, pre); err != nil || !adm.Existing {
		t.Fatalf("resend = %+v, %v", adm, err)
	}
	// A released reservation frees the session.
	e2 := newEnv(t)
	if _, err := e2.m.Admit(context.Background(), o, pre); err != nil {
		t.Fatal(err)
	}
	e2.m.Release(session, o.TaskHash)
	if _, err := e2.m.Admit(context.Background(), another, anotherPre); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// Submit stores the takeover, starts the order's task and hands the recorder the takeover entry
// with the session's bound_change_height, recordable up to and including order_expire_height.
func TestSubmitRecordsTheTakeoverEntry(t *testing.T) {
	e := newEnv(t)
	o := e.submit(5)
	e.wantCalls("held task5")
	if len(e.rec.bundles) != 1 {
		t.Fatalf("%d bundles", len(e.rec.bundles))
	}
	b := e.rec.bundles[0]
	if b.SessionID != session || b.Sequence != 5 || b.TaskID != "task5" || b.BoundChangeHeight != 40 || b.Deadline != expiresAt {
		t.Fatalf("bundle = %+v", b)
	}
	var signed taskv1.SignedOrderV2
	_ = proto.Unmarshal(o.SignedOrder, &signed)
	if !proto.Equal(b.Entry.GetSignedOrder(), &signed) {
		t.Fatalf("entry = %v", b.Entry)
	}
	if e.stored() != 1 {
		t.Fatal("the takeover is not stored")
	}
	// A recorder that cannot take it ends the task and holds nothing.
	e = newEnv(t)
	e.rec.err = errors.New("disk full")
	o, pre := takeoverOrder(5, 1)
	if _, err := e.m.Admit(context.Background(), o, pre); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Submit(context.Background(), o); err == nil {
		t.Fatal("Submit without the recorder succeeded")
	}
	e.wantCalls("held task5", "ended task5 TASK_FAILED drop=false")
	if e.stored() != 0 || len(e.m.records) != 0 {
		t.Fatal("a failed submit is held")
	}
}

// Registered, the task hears the activation height (from the session state after the result, and
// again only if the event says otherwise); bound here, confirmed by the session query, the order
// is prechecked again without freshness and dispatched, and nothing stays held.
func TestRegisteredThenBoundDispatchesTheOrder(t *testing.T) {
	e := newEnv(t)
	o := e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 60, Typed: chaincli.SessionTakeoverRegistered{
		SessionID: session, CandidateBuilder: self, OrderSequence: 5, RegisteredHeight: 60, ActivationHeight: 70,
	}})
	if adm, held := e.m.Held(session, 5, o.TaskHash); !held || adm.ActivationHeight != 70 {
		t.Fatalf("Held = %+v, %t", adm, held)
	}
	// Before the binding moved, a block below the activation height changes nothing.
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 69})
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{
		SessionID: session, OldBuilder: bound, NewBuilder: self, Trigger: taskv1.SessionBuilderBoundTriggerV1_SESSION_BUILDER_BOUND_TRIGGER_V1_TAKEOVER, BoundChangeHeight: 70,
	}})
	e.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
	if len(e.precheck.orders) != 1 || !e.precheck.orders[0].Takeover || e.precheck.orders[0].TaskHash != o.TaskHash {
		t.Fatalf("prechecked %+v", e.precheck.orders)
	}
	if _, held := e.m.Held(session, 5, o.TaskHash); held || e.stored() != 0 {
		t.Fatal("a dispatched order is still held")
	}
}

// A binding event missed while the stream was down: at the activation height the session is
// read and the order dispatched.
func TestActivationHeightResolvesAMissedBinding(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	e.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
}

// The registration was voided (the bound Builder recorded the sequence, it was cancelled or the
// session closed): the order and its input are dropped.
func TestVoidedTakeoverDropsTheOrder(t *testing.T) {
	e := newEnv(t)
	o := e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	// Another candidate's void changes nothing.
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 65, Typed: chaincli.SessionTakeoverVoided{SessionID: session, CandidateBuilder: other, OrderSequence: 5}})
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 65, Typed: chaincli.SessionTakeoverVoided{
		SessionID: session, CandidateBuilder: self, OrderSequence: 5, Reason: taskv1.SessionTakeoverVoidReasonV1_SESSION_TAKEOVER_VOID_REASON_V1_ORDER_RECORDED,
	}})
	e.wantCalls("held task5", "registered task5 70", "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1bound")
	if _, held := e.m.Held(session, 5, o.TaskHash); held || e.stored() != 0 || e.rec.withdrawn != 1 {
		t.Fatalf("a voided order is still held (withdrawn %d)", e.rec.withdrawn)
	}
}

// The session went to another Builder: a registered takeover will not take effect. A submitted
// entry waits for its result, which decides.
func TestBindingToAnotherBuilderVoidsTheTakeover(t *testing.T) {
	bindOther := func(e *env) {
		e.chain.set(func(s *chaincli.SessionState) {
			s.BoundBuilder, s.BoundChangeHeight, s.PendingTakeover = other, 70, nil
		})
		e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, OldBuilder: bound, NewBuilder: other, BoundChangeHeight: 70}})
	}
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	bindOther(e)
	e.wantCalls("held task5", "registered task5 70")
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 71})
	e.wantCalls("held task5", "registered task5 70", "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1other")

	e = newEnv(t)
	e.submit(5)
	bindOther(e)
	e.wantCalls("held task5")
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING)
	e.wantCalls("held task5", "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1other")
}

// A registration result read while the session shows the takeover neither pending nor taken
// effect: the node read may trail the registration, so it is read again, and only a second such
// read at a higher head voids it.
func TestRegisteredButGoneIsVoided(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 60})
	e.m.TakeoverRegistered(session, 5, 60)
	e.wantCalls("held task5")
	// Another block event at the same head does not count.
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 60})
	e.wantCalls("held task5")
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.wantCalls("held task5", "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1bound")

	// A read that catches up in between keeps it.
	e = newEnv(t)
	e.submit(5)
	e.m.TakeoverRegistered(session, 5, 60)
	e.registerAt(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.wantCalls("held task5", "registered task5 70")
}

// An unreadable session is resolved again at the next block, once.
func TestUnreadableSessionIsResolvedAtTheNextBlock(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.chain.stateErr = errors.New("down")
	e.m.TakeoverRegistered(session, 5, 60)
	e.chain.stateErr = nil
	e.registerAt(70)
	reads := e.chain.reads
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 62})
	e.wantCalls("held task5", "registered task5 70")
	if e.chain.reads != reads+1 {
		t.Fatalf("%d session reads after the failure", e.chain.reads-reads)
	}
}

// A refused takeover entry: the sequence consumed or another takeover registered voids it (the
// SDK goes where the chain says); any other refusal is RECORD_REJECTED and keeps the input.
func TestTakeoverEntryRefusals(t *testing.T) {
	for _, tc := range []struct {
		code taskv1.DispatchRejectCodeV1
		want string
	}{
		{taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_SEQUENCE_CONSUMED, "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1bound"},
		{taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING, "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1bound"},
		{taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_KEY_EXPIRED, "ended task5 RECORD_REJECTED drop=false reject=DISPATCH_REJECT_CODE_V1_SESSION_KEY_EXPIRED"},
		// A refusal without a code still carries a nonzero category.
		{taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_UNSPECIFIED, "ended task5 RECORD_REJECTED drop=false reject=DISPATCH_REJECT_CODE_V1_CONFLICT"},
	} {
		e := newEnv(t)
		e.submit(5)
		e.m.TakeoverRefused(session, 5, tc.code)
		e.wantCalls("held task5", tc.want)
		if e.stored() != 0 {
			t.Fatalf("%s: still stored", tc.code)
		}
	}
}

// An entry ahead of the session's next expected sequence (SEQUENCE_NOT_NEXT) consumed nothing: the
// takeover stays and the entry goes again at the same sequence once the earlier sequences are
// recorded, neither voided nor rejected. An order that expires while it waits ends ORDER_EXPIRED.
func TestTakeoverAheadOfTheNextSequenceWaits(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 4 })
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_NOT_NEXT)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.wantCalls("held task5")
	if len(e.rec.bundles) != 1 || e.stored() != 1 {
		t.Fatalf("while an earlier sequence is unrecorded: bundles %d, stored %d", len(e.rec.bundles), e.stored())
	}
	e.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 5 })
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 62})
	e.wantCalls("held task5")
	if len(e.rec.bundles) != 2 || e.rec.bundles[1].Sequence != 5 {
		t.Fatalf("entry not sent again at its sequence: %+v", e.rec.bundles)
	}

	e = newEnv(t)
	e.submit(5)
	e.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 4 })
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_NOT_NEXT)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: expiresAt + 1})
	e.wantCalls("held task5", "ended task5 ORDER_EXPIRED drop=false")
}

// The order expired while the takeover waited: once bound here it is not dispatched; the task
// ends ORDER_EXPIRED and the SDK resends the sequence re-signed. An entry that lapsed without
// registering is ORDER_EXPIRED too.
func TestOrderExpiredByTheActivation(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.precheck.errs = []error{fmt.Errorf("%w: past its deadline", inflight.ErrOrderExpired)}
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: self, BoundChangeHeight: 70}})
	e.wantCalls("held task5", "activated task5 70", "ended task5 ORDER_EXPIRED drop=false")

	e = newEnv(t)
	e.submit(5)
	e.m.TakeoverLapsed(session, 5)
	e.wantCalls("held task5", "ended task5 ORDER_EXPIRED drop=false")
}

// A precheck without a verdict (the cached state not bound here yet, or unreadable) is tried
// again at the next block; any other refusal ends the task as TASK_FAILED.
func TestActivationRetriesAPrecheckWithoutVerdict(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.precheck.results = []inflight.Result{{Binding: inflight.BoundElsewhere}}
	e.precheck.errs = []error{nil, fmt.Errorf("%w: down", inflight.ErrUnavailable)}
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: self, BoundChangeHeight: 70}})
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 71})
	e.wantCalls("held task5")
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 72})
	e.wantCalls("held task5", "activated task5 70", "dispatch task5")

	e = newEnv(t)
	e.submit(5)
	e.precheck.errs = []error{fmt.Errorf("%w: short", inflight.ErrSessionBalanceInsufficient)}
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: self, BoundChangeHeight: 70}})
	e.wantCalls("held task5", "activated task5 70", "ended task5 TASK_FAILED drop=false")

	// The dispatcher refusing the order releases the reservation.
	e = newEnv(t)
	e.submit(5)
	e.tasks.orderErr = errors.New("dispatch unavailable")
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: self, BoundChangeHeight: 70}})
	if e.precheck.released != 1 {
		t.Fatalf("released %d", e.precheck.released)
	}
	e.wantCalls("held task5", "activated task5 70", "dispatch task5", "ended task5 TASK_FAILED drop=false")
}

// A restart resumes the held takeovers: a submitted entry goes to the recorder again as the same
// entry, a registered takeover is resolved with the chain, and their sessions are followed.
func TestRestartResumesTheTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	first := e.rec.bundles[0]
	e.open()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.rec.bundles) != 2 || !reflect.DeepEqual(e.rec.bundles[1], first) {
		t.Fatalf("bundles after restart = %+v", e.rec.bundles)
	}
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)

	e.open()
	e.bindHere(70)
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.tracked, []string{session, session}) {
		t.Fatalf("tracked %v", e.tracked)
	}
	e.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
	if e.stored() != 0 {
		t.Fatal("still stored")
	}
}

// A restart after the order was handed to the dispatcher but before the takeover was dropped:
// the precheck finds the order and nothing is dispatched twice.
func TestRestartAfterTheHandOver(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.bindHere(70)
	e.precheck.results = []inflight.Result{{Binding: inflight.BoundHere, Existing: &inflight.Entry{Sequence: 5}}}
	e.open()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.wantCalls("held task5", "registered task5 70")
	if e.stored() != 0 {
		t.Fatal("still stored")
	}
}

// A refusal that voids the takeover records where the session went: the Builder that recorded
// the order with its task, or the other candidate with its activation height.
func TestRefusalRecordsWhereTheSessionWent(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.chain.records[5] = &taskv1.DispatchRecordState{BuilderAddress: bound, TaskId: bytes.Repeat([]byte{0x05}, 32)}
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_SEQUENCE_CONSUMED)
	e.wantCalls("held task5", "ended task5 TAKEOVER_VOIDED drop=true where=recorded:trueopen1bound/"+hex.EncodeToString(bytes.Repeat([]byte{0x05}, 32)))

	e = newEnv(t)
	e.submit(5)
	e.chain.set(func(s *chaincli.SessionState) {
		s.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: other, OrderSequence: 5, ActivationHeight: 80}
	})
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING)
	e.wantCalls("held task5", "ended task5 TAKEOVER_VOIDED drop=true where=candidate:trueopen1other@80")
}

// A session that closed while the takeover waited is gone from the chain: the takeover is voided
// rather than read again forever.
func TestClosedSessionVoidsTheTakeover(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.chain.stateErr = fmt.Errorf("query session: %w", chaincli.ErrNotFound)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	e.wantCalls("held task5", "registered task5 70", "ended task5 TAKEOVER_VOIDED drop=true")
	if e.stored() != 0 {
		t.Fatal("still stored")
	}
}

// No takeover while this Builder's own key rotation is pending (BUILDER_KEY_ROTATING naming the
// effective height), its key is revoked or its compensation account is below the minimum; a key
// that cannot be confirmed is retryable.
func TestAdmitNeedsThisBuildersKey(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want error
	}{
		{&handraise.RotationPendingError{NextNonce: 2, RegisteredHeight: 40, EffectiveHeight: 90}, inflight.ErrBuilderKeyRotating},
		{dispatcher.ErrCompensationBelowMin, dispatchdraw.ErrNoCapacity},
		{&servicekey.RevokedError{Nonce: 1, NextNonce: 2, NextEffectiveHeight: 90}, dispatchdraw.ErrNoCapacity},
		{errors.New("key unreadable"), inflight.ErrUnavailable},
	} {
		e := newEnv(t)
		e.keys.err = tc.err
		o, pre := takeoverOrder(5, 1)
		_, err := e.m.Admit(context.Background(), o, pre)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%v: Admit = %v, want %v", tc.err, err, tc.want)
		}
		if rotating := (*inflight.BuilderKeyRotatingError)(nil); errors.As(err, &rotating) && rotating.EffectiveHeight != 90 {
			t.Fatalf("Admit = %v, want the effective height 90", err)
		}
		if len(e.m.records) != 0 {
			t.Fatal("held")
		}
	}
}

// A restart judges a submitted entry again by Admit's rules before sending it again: under a
// moved bound_change_height it is withdrawn and sent under the new one; with this Builder's key
// rotation pending it ends while no transaction carries it, and is sent again once one does (a
// takeover already registered goes on); recorded meanwhile by
// the bound Builder it is voided; a recorder that cannot take it ends it TASK_FAILED. None of them
// stops the start.
func TestRestartJudgesSubmittedEntriesAgain(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.chain.set(func(s *chaincli.SessionState) { s.BoundChangeHeight = 55 })
	e.open()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.rec.bundles) != 2 || e.rec.bundles[1].BoundChangeHeight != 55 || e.rec.withdrawn != 1 {
		t.Fatalf("bundles %+v, withdrawn %d", e.rec.bundles, e.rec.withdrawn)
	}
	// The record keeps the new generation.
	e.open()
	_ = e.m.Start(context.Background())
	if len(e.rec.bundles) != 3 || e.rec.bundles[2].BoundChangeHeight != 55 || e.rec.withdrawn != 1 {
		t.Fatalf("bundles %+v, withdrawn %d", e.rec.bundles, e.rec.withdrawn)
	}

	for _, tc := range []struct {
		name string
		edit func(*env)
		want string
	}{
		{"recorded", func(e *env) {
			e.chain.records[5] = &taskv1.DispatchRecordState{BuilderAddress: bound, TaskId: bytes.Repeat([]byte{0x05}, 32)}
		}, "ended task5 TAKEOVER_VOIDED drop=true where=recorded:trueopen1bound/" + hex.EncodeToString(bytes.Repeat([]byte{0x05}, 32))},
		{"recorder fails", func(e *env) { e.rec.err = errors.New("disk full") }, "ended task5 TASK_FAILED drop=false"},
	} {
		e := newEnv(t)
		e.submit(5)
		tc.edit(e)
		e.open()
		if err := e.m.Start(context.Background()); err != nil {
			t.Fatalf("%s: Start = %v", tc.name, err)
		}
		e.wantCalls("held task5", tc.want)
		if e.stored() != 0 {
			t.Fatalf("%s: still stored", tc.name)
		}
	}

	pending := newEnv(t)
	pending.submit(5)
	pending.keys.err = &handraise.RotationPendingError{NextNonce: 2, RegisteredHeight: 40, EffectiveHeight: 90}
	pending.open()
	if err := pending.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
	if len(pending.rec.bundles) != 1 || pending.stored() != 0 {
		t.Fatalf("with the rotation pending: bundles %d, stored %d", len(pending.rec.bundles), pending.stored())
	}

	sent := newEnv(t)
	sent.rec.sent = map[string]bool{session: true}
	sent.submit(5)
	sent.keys.err = &handraise.RotationPendingError{NextNonce: 2, RegisteredHeight: 40, EffectiveHeight: 90}
	sent.open()
	if err := sent.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent.wantCalls("held task5")
	if len(sent.rec.bundles) != 2 || sent.stored() != 1 {
		t.Fatalf("sent, with the rotation pending: bundles %d, stored %d", len(sent.rec.bundles), sent.stored())
	}
}

// An unattributable result drops the entry: the takeover is judged again with the chain, here
// registered after all.
func TestUnsettledResultIsSettledWithTheChain(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverUnsettled(session, 5)
	e.wantCalls("held task5", "registered task5 70")
	if len(e.rec.bundles) != 1 {
		t.Fatalf("sent again: %d", len(e.rec.bundles))
	}
}

// A stored takeover that cannot be resumed ends its task; a record that does not decode is
// dropped; the start goes on.
func TestStartEndsBrokenRecords(t *testing.T) {
	e := newEnv(t)
	broken, _ := json.Marshal(map[string]any{"session_id": session, "task_id": "task5", "phase": 9})
	_ = e.store.Set(kv.NSTakeover, session, broken)
	_ = e.store.Set(kv.NSTakeover, "garbage", []byte("{"))
	e.open()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.wantCalls("ended task5 TASK_FAILED drop=false")
	if e.stored() != 0 {
		t.Fatal("broken records kept")
	}
}

// A read without a verdict keeps every job it interrupted: a check failing after a settle failed
// in the same block does not replace the settle, which a submitted entry dropped as unsettled
// needs to be sent again.
func TestRetriesKeepEveryJob(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.chain.stateErr = errors.New("down")
	e.m.TakeoverUnsettled(session, 5)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 60, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: other, BoundChangeHeight: 60}})
	e.chain.stateErr = nil
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	if len(e.rec.bundles) != 2 {
		t.Fatalf("the unsettled entry was not sent again: %d bundles", len(e.rec.bundles))
	}
}

// The bound Builder already recorded the order: that is the answer even while this Builder's key
// rotation is pending.
func TestAdmitReadsTheRecordBeforeTheKey(t *testing.T) {
	e := newEnv(t)
	e.keys.err = handraise.ErrBuilderRotationPending
	e.chain.records[5] = &taskv1.DispatchRecordState{BuilderAddress: bound, TaskId: bytes.Repeat([]byte{0x05}, 32)}
	o, pre := takeoverOrder(5, 1)
	if _, err := e.m.Admit(context.Background(), o, pre); !errors.Is(err, inflight.ErrSessionBoundElsewhere) {
		t.Fatalf("Admit = %v", err)
	}
}

// A void that arrives before the entry's result ends the takeover.
func TestVoidedWhileSubmitted(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 61, Typed: chaincli.SessionTakeoverVoided{SessionID: session, CandidateBuilder: self, OrderSequence: 5}})
	e.wantCalls("held task5", "ended task5 TAKEOVER_VOIDED drop=true where=bound:trueopen1bound")
	if e.rec.withdrawn != 1 || e.stored() != 0 {
		t.Fatalf("withdrawn %d, stored %d", e.rec.withdrawn, e.stored())
	}
}

// With jobs on their own goroutines, results and events of one takeover still run one at a
// time: registered, bound here, dispatched once.
func TestJobsRunOneAtATimeInTheBackground(t *testing.T) {
	e := newEnv(t)
	m, err := New(Config{
		Builder: self, Store: e.store, Chain: e.chain, Recorder: e.rec, Precheck: e.precheck, Tasks: e.tasks, Keys: e.keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.m = m
	e.submit(5)
	e.bindHere(70)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.TakeoverRegistered(session, 5, 60)
			m.HandleChainEvent(chaincli.ChainEvent{Height: 70, Typed: chaincli.SessionBuilderBound{SessionID: session, NewBuilder: self, BoundChangeHeight: 70}})
			m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 71})
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for e.stored() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	dispatched := 0
	for _, c := range e.tasks.calls() {
		if c == "dispatch task5" {
			dispatched++
		}
	}
	if dispatched != 1 || e.stored() != 0 {
		t.Fatalf("calls %q, stored %d", e.tasks.calls(), e.stored())
	}
}

// A stored record under another session's key is dropped and its task ends.
func TestStartEndsARecordUnderTheWrongKey(t *testing.T) {
	e := newEnv(t)
	moved, _ := json.Marshal(map[string]any{"session_id": session, "task_id": "task5", "phase": int(phaseSubmitted)})
	_ = e.store.Set(kv.NSTakeover, "other-key", moved)
	e.open()
	if err := e.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.wantCalls("ended task5 TASK_FAILED drop=false")
	if e.stored() != 0 {
		t.Fatal("kept")
	}
}
