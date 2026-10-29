package inflight

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/sdkauth"
)

var testKey = [20]byte{0xaa}

var testParams = Params{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, BuilderMaxInflightPerSession: 3, MaxPendingPerSession: 4}

type precheckFixture struct {
	chain  *fakeChain
	store  kv.Store
	cache  *SessionCache
	ledger *Ledger
	p      *Prechecker
}

// newFixture: head 100; session bound to "builder" at 10, next 5, balance 1000, frozen 100, the
// registered key testKey until 500 with cap 1000 and 500 spent.
func newFixture(t testing.TB, edit func(*chaincli.SessionState)) *precheckFixture {
	t.Helper()
	state := baseSessionState()
	state.Key, state.ExpiryHeight, state.SetHeight, state.SpendCap, state.Spent = testKey[:], 500, 1, "1000", "500"
	if edit != nil {
		edit(&state)
	}
	f := &precheckFixture{chain: &fakeChain{state: state, found: true, height: 100}, store: kv.NewMemStore()}
	f.restart(t)
	return f
}

// restart builds the cache, ledger and prechecker again over the same store, as after a restart.
func (f *precheckFixture) restart(t testing.TB) {
	t.Helper()
	var err error
	if f.ledger, err = NewLedger(f.store); err != nil {
		t.Fatal(err)
	}
	f.cache, err = NewSessionCache(SessionCacheConfig{
		Read: f.chain.read, LatestHeight: f.chain.latest, Tracker: f.chain, Ledger: f.ledger,
		Background: func(fn func()) { fn() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.p, err = NewPrechecker(PrecheckConfig{Builder: "builder", Params: testParams, Sessions: f.cache, Ledger: f.ledger}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := f.cache.Lookup(ctx, testSession); err != nil {
		t.Fatal(err)
	}
	f.cache.SessionStreamUp(testSession)
	if _, _, err := f.cache.Lookup(ctx, testSession); err != nil {
		t.Fatal(err)
	}
}

func order(seq uint64) Order {
	return Order{
		SessionID: testSession, Sequence: seq, TaskID: fmt.Sprintf("task%d", seq), TaskHash: fmt.Sprintf("hash%d", seq),
		User: "owner", MaxFee: 100, EarliestSubmitHeight: 100, ExpireHeight: 200, SessionAnchorHeight: 50,
	}
}

func keyOrder(seq uint64) Order {
	o := order(seq)
	key := testKey
	o.SessionKey = &key
	return o
}

func (f *precheckFixture) reserve(t testing.TB, o Order) Result {
	t.Helper()
	res, err := f.p.Reserve(context.Background(), o)
	if err != nil {
		t.Fatalf("reserve %d: %v", o.Sequence, err)
	}
	return res
}

func TestPrecheckAdmitsAndReserves(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.p.Check(context.Background(), order(5))
	if err != nil || res.Binding != BoundHere || res.Existing != nil || res.Retry || res.Head != 100 || res.Deadline != 120 {
		t.Fatalf("check = %+v, %v", res, err)
	}
	if len(f.ledger.Entries(testSession)) != 0 {
		t.Fatal("Check changed the ledger")
	}
	f.reserve(t, keyOrder(5))
	e, ok := f.ledger.Get(testSession, 5)
	if !ok || e.State != StateDispatching || e.MaxFee != 100 || !e.SessionKey || e.Deadline != 120 || e.TaskHash != "hash5" {
		t.Fatalf("reserved entry = %+v, %v", e, ok)
	}
	// Sequence n+1 may be dispatched while n is in flight.
	f.reserve(t, order(6))
	if f.chain.readCount() != 2 {
		t.Fatalf("warm precheck read the chain: %d reads", f.chain.readCount())
	}
}

// One test per error code, each from the admitted base case.
func TestPrecheckErrorCodes(t *testing.T) {
	cases := []struct {
		name  string
		state func(*chaincli.SessionState)
		setup func(*testing.T, *precheckFixture)
		order func(*Order)
		want  error
	}{
		{name: "unknown session", setup: func(t *testing.T, f *precheckFixture) {
			f.chain.found = false
			f.cache.SessionStreamDown(testSession)
		}, want: registeredkey.ErrKeyInvalid},
		{name: "not the owner", order: func(o *Order) { o.User = "mallory" }, want: registeredkey.ErrKeyInvalid},
		{name: "closed", state: func(s *chaincli.SessionState) { s.Closed = true }, want: ErrSessionClosing},
		{name: "session key expires before the deadline", state: func(s *chaincli.SessionState) { s.ExpiryHeight = 119 }, order: withKey, want: registeredkey.ErrKeyExpired},
		{name: "session key spend cap", state: func(s *chaincli.SessionState) { s.Spent = "901" }, order: withKey, want: registeredkey.ErrSpendCapExceeded},
		{name: "expired: no block left before order_expire_height", order: func(o *Order) { o.ExpireHeight = 101 }, want: ErrOrderExpired},
		{name: "stale", order: func(o *Order) { o.EarliestSubmitHeight = 94 }, want: ErrOrderStale},
		{name: "future", order: func(o *Order) { o.EarliestSubmitHeight = 102 }, want: ErrOrderFuture},
		{name: "takeover pending", state: func(s *chaincli.SessionState) {
			s.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: "other", OrderSequence: 5, ActivationHeight: 130}
		}, want: ErrTakeoverPending},
		{name: "replacement while dispatching", setup: func(t *testing.T, f *precheckFixture) { f.reserve(t, order(5)) },
			order: func(o *Order) { o.TaskHash = "other" }, want: ErrOrderReplacementUnsupported},
		{name: "replacement after accept", setup: func(t *testing.T, f *precheckFixture) {
			f.reserve(t, order(5))
			_ = f.ledger.MarkAccepted(testSession, 5)
		}, order: func(o *Order) { o.TaskHash = "other" }, want: ErrOrderLocked},
		{name: "replacement after record", setup: func(t *testing.T, f *precheckFixture) {
			f.reserve(t, order(5))
			_ = f.ledger.MarkRecorded(testSession, 5)
		}, order: func(o *Order) { o.TaskHash = "other" }, want: ErrTaskTerminal},
		{name: "suspended", setup: func(t *testing.T, f *precheckFixture) {
			f.reserve(t, order(5))
			f.reserve(t, order(6))
			_ = f.ledger.Suspend(testSession, 5)
		}, order: func(o *Order) { o.Sequence = 6; o.TaskHash = "new6" }, want: ErrSessionSuspended},
		{name: "sequence gap", order: func(o *Order) { o.Sequence = 6 }, want: ErrOrderSequenceConflict},
		{name: "sequence already consumed", order: func(o *Order) { o.Sequence = 4 }, want: ErrOrderSequenceConflict},
		{name: "cancellation registered", setup: func(t *testing.T, f *precheckFixture) {
			_ = f.cache.HandleChainEvent(sessionEvent(101, chaincli.OrderCancelRequested{SessionID: testSession, OrderSequence: 5, CancelEffectiveHeight: 140}))
		}, want: ErrOrderSequenceConflict},
		{name: "builder in-flight limit", setup: func(t *testing.T, f *precheckFixture) {
			for seq := uint64(5); seq < 8; seq++ {
				f.reserve(t, order(seq))
			}
		}, order: func(o *Order) { o.Sequence = 8 }, want: ErrInflightLimit},
		{name: "max pending limit", setup: func(t *testing.T, f *precheckFixture) {
			setParams(t, f, Params{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, BuilderMaxInflightPerSession: 3, MaxPendingPerSession: 1})
			f.reserve(t, order(5))
		}, order: func(o *Order) { o.Sequence = 6 }, want: ErrInflightLimit},
		{name: "close registered", state: func(s *chaincli.SessionState) {
			s.PendingWithdrawKind = taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE
		}, want: ErrSessionClosing},
		{name: "balance", order: func(o *Order) { o.MaxFee = 901 }, want: ErrSessionBalanceInsufficient},
		{name: "balance after pending withdrawal", state: func(s *chaincli.SessionState) {
			s.PendingWithdrawKind = taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT
			s.PendingWithdrawAmount = "801"
		}, want: ErrSessionBalanceInsufficient},
		{name: "balance after in-flight orders", setup: func(t *testing.T, f *precheckFixture) {
			o := order(5)
			o.MaxFee = 801
			f.reserve(t, o)
		}, order: func(o *Order) { o.Sequence = 6 }, want: ErrSessionBalanceInsufficient},
		{name: "chain unreadable", setup: func(t *testing.T, f *precheckFixture) {
			f.chain.err = errors.New("node down")
			f.cache.SessionStreamDown(testSession)
		}, want: sdkauth.ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.state)
			if c.setup != nil {
				c.setup(t, f)
			}
			o := order(5)
			if c.order != nil {
				c.order(&o)
			}
			_, err := f.p.Check(context.Background(), o)
			if !errors.Is(err, c.want) {
				t.Fatalf("Check = %v, want %v", err, c.want)
			}
			if _, err := f.p.Reserve(context.Background(), o); !errors.Is(err, c.want) {
				t.Fatalf("Reserve = %v, want %v", err, c.want)
			}
		})
	}
}

func setParams(t testing.TB, f *precheckFixture, params Params) {
	t.Helper()
	if err := f.p.SetParams(params); err != nil {
		t.Fatal(err)
	}
}

// An in-flight limit of zero refuses every order: a missing param must not lift the bound.
func TestPrecheckZeroInflightLimitRefuses(t *testing.T) {
	for _, params := range []Params{
		{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, MaxPendingPerSession: 4},
		{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, BuilderMaxInflightPerSession: 3},
	} {
		f := newFixture(t, nil)
		setParams(t, f, params)
		if _, err := f.p.Check(context.Background(), order(5)); !errors.Is(err, ErrInflightLimit) {
			t.Fatalf("params %+v: Check = %v, want in-flight limit", params, err)
		}
	}
}

// The freshness margin must stay below record_deadline_blocks: an order admitted at the margin
// would otherwise already be past its record deadline.
func TestPrecheckSetParamsChecksTheFreshnessMargin(t *testing.T) {
	f := newFixture(t, nil)
	for _, params := range []Params{
		{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 20, BuilderMaxInflightPerSession: 3, MaxPendingPerSession: 4},
		{OrderFreshnessMarginBlocks: 0, BuilderMaxInflightPerSession: 3, MaxPendingPerSession: 4},
	} {
		if err := f.p.SetParams(params); err == nil {
			t.Fatalf("SetParams(%+v) accepted", params)
		}
	}
	if res, err := f.p.Check(context.Background(), order(5)); err != nil || res.Deadline != 120 {
		t.Fatalf("Check after refused params = %+v, %v", res, err)
	}
	bad := testParams
	bad.OrderFreshnessMarginBlocks = bad.RecordDeadlineBlocks
	if _, err := NewPrechecker(PrecheckConfig{Builder: "builder", Params: bad, Sessions: f.cache, Ledger: f.ledger}); err == nil {
		t.Fatal("NewPrechecker accepted a freshness margin at record_deadline_blocks")
	}
}

func withKey(o *Order) {
	key := testKey
	o.SessionKey = &key
}

func TestPrecheckTakeoverPendingCarriesTheCandidate(t *testing.T) {
	f := newFixture(t, func(s *chaincli.SessionState) {
		s.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: "other", ActivationHeight: 130}
	})
	_, err := f.p.Check(context.Background(), order(5))
	var pending *TakeoverPendingError
	if !errors.As(err, &pending) || pending.Candidate != "other" || pending.ActivationHeight != 130 {
		t.Fatalf("Check = %v", err)
	}
}

// A session bound elsewhere ends the precheck before freshness: the takeover path decides.
func TestPrecheckBoundElsewhere(t *testing.T) {
	f := newFixture(t, func(s *chaincli.SessionState) { s.BoundBuilder = "other"; s.BoundChangeHeight = 110 })
	o := order(5)
	o.EarliestSubmitHeight = 50 // stale for a bound session
	res, err := f.p.Reserve(context.Background(), o)
	if err != nil || res.Binding != BoundElsewhere || res.Session.BoundBuilder != "other" || res.Deadline != 130 {
		t.Fatalf("Reserve = %+v, %v", res, err)
	}
	if len(f.ledger.Entries(testSession)) != 0 {
		t.Fatal("an order bound elsewhere entered the ledger")
	}
	// The expiry still applies.
	o.ExpireHeight = 100
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderExpired) {
		t.Fatalf("expired order bound elsewhere = %v", err)
	}
}

func TestPrecheckFreshnessBoundaries(t *testing.T) {
	f := newFixture(t, nil)
	for _, esh := range []uint64{95, 101} {
		o := order(5)
		o.EarliestSubmitHeight = esh
		if _, err := f.p.Check(context.Background(), o); err != nil {
			t.Fatalf("earliest_submit_height %d at head 100: %v", esh, err)
		}
	}
}

// The order must stay recordable until its record deadline D = max(earliest_submit_height,
// bound_change_height) + record_deadline_blocks: the Keeper refuses a record at or after
// order_expire_height, and an order that expires before this Builder could record it is this
// Builder's precheck fault, which the accepting GPU can claim for.
func TestPrecheckExpiryCoversTheRecordDeadline(t *testing.T) {
	f := newFixture(t, nil) // head 100, record_deadline_blocks 20, bound at 10
	o := order(5)           // earliest_submit_height 100: D = 120
	o.ExpireHeight = 121
	if _, err := f.p.Check(context.Background(), o); err != nil {
		t.Fatalf("order expiring after D: %v", err)
	}
	for _, expire := range []uint64{120, 102} {
		o.ExpireHeight = expire
		if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderExpired) {
			t.Fatalf("order_expire_height %d with D 120 = %v, want expired", expire, err)
		}
	}
	// A later bound_change_height moves D.
	f = newFixture(t, func(s *chaincli.SessionState) { s.BoundChangeHeight = 110 })
	o.ExpireHeight = 130
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderExpired) {
		t.Fatalf("order_expire_height 130 with D 130 = %v, want expired", err)
	}
}

// The cached head trails the chain (height polls are slower than blocks): an order the SDK built
// on a newer head looks like it is from the future. The head is read again once before
// ORDER_FUTURE is returned.
func TestPrecheckRereadsTheHeadBeforeOrderFuture(t *testing.T) {
	f := newFixture(t, nil) // cached head 100
	o := order(5)
	o.EarliestSubmitHeight = 104
	f.chain.mu.Lock()
	f.chain.height = 103
	f.chain.mu.Unlock()
	res, err := f.p.Check(context.Background(), o)
	if err != nil || res.Head != 103 {
		t.Fatalf("order built on head 103 = %+v, %v", res, err)
	}
	if f.cache.Head() != 103 {
		t.Fatalf("cached head = %d, want 103", f.cache.Head())
	}
	// Still ahead of the chain after the re-read: ORDER_FUTURE.
	o.EarliestSubmitHeight = 105
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderFuture) {
		t.Fatalf("order ahead of the chain = %v, want future", err)
	}
}

func TestPrecheckIdempotency(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.p.Commit(f.reserve(t, order(5)).Reservation); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		mark func() error
		want State
	}{
		{func() error { return nil }, StateDispatching},
		{func() error { return f.ledger.MarkAccepted(testSession, 5) }, StateAccepted},
		{func() error { return f.ledger.MarkRecorded(testSession, 5) }, StateRecorded},
	} {
		if err := step.mark(); err != nil {
			t.Fatal(err)
		}
		res, err := f.p.Reserve(context.Background(), order(5))
		if err != nil || res.Existing == nil || res.Existing.State != step.want {
			t.Fatalf("retry at %s = %+v, %v", step.want, res, err)
		}
	}
	// After the chain view includes the record the order is still answered until its deadline.
	f.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 6 })
	f.cache.SessionKeyUpdated(testSession)
	if res, err := f.p.Check(context.Background(), order(5)); err != nil || res.Existing == nil {
		t.Fatalf("retry of a recorded order = %+v, %v", res, err)
	}
}

// After a failed attempt the same sequence, even a new version of the order, is a retry.
func TestPrecheckRetryAfterFailure(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	if err := f.ledger.MarkFailed(testSession, 5); err != nil {
		t.Fatal(err)
	}
	o := order(5)
	o.TaskHash = "resigned"
	res := f.reserve(t, o)
	if !res.Retry || res.Existing != nil {
		t.Fatalf("retry = %+v", res)
	}
	if e, _ := f.ledger.Get(testSession, 5); e.State != StateDispatching || e.TaskHash != "resigned" {
		t.Fatalf("entry after retry = %+v", e)
	}
}

// MarkFailed does not cascade: n can fail (no capacity, revoked) while n+1 is still live. The
// chain admits nothing past n until n is recorded, so the resend of n must be admitted as a retry,
// and no order past the run of live orders may be.
func TestPrecheckRetriesAHoleBelowLiveOrders(t *testing.T) {
	f := newFixture(t, nil) // next 5
	f.reserve(t, order(5))
	f.reserve(t, order(6))
	if err := f.ledger.MarkFailed(testSession, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Check(context.Background(), order(7)); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("7 while 5 is a hole = %v, want sequence conflict", err)
	}
	o := order(5)
	o.TaskHash = "resigned5"
	if res := f.reserve(t, o); !res.Retry {
		t.Fatalf("resend of 5 = %+v", res)
	}
	if res := f.reserve(t, order(7)); res.Retry || res.Existing != nil {
		t.Fatalf("7 after 5 was resent = %+v", res)
	}
}

func TestPrecheckRetriesAHoleInTheMiddle(t *testing.T) {
	f := newFixture(t, nil)
	for seq := uint64(5); seq <= 7; seq++ {
		f.reserve(t, order(seq))
	}
	if err := f.ledger.MarkFailed(testSession, 6); err != nil {
		t.Fatal(err)
	}
	setParams(t, f, Params{RecordDeadlineBlocks: 20, OrderFreshnessMarginBlocks: 5, BuilderMaxInflightPerSession: 4, MaxPendingPerSession: 4})
	if _, err := f.p.Check(context.Background(), order(8)); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("8 while 6 is a hole = %v, want sequence conflict", err)
	}
	if res := f.reserve(t, order(6)); !res.Retry {
		t.Fatalf("resend of 6 = %+v", res)
	}
	f.reserve(t, order(8))
}

// The chain recorded an order whose record event this Builder has not seen yet: the state has
// moved past it while the ledger still holds it live. An exact resend is the existing order.
func TestPrecheckResendBelowNextIsExisting(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	_ = f.ledger.MarkAccepted(testSession, 5)
	f.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 6; s.FrozenTotal = "200" })
	f.cache.SessionKeyUpdated(testSession)
	res, err := f.p.Check(context.Background(), order(5))
	if err != nil || res.Existing == nil || res.Existing.State != StateAccepted {
		t.Fatalf("resend of 5 = %+v, %v", res, err)
	}
	o := order(5)
	o.TaskHash = "other"
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("another version of 5 = %v, want sequence conflict", err)
	}
}

// Release undoes a reservation that never reached dispatch: a new order is dropped, a retry puts
// the failed attempt back, and a suspension the retry ended is restored.
func TestPrecheckRelease(t *testing.T) {
	f := newFixture(t, nil)
	res := f.reserve(t, order(5))
	if res.Reservation == nil || res.Reservation.Sequence != 5 || res.Reservation.TaskHash != "hash5" {
		t.Fatalf("reservation = %+v", res.Reservation)
	}
	if err := f.p.Release(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.ledger.Get(testSession, 5); ok {
		t.Fatal("released order still in the ledger")
	}
	if err := f.p.Commit(f.reserve(t, order(5)).Reservation); err != nil {
		t.Fatal(err)
	}

	// A retry of a failed order, released: the failed attempt is back.
	f.reserve(t, order(6))
	_ = f.ledger.MarkFailed(testSession, 6)
	o := order(6)
	o.TaskHash = "resigned6"
	res = f.reserve(t, o)
	if err := f.p.Release(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.ledger.Get(testSession, 6); e.State != StateFailed || e.TaskHash != "hash6" {
		t.Fatalf("entry 6 after releasing its retry = %+v", e)
	}

	// The resend of a suspended sequence, released: the suspension is back.
	if err := f.ledger.Suspend(testSession, 6); err != nil {
		t.Fatal(err)
	}
	res = f.reserve(t, o)
	if _, suspended := f.ledger.SuspendedFrom(testSession); suspended {
		t.Fatal("suspension kept after the resend")
	}
	if err := f.p.Release(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if from, suspended := f.ledger.SuspendedFrom(testSession); !suspended || from != 6 {
		t.Fatalf("suspension after releasing the resend = %d, %v", from, suspended)
	}

	// A reservation the order moved past is not undone.
	res = f.reserve(t, o)
	_ = f.ledger.MarkAccepted(testSession, 6)
	if err := f.p.Release(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.ledger.Get(testSession, 6); e.State != StateAccepted {
		t.Fatalf("accepted order after a late release = %+v", e)
	}
	// Check, an existing order and a session bound elsewhere reserve nothing.
	if res, _ := f.p.Check(context.Background(), order(7)); res.Reservation != nil {
		t.Fatal("Check returned a reservation")
	}
	if res := f.reserve(t, order(5)); res.Existing == nil || res.Reservation != nil {
		t.Fatalf("existing order = %+v", res)
	}
}

// A reservation is uncommitted until its order reached the dispatcher: an exact resend while the
// first stream still uploads the input must not be answered as accepted (the first stream may
// still fail and release the entry, losing the order), so it gets a retryable code. Once
// committed, the resend is the existing order.
func TestPrecheckUncommittedReservationIsRetryable(t *testing.T) {
	f := newFixture(t, nil)
	res := f.reserve(t, order(5))
	if _, err := f.p.Check(context.Background(), order(5)); !errors.Is(err, ErrOrderUploading) {
		t.Fatalf("resend during the upload = %v, want uploading", err)
	}
	if err := f.p.Commit(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if res, err := f.p.Check(context.Background(), order(5)); err != nil || res.Existing == nil {
		t.Fatalf("resend after commit = %+v, %v", res, err)
	}
	// A committed reservation is not released.
	if err := f.p.Release(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.ledger.Get(testSession, 5); !ok || !e.Committed {
		t.Fatalf("committed entry after release = %+v, %v", e, ok)
	}
	// The dispatcher's state changes commit too.
	res = f.reserve(t, order(6))
	if err := f.ledger.MarkAccepted(testSession, 6); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.ledger.Get(testSession, 6); !e.Committed {
		t.Fatalf("accepted entry = %+v", e)
	}
}

// After a restart an uncommitted reservation never reached the dispatcher: it is released, and
// Unfinished lists only committed orders.
func TestLedgerReleasesUncommittedReservationsOnRestart(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	r6 := f.reserve(t, order(6)).Reservation
	if err := f.p.Commit(r6); err != nil {
		t.Fatal(err)
	}
	if u := f.ledger.Unfinished(); len(u) != 1 || u[0].Sequence != 6 {
		t.Fatalf("unfinished with 5 still uploading = %+v", u)
	}
	f.restart(t)
	if _, ok := f.ledger.Get(testSession, 5); ok {
		t.Fatal("uncommitted reservation survived the restart")
	}
	if u := f.ledger.Unfinished(); len(u) != 1 || u[0].Sequence != 6 || !u[0].Committed {
		t.Fatalf("unfinished after restart = %+v", u)
	}
	// 5 is now a hole the resend fills.
	f.reserve(t, order(5))
}

// A released order leaves no entry; when later orders are live it is a hole, retried like a
// failed one.
func TestPrecheckReleasedOrderIsAHole(t *testing.T) {
	f := newFixture(t, nil)
	r5 := f.reserve(t, order(5)).Reservation
	f.reserve(t, order(6))
	if err := f.p.Release(r5); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Check(context.Background(), order(7)); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("7 past the released 5 = %v", err)
	}
	f.reserve(t, order(5))
}

// The resend of the suspended sequence is admitted and ends the suspension.
func TestPrecheckSuspensionEndsWithTheResend(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	f.reserve(t, order(6))
	if err := f.ledger.Suspend(testSession, 5); err != nil {
		t.Fatal(err)
	}
	res := f.reserve(t, order(5))
	if !res.Retry {
		t.Fatalf("resend = %+v", res)
	}
	if _, suspended := f.ledger.SuspendedFrom(testSession); suspended {
		t.Fatal("suspension kept after the resend was admitted")
	}
	if res := f.reserve(t, order(6)); !res.Retry {
		t.Fatalf("sequence 6 after the resend = %+v", res)
	}
}

// Two in-flight orders signed by the session key: each fits the cap alone, the second must count
// the first, or the Keeper would admit one and reject the other at record time.
func TestPrecheckSpendCapCountsInFlightOrders(t *testing.T) {
	f := newFixture(t, func(s *chaincli.SessionState) { s.SpendCap = "700" }) // 500 spent: room for 200
	f.reserve(t, keyOrder(5))
	f.reserve(t, keyOrder(6))
	if _, err := f.p.Check(context.Background(), keyOrder(7)); !errors.Is(err, registeredkey.ErrSpendCapExceeded) {
		t.Fatalf("third key order = %v, want spend cap exceeded", err)
	}
	// Wallet orders in flight do not use the key's cap, and a wallet order is not bound by it.
	if _, err := f.p.Check(context.Background(), order(7)); err != nil {
		t.Fatalf("wallet order = %v", err)
	}
}

func TestPrecheckPendingRestrictionIsEffective(t *testing.T) {
	cases := []struct {
		name   string
		change *chaincli.PendingSessionKeyChange
		want   error
	}{
		{name: "clear", change: &chaincli.PendingSessionKeyChange{
			Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR, EffectiveHeight: 400,
		}, want: registeredkey.ErrKeyInvalid},
		{name: "lower cap", change: &chaincli.PendingSessionKeyChange{
			Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET, Key: testKey[:], ExpiryHeight: 500, SpendCap: "550", EffectiveHeight: 400,
		}, want: registeredkey.ErrSpendCapExceeded},
		{name: "higher cap", change: &chaincli.PendingSessionKeyChange{
			Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET, Key: testKey[:], ExpiryHeight: 500, SpendCap: "9000", EffectiveHeight: 400,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, func(s *chaincli.SessionState) { s.PendingKeyChange = c.change })
			if _, err := f.p.Check(context.Background(), keyOrder(5)); !errors.Is(err, c.want) {
				t.Fatalf("Check = %v, want %v", err, c.want)
			}
		})
	}
	// A clear registered after the state was read arrives as an event and applies at once.
	f := newFixture(t, nil)
	_ = f.cache.HandleChainEvent(sessionEvent(101, chaincli.SessionKeyChangeRequested{
		SessionID: testSession, Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR, EffectiveHeight: 400,
	}))
	if _, err := f.p.Check(context.Background(), keyOrder(5)); !errors.Is(err, registeredkey.ErrKeyInvalid) {
		t.Fatalf("key order after a clear event = %v", err)
	}
}

func TestPrecheckCancellation(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	_ = f.cache.HandleChainEvent(sessionEvent(101, chaincli.OrderCancelRequested{SessionID: testSession, OrderSequence: 6, CancelEffectiveHeight: 140}))
	if !f.ledger.CancelRequested(testSession, 6) {
		t.Fatal("cancellation not recorded")
	}
	if _, err := f.p.Check(context.Background(), order(6)); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("order of a sequence being cancelled = %v", err)
	}
	// 5 fails (say, no capacity) and is cancelled: the chain's next moves past it and the ledger
	// stops counting it.
	_ = f.cache.HandleChainEvent(sessionEvent(140, chaincli.OrderCancelled{SessionID: testSession, OrderSequence: 5}))
	if e, _ := f.ledger.Get(testSession, 5); e.State != StateFailed {
		t.Fatalf("cancelled in-flight order = %s", e.State)
	}
	o6 := order(6)
	o6.EarliestSubmitHeight = 140
	if _, err := f.p.Check(context.Background(), o6); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("6 while its cancellation is pending = %v", err)
	}
	_ = f.cache.HandleChainEvent(sessionEvent(141, chaincli.OrderCancelled{SessionID: testSession, OrderSequence: 6}))
	o := order(7)
	o.EarliestSubmitHeight = 141
	_ = f.cache.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 141})
	if _, err := f.p.Check(context.Background(), o); err != nil {
		t.Fatalf("7 after 5 and 6 were cancelled = %v", err)
	}
}

// An order cancellation moves the cached next and fails the ledger entry in two steps. A precheck
// that read the state before the first and the ledger after the second would see sequence 5 as a
// failed hole at next and admit a retry of a sequence the chain already consumed; it must judge
// the new state instead.
func TestPrecheckRetriesWhenTheSessionChangesAfterLookup(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	f.reserve(t, order(6))
	var once sync.Once
	f.p.afterLookup = func() {
		once.Do(func() {
			if err := f.cache.HandleChainEvent(sessionEvent(101, chaincli.OrderCancelled{SessionID: testSession, OrderSequence: 5})); err != nil {
				t.Error(err)
			}
		})
	}
	o := order(5)
	o.TaskHash = "resigned5"
	if res, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrOrderSequenceConflict) {
		t.Fatalf("resend of cancelled 5 = %+v, %v, want sequence conflict", res, err)
	}
	if _, err := f.p.Check(context.Background(), order(7)); err != nil {
		t.Fatalf("7 after 5 was cancelled = %v", err)
	}
}

func TestPrecheckRecoversAfterRestart(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, keyOrder(5))
	if err := f.p.Commit(f.reserve(t, order(6)).Reservation); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.MarkAccepted(testSession, 5); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	if res, err := f.p.Check(context.Background(), keyOrder(5)); err != nil || res.Existing == nil || res.Existing.State != StateAccepted {
		t.Fatalf("retry of 5 after restart = %+v, %v", res, err)
	}
	if _, err := f.p.Check(context.Background(), order(6)); err != nil {
		t.Fatalf("retry of 6 after restart = %v", err)
	}
	// Both still count: the next order is 7 and must fit after 200 in flight.
	o := order(7)
	o.MaxFee = 701
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrSessionBalanceInsufficient) {
		t.Fatalf("7 after restart = %v", err)
	}
	o.MaxFee = 700
	if _, err := f.p.Check(context.Background(), o); err != nil {
		t.Fatalf("7 within the balance after restart = %v", err)
	}
}

// The record of an in-flight order keeps the precheck exact before and after the cached state
// catches up.
func TestPrecheckAcrossARecord(t *testing.T) {
	f := newFixture(t, nil)
	f.reserve(t, order(5))
	_ = f.cache.HandleChainEvent(sessionEvent(101, chaincli.DispatchRecorded{SessionID: testSession, OrderSequence: 5, ReservedAmount: "100"}))
	check := func(stage string) {
		o := order(6)
		o.MaxFee = 801
		if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrSessionBalanceInsufficient) {
			t.Fatalf("%s: 801 = %v", stage, err)
		}
		o.MaxFee = 800
		if _, err := f.p.Check(context.Background(), o); err != nil {
			t.Fatalf("%s: 800 = %v", stage, err)
		}
	}
	f.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 6; s.FrozenTotal = "200" })
	check("before the refresh") // this lookup starts the refresh
	check("after the refresh")
}

// A session prefunded for exactly two orders: once the first settles, its frozen max_fee is
// released without any session-level event, and a third order fits again.
func TestPrecheckSeesFundsReleasedBySettlement(t *testing.T) {
	f := newFixture(t, func(s *chaincli.SessionState) { s.FrozenTotal = "0"; s.Balance = "900" })
	for seq := uint64(5); seq <= 6; seq++ {
		o := order(seq)
		o.MaxFee = 450
		f.reserve(t, o)
		_ = f.cache.HandleChainEvent(sessionEvent(101, chaincli.DispatchRecorded{SessionID: testSession, OrderSequence: seq, ReservedAmount: "450"}))
	}
	f.chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 7; s.FrozenTotal = "900" })
	o := order(7)
	o.MaxFee = 450
	o.EarliestSubmitHeight = 101
	if _, err := f.p.Check(context.Background(), o); !errors.Is(err, ErrSessionBalanceInsufficient) {
		t.Fatalf("third order with both in flight = %v", err)
	}
	// Task 5 settles at 102 and is refunded in full: frozen drops by its max_fee.
	f.chain.set(func(s *chaincli.SessionState) { s.FrozenTotal = "450" })
	_ = f.cache.HandleChainEvent(taskEvent(102, "TASK_SETTLED"))
	if _, err := f.p.Check(context.Background(), o); err != nil {
		t.Fatalf("third order after the first settled = %v", err)
	}
}

// A balance or spend cap rejection reads the session once more first: funds can be released, and
// a cap raised, by changes no event reported yet.
func TestPrecheckRereadsTheSessionBeforeRejectingFunds(t *testing.T) {
	f := newFixture(t, nil) // balance 1000, frozen 100
	_ = f.cache.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 101})
	f.chain.set(func(s *chaincli.SessionState) { s.FrozenTotal = "0"; s.SpendCap = "2000" })
	o := keyOrder(5)
	o.MaxFee = 1000
	if _, err := f.p.Check(context.Background(), o); err != nil {
		t.Fatalf("order fitting the chain's balance and cap = %v", err)
	}
	reads := f.chain.readCount()
	// A rejection that stays one reads the chain at most once per block.
	o.MaxFee = 5000
	for i := 0; i < 3; i++ {
		if _, err := f.p.Check(context.Background(), o); err == nil {
			t.Fatal("order above the balance admitted")
		}
	}
	if f.chain.readCount() > reads+1 {
		t.Fatalf("rejections in one block read the chain %d times", f.chain.readCount()-reads)
	}
}

// BenchmarkOpenTaskPrecheck measures Check on a warm session with two orders in flight.
func BenchmarkOpenTaskPrecheck(b *testing.B) {
	f := newFixture(b, nil)
	f.reserve(b, keyOrder(5))
	f.reserve(b, keyOrder(6))
	o := keyOrder(7)
	ctx := context.Background()
	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := f.p.Check(ctx, o); err != nil {
			b.Fatal(err)
		}
		durations = append(durations, time.Since(start))
	}
	b.StopTimer()
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	b.ReportMetric(float64(durations[len(durations)/2].Nanoseconds()), "p50-ns")
	b.ReportMetric(float64(durations[len(durations)*99/100].Nanoseconds()), "p99-ns")
	if f.chain.readCount() != 2 {
		b.Fatalf("warm precheck read the chain: %d reads", f.chain.readCount())
	}
}

// Concurrent orders for the same sequence and funds: exactly one is reserved.
func TestPrecheckReserveIsAtomic(t *testing.T) {
	f := newFixture(t, nil)
	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			o := order(5)
			o.TaskHash = fmt.Sprintf("version%d", i)
			o.MaxFee = 800
			_, err := f.p.Reserve(context.Background(), o)
			errs <- err
		}(i)
	}
	admitted := 0
	for i := 0; i < n; i++ {
		if err := <-errs; err == nil {
			admitted++
		} else if !errors.Is(err, ErrOrderReplacementUnsupported) {
			t.Fatalf("concurrent reserve = %v", err)
		}
	}
	if admitted != 1 {
		t.Fatalf("%d concurrent orders for one sequence were reserved", admitted)
	}
}
