package dispatcher

import (
	"context"
	"testing"

	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// syncCost is the synced and deferred kv writes of one step.
type syncCost struct{ Synced, Deferred int }

// syncSteps checks the writes a store took since the previous step.
type syncSteps struct {
	t     *testing.T
	store *kvtest.Store
	last  syncCost
}

func (s *syncSteps) step(name string, want syncCost) {
	s.t.Helper()
	now := syncCost{s.store.Synced(), s.store.Deferred()}
	if got := (syncCost{now.Synced - s.last.Synced, now.Deferred - s.last.Deferred}); got != want {
		s.t.Fatalf("%s cost %+v, want %+v", name, got, want)
	}
	s.last = now
}

// newCountingEnv is newEnv over a kvtest store, with every downlink send stored synced as the
// stream hub does and background work held until runBackground.
func newCountingEnv(t *testing.T) (*env, *kvtest.Store, func()) {
	t.Helper()
	e := newEnv(t)
	store := kvtest.New()
	e.store = store
	e.open(store)
	e.streams.durable = store
	var queued []func()
	e.d.cfg.Background = func(f func()) { queued = append(queued, f) }
	run := func() {
		for len(queued) > 0 {
			f := queued[0]
			queued = queued[1:]
			f()
		}
	}
	return e, store, run
}

// TestSyncedWritesPerOrderUntilTheWorkerHasItsInput pins the synced and deferred writes the
// dispatcher's path makes for one order, from the precheck's reservation to the last input chunk
// queued to the winner, step by step. The accept step is what runs before the accept is
// acknowledged, so before the Worker's input request is read; "after accept" is the work handed
// to the background. The input has 3 chunks.
func TestSyncedWritesPerOrderUntilTheWorkerHasItsInput(t *testing.T) {
	e, store, runBackground := newCountingEnv(t)
	steps := &syncSteps{t: t, store: store}
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	steps.step("reserve", syncCost{Deferred: 1})
	e.dispatch(o)
	steps.step("dispatch", syncCost{Synced: 1, Deferred: 1})
	runBackground()
	steps.step("offer", syncCost{Synced: 2})
	_, ticket, hash := e.lastOffer()
	accept, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, accept); err != nil {
		t.Fatal(err)
	}
	steps.step("accept", syncCost{Synced: 3})
	request := &nexusv1InputRequest{ticket: ticket, hash: hash}
	if err := e.d.HandleDispatchInputRequest(context.Background(), from, request.msg(from.Digest[:])); err != nil {
		t.Fatal(err)
	}
	if n := len(e.streams.inputResponses()); n != 3 {
		t.Fatalf("%d input chunks, want 3", n)
	}
	steps.step("input", syncCost{Synced: 3})
	runBackground()
	steps.step("after accept", syncCost{})
	if len(e.recorder.recorded()) != 1 {
		t.Fatal("the accepted order did not reach the recorder")
	}
}

// crashTo starts the dispatcher again over what a crash left, without stopping the old one: a
// crash runs nothing more.
func (e *env) crashTo(store *kvtest.Store) {
	e.t.Helper()
	e.store = store
	e.open(store)
	if err := e.d.Start(context.Background()); err != nil {
		e.t.Fatalf("start: %v", err)
	}
}

// A crash while Dispatch commits the order, its state written but the commit not durable yet,
// leaves neither the reservation nor the state: both are deferred writes the commit makes
// durable. No ticket went out, and the resent order is dispatched as new.
func TestCrashBeforeTheDispatchCommitLeavesNoOrder(t *testing.T) {
	e, store, _ := newCountingEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	var atCommit *kvtest.Store
	store.BeforeSync = func(ops []kv.WriteOp) {
		if atCommit == nil && ops[0].NS == kv.NSInflight {
			atCommit = store.Crash()
		}
	}
	e.dispatch(o)
	if atCommit == nil {
		t.Fatal("the commit was not a synced write")
	}
	e.crashTo(atCommit)
	if _, ok := e.ledger.Get(s, 0); ok {
		t.Fatal("the reservation survived a crash before its commit")
	}
	if states, err := loadStates(e.store); err != nil || len(states) != 0 {
		t.Fatalf("dispatch states after the crash: %d %v", len(states), err)
	}
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers before the commit was durable", n)
	}
	e.dispatch(e.order(s, 0, 1))
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers for the resent order, want 1", n)
	}
}

// A crash once Dispatch returned keeps the order: the restart resumes it and offers its ticket.
func TestCrashAfterTheDispatchCommitResumesTheOrder(t *testing.T) {
	e, store, _ := newCountingEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.crashTo(store.Crash())
	if e.ledgerState(o) != inflight.StateDispatching {
		t.Fatalf("ledger after the crash = %v", e.ledgerState(o))
	}
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers after the restart, want 1", n)
	}
}
