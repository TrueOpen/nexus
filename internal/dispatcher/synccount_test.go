package dispatcher

import (
	"context"
	"testing"

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
	steps.step("reserve", syncCost{Synced: 1})
	e.dispatch(o)
	steps.step("dispatch", syncCost{Synced: 2})
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
