package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// nextEpoch is the epoch after testEpoch, whose first height a retry of an exhausted sequence
// waits for.
var nextEpoch = dispatchdraw.Epoch{Number: testEpoch.Number + 1, ReferenceHeight: (testEpoch.Number + 1) * testEpochLength,
	Seed: testEpoch.Seed, SnapshotID: testEpoch.SnapshotID}

// A retry of a sequence whose walk passed its last member in this epoch would fail at once: the
// cursor continues across rounds. Probe refuses it before its input is stored, as NO_CAPACITY
// naming the first height of the next epoch, from which a re-signed retry is drawn afresh.
func TestProbeRefusesARetryPastTheLastMember(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 10, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	for range 3 {
		e.reject()
	}
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("not failed")
	}
	retry := e.order(s, 0, 2)
	err := e.d.Probe(context.Background(), retry)
	var exhausted *dispatchdraw.EpochExhaustedError
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.As(err, &exhausted) {
		t.Fatalf("probe = %v", err)
	}
	if exhausted.Epoch != testEpoch.Number || exhausted.RetryHeight != nextEpoch.ReferenceHeight {
		t.Fatalf("exhausted = %+v", exhausted)
	}
	want := fmt.Sprintf("%v: epoch %d: no member of the order is left after rank 3 of 3 (attempts: 0 timed out, 0 unreachable, 3 rejected); dispatchable_height=%d",
		dispatchdraw.ErrNoCapacity, testEpoch.Number, nextEpoch.ReferenceHeight)
	if err.Error() != want {
		t.Fatalf("probe = %q\nwant    %q", err, want)
	}

	// Re-signed in the next epoch, the retry restarts the order.
	e.drawer.mu.Lock()
	e.drawer.epoch = nextEpoch
	e.drawer.mu.Unlock()
	if err := e.d.Probe(context.Background(), retry); err != nil {
		t.Fatalf("probe in the next epoch = %v", err)
	}
}

// The refusal tells an order nobody answered in time from one the Workers rejected: every member
// of the order timed out here, and the reason says so.
func TestProbeRetryRefusalNamesTimeouts(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 10, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	for range 2 {
		_, ticket, _ := e.lastOffer()
		e.clock.advance(time.Duration(ticket.GetAcceptDeadlineMs()-uint64(e.clock.Now().UnixMilli())) * time.Millisecond)
	}
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("not failed")
	}
	err := e.d.Probe(context.Background(), e.order(s, 0, 2))
	want := fmt.Sprintf("%v: epoch %d: no member of the order is left after rank 3 of 3 (attempts: 2 timed out, 0 unreachable, 1 rejected); dispatchable_height=%d",
		dispatchdraw.ErrNoCapacity, testEpoch.Number, nextEpoch.ReferenceHeight)
	if err == nil || err.Error() != want {
		t.Fatalf("probe = %v\nwant    %q", err, want)
	}
}

// A retry of a sequence that failed past max_skips in this epoch would fail at once too: the skip
// count continues across rounds.
func TestProbeRefusesARetryPastMaxSkips(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("not failed")
	}
	retry := e.order(s, 0, 2)
	err := e.d.Probe(context.Background(), retry)
	var exhausted *dispatchdraw.EpochExhaustedError
	if !errors.As(err, &exhausted) || exhausted.RetryHeight != nextEpoch.ReferenceHeight {
		t.Fatalf("probe = %v", err)
	}
	want := fmt.Sprintf("%v: epoch %d: the earlier attempts of the sequence took 1 skips, past max_skips 0 (attempts: 0 timed out, 0 unreachable, 1 rejected); dispatchable_height=%d",
		dispatchdraw.ErrNoCapacity, testEpoch.Number, nextEpoch.ReferenceHeight)
	if err.Error() != want {
		t.Fatalf("probe = %q\nwant    %q", err, want)
	}

	// A raised max_skips lets the retry continue.
	e.d.SetParams(e.params)
	if err := e.d.Probe(context.Background(), retry); err != nil {
		t.Fatalf("probe under a raised max_skips = %v", err)
	}
}

// A retry that still has members left, or that a binding change restarts, is not refused, and a
// height that cannot be read leaves the answer without one.
func TestProbeRetryRefusalOnlyWhenCertain(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 10, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.handraises.setRoot(0xd2, 2, op7) // op1 and op3 out of the first round: it fails past rank 0
	e.dispatch(o)
	e.reject()
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("not failed")
	}
	e.handraises.setRoot(0xd3, 2, op1, op3, op7)
	if err := e.d.Probe(context.Background(), e.order(s, 0, 2)); err != nil {
		t.Fatalf("probe with members left = %v", err)
	}

	e2 := newEnv(t)
	e2.d.SetParams(Params{MaxSkips: 0, Sticky: e2.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s2 := e2.session(0xbb, 0)
	o2 := e2.order(s2, 0, 1)
	e2.dispatch(o2)
	e2.reject()
	retry := e2.order(s2, 0, 2)
	e2.drawer.mu.Lock()
	e2.drawer.startErr = errors.New("params unreadable")
	e2.drawer.mu.Unlock()
	err := e2.d.Probe(context.Background(), retry)
	var exhausted *dispatchdraw.EpochExhaustedError
	if !errors.As(err, &exhausted) || exhausted.RetryHeight != 0 {
		t.Fatalf("probe without the next epoch's height = %v", err)
	}
	e2.drawer.mu.Lock()
	e2.drawer.startErr = nil
	e2.drawer.mu.Unlock()
	// The session moved away and back: a new binding generation restarts the rounds.
	e2.chain.update(s2, func(st *chaincli.SessionState) { st.BoundChangeHeight = testBound + 5 })
	bound := chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s2, NewBuilder: e2.builder, BoundChangeHeight: testBound + 5}}
	if err := e2.sessions.HandleChainEvent(bound); err != nil {
		t.Fatal(err)
	}
	e2.d.HandleChainEvent(bound)
	if err := e2.d.Probe(context.Background(), retry); err != nil {
		t.Fatalf("probe after a binding change = %v", err)
	}
}
