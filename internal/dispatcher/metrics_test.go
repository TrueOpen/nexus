package dispatcher

import (
	"reflect"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// newMeteredEnv is newEnv with a metrics registry wired into the dispatcher.
func newMeteredEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.metrics = opsmetrics.New()
	e.open(e.store)
	return e
}

// A walk that skips an unreachable member, takes a reject and wins on the third ticket moves the
// skip counters by reason, each Worker's outcomes and the stage timings of the order.
func TestMetricsOfAnAcceptedWalk(t *testing.T) {
	e := newMeteredEnv(t)
	e.streams.disconnected[op7] = true
	e.streams.rtt[op1] = 30 * time.Millisecond
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.reject() // op1
	e.clock.advance(40 * time.Millisecond)
	e.accept() // op3

	snap := e.metrics.Snapshot()
	if got := snap.Counters[opsmetrics.CounterSkips]; !reflect.DeepEqual(got, map[string]uint64{opsmetrics.SkipUnreachable: 1, opsmetrics.SkipRejected: 1}) {
		t.Fatalf("skips = %v", got)
	}
	if got := snap.Counters[opsmetrics.CounterTicketsPerOrder]; !reflect.DeepEqual(got, map[string]uint64{"3": 1}) {
		t.Fatalf("tickets per order = %v", got)
	}
	if got := snap.Counters[opsmetrics.CounterOrders]; !reflect.DeepEqual(got, map[string]uint64{"accepted": 1}) {
		t.Fatalf("orders = %v", got)
	}
	if w := snap.Workers[op7]; w.Unsent != 1 || w.Received != 0 {
		t.Fatalf("op7 = %+v", w)
	}
	if w := snap.Workers[op1]; w.Received != 1 || w.Rejected != 1 || w.ReceivedByTier[1] != 1 {
		t.Fatalf("op1 = %+v", w)
	}
	if w := snap.Workers[op3]; w.Received != 1 || w.Accepted != 1 {
		t.Fatalf("op3 = %+v", w)
	}
	for _, stage := range []string{opsmetrics.StageWaitESH, opsmetrics.StageDraw, opsmetrics.StageTicketToAccept} {
		if snap.Stages[stage].Count != 1 {
			t.Fatalf("stage %s = %+v", stage, snap.Stages[stage])
		}
	}
	if got := snap.Stages[opsmetrics.StageTicketToAccept].TotalMs; got != 40 {
		t.Fatalf("ticket to accept = %v ms", got)
	}
	// The accept starts the wait for the first output frame.
	e.metrics.OutputFrame(e.onlyBundle().TaskID)
	if e.metrics.Snapshot().Stages[opsmetrics.StageAcceptToFirstOutput].Count != 1 {
		t.Fatal("first output frame not timed from the accept")
	}
}

// Drawn members outside the roster, a received timeout and a member whose key rotation is pending
// are counted apart; the order that runs out of members fails with the tickets it took.
func TestMetricsOfAFailedWalk(t *testing.T) {
	e := newMeteredEnv(t)
	e.handraises.setRoot(0xd2, 2, op1, op3)
	e.keys.pendCortex(op3, testESH)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1)) // drawn op7 (not in the roster), op1, op3
	e.clock.advance(time.Second)

	snap := e.metrics.Snapshot()
	want := map[string]uint64{opsmetrics.SkipNotInRoster: 1, opsmetrics.SkipTimeout: 1, opsmetrics.SkipRotationPending: 1}
	if got := snap.Counters[opsmetrics.CounterSkips]; !reflect.DeepEqual(got, want) {
		t.Fatalf("skips = %v", got)
	}
	if got := snap.Counters[opsmetrics.CounterOrders]; !reflect.DeepEqual(got, map[string]uint64{"failed": 1}) {
		t.Fatalf("orders = %v", got)
	}
	if got := snap.Counters[opsmetrics.CounterTicketsPerOrder]; !reflect.DeepEqual(got, map[string]uint64{"2": 1}) {
		t.Fatalf("tickets per order = %v", got)
	}
	if w := snap.Workers[op1]; w.Received != 1 || w.Timeouts != 1 || w.TimeoutRate() != 1 {
		t.Fatalf("op1 = %+v", w)
	}
	if w := snap.Workers[op3]; w.Unsent != 1 {
		t.Fatalf("op3 = %+v", w)
	}
	if got := e.handraises.outcomeCalls(); !reflect.DeepEqual(got, []outcomeCall{{op1, false}}) {
		t.Fatalf("reject-rate outcomes = %v", got)
	}
}
