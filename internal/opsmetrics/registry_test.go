package opsmetrics

import (
	"testing"
	"time"
)

func TestStagesSumCountAndMax(t *testing.T) {
	r := New()
	r.ObserveStage(StageDraw, 2*time.Millisecond)
	r.ObserveStage(StageDraw, 4500*time.Microsecond)
	got := r.Snapshot().Stages[StageDraw]
	if got.Count != 2 || got.TotalMs != 6.5 || got.MaxMs != 4.5 || got.MeanMs != 3.25 {
		t.Fatalf("draw timing = %+v", got)
	}
}

func TestCountersByLabel(t *testing.T) {
	r := New()
	r.Inc(CounterSkips, SkipTimeout)
	r.Inc(CounterSkips, SkipTimeout)
	r.Add(CounterSkips, SkipNotInRoster, 3)
	r.Add(CounterSkips, SkipRejected, 0)
	got := r.Snapshot().Counters[CounterSkips]
	if len(got) != 2 || got[SkipTimeout] != 2 || got[SkipNotInRoster] != 3 {
		t.Fatalf("skips = %v", got)
	}
}

// The reject and timeout rates share the denominator the reject-rate suspension uses: the tickets
// the Worker received. Tickets that never reached it are counted apart.
func TestWorkerRates(t *testing.T) {
	r := New()
	w := "cortex1"
	r.WorkerOutcome(w, 0, OutcomeAccepted)
	r.WorkerOutcome(w, 0, OutcomeRejected)
	r.WorkerOutcome(w, 1, OutcomeRejectedWithoutFreeSlot)
	r.WorkerOutcome(w, 1, OutcomeTimeout)
	r.WorkerOutcome(w, 2, OutcomeUnsent)
	got := r.Snapshot().Workers[w]
	if got.Received != 4 || got.Accepted != 1 || got.Rejected != 1 || got.RejectedWithoutFreeSlot != 1 || got.Timeouts != 1 || got.Unsent != 1 {
		t.Fatalf("worker = %+v", got)
	}
	if got.RejectRate() != 0.25 || got.TimeoutRate() != 0.25 {
		t.Fatalf("rates = %v %v", got.RejectRate(), got.TimeoutRate())
	}
	if got.TimeoutsByTier[1] != 1 || got.ReceivedByTier[0] != 2 || got.ReceivedByTier[1] != 2 || got.ReceivedByTier[2] != 0 {
		t.Fatalf("tiers = %v %v", got.TimeoutsByTier, got.ReceivedByTier)
	}
	if (WorkerStats{}).RejectRate() != 0 || (WorkerStats{}).TimeoutRate() != 0 {
		t.Fatal("a Worker without tickets has a rate")
	}
}

func TestFirstOutputFrameIsTimedFromTheAcceptOnce(t *testing.T) {
	r := New()
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	r.Accepted("task1")
	now = now.Add(80 * time.Millisecond)
	r.OutputFrame("task1")
	now = now.Add(time.Second)
	r.OutputFrame("task1")
	r.OutputFrame("unknown")
	got := r.Snapshot().Stages[StageAcceptToFirstOutput]
	if got.Count != 1 || got.TotalMs != 80 {
		t.Fatalf("first output = %+v", got)
	}
}

func TestAcceptedTasksAreBounded(t *testing.T) {
	r := New()
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	for i := 0; i < maxAwaitingOutput; i++ {
		r.Accepted(string(rune(i)))
	}
	r.Accepted("late")
	if _, ok := r.acceptedAt["late"]; ok || len(r.acceptedAt) != maxAwaitingOutput {
		t.Fatalf("awaiting %d tasks", len(r.acceptedAt))
	}
	now = now.Add(awaitingOutputMaxAge + time.Second)
	r.Accepted("later")
	if _, ok := r.acceptedAt["later"]; !ok || len(r.acceptedAt) != 1 {
		t.Fatalf("old tasks not dropped: %d", len(r.acceptedAt))
	}
}

func TestNilRegistryIsANoOp(t *testing.T) {
	var r *Registry
	r.ObserveStage(StageDraw, time.Second)
	r.Inc(CounterSkips, SkipTimeout)
	r.Add(CounterSkips, SkipTimeout, 2)
	r.WorkerOutcome("w", 0, OutcomeAccepted)
	r.Accepted("t")
	r.OutputFrame("t")
	if s := r.Snapshot(); len(s.Stages) != 0 || len(s.Counters) != 0 || len(s.Workers) != 0 {
		t.Fatalf("nil registry snapshot = %+v", s)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	r := New()
	r.Inc(CounterSkips, SkipTimeout)
	r.WorkerOutcome("w", 1, OutcomeTimeout)
	s := r.Snapshot()
	s.Counters[CounterSkips][SkipTimeout] = 9
	s.Workers["w"].TimeoutsByTier[1] = 9
	again := r.Snapshot()
	if again.Counters[CounterSkips][SkipTimeout] != 1 || again.Workers["w"].TimeoutsByTier[1] != 1 {
		t.Fatal("snapshot shares state with the registry")
	}
}
