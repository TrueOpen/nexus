package recorder

import (
	"reflect"
	"testing"

	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// Resolved entries are counted by outcome, and an entry handed over and broadcast in this run is
// timed from the accept to its broadcast and from its broadcast to its admission.
func TestMetricsOfRecordOutcomes(t *testing.T) {
	e := newEnv(t)
	e.metrics = opsmetrics.New()
	e.open()
	a0, a1, b0 := bundle(0xaa, 0, 1, 50), bundle(0xaa, 1, 2, 50), bundle(0xbb, 0, 3, 50)
	e.record(a0, a1, b0)
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.execute(raw, executed(t, msg, 11, ok(), refused(codeBalance), result{status: noop}))
	e.block(11)

	snap := e.metrics.Snapshot()
	want := map[string]uint64{"ADMITTED": 2, "SESSION_BALANCE_INSUFFICIENT": 1}
	if got := snap.Counters[opsmetrics.CounterRecordOutcomes]; !reflect.DeepEqual(got, want) {
		t.Fatalf("record outcomes = %v", got)
	}
	if got := snap.Stages[opsmetrics.StageAcceptToRecordSubmit].Count; got != 3 {
		t.Fatalf("accept to record submit timed %d times", got)
	}
	if got := snap.Stages[opsmetrics.StageRecordToAdmitted].Count; got != 2 {
		t.Fatalf("record to admitted timed %d times", got)
	}
	if len(e.r.queuedAt) != 0 || len(e.r.sentAt) != 0 {
		t.Fatalf("timings of resolved entries kept: %d queued, %d sent", len(e.r.queuedAt), len(e.r.sentAt))
	}
}
