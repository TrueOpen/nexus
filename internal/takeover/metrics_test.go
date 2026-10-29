package takeover

import (
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// Ended takeovers are counted by how they ended: activated with the order dispatched, or the code
// their task ended with.
func TestMetricsOfTakeoverOutcomes(t *testing.T) {
	metrics := opsmetrics.New()
	e := newEnv(t)
	e.metrics = metrics
	e.open()
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.m.HandleChainEvent(chaincli.ChainEvent{Height: 65, Typed: chaincli.SessionTakeoverVoided{
		SessionID: session, CandidateBuilder: self, OrderSequence: 5, Reason: taskv1.SessionTakeoverVoidReasonV1_SESSION_TAKEOVER_VOID_REASON_V1_ORDER_RECORDED,
	}})
	e = newEnv(t)
	e.metrics = metrics
	e.open()
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})

	want := map[string]uint64{"TAKEOVER_VOIDED": 1, outcomeActivated: 1}
	if got := metrics.Snapshot().Counters[opsmetrics.CounterTakeoverOutcomes]; !reflect.DeepEqual(got, want) {
		t.Fatalf("takeover outcomes = %v", got)
	}
}
