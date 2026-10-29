package takeover

import (
	"context"
	"errors"
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
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

// Pending counts the takeovers held, until they end.
func TestPendingCountsHeldTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	if e.m.Pending() != 1 {
		t.Fatalf("pending = %d", e.m.Pending())
	}
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	if e.m.Pending() != 0 {
		t.Fatalf("pending after the activation = %d", e.m.Pending())
	}
}

// While the Builder drains no new takeover is admitted; a takeover held already goes on to take
// effect, and the same order sent again is still answered with it.
func TestDrainAdmitsNoNewTakeover(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.draining.Store(true)
	o, pre := takeoverOrder(5, 1)
	if adm, err := e.m.Admit(context.Background(), o, pre); err != nil || !adm.Existing {
		t.Fatalf("Admit of the held order = %+v, %v", adm, err)
	}
	other := newEnv(t)
	other.draining.Store(true)
	_, err := other.m.Admit(context.Background(), o, pre)
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.Is(err, dispatcher.ErrDraining) || other.m.Pending() != 0 {
		t.Fatalf("Admit while draining = %v (pending %d)", err, other.m.Pending())
	}
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.bindHere(70)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	e.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
}

// A drain ends the candidate takeovers whose entry has not gone out yet as NO_CAPACITY, dropping
// their input, so the user goes elsewhere at once; one whose entry went out stays and takes effect.
func TestDrainEndsUnsentTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.draining.Store(true)
	e.m.EndUnsent()
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
	if e.m.Pending() != 0 || e.stored() != 0 {
		t.Fatalf("an ended takeover is still held (pending %d)", e.m.Pending())
	}

	sent := newEnv(t)
	sent.rec.sent = map[string]bool{session: true}
	sent.submit(5)
	sent.draining.Store(true)
	sent.m.EndUnsent()
	if sent.m.Pending() != 1 {
		t.Fatal("a takeover whose entry went out was ended")
	}
	sent.registerAt(70)
	sent.m.TakeoverRegistered(session, 5, 60)
	sent.bindHere(70)
	sent.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	sent.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
}

// An order admitted before the drain but submitted after it began is refused: nothing is held.
func TestDrainRefusesASubmitAfterItBegan(t *testing.T) {
	e := newEnv(t)
	o, pre := takeoverOrder(5, 1)
	if _, err := e.m.Admit(context.Background(), o, pre); err != nil {
		t.Fatal(err)
	}
	e.draining.Store(true)
	err := e.m.Submit(context.Background(), o)
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.Is(err, dispatcher.ErrDraining) {
		t.Fatalf("Submit while draining = %v", err)
	}
	e.m.Release(session, o.TaskHash)
	if e.m.Pending() != 0 || len(e.rec.bundles) != 0 {
		t.Fatal("a takeover submitted while draining is held")
	}
}
