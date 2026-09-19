package coordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	wirebus "github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
)

// The old "§5.5 JSON field-set line-by-line assertion" was removed with the bus format migration:
// the hand-raise payload is now the frozen wire task.v1.WorkerHandraiseV1 proto itself; the
// field set is pinned by the proto mirror + make proto generation discipline, both sides share one
// declaration, and there is no drift surface of "each side writing its own JSON field table"
// (which was the root cause of the old gh incident).

// TestWorkerHandraiseAcceptsFrozenFrame: a hand-raise built per the frozen contract must be
// accepted and recorded under member.operator_address.
func TestWorkerHandraiseAcceptsFrozenFrame(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)

	session := "sess-5-5"
	task := testTaskID("task-5-5")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	worker := testOperator("worker-1")
	publishEnvelope(t, bus, keys, worker, msgbus.SubjectWorkerHandraiseV1(task),
		wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, worker))

	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM is missing")
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if len(fsm.workerHR) != 1 {
		t.Fatalf("frozen handraise was dropped: collected %d", len(fsm.workerHR))
	}
	if _, exists := fsm.workerHR[worker]; !exists {
		t.Fatalf("handraise is not keyed by member.operator_address: %+v", fsm.workerHR)
	}
}

// TestWorkerHandraiseRejectsForeignChainID covers payload-level chain_id validation: it must equal
// the target chain; frames sent to the wrong place or replayed cross-chain must not enter the FSM.
func TestWorkerHandraiseRejectsForeignChainID(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)

	session := "sess-foreign-chain"
	task := testTaskID("task-foreign-chain")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	worker := testOperator("worker-1")
	handraise := testWorkerHandraise(session, task, worker)
	handraise.ChainId = "some-other-chain"
	publishEnvelope(t, bus, keys, worker, msgbus.SubjectWorkerHandraiseV1(task),
		wirebus.KindWorkerHandraise, handraise)

	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM is missing")
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if len(fsm.workerHR) != 0 {
		t.Fatalf("handraise bound to another chain was accepted: %+v", fsm.workerHR)
	}
}
