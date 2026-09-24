package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// startWithSnapshot persists one task snapshot and starts a coordinator over the given chain
// facts, so recovery runs against them.
func startWithSnapshot(t *testing.T, snapshot taskSnapshot, facts *chainFactsFake) *Coordinator {
	t.Helper()
	store := kv.NewMemStore()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSTask, taskKey(snapshot.SessionID, snapshot.TaskID), raw); err != nil {
		t.Fatal(err)
	}
	c, _, _ := newRecoveryCoordinator(t, store, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	return c
}

func compactedSnapshot(state types.TaskState) chaincli.OnChainTask {
	return chaincli.OnChainTask{
		SessionID: "session-1", TaskID: "task-1", State: state, Compacted: true,
		TaskVerdict: types.VerdictPass, Winner: "worker-1",
		Settlement: chaincli.TaskSettlementState{
			SettlementStatus: "FINALIZED", SettlementHeight: 90,
			FinalityStatus: "FINAL", TaskFinalityHeight: 88,
		},
	}
}

func baseSnapshot(state types.TaskState, phase types.TaskPhase) taskSnapshot {
	return taskSnapshot{
		Version: 2, SessionID: "session-1", TaskID: "task-1",
		ModelID: "model", PayloadCID: "cid", State: state, Phase: phase,
	}
}

// The stuck case seen on the dev network: a task settled locally, whose settlement carries no
// finality yet, is closed as soon as the chain reports it FINAL.
func TestSettledTaskClosesOnChainFinality(t *testing.T) {
	facts := &chainFactsFake{height: 200, tasks: map[string]chaincli.OnChainTask{
		taskKey("session-1", "task-1"): {
			SessionID: "session-1", TaskID: "task-1", State: types.Settled,
			Settlement: chaincli.TaskSettlementState{SettlementStatus: "FINALIZED", FinalityStatus: "FINAL", TaskFinalityHeight: 150},
		},
	}}
	snapshot := baseSnapshot(types.Settled, types.PhaseSettle)
	snapshot.Settlement = chaincli.TaskSettlementState{SettlementHeight: 140, TaskFinalityHeight: 150}
	c := startWithSnapshot(t, snapshot, facts)
	if _, err := c.TaskStatus(context.Background(), "session-1", "task-1"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("settled task with chain finality was not closed: %v", err)
	}
}

// Recovery closes a task the chain has compacted, whatever local phase it had reached.
func TestRecoveryClosesCompactedTask(t *testing.T) {
	for _, tt := range []struct {
		name  string
		local types.TaskState
		phase types.TaskPhase
		chain types.TaskState
	}{
		{"settled on chain, assigned locally", types.Assigned, types.PhaseAssignmentFinalized, types.Settled},
		{"settled on chain, verifying locally", types.Verifying, types.PhaseOpenVerify, types.Settled},
		{"failed on chain", types.Assigned, types.PhaseAssignmentFinalized, types.Failed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			facts := &chainFactsFake{height: 200, tasks: map[string]chaincli.OnChainTask{
				taskKey("session-1", "task-1"): compactedSnapshot(tt.chain),
			}}
			c := startWithSnapshot(t, baseSnapshot(tt.local, tt.phase), facts)
			if _, err := c.TaskStatus(context.Background(), "session-1", "task-1"); !errors.Is(err, ErrTaskNotFound) {
				t.Fatalf("compacted task was not closed: %v", err)
			}
		})
	}
}

// At runtime, reconciling a task the chain has since compacted closes it and reports the
// reconciliation as done, instead of failing on every block.
func TestReconcileClosesCompactedTask(t *testing.T) {
	facts := &chainFactsFake{height: 200, taskErr: errors.New("node unavailable")}
	c := startWithSnapshot(t, baseSnapshot(types.Assigned, types.PhaseAssignmentFinalized), facts)
	if _, err := c.TaskStatus(context.Background(), "session-1", "task-1"); err != nil {
		t.Fatalf("task should survive recovery while the chain is unavailable: %v", err)
	}
	facts.mu.Lock()
	facts.taskErr = nil
	facts.tasks = map[string]chaincli.OnChainTask{taskKey("session-1", "task-1"): compactedSnapshot(types.Settled)}
	facts.mu.Unlock()
	if !c.reconcileTask("session-1", "task-1", 0, "test", nil) {
		t.Fatal("reconciliation of a compacted task did not complete")
	}
	if _, err := c.TaskStatus(context.Background(), "session-1", "task-1"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("compacted task was not closed: %v", err)
	}
}
