package coordinator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// A refused record ends the Pending task with RECORD_REJECTED, from the Recorder or as the
// dispatcher's failure of a later order of the session; a resend of the sequence starts again.
func TestRecordRejectedEndsThePendingTask(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	o := testPlaceholderOrder("session-1", "task-1")
	later := testPlaceholderOrder("session-1", "task-2")
	for _, order := range []types.Order{o, later} {
		if err := c.OnOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
	}
	c.DispatchAccepted(o.SessionID, o.TaskID, [32]byte{1}, "worker-1")
	c.RecordRejected(o.SessionID, o.TaskID, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_BALANCE_INSUFFICIENT)
	c.DispatchFailed(later.SessionID, later.TaskID, fmt.Errorf("%w: sequence 0", dispatcher.ErrRecordRejected))
	for _, order := range []types.Order{o, later} {
		if _, ok := c.getFSM(order.SessionID, order.TaskID); ok {
			t.Fatalf("%s kept its task", order.TaskID)
		}
	}
	if got := strings.Join(eventCodes(c, o.SessionID, o.TaskID), ","); got != "ORDER_RECEIVED,DISPATCH_ACCEPTED,RECORD_REJECTED" {
		t.Fatalf("events = %s", got)
	}
	if got := strings.Join(eventCodes(c, later.SessionID, later.TaskID), ","); got != "ORDER_RECEIVED,RECORD_REJECTED" {
		t.Fatalf("later events = %s", got)
	}
	if err := c.OnOrder(ctx, o); err != nil {
		t.Fatalf("resend: %v", err)
	}
}

// A recorded dispatch reconciles the task with the chain, which moves it to Assigned.
func TestDispatchRecordedReconcilesTheTask(t *testing.T) {
	const sessionID, taskID = "session-1", "task-1"
	facts := &chainFactsFake{height: 50, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := trackTestOrder(c, testPlaceholderOrder(sessionID, taskID)); err != nil {
		t.Fatal(err)
	}
	facts.mu.Lock()
	facts.tasks[taskKey(sessionID, taskID)] = chaincli.OnChainTask{SessionID: sessionID, TaskID: taskID, State: types.Assigned, Winner: "worker-1"}
	facts.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)
	c.DispatchRecorded(sessionID, taskID, 50)
	eventually(t, func() bool {
		fsm, ok := c.getFSM(sessionID, taskID)
		if !ok {
			return false
		}
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return fsm.state == types.Assigned && fsm.winner == "worker-1"
	})
}

// A Pending task the chain does not hold fails as RECORD_REJECTED once the head is past its record
// deadline, long before the order expires.
func TestReconcileFailsPendingPastTheRecordDeadline(t *testing.T) {
	const sessionID, taskID = "session-1", "task-1"
	facts := &chainFactsFake{height: 90, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	o := testCurrentOrder(sessionID, taskID, testUserAddress)
	o.DeadlineHeight = 1000
	c.SetDispatcher(&fakeDispatcher{deadlines: map[uint64]uint64{o.OrderSequence: 90}})
	if err := trackTestOrder(c, o); err != nil {
		t.Fatal(err)
	}
	if _, err := c.refreshChainHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.reconcileTask(sessionID, taskID, 0, "test", nil)
	if _, ok := c.getFSM(sessionID, taskID); !ok {
		t.Fatal("failed at its record deadline height")
	}
	facts.mu.Lock()
	facts.height = 91
	facts.mu.Unlock()
	if _, err := c.refreshChainHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.reconcileTask(sessionID, taskID, 0, "test", nil)
	if _, ok := c.getFSM(sessionID, taskID); ok {
		t.Fatal("still Pending past its record deadline")
	}
	events := c.journalFor(taskKey(sessionID, taskID)).snapshot()
	if len(events) == 0 || events[len(events)-1].EventCode != EvRecordRejected || events[len(events)-1].ChainHeight != 91 {
		t.Fatalf("last event = %+v", events)
	}
}
