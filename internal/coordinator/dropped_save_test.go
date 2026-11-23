package coordinator

import (
	"context"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// blockingTaskQuerier holds QueryTask until released, so a test can end the task while a
// reconciliation's chain query is in flight.
type blockingTaskQuerier struct {
	entered chan struct{}
	release chan struct{}
	task    chaincli.OnChainTask
}

func (q *blockingTaskQuerier) QueryTask(ctx context.Context, _ chaincli.TaskKey) (chaincli.OnChainTask, error) {
	close(q.entered)
	select {
	case <-q.release:
	case <-ctx.Done():
		return chaincli.OnChainTask{}, ctx.Err()
	}
	return q.task, nil
}

// A reconciliation whose chain query was in flight when a voided takeover dropped the task must
// not write the dropped task's snapshot back: nothing would delete it before the next restart.
func TestReconcileDoesNotResurrectDroppedTakeoverTask(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnTakeover(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	q := &blockingTaskQuerier{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		// The bound Builder recorded the task: the chain holds it, short of Failed.
		task: chaincli.OnChainTask{SessionID: o.SessionID, TaskID: o.TaskID, State: types.Pending},
	}
	c.query = q
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.reconcileTask(o.SessionID, o.TaskID, 0, "test", nil)
	}()
	<-q.entered
	c.TakeoverEnded(o.SessionID, o.TaskID, EvTakeoverVoided, 120, true, nil)
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("the voided takeover kept its task")
	}
	close(q.release)
	<-done
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, err := store.GetWithError(kv.NSTask, key); err != nil || found {
		t.Fatalf("task snapshot after the reconciliation: found=%v err=%v", found, err)
	}
}

// Once a task is removed from the live set, a save of that FSM no longer reaches disk; a new FSM of
// the same key is unaffected.
func TestSaveAfterRemovalIsNotPersisted(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnTakeover(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(o.SessionID, o.TaskID)
	if !ok {
		t.Fatal("no task")
	}
	c.TakeoverEnded(o.SessionID, o.TaskID, EvTakeoverVoided, 120, true, nil)
	key := taskKey(o.SessionID, o.TaskID)
	fsm.mu.Lock()
	err := fsm.save()
	fsm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.GetWithError(kv.NSTask, key); found {
		t.Fatal("a save after the drop wrote the snapshot back")
	}
	// The same order taken over again is a new task and persists as usual.
	if err := c.OnTakeover(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.GetWithError(kv.NSTask, key); !found {
		t.Fatal("a new task of the same key was not persisted")
	}
}

// A dispatch failure drops the task while it is still Pending: a snapshot written back afterwards
// would be recovered as an in-flight task on the next restart, so a late save must write nothing.
func TestSaveAfterDispatchFailureIsNotPersisted(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(o.SessionID, o.TaskID)
	if !ok {
		t.Fatal("no task")
	}
	c.DispatchFailed(o.SessionID, o.TaskID, dispatchdraw.ErrNoCapacity)
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("the failed dispatch kept its task")
	}
	fsm.mu.Lock()
	state := fsm.state
	err := fsm.save()
	fsm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if state != types.Pending {
		t.Fatalf("state after the dispatch failure = %s, want Pending", state)
	}
	if _, found, _ := store.GetWithError(kv.NSTask, taskKey(o.SessionID, o.TaskID)); found {
		t.Fatal("a save after the dispatch failure wrote a Pending snapshot back")
	}
}

// A task closed on the terminal path (removed and its snapshot deleted) is not written back by a
// save through a stale pointer.
func TestSaveAfterCloseIsNotPersisted(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	recordTestWinner(c, o.SessionID, o.TaskID, testOperator("worker-1"), 101)
	fsm, ok := c.getFSM(o.SessionID, o.TaskID)
	if !ok {
		t.Fatal("no task")
	}
	if !fsm.closeGone(300) {
		t.Fatal("task did not close")
	}
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, _ := store.GetWithError(kv.NSTask, key); found {
		t.Fatal("precondition: the closed task kept its snapshot")
	}
	fsm.mu.Lock()
	err := fsm.save()
	fsm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.GetWithError(kv.NSTask, key); found {
		t.Fatal("a save after the close wrote the snapshot back")
	}
}
