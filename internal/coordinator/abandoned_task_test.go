package coordinator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

const abandonedTestOwner = "trueopen1abandonedowner"

func abandonedTestOrder() types.Order {
	o := testPlaceholderOrder("session-1", "task-1")
	o.User = abandonedTestOwner
	return o
}

// startAbandonedTestTask tracks an acknowledged order on c whose dispatch then fails.
func startAbandonedTestTask(t *testing.T, c *Coordinator) types.Order {
	t.Helper()
	seedTestBuilderSet(c)
	c.SetDispatcher(&fakeDispatcher{})
	o := abandonedTestOrder()
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// The snapshot is stored before the failure, so the tests that see it deleted afterwards
	// check a real deletion.
	if _, found, err := c.kv.GetWithError(kv.NSTask, taskKey(o.SessionID, o.TaskID)); err != nil || !found {
		t.Fatalf("snapshot before the dispatch failure: found=%v err=%v", found, err)
	}
	c.DispatchFailed(o.SessionID, o.TaskID, dispatchdraw.ErrNoCapacity)
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("a failed dispatch kept its task")
	}
	return o
}

func replayCodes(t *testing.T, c *Coordinator, o types.Order, cursor uint64) ([]types.TaskEvent, func()) {
	t.Helper()
	replay, _, cancel, err := c.TaskEvents(context.Background(), o.SessionID, o.TaskID, cursor)
	if err != nil {
		t.Fatalf("TaskEvents: %v", err)
	}
	return replay, cancel
}

func joinCodes(events []types.TaskEvent) string {
	codes := make([]string, 0, len(events))
	for _, ev := range events {
		codes = append(codes, ev.EventCode)
	}
	return strings.Join(codes, ",")
}

func assertAbandonedTaskReadable(t *testing.T, c *Coordinator, o types.Order) {
	t.Helper()
	ctx := context.Background()
	owner, err := c.TaskOwner(ctx, o.SessionID, o.TaskID)
	if err != nil || owner != abandonedTestOwner {
		t.Fatalf("TaskOwner = %q, %v", owner, err)
	}
	replay, cancel := replayCodes(t, c, o, 0)
	cancel()
	if got, want := joinCodes(replay), EvOrderReceived+","+EvNoCapacity; got != want {
		t.Fatalf("events = %s, want %s", got, want)
	}
	status, err := c.TaskStatus(ctx, o.SessionID, o.TaskID)
	if err != nil || status.State != types.Failed.String() || status.TaskPhase != types.PhaseUnspecified.String() {
		t.Fatalf("TaskStatus = %+v, %v", status, err)
	}
}

// An acknowledged order whose dispatch fails keeps its owner, journal and a FAILED status
// readable, and its snapshot is replaced by the abandoned task record.
func TestDispatchFailedKeepsTheAbandonedTaskReadable(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	o := startAbandonedTestTask(t, c)
	assertAbandonedTaskReadable(t, c, o)
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, _ := store.GetWithError(kv.NSTask, key); found {
		t.Fatal("the abandoned task's snapshot is still stored")
	}
	if _, found, _ := store.GetWithError(kv.NSAbandonedTask, key); !found {
		t.Fatal("no abandoned task record")
	}
}

// After a restart the abandoned task is still readable from its record.
func TestAbandonedTaskSurvivesARestart(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	o := startAbandonedTestTask(t, c)

	restarted, _ := newTaskTrackingCoordinator(t, store)
	if err := restarted.recoverTasks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.loadAbandonedTasks(); err != nil {
		t.Fatal(err)
	}
	assertAbandonedTaskReadable(t, restarted, o)
}

// A retry of the sequence after a restart continues the journal: a subscriber holding the cursor
// of NO_CAPACITY receives the retry's ORDER_RECEIVED, and the record gives way to the new task.
func TestRetryAfterARestartContinuesTheCursor(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	o := startAbandonedTestTask(t, c)

	restarted, _ := newTaskTrackingCoordinator(t, store)
	if err := restarted.loadAbandonedTasks(); err != nil {
		t.Fatal(err)
	}
	replay, live, cancel, err := restarted.TaskEvents(context.Background(), o.SessionID, o.TaskID, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	cursor := replay[len(replay)-1].Seq
	if replay[len(replay)-1].EventCode != EvNoCapacity || cursor != 2 {
		t.Fatalf("replay = %+v", replay)
	}

	seedTestBuilderSet(restarted)
	restarted.SetDispatcher(&fakeDispatcher{})
	retry := o
	retry.TaskHash = strings.Repeat("b", 64)
	if err := restarted.OnOrder(context.Background(), retry); err != nil {
		t.Fatalf("retry: %v", err)
	}
	select {
	case ev := <-live:
		if ev.EventCode != EvOrderReceived || ev.Seq != cursor+1 {
			t.Fatalf("live event = %+v, want ORDER_RECEIVED at %d", ev, cursor+1)
		}
	case <-time.After(time.Second):
		t.Fatal("the retry's ORDER_RECEIVED did not reach the subscriber")
	}
	again, cancelAgain := replayCodes(t, restarted, o, cursor)
	cancelAgain()
	if got := joinCodes(again); got != EvOrderReceived {
		t.Fatalf("replay after cursor = %s", got)
	}
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, _ := store.GetWithError(kv.NSAbandonedTask, key); found || restarted.hasAbandonedRecord(key) {
		t.Fatal("the retry left the abandoned task record")
	}
}

// An order refused before its ack (the dispatcher did not take it) keeps no record: the client got
// an error, not an accepted order.
func TestRefusedOrderKeepsNoAbandonedRecord(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	seedTestBuilderSet(c)
	c.SetDispatcher(&fakeDispatcher{dispatchEr: errors.New("not reserved")})
	o := abandonedTestOrder()
	if err := c.OnOrder(context.Background(), o); err == nil {
		t.Fatal("OnOrder ignored the dispatcher's refusal")
	}
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, _ := store.GetWithError(kv.NSAbandonedTask, key); found || c.hasAbandonedRecord(key) {
		t.Fatal("a refused order kept an abandoned task record")
	}
	if _, err := c.TaskOwner(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, types.ErrTaskNotFound) {
		t.Fatalf("TaskOwner = %v", err)
	}
	if _, err := c.TaskStatus(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("TaskStatus = %v", err)
	}
}

// A refused dispatch record ends the task with RECORD_REJECTED and keeps its record too.
func TestRecordRejectedKeepsTheAbandonedRecord(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	seedTestBuilderSet(c)
	c.SetDispatcher(&fakeDispatcher{})
	o := abandonedTestOrder()
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(o.SessionID, o.TaskID)
	if !ok {
		t.Fatal("no task")
	}
	c.failRecord(fsm, 10, &types.TaskEventDetail{RejectCode: 1})
	status, err := c.TaskStatus(context.Background(), o.SessionID, o.TaskID)
	if err != nil || status.State != types.Failed.String() {
		t.Fatalf("TaskStatus = %+v, %v", status, err)
	}
	replay, cancel := replayCodes(t, c, o, 0)
	cancel()
	if got := joinCodes(replay); got != EvOrderReceived+","+EvRecordRejected {
		t.Fatalf("events = %s", got)
	}
}

// The sweep removes records past the retention with their journals, and leaves a key that has a
// task again with its journal.
func TestAbandonedTaskSweep(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	start := time.Unix(1_700_000_000, 0)
	now := start
	c.now = func() time.Time { return now }
	c.SetAbandonedTaskRetention(time.Hour)
	o := startAbandonedTestTask(t, c)
	key := taskKey(o.SessionID, o.TaskID)

	now = start.Add(time.Hour - time.Second)
	c.sweepAbandonedTasks()
	if !c.hasAbandonedRecord(key) {
		t.Fatal("a record inside its retention was swept")
	}

	now = start.Add(time.Hour)
	c.sweepAbandonedTasks()
	if c.hasAbandonedRecord(key) {
		t.Fatal("an expired record was kept")
	}
	if _, found, _ := store.GetWithError(kv.NSAbandonedTask, key); found {
		t.Fatal("an expired record is still stored")
	}
	c.jmu.Lock()
	_, journalKept := c.journals[key]
	c.jmu.Unlock()
	if journalKept {
		t.Fatal("an expired record kept its journal")
	}
	if _, err := c.TaskOwner(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, types.ErrTaskNotFound) {
		t.Fatalf("TaskOwner after expiry = %v", err)
	}

	// A key with a task again: an index entry left behind does not take the live journal.
	other := testPlaceholderOrder("session-2", "task-2")
	if err := c.OnOrder(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	otherKey := taskKey(other.SessionID, other.TaskID)
	c.amu.Lock()
	c.abandoned[otherKey] = start.Unix()
	c.amu.Unlock()
	c.sweepAbandonedTasks()
	c.jmu.Lock()
	_, liveKept := c.journals[otherKey]
	c.jmu.Unlock()
	if !liveKept {
		t.Fatal("the sweep removed the journal of a live task")
	}
}

// abandonedBatchFailStore fails every batch that writes an abandoned task record.
type abandonedBatchFailStore struct {
	kv.Store
}

func (s abandonedBatchFailStore) WriteBatch(ops ...kv.WriteOp) error {
	for _, op := range ops {
		if op.NS == kv.NSAbandonedTask {
			return errors.New("disk full")
		}
	}
	return s.Store.WriteBatch(ops...)
}

// When the abandoned task record cannot be written the task still ends as before: its snapshot is
// deleted, so a restart does not bring it back, and no record is indexed.
func TestAbandonedRecordWriteFailureStillDeletesTheSnapshot(t *testing.T) {
	inner := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, abandonedBatchFailStore{Store: inner})
	o := startAbandonedTestTask(t, c)
	key := taskKey(o.SessionID, o.TaskID)
	if _, found, _ := inner.GetWithError(kv.NSTask, key); found {
		t.Fatal("the snapshot survived a failed record write")
	}
	if _, found, _ := inner.GetWithError(kv.NSAbandonedTask, key); found || c.hasAbandonedRecord(key) {
		t.Fatal("a failed record write left a record")
	}
}

// A reader of a key whose record is gone gets NotFound and leaves no journal behind.
func TestTaskEventsWithoutARecordCreatesNoJournal(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	key := taskKey("session-9", "task-9")
	c.amu.Lock()
	c.abandoned[key] = c.now().Unix() // indexed, but the record is not stored
	c.amu.Unlock()
	if _, _, _, err := c.TaskEvents(context.Background(), "session-9", "task-9", 0); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("TaskEvents = %v", err)
	}
	c.jmu.Lock()
	_, created := c.journals[key]
	c.jmu.Unlock()
	if created {
		t.Fatal("a read without a record created a journal")
	}
}
