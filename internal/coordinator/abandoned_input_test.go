package coordinator

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// orderInputKey is the INPUT object key OpenTask stores the order's input under.
func orderInputKey(o types.Order) taskdata.ObjectKey {
	return taskdata.ObjectKey{
		TaskHash: o.TaskHash, SessionID: o.SessionID, TaskID: o.TaskID,
		Kind: taskdata.ObjectKindInput, ContentHash: taskdata.InputContentHash(o.PayloadHash),
	}
}

func checkTerminated(t *testing.T, c *Coordinator, stage string, key taskdata.ObjectKey, want bool) {
	t.Helper()
	got, err := c.HasTerminatedOrder(context.Background(), key)
	if err != nil || got != want {
		t.Fatalf("%s: HasTerminatedOrder(task_hash=%s content_hash=%s) = %t, %v; want %t", stage, key.TaskHash, key.ContentHash, got, err, want)
	}
}

// An order dropped before it reached the chain ends its own INPUT version: the version is
// terminated (so its input is released once its retention ends), durably, while the task itself is
// not terminal and a re-signed retry of the sequence (a new version) is not affected. The same
// version ordered again is live until it ends again.
func TestDroppedOrderEndsOnlyItsInputVersion(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	first := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("first input"), 100)
	retry := withPayload(t, first, []byte("retried input"))
	retry.TaskHash = strings.Repeat("6f", 32)
	firstKey, retryKey := orderInputKey(first), orderInputKey(retry)
	otherContent := firstKey
	otherContent.ContentHash = strings.Repeat("7a", 32)

	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	checkTerminated(t, c, "dispatching", firstKey, false)
	c.DispatchFailed(first.SessionID, first.TaskID, dispatchdraw.ErrNoCapacity)
	checkTerminated(t, c, "dropped", firstKey, true)
	checkTerminated(t, c, "dropped, other content", otherContent, false)
	checkTerminated(t, c, "dropped, other version", retryKey, false)
	if _, found := store.Get(kv.NSTerminalTask, taskKey(first.SessionID, first.TaskID)); found {
		t.Fatal("a task dropped before the chain got a terminal task marker")
	}
	if accepted, err := c.HasAcceptedOrder(ctx, firstKey); err != nil || accepted {
		t.Fatalf("dropped version accepted = %t, %v", accepted, err)
	}

	// The end of the version is durable.
	restarted, _ := newTaskTrackingCoordinator(t, store)
	checkTerminated(t, restarted, "after restart", firstKey, true)

	if err := c.OnOrder(ctx, retry); err != nil {
		t.Fatalf("retry: %v", err)
	}
	checkTerminated(t, c, "retry dispatching", retryKey, false)
	checkTerminated(t, c, "retry dispatching, dropped version", firstKey, true)
	if accepted, err := c.HasAcceptedOrder(ctx, retryKey); err != nil || !accepted {
		t.Fatalf("retried version accepted = %t, %v", accepted, err)
	}
	c.RecordRejected(retry.SessionID, retry.TaskID, [32]byte{1}, 0)
	checkTerminated(t, c, "retry record rejected", retryKey, true)

	// The first version ordered again is live until it ends again.
	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatalf("same version again: %v", err)
	}
	checkTerminated(t, c, "same version again", firstKey, false)
	checkTerminated(t, restarted, "same version again, snapshot only", firstKey, false)
	c.DispatchFailed(first.SessionID, first.TaskID, dispatchdraw.ErrNoCapacity)
	checkTerminated(t, c, "same version dropped again", firstKey, true)
}

// A tracked version replaced by a re-signed retry (OnOrder of another version) ends as well.
func TestReplacedOrderVersionEnds(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	first := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("first input"), 100)
	retry := withPayload(t, first, []byte("retried input"))
	retry.TaskHash = strings.Repeat("6f", 32)
	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := c.OnOrder(ctx, retry); err != nil {
		t.Fatal(err)
	}
	checkTerminated(t, c, "replaced", orderInputKey(first), true)
	checkTerminated(t, c, "replacement", orderInputKey(retry), false)
}

// noCleanupYet answers every evidence cleanup query as a task the chain does not hold.
type noCleanupYet struct{}

func (noCleanupYet) QueryEvidenceCleanup(context.Context, string) (chaincli.EvidenceCleanupStatus, error) {
	return "", chaincli.ErrNotFound
}

// retentionAuthority is the Task Chain authority the retention decision needs no call of.
type retentionAuthority struct{ taskdata.Authority }

// The input of an order dropped before the chain is released by the retention sweep once its
// retention height (the order's expiry) is reached, and not before; a retried version of the same
// task keeps its own input.
func TestDroppedOrderInputIsReleasedAtItsRetentionHeight(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore, payloads := newCoordinatorTaskData(t, backend)
	c, _ := newTaskTrackingCoordinator(t, backend)
	c.payloads = payloads
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	policy, err := taskdata.NewRecoveryPolicy(retentionAuthority{}, noCleanupYet{}, nil, c)
	if err != nil {
		t.Fatal(err)
	}
	first := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("first input"), 100)
	retry := withPayload(t, first, []byte("retried input"))
	retry.TaskHash = strings.Repeat("6f", 32)
	retry.Deadline, retry.DeadlineHeight = 300, 300

	firstInput := stageOrderInput(t, taskStore, first, []byte("first input"), true)
	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	c.DispatchFailed(first.SessionID, first.TaskID, dispatchdraw.ErrNoCapacity)
	retryInput := stageOrderInput(t, taskStore, retry, []byte("retried input"), true)
	if err := c.OnOrder(ctx, retry); err != nil {
		t.Fatal(err)
	}

	if err := taskStore.Sweep(ctx, 99, policy); err != nil {
		t.Fatal(err)
	}
	if inputDeleted(t, taskStore, firstInput) {
		t.Fatal("the dropped version's input was released before its retention height")
	}
	if err := taskStore.Sweep(ctx, 100, policy); err != nil {
		t.Fatal(err)
	}
	if !inputDeleted(t, taskStore, firstInput) {
		t.Fatal("the dropped version's input was kept past its retention height")
	}
	if inputDeleted(t, taskStore, retryInput) {
		t.Fatal("the retried version's input was released with the dropped one")
	}
	if ref, err := taskStore.ResolveObject(ctx, retry.SessionID, retry.TaskID, taskdata.ObjectKindInput); err != nil || ref != retryInput {
		t.Fatalf("input index = %#v, %v; want the retried version", ref, err)
	}
}

// An input with no local end of its order (dropped by a release that marked nothing) is released
// once the chain is past its retention height by the margin, and never while a task is tracked
// for it, in memory or by its snapshot after a restart.
func TestUnmarkedInputIsReleasedOnlyWhenNoTaskIsTracked(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore, payloads := newCoordinatorTaskData(t, backend)
	c, _ := newTaskTrackingCoordinator(t, backend)
	c.payloads = payloads
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	sweep := func(c *Coordinator, height uint64) {
		t.Helper()
		policy, err := taskdata.NewRecoveryPolicy(retentionAuthority{}, noCleanupYet{}, nil, c)
		if err != nil {
			t.Fatal(err)
		}
		if err := taskStore.Sweep(ctx, height, policy); err != nil {
			t.Fatal(err)
		}
	}
	unmarked := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("unmarked input"), 100)
	unmarkedInput := stageOrderInput(t, taskStore, unmarked, []byte("unmarked input"), true)
	tracked := taskPayloadOrder(t, testPayloadSession, strings.Repeat("3c", 32), testUserAddress, []byte("tracked input"), 100)
	trackedInput := stageOrderInput(t, taskStore, tracked, []byte("tracked input"), true)
	if err := c.OnOrder(ctx, tracked); err != nil {
		t.Fatal(err)
	}

	sweep(c, 100)
	if inputDeleted(t, taskStore, unmarkedInput) || inputDeleted(t, taskStore, trackedInput) {
		t.Fatal("an input with no local end of its order was released at its retention height")
	}
	sweep(c, 10000)
	if !inputDeleted(t, taskStore, unmarkedInput) {
		t.Fatal("an input with no local end of its order and no task was kept past its retention")
	}
	if inputDeleted(t, taskStore, trackedInput) {
		t.Fatal("the input of a tracked task was released")
	}
	restarted, _ := newTaskTrackingCoordinator(t, backend)
	sweep(restarted, 20000)
	if inputDeleted(t, taskStore, trackedInput) {
		t.Fatal("the input of a task with a snapshot was released after a restart")
	}
}
