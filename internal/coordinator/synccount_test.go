package coordinator

import (
	"context"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// TestTaskJournalSyncCountPerOrder pins the synced and deferred writes the task journal makes for
// one order on its way to a Worker: ORDER_RECEIVED when the order is taken, DISPATCH_ACCEPTED when
// a Worker accepted it.
func TestTaskJournalSyncCountPerOrder(t *testing.T) {
	store := kvtest.New()
	c, _ := newTaskTrackingCoordinator(t, store)
	seedTestBuilderSet(c)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	type cost struct{ synced, deferred int }
	last := cost{}
	step := func(name string, want cost) {
		t.Helper()
		now := cost{store.Synced(), store.Deferred()}
		if got := (cost{now.synced - last.synced, now.deferred - last.deferred}); got != want {
			t.Fatalf("%s cost %+v, want %+v", name, got, want)
		}
		last = now
	}
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	step("OnOrder", cost{deferred: 1})
	c.DispatchAccepted(o.SessionID, o.TaskID, [32]byte{1}, "worker-1")
	step("DispatchAccepted", cost{synced: 1})
}

// ORDER_RECEIVED is lost by a crash before the order's commit (the next synced write) and kept
// after it; the snapshot and its task_id index are stored together or not at all.
func TestOrderReceivedCrashRecovery(t *testing.T) {
	store := kvtest.New()
	c, _ := newTaskTrackingCoordinator(t, store)
	seedTestBuilderSet(c)
	c.SetDispatcher(&fakeDispatcher{})
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnOrder(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	stored := func(s kv.Store) (snapshot, index bool) {
		_, snapshot = s.Get(kv.NSTask, taskKey(o.SessionID, o.TaskID))
		_, index = s.Get(kv.NSTaskSession, o.TaskID)
		return snapshot, index
	}
	if snapshot, index := stored(store.Crash()); snapshot || index {
		t.Fatalf("a crash before the commit kept snapshot %v index %v", snapshot, index)
	}
	if err := store.Set(kv.NSInflight, "order/commit", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if snapshot, index := stored(store.Crash()); !snapshot || !index {
		t.Fatalf("a crash after the commit kept snapshot %v index %v", snapshot, index)
	}
}
