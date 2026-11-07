package coordinator

import (
	"context"
	"testing"

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
	step("OnOrder", cost{synced: 2})
	c.DispatchAccepted(o.SessionID, o.TaskID, [32]byte{1}, "worker-1")
	step("DispatchAccepted", cost{synced: 2})
}
