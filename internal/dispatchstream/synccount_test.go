package dispatchstream

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// TestDownlinkSyncCount pins the synced and deferred writes of one downlink message: storing it
// before it is queued, and releasing it once the Cortex acknowledged it.
func TestDownlinkSyncCount(t *testing.T) {
	store := kvtest.New()
	h := newHarnessOn(t, store, newTestKeys())
	s := h.connect(cortexA, "1")
	type cost struct{ synced, deferred int }
	last := cost{store.Synced(), store.Deferred()}
	step := func(name string, want cost) {
		t.Helper()
		now := cost{store.Synced(), store.Deferred()}
		if got := (cost{now.synced - last.synced, now.deferred - last.deferred}); got != want {
			t.Fatalf("%s cost %+v, want %+v", name, got, want)
		}
		last = now
	}
	mustSend(t, h, cortexA, "a")
	step("send", cost{synced: 1})
	receiveOffers(t, s, 1)
	s.ack(1)
	waitPending(t, h, cortexA, 0)
	step("ack", cost{synced: 1})
}
