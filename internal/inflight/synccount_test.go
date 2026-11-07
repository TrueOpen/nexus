package inflight

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// TestLedgerSyncCountPerOrder pins the synced and deferred writes the ledger makes for one order
// on its way to a Worker: the precheck's reservation, the commit when the dispatcher takes the
// order, and the accept.
func TestLedgerSyncCountPerOrder(t *testing.T) {
	f := newFixture(t, nil)
	store := kvtest.New()
	f.store = store
	f.restart(t)
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
	res := f.reserve(t, order(5))
	step("reserve", cost{synced: 1})
	if err := f.p.Commit(res.Reservation); err != nil {
		t.Fatal(err)
	}
	step("commit", cost{synced: 1})
	if err := f.ledger.MarkAccepted(testSession, 5); err != nil {
		t.Fatal(err)
	}
	step("accept", cost{synced: 1})
}
