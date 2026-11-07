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
	step("reserve", cost{deferred: 1})
	if err := f.p.Commit(res.Reservation); err != nil {
		t.Fatal(err)
	}
	step("commit", cost{synced: 1})
	if err := f.ledger.MarkAccepted(testSession, 5); err != nil {
		t.Fatal(err)
	}
	step("accept", cost{synced: 1})
}

// A reservation is written without waiting for the disk. A crash before the order's commit (the
// next synced write) leaves the ledger as before the request: no entry for a new order, the failed
// attempt for a retry, which the next resend may retry again. Once committed, it survives.
func TestReservationCrashRecovery(t *testing.T) {
	f := newFixture(t, nil)
	store := kvtest.New()
	f.store = store
	f.restart(t)
	reopen := func() *Ledger {
		t.Helper()
		l, err := NewLedger(store.Crash())
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	res := f.reserve(t, order(5))
	if _, ok := reopen().Get(testSession, 5); ok {
		t.Fatal("an uncommitted reservation survived a crash before any synced write")
	}
	if err := f.p.Commit(res.Reservation); err != nil {
		t.Fatal(err)
	}
	if e, ok := reopen().Get(testSession, 5); !ok || !e.Committed || e.TaskHash != "hash5" {
		t.Fatalf("committed order after a crash = %+v %v", e, ok)
	}
	if err := f.ledger.MarkFailed(testSession, 5); err != nil {
		t.Fatal(err)
	}
	retry := order(5)
	retry.TaskHash = "resigned"
	if res := f.reserve(t, retry); !res.Retry {
		t.Fatalf("retry = %+v", res)
	}
	if e, ok := reopen().Get(testSession, 5); !ok || e.State != StateFailed || e.TaskHash != "hash5" {
		t.Fatalf("after a crash before the retry's commit the failed attempt is back: %+v %v", e, ok)
	}
}
