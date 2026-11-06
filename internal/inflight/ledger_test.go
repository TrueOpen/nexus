package inflight

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

const testSession = "1111111111111111111111111111111111111111111111111111111111111111"

func entry(seq, maxFee uint64, sessionKey bool) Entry {
	return Entry{Sequence: seq, TaskID: "t", TaskHash: "h", MaxFee: maxFee, SessionKey: sessionKey, Deadline: 100, State: StateDispatching}
}

func TestLedgerCountsOnlyLiveOrdersAtOrAboveNext(t *testing.T) {
	l, err := NewLedger(kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(3); seq <= 6; seq++ {
		if err := l.put(testSession, entry(seq, 10*seq, seq%2 == 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.MarkRecorded(testSession, 3); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkFailed(testSession, 6); err != nil {
		t.Fatal(err)
	}
	// next 3: 3 (recorded, the chain view has not caught up), 4, 5 count; 6 failed does not.
	l.mu.Lock()
	sum := l.sessionLocked(testSession).inFlight(3)
	l.mu.Unlock()
	if sum.count != 3 || sum.maxFee.String() != "120" || sum.sessionKeyMaxFee.String() != "40" {
		t.Fatalf("in flight at next 3 = %d, %s, %s", sum.count, sum.maxFee, sum.sessionKeyMaxFee)
	}
	// next 4: the chain view includes 3.
	l.mu.Lock()
	sum = l.sessionLocked(testSession).inFlight(4)
	l.mu.Unlock()
	if sum.count != 2 || sum.maxFee.String() != "90" {
		t.Fatalf("in flight at next 4 = %d, %s", sum.count, sum.maxFee)
	}
}

func TestLedgerRecoversAfterRestart(t *testing.T) {
	store := kv.NewMemStore()
	l, err := NewLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.put(testSession, entry(7, 5, true)); err != nil {
		t.Fatal(err)
	}
	if err := l.put(testSession, entry(8, 6, false)); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkAccepted(testSession, 7); err != nil {
		t.Fatal(err)
	}
	if err := l.Suspend(testSession, 8); err != nil {
		t.Fatal(err)
	}
	if err := l.cancelRequested(testSession, 9, 120); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := restarted.Get(testSession, 7)
	if !ok || got.State != StateAccepted || got.MaxFee != 5 || !got.SessionKey || got.Deadline != 100 {
		t.Fatalf("entry 7 after restart = %+v, %v", got, ok)
	}
	got, ok = restarted.Get(testSession, 8)
	if !ok || got.State != StateFailed {
		t.Fatalf("entry 8 after restart = %+v, %v (Suspend fails orders from the mark)", got, ok)
	}
	from, suspended := restarted.SuspendedFrom(testSession)
	if !suspended || from != 8 {
		t.Fatalf("suspension after restart = %d, %v", from, suspended)
	}
	if !restarted.CancelRequested(testSession, 9) || restarted.CancelRequested(testSession, 8) {
		t.Fatal("pending cancellation of 9 not recovered")
	}
	if sessions := restarted.Sessions(); len(sessions) != 1 || sessions[0] != testSession {
		t.Fatalf("sessions after restart = %v", sessions)
	}
}

func TestLedgerSuspendKeepsRecordedOrders(t *testing.T) {
	l, _ := NewLedger(kv.NewMemStore())
	for seq := uint64(1); seq <= 3; seq++ {
		_ = l.put(testSession, entry(seq, 1, false))
	}
	_ = l.MarkRecorded(testSession, 2)
	if err := l.Suspend(testSession, 1); err != nil {
		t.Fatal(err)
	}
	for seq, want := range map[uint64]State{1: StateFailed, 2: StateRecorded, 3: StateFailed} {
		if got, _ := l.Get(testSession, seq); got.State != want {
			t.Fatalf("entry %d = %s, want %s", seq, got.State, want)
		}
	}
}

func TestLedgerReleaseAndPrune(t *testing.T) {
	store := kv.NewMemStore()
	l, _ := NewLedger(store)
	_ = l.put(testSession, entry(1, 1, false))
	_ = l.put(testSession, entry(2, 1, false))
	_ = l.put(testSession, entry(3, 1, false))
	_ = l.MarkRecorded(testSession, 1)
	_ = l.MarkFailed(testSession, 2)
	if err := l.Release(&Reservation{SessionID: testSession, Sequence: 3, TaskHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Get(testSession, 3); ok {
		t.Fatal("released entry still present")
	}
	// Below next but inside its deadline: kept, so a retry of a recorded order is still answered.
	if err := l.Prune(testSession, 3, 100); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Get(testSession, 1); !ok {
		t.Fatal("recorded entry pruned before its deadline")
	}
	if err := l.Prune(testSession, 3, 101); err != nil {
		t.Fatal(err)
	}
	if len(l.Entries(testSession)) != 0 {
		t.Fatalf("entries after prune = %+v", l.Entries(testSession))
	}
	restarted, _ := NewLedger(store)
	if len(restarted.Sessions()) != 0 {
		t.Fatalf("pruned session recovered: %v", restarted.Sessions())
	}
}

func TestLedgerUnknownOrder(t *testing.T) {
	l, _ := NewLedger(kv.NewMemStore())
	if err := l.MarkRecorded(testSession, 4); err == nil {
		t.Fatal("MarkRecorded of an unknown order succeeded")
	}
}

func TestLedgerRefusesMalformedRecord(t *testing.T) {
	store := kv.NewMemStore()
	_ = store.Set(kv.NSInflight, orderKey(testSession, 1), []byte("{"))
	if _, err := NewLedger(store); err == nil {
		t.Fatal("malformed ledger record accepted")
	}
}

// Unfinished lists the orders still dispatching or accepted, across sessions: after a crash
// nothing else remembers them.
func TestLedgerUnfinished(t *testing.T) {
	store := kv.NewMemStore()
	l, _ := NewLedger(store)
	other := "2222222222222222222222222222222222222222222222222222222222222222"
	for seq := uint64(1); seq <= 4; seq++ {
		_ = l.put(testSession, entry(seq, 1, false))
	}
	_ = l.put(other, entry(9, 1, false))
	for _, e := range []struct {
		session string
		seq     uint64
	}{{testSession, 1}, {other, 9}} {
		if err := l.Commit(&Reservation{SessionID: e.session, Sequence: e.seq, TaskHash: "h"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.MarkAccepted(testSession, 2)
	_ = l.MarkRecorded(testSession, 3)
	_ = l.MarkFailed(testSession, 4)
	restarted, _ := NewLedger(store)
	got := restarted.Unfinished()
	want := []struct {
		session string
		seq     uint64
		state   State
	}{{testSession, 1, StateDispatching}, {testSession, 2, StateAccepted}, {other, 9, StateDispatching}}
	if len(got) != len(want) {
		t.Fatalf("unfinished = %+v", got)
	}
	for i, w := range want {
		if got[i].SessionID != w.session || got[i].Sequence != w.seq || got[i].State != w.state {
			t.Fatalf("unfinished[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// An accept whose ticket was voided (the session's binding changed before the record) puts the
// order back to DISPATCHING: it is dispatched again, and still counts.
func TestLedgerMarkDispatchingAfterVoidedAccept(t *testing.T) {
	store := kv.NewMemStore()
	l, err := NewLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.put(testSession, entry(4, 5, false)); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkAccepted(testSession, 4); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkDispatching(testSession, 4); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewLedger(store)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := reloaded.Get(testSession, 4); !ok || e.State != StateDispatching || !e.Committed {
		t.Fatalf("entry = %+v %v", e, ok)
	}
	if err := l.MarkDispatching(testSession, 9); err == nil {
		t.Fatal("unknown order marked")
	}
}

// Summary counts sessions, suspended sessions, the orders still dispatching or accepted with their
// max_fee, and the recorded ones.
func TestLedgerSummary(t *testing.T) {
	l, _ := NewLedger(kv.NewMemStore())
	other := "2222222222222222222222222222222222222222222222222222222222222222"
	for seq := uint64(1); seq <= 4; seq++ {
		_ = l.put(testSession, entry(seq, 10*seq, false))
	}
	_ = l.put(other, entry(9, 7, false))
	_ = l.MarkAccepted(testSession, 2)
	_ = l.MarkRecorded(testSession, 3)
	_ = l.MarkFailed(testSession, 4)
	_ = l.Suspend(other, 9)
	s := l.Summary()
	if s.Sessions != 2 || s.Suspended != 1 || s.Pending != 2 || s.PendingMaxFee.Uint64() != 30 || s.Recorded != 1 {
		t.Fatalf("summary = %+v (max fee %s)", s, s.PendingMaxFee)
	}
}
