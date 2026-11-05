package dispatcher

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/inflight"
)

type fakeSync struct {
	mu    sync.Mutex
	views []*dispatchevidence.Order
}

func (f *fakeSync) OrderChanged(o *dispatchevidence.Order) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.views = append(f.views, o)
}

func (f *fakeSync) last(t *testing.T) *dispatchevidence.Order {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.views) == 0 {
		t.Fatal("no order change reached the sync")
	}
	return f.views[len(f.views)-1]
}

func (f *fakeSync) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.views = nil
}

func withSync(e *env) *env {
	e.syncer = &fakeSync{}
	e.open(e.store)
	return e
}

// Every stored change of an order reaches the group sync as the order's evidence: the round and
// its first ticket once it is issued, each answer, and the signed record once a Worker accepted.
// No record is signed for the sync while the order is still dispatching.
func TestOrderChangesReachTheSync(t *testing.T) {
	e := withSync(newEnv(t))
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	v := e.syncer.last(t)
	if len(v.Rounds) != 1 || len(v.Rounds[0].Attempts) != 1 || len(v.Record) != 0 || len(v.Rounds[0].Roster) == 0 ||
		!bytes.Equal(v.SignedOrder, o.SignedOrder) {
		t.Fatalf("view after the first ticket = %+v", v)
	}
	if a := v.Rounds[0].Attempts[0]; !a.Sent || a.Outcome != taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED {
		t.Fatalf("first attempt = %+v", a)
	}

	e.reject()
	v = e.syncer.last(t)
	if len(v.Rounds[0].Attempts) != 2 || v.Rounds[0].Attempts[0].Outcome != outcomeRejected || len(v.Rounds[0].Attempts[0].Reject) == 0 || len(v.Record) != 0 {
		t.Fatalf("view after the reject = %+v", v.Rounds[0].Attempts)
	}

	_, hash := e.accept()
	v = e.syncer.last(t)
	if len(v.Accept) == 0 || len(v.Record) == 0 {
		t.Fatalf("view after the accept has no accept or record: %+v", v)
	}
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(v.Record, &rec); err != nil || !bytes.Equal(rec.GetDispatchTicketHash(), hash[:]) {
		t.Fatalf("synced record = %v, %v", &rec, err)
	}
}

// A restart hands the orders the dispatcher still holds to the sync again: a change stored just
// before the stop may not have reached it.
func TestRestartHandsHeldOrdersToTheSync(t *testing.T) {
	e := withSync(newEnv(t))
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.reject()
	e.syncer.reset()
	e.restart()
	if v := e.syncer.last(t); len(v.Rounds) != 1 || len(v.Rounds[0].Attempts) != 2 {
		t.Fatalf("view after the restart = %+v", v)
	}
}

// failFirstVersion dispatches version 1 of sequence 0 and fails it on the first reject (no skip
// left), as an order whose dispatch failed before the client re-signs it.
func failFirstVersion(e *env) string {
	e.t.Helper()
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	if e.ledgerState(o) != inflight.StateFailed {
		e.t.Fatal("first version not failed")
	}
	e.d.SetParams(e.params)
	return s
}

// A re-signed retry (same task_id, new task_hash) continues the order's rounds: each round of the
// evidence names the version whose tickets it holds, so the group can hold the earlier version's
// rounds next to the retry's.
func TestRetryRoundsNameTheirVersion(t *testing.T) {
	e := withSync(newEnv(t))
	s := failFirstVersion(e)
	retry := e.order(s, 0, 2)
	e.dispatch(retry)
	v := e.syncer.last(t)
	if len(v.Rounds) != 2 || v.TaskHash != retry.TaskHash {
		t.Fatalf("view of the retry = %+v", v)
	}
	first := hex.EncodeToString(bytes.Repeat([]byte{1, 0}, 16))
	if v.Rounds[0].TaskHash != first || v.Rounds[1].TaskHash != retry.TaskHash {
		t.Fatalf("round versions = %q, %q; want %q, %q", v.Rounds[0].TaskHash, v.Rounds[1].TaskHash, first, retry.TaskHash)
	}
}

// Each round of the evidence also names the earliest_submit_height of its version, recorded when
// its first ticket was issued: the group verifies the round's root and tickets under the key
// generation that height selects, and the earlier version's rounds may reach it only after the
// retry (a later height) took over the order's evidence.
func TestRetryRoundsNameTheirVersionsSubmitHeight(t *testing.T) {
	e := withSync(newEnv(t))
	s := failFirstVersion(e)
	retry := e.orderAt(s, 0, 2, testESH+1)
	e.dispatch(retry)
	v := e.syncer.last(t)
	if len(v.Rounds) != 2 || v.TaskHash != retry.TaskHash {
		t.Fatalf("view of the retry = %+v", v)
	}
	if v.Rounds[0].EarliestSubmitHeight != testESH || v.Rounds[1].EarliestSubmitHeight != testESH+1 {
		t.Fatalf("round heights = %d, %d; want %d, %d", v.Rounds[0].EarliestSubmitHeight, v.Rounds[1].EarliestSubmitHeight, testESH, testESH+1)
	}
}

// A retry that fails before its first ticket shows only the earlier version's attempts: its record
// without a winner names that version's task_hash, the version every ticket it lists was issued
// for.
func TestRetryFailedBeforeItsFirstTicketKeepsTheEarlierVersionsRecord(t *testing.T) {
	e := withSync(newEnv(t))
	s := failFirstVersion(e)
	e.drawer.mu.Lock()
	e.drawer.err = dispatchdraw.ErrNoCapacity
	e.drawer.mu.Unlock()
	retry := e.order(s, 0, 2)
	e.dispatch(retry)
	if e.ledgerState(retry) != inflight.StateFailed {
		t.Fatal("retry not failed")
	}
	v := e.syncer.last(t)
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(v.Record, &rec); err != nil {
		t.Fatal(err)
	}
	if want := bytes.Repeat([]byte{1, 0}, 16); !bytes.Equal(rec.GetTaskHash(), want) {
		t.Fatalf("record task_hash = %x, want the earlier version's %x", rec.GetTaskHash(), want)
	}
}
