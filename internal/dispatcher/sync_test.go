package dispatcher

import (
	"bytes"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
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
