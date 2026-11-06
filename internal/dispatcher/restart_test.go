package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
)

// restart stops the dispatcher and starts a new one over the same store, as a process restart.
func (e *env) restart() {
	e.t.Helper()
	if err := e.d.Stop(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.open(e.store)
	if err := e.d.Start(context.Background()); err != nil {
		e.t.Fatalf("start: %v", err)
	}
}

// A restart with a ticket out signs nothing new: the stream hub replays the stored offer, the
// ticket keeps its deadline, and the walk goes on from it with the same ticket bytes on record.
func TestRestartMidWalkResumesWithTheSameTickets(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject() // op7
	_, before, beforeHash := e.lastOffer()
	e.clock.advance(200 * time.Millisecond)

	e.restart()
	if n := len(e.streams.offers()); n != 2 {
		t.Fatalf("%d offers after the restart, want the 2 sent before", n)
	}
	if e.ledgerState(o) != inflight.StateDispatching {
		t.Fatal("the restarted order is not dispatching")
	}
	// The ticket out keeps its deadline: 300 ms of its 500 ms are left.
	e.clock.advance(299 * time.Millisecond)
	if n := len(e.streams.offers()); n != 2 {
		t.Fatal("the resumed ticket timed out early")
	}
	e.clock.advance(time.Millisecond)
	if op, _, _ := e.lastOffer(); op != op3 {
		t.Fatalf("after the resumed timeout the offer went to %s", op)
	}
	e.accept()
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	attempts := rec.GetRounds()[0].GetAttempts()
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:REJECTED", "0:1:TIMEOUT", "0:2:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	if !bytes.Equal(attempts[1].GetDispatchTicketHash(), beforeHash[:]) || before.GetAcceptDeadlineMs() == 0 {
		t.Fatal("the ticket out before the restart was signed again")
	}
}

// An accept received just before a restart is answered from the stored state: the restarted
// Builder hands the same dispatch entry bytes to the Recorder again and keeps the order ACCEPTED.
func TestRestartAfterAcceptHandsTheSameEntryAgain(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.accept()
	first := e.onlyBundle()
	e.recorder = &fakeRecorder{}
	e.restart()
	again := e.onlyBundle()
	if !proto.Equal(first.Entry, again.Entry) || first.Deadline != again.Deadline {
		t.Fatal("the restarted dispatcher handed a different entry")
	}
	if e.ledgerState(o) != inflight.StateAccepted {
		t.Fatal("not ACCEPTED after the restart")
	}
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers", n)
	}
	if a, ok := e.attempts.Current(o.TaskID); !ok || a.Status != attempt.Pending {
		t.Fatalf("attempt after the restart = %+v %v", a, ok)
	}
}

// A ticket whose deadline passed while the Builder was down times out on start.
func TestRestartTimesOutExpiredTickets(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.d.Stop(context.Background())
	e.clock.advance(time.Second)
	e.restart()
	e.clock.advance(0)
	if op, _, _ := e.lastOffer(); op != op1 {
		t.Fatalf("the expired ticket did not time out: last offer to %s", op)
	}
}

// Start reconciles the ledger and the stored states: a committed order without a state fails (it
// is told to the observer), a state of an order whose reservation was never committed is dropped.
func TestRestartReconcilesTheLedger(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	lost := e.order(s, 0, 1)
	if err := e.ledger.Commit(&inflight.Reservation{SessionID: s, Sequence: 0, TaskHash: lost.TaskHash}); err != nil {
		t.Fatal(err)
	}
	uncommitted := e.order(s, 1, 1)
	if err := saveState(e.store, &orderState{SessionID: s, Sequence: 1, TaskID: uncommitted.TaskID, TaskHash: uncommitted.TaskHash,
		SignedOrder: uncommitted.SignedOrder, Phase: phaseDispatching}); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if e.ledgerState(lost) != inflight.StateFailed {
		t.Fatal("a committed order without dispatch state is not failed")
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], errLost) {
		t.Fatalf("failed = %v", got)
	}
	if _, ok := e.ledger.Get(s, 1); ok {
		t.Fatal("the uncommitted reservation survived")
	}
	states, err := loadStates(e.store)
	if err != nil || len(states) != 0 {
		t.Fatalf("states after the restart = %d, %v", len(states), err)
	}
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers", n)
	}
}

// A failed order's state is kept across a restart, so a retry continues it as a new round.
func TestRestartKeepsFailedOrdersForRetry(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.reject()
	e.params.MaxSkips = 1
	e.restart()
	e.dispatch(e.order(s, 0, 2))
	if op, ticket, _ := e.lastOffer(); op != op1 || ticket.GetDispatchRound() != 1 {
		t.Fatalf("retry after a restart: %s round %d", op, ticket.GetDispatchRound())
	}
}

// An order the ledger shows recorded whose state outlived the record (the evidence write failed
// or the process stopped in between) is dropped on restart with its evidence marked recorded.
func TestRestartMarksTheEvidenceOfARecordedOrder(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, hash := e.accept()
	if err := e.ledger.MarkRecorded(s, 0); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if states, _ := loadStates(e.store); len(states) != 0 {
		t.Fatal("state of a recorded order kept")
	}
	ev, _ := e.evidenceOf(hash)
	if !ev.Recorded || ev.RecordedHeight != testDeadline {
		t.Fatalf("evidence recorded %v at %d, want at the record deadline %d", ev.Recorded, ev.RecordedHeight, testDeadline)
	}
}

// An accepted order the ledger no longer holds at all was recorded and let go by the ledger: it is
// dropped on restart with its evidence marked recorded at the head then.
func TestRestartMarksTheEvidenceOfAnOrderTheLedgerLetGo(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, hash := e.accept()
	var keys []string
	if err := e.store.Scan(kv.NSInflight, func(key string, _ []byte) bool { keys = append(keys, key); return true }); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if err := e.store.Delete(kv.NSInflight, key); err != nil {
			t.Fatal(err)
		}
	}
	e.restart()
	if states, _ := loadStates(e.store); len(states) != 0 {
		t.Fatal("state of an order the ledger let go kept")
	}
	ev, _ := e.evidenceOf(hash)
	if !ev.Recorded || ev.RecordedHeight != testESH {
		t.Fatalf("evidence recorded %v at %d, want at the head %d", ev.Recorded, ev.RecordedHeight, testESH)
	}
}
