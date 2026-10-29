package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
)

func (e *env) phaseOf(sessionID string, seq uint64) (phase, *orderState) {
	e.t.Helper()
	o := e.d.get(stateKey(sessionID, seq))
	if o == nil {
		e.t.Fatalf("no order %s/%d", sessionID, seq)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.st.Phase, cloneState(o.st)
}

// A refused record fails the session from its sequence: an accepted order loses its winner
// (VOIDED), a dispatching one stops with its ticket out VOIDED and is reported failed, earlier
// orders and other sessions go on, and a resend of a failed sequence is a new round.
func TestSuspendFailsTheSessionFromASequence(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	other := e.session(0xbb, 0)
	e.dispatch(e.order(s, 0, 1))
	e.accept()
	e.dispatch(e.order(s, 1, 1))
	e.accept()
	e.dispatch(e.order(s, 2, 1))
	_, outTicket, outHash := e.lastOffer()
	e.dispatch(e.order(other, 0, 1))
	if d, ok := e.d.RecordDeadline(s, 2); !ok || d != testDeadline {
		t.Fatalf("record deadline = %d, %v", d, ok)
	}

	e.d.Suspend(context.Background(), s, 1, fmt.Errorf("%w: sequence 1", ErrRecordRejected))
	if p, _ := e.phaseOf(s, 0); p != phaseAccepted {
		t.Fatalf("order 0 = %s", p)
	}
	p1, st1 := e.phaseOf(s, 1)
	p2, st2 := e.phaseOf(s, 2)
	if p1 != phaseFailed || p2 != phaseFailed {
		t.Fatalf("orders 1, 2 = %s, %s", p1, p2)
	}
	if got := outcomesOf(st1); !reflect.DeepEqual(got, []string{"0:0:VOIDED"}) {
		t.Fatalf("order 1 attempts = %v", got)
	}
	if got := outcomesOf(st2); !reflect.DeepEqual(got, []string{"0:0:VOIDED"}) {
		t.Fatalf("order 2 attempts = %v", got)
	}
	if len(st1.Accept) != 0 || len(st1.Record) != 0 {
		t.Fatal("order 1 keeps its accept")
	}
	if p, _ := e.phaseOf(other, 0); p != phaseDispatching {
		t.Fatalf("other session = %s", p)
	}
	failed := e.observer.snapshot().failed
	if len(failed) != 1 || !errors.Is(failed[0], ErrRecordRejected) {
		t.Fatalf("failed = %v", failed)
	}
	m, from := e.acceptMsg(outTicket, outHash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("late accept of a suspended order = %v", err)
	}

	if err := e.ledger.Suspend(s, 1); err != nil {
		t.Fatal(err)
	}
	e.dispatch(e.order(s, 1, 1))
	if _, ticket, _ := e.lastOffer(); ticket.GetOrderSequence() != 1 || ticket.GetDispatchRound() != 1 {
		t.Fatalf("resend offer = %v", ticket)
	}
}

// While the compensation account is below its minimum no ticket is issued and new orders are
// refused before their input is stored; once it is funded the parked order goes on.
func TestCompensationBelowMinIssuesNoTickets(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.keys.builderErr = fmt.Errorf("%w: balance 5 below 10", ErrCompensationBelowMin)
	if err := e.d.Probe(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe = %v", err)
	}
	e.dispatch(o)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers below the minimum", n)
	}
	e.keys.mu.Lock()
	e.keys.builderErr = nil
	e.keys.mu.Unlock()
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7}) {
		t.Fatalf("offers once funded = %v", got)
	}
}

func outcomesOf(st *orderState) []string {
	var out []string
	for _, r := range st.Rounds {
		for _, a := range r.Attempts {
			out = append(out, fmt.Sprintf("%d:%d:%s", r.Number, a.Rank, a.Outcome.String()[len("DISPATCH_ATTEMPT_OUTCOME_V1_"):]))
		}
	}
	return out
}
