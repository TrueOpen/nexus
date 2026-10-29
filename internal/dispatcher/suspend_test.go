package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
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
	o0, o1, o2, ox := e.order(s, 0, 1), e.order(s, 1, 1), e.order(s, 2, 1), e.order(other, 0, 1)
	// Past earliest_submit_height a later order does not wait for the record of an earlier one.
	e.sessions.ObserveHeight(testESH + 1)
	e.dispatch(o0)
	e.accept()
	e.dispatch(o1)
	e.accept()
	e.dispatch(o2)
	_, outTicket, outHash := e.lastOffer()
	e.dispatch(ox)
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

// An entry accepted while the head is h goes out with the record of block h+1 and lands in block
// h+2 at the earliest: an accept with the head one block before the record deadline can no longer
// be recorded in time and is refused, one two blocks before is taken.
func TestAcceptMustLeaveTimeToRecord(t *testing.T) {
	e := newEnv(t)
	s, other := e.session(0xaa, 0), e.session(0xbb, 0)
	e.dispatch(e.order(s, 0, 1))
	_, first, firstHash := e.lastOffer()
	e.dispatch(e.order(other, 0, 1))
	_, ticket, hash := e.lastOffer()
	e.sessions.ObserveHeight(testDeadline - 2)
	m, from := e.acceptMsg(first, firstHash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); err != nil {
		t.Fatalf("accept two blocks before the record deadline = %v", err)
	}
	e.sessions.ObserveHeight(testDeadline - 1)
	m, from = e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept one block before the record deadline = %v", err)
	}
	if got := e.observer.snapshot(); len(got.accepted) != 1 || len(got.failed) != 1 || !errors.Is(got.failed[0], ErrRecordDeadline) {
		t.Fatalf("observed %+v", got)
	}
}

// An accept that came within its ticket's accept deadline but after the order became too late to
// record is not the Worker's timeout: the attempt is VOIDED with the accept kept as received (a
// compensation claim on it is matched against it), the Worker's reject rate is not fed and the
// order fails on its record deadline.
func TestOnTimeAcceptPastTheRecordDeadlineIsVoided(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	calls := len(e.handraises.outcomeCalls())
	e.sessions.ObserveHeight(testDeadline - 1)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept = %v", err)
	}
	p, st := e.phaseOf(s, 0)
	if p != phaseFailed || st.Skips != 0 {
		t.Fatalf("phase %s, skips %d", p, st.Skips)
	}
	a := st.Rounds[0].Attempts[0]
	if a.Outcome != outcomeVoided || !bytes.Equal(a.LateAccept, from.Raw) || !bytes.Equal(a.LateAcceptDigest, from.Digest[:]) {
		t.Fatalf("attempt = %s, late accept kept %v", a.Outcome, bytes.Equal(a.LateAccept, from.Raw))
	}
	if a.rebuttable() {
		t.Fatal("a voided attempt is rebuttable")
	}
	if got := e.handraises.outcomeCalls(); len(got) != calls {
		t.Fatalf("reject rate fed: %v", got[calls:])
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], ErrRecordDeadline) {
		t.Fatalf("failed = %v", got)
	}
}

// Only an attempt whose ticket reached the Worker and that ended REJECTED, TIMEOUT or REVOKED may
// rebut a compensation claim; an unsent ticket, a VOIDED or ACCEPTED one may not.
func TestRebuttableAttempts(t *testing.T) {
	for _, tc := range []struct {
		outcome taskv1.DispatchAttemptOutcomeV1
		sent    bool
		want    bool
	}{
		{outcomeRejected, true, true},
		{outcomeTimeout, true, true},
		{taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REVOKED, true, true},
		{outcomeTimeout, false, false},
		{outcomeRejected, false, false},
		{outcomeVoided, true, false},
		{outcomeAccepted, true, false},
		{taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED, true, false},
	} {
		a := attemptState{Outcome: tc.outcome, Sent: tc.sent}
		if got := a.rebuttable(); got != tc.want {
			t.Fatalf("%s sent=%v: rebuttable %v", tc.outcome, tc.sent, got)
		}
	}
}

// A ticket whose offer could not be queued on the Worker's stream times out unsent.
func TestOfferNotSentIsUnsent(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.streams.mu.Lock()
	e.streams.sendErr = errors.New("not connected")
	e.streams.mu.Unlock()
	e.dispatch(e.order(s, 0, 1))
	_, st := e.phaseOf(s, 0)
	if len(st.Rounds) == 0 || len(st.Rounds[0].Attempts) == 0 {
		t.Fatal("no attempt")
	}
	for _, a := range st.Rounds[0].Attempts {
		if a.Sent || a.Outcome != outcomeTimeout {
			t.Fatalf("attempt rank %d: sent %v, %s", a.Rank, a.Sent, a.Outcome)
		}
	}
}
