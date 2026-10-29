package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// The record deadline is the Recorder's: max(the deadline handed over, max(earliest_submit_height,
// bound_change_height) + record_deadline_blocks with the current params).
func TestEffectiveRecordDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		stored, esh, bound, blocks, want uint64
	}{
		{"as handed over", 120, 100, 0, 20, 120},
		{"params raised", 120, 100, 0, 40, 140},
		{"params lowered", 120, 100, 0, 5, 120},
		{"bound later than esh", 120, 100, 130, 20, 150},
		{"bound earlier than esh", 120, 100, 90, 20, 120},
	} {
		if got := EffectiveRecordDeadline(tc.stored, tc.esh, tc.bound, tc.blocks); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// Raised record_deadline_blocks move the deadline the dispatcher reports and accepts against, as
// they move the Recorder's: an accept past the deadline handed over but before the new one is
// taken. Lowered params never pull the deadline in.
func TestRecordDeadlineFollowsTheParams(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	if d, ok := e.d.RecordDeadline(s, 0); !ok || d != testDeadline {
		t.Fatalf("record deadline = %d, %v", d, ok)
	}
	lowered := e.params
	lowered.RecordDeadlineBlocks = 5
	e.d.SetParams(lowered)
	if d, _ := e.d.RecordDeadline(s, 0); d != testDeadline {
		t.Fatalf("record deadline after lowered params = %d", d)
	}
	raised := e.params
	raised.RecordDeadlineBlocks = 40
	e.d.SetParams(raised)
	if d, _ := e.d.RecordDeadline(s, 0); d != testESH+40 {
		t.Fatalf("record deadline after raised params = %d", d)
	}
	e.sessions.ObserveHeight(testDeadline + 1)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); err != nil {
		t.Fatalf("accept before the raised deadline = %v", err)
	}
	b := e.recorder.recorded()
	if len(b) != 1 || b[0].Deadline != testESH+40 {
		t.Fatalf("bundles = %+v", b)
	}
}

// A binding change of this Builder moves the record deadline with the new bound_change_height:
// the new round still issues tickets and takes accepts past the deadline handed over.
func TestBindingChangeMovesTheRecordDeadline(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	const bound = testESH + 30
	e.chain.update(s, func(st *chaincli.SessionState) { st.BoundChangeHeight = bound })
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: bound}})
	if d, ok := e.d.RecordDeadline(s, 0); !ok || d != bound+20 {
		t.Fatalf("record deadline = %d, %v", d, ok)
	}
	e.sessions.ObserveHeight(testDeadline + 1)
	_, ticket, _ := e.lastOffer()
	if ticket.GetBoundChangeHeight() != bound {
		t.Fatalf("ticket = %v", ticket)
	}
	// A rejection walks on to the next member: the step past the deadline handed over issues it.
	e.reject()
	_, next, nextHash := e.lastOffer()
	if next.GetRank() != ticket.GetRank()+1 {
		t.Fatalf("no new ticket after the rejection: %v", next)
	}
	m, from := e.acceptMsg(next, nextHash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); err != nil {
		t.Fatalf("accept before the moved deadline = %v", err)
	}
	if got := e.observer.snapshot().failed; len(got) != 0 {
		t.Fatalf("failed = %v", got)
	}
	// Past the moved deadline the order fails.
	e2 := newEnv(t)
	s2 := e2.session(0xaa, 0)
	e2.dispatch(e2.order(s2, 0, 1))
	e2.chain.update(s2, func(st *chaincli.SessionState) { st.BoundChangeHeight = bound })
	e2.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s2, NewBuilder: e2.builder, BoundChangeHeight: bound}})
	e2.sessions.ObserveHeight(bound + 20)
	_, t2, h2 := e2.lastOffer()
	m, from = e2.acceptMsg(t2, h2)
	if err := e2.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept past the moved deadline = %v", err)
	}
}

func TestParamsFromChainTakeRecordDeadlineBlocks(t *testing.T) {
	p, err := ParamsFromChain(&taskv1.DispatchParamsV1{MaxDispatchRosterBytes: 1, RecordDeadlineBlocks: 33},
		&taskv1.CandidateWeightParamsV1{MaxWeightedDrawAttemptsPerSelection: 1})
	if err != nil || p.RecordDeadlineBlocks != 33 {
		t.Fatalf("params = %+v, %v", p, err)
	}
}

// A binding change of this Builder that arrives once the head passed the deadline of the old
// bound_change_height opens the new round against the new one: the order is not failed.
func TestBindingEventPastTheOldDeadline(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	const bound = testESH + 30
	e.sessions.ObserveHeight(testDeadline + 1)
	e.chain.update(s, func(st *chaincli.SessionState) { st.BoundChangeHeight = bound })
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: bound}})
	if got := e.observer.snapshot().failed; len(got) != 0 {
		t.Fatalf("failed = %v", got)
	}
	_, ticket, _ := e.lastOffer()
	if ticket.GetDispatchRound() != 1 || ticket.GetBoundChangeHeight() != bound {
		t.Fatalf("ticket = %v", ticket)
	}
}

// The new bound_change_height is stored with the voided round: an order that could not step at
// the event (its Builder key rotation pending) and resumes after a restart, with the head past the
// old deadline, opens its new round instead of failing.
func TestBindingChangeSurvivesARestartPastTheOldDeadline(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	const bound = testESH + 30
	e.keys.mu.Lock()
	e.keys.builderErr = fmt.Errorf("%w: nonce 5", handraise.ErrBuilderRotationPending)
	e.keys.mu.Unlock()
	e.chain.update(s, func(st *chaincli.SessionState) { st.BoundChangeHeight = bound })
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: bound}})
	offers := len(e.streams.offers())
	e.keys.mu.Lock()
	e.keys.builderErr = nil
	e.keys.mu.Unlock()
	// Restarted with the head already past the old deadline.
	if err := e.d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.open(e.store)
	e.sessions.ObserveHeight(testDeadline + 1)
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testDeadline + 1})
	if got := e.observer.snapshot().failed; len(got) != 0 {
		t.Fatalf("failed = %v", got)
	}
	if len(e.streams.offers()) <= offers {
		t.Fatal("no ticket of the new round")
	}
	if _, ticket, _ := e.lastOffer(); ticket.GetDispatchRound() != 1 || ticket.GetBoundChangeHeight() != bound {
		t.Fatalf("ticket = %v", ticket)
	}
}

// The attempt book learns the order's user with the winner: it names the task's one output
// subscriber after the task itself is gone.
func TestAcceptedWinnerNamesTheOrderUser(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.accept()
	if a, ok := e.attempts.Current(o.TaskID); !ok || a.User != testUser {
		t.Fatalf("attempt = %+v, %v", a, ok)
	}
}

// flakyAttempts fails the first fails Accepted calls.
type flakyAttempts struct {
	Attempts
	mu    sync.Mutex
	fails int
	err   error // the failure; a store error when nil
}

func (f *flakyAttempts) Accepted(w attempt.Winner) error {
	f.mu.Lock()
	failing := f.fails > 0
	if failing {
		f.fails--
	}
	f.mu.Unlock()
	if failing {
		if f.err != nil {
			return f.err
		}
		return errors.New("attempt store unavailable")
	}
	return f.Attempts.Accepted(w)
}

// A winner the attempt book could not take is handed to it again on the next block.
func TestAcceptedWinnerRetriedOnTheNextBlock(t *testing.T) {
	e := newEnv(t)
	e.d.cfg.Attempts = &flakyAttempts{Attempts: e.attempts, fails: 1}
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, hash := e.accept()
	if _, ok := e.attempts.Current(o.TaskID); ok {
		t.Fatal("the failed winner is in the book")
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if a, ok := e.attempts.Current(o.TaskID); !ok || a.TicketHash != hash {
		t.Fatalf("attempt after the next block = %+v, %v", a, ok)
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 2})
}

// The chain recorded a winner a binding change had voided (its withdrawal came too late), and the
// new round finds no taker: the Recorder's report of the record ends the order. Its ticket out no
// longer times out into more tickets or a failure, and its late accept is DISPATCH_TICKET_CLOSED.
func TestRecordOfAVoidedWinnerEndsTheNewRound(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, first := e.accept()
	const bound = testBound + 10
	e.chain.update(s, func(st *chaincli.SessionState) { st.BoundChangeHeight = bound })
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: bound}})
	if w := e.recorder.withdrawn; len(w) != 1 || w[0] != first {
		t.Fatalf("withdrawn = %x", w)
	}
	_, ticket, hash := e.lastOffer()
	offers := len(e.streams.offers())
	if err := e.d.Recorded(s, 0, bound); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(10 * time.Second)
	if n := len(e.streams.offers()); n != offers {
		t.Fatalf("%d offers after the record, want %d", n, offers)
	}
	if got := e.observer.snapshot().failed; len(got) != 0 {
		t.Fatalf("failed = %v", got)
	}
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrUnknownTicket) {
		t.Fatalf("late accept of the new round = %v", err)
	}
	if got := e.observer.snapshot(); len(got.failed) != 0 || len(got.accepted) != 1 {
		t.Fatalf("observed %+v", got)
	}
}

// A binding event of this Builder at a height below the order's current bound_change_height (a
// replay or one out of order) is stale: the tickets out and the accepted winner stay.
func TestStaleRebindingIsIgnored(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.accept()
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: testBound - 1}})
	if len(e.recorder.withdrawn) != 0 {
		t.Fatalf("withdrawn = %x", e.recorder.withdrawn)
	}
	if e.ledgerState(o) != inflight.StateAccepted {
		t.Fatal("the accepted order was reopened")
	}
}

// An accept for a task the attempt book holds recorded with another ticket still goes to the
// Recorder: the chain answers its entry (CONFLICT), and the book is not asked again.
func TestEntryGoesOutWhenTheBookHasAnotherRecordedTicket(t *testing.T) {
	e := newEnv(t)
	recorded := &flakyAttempts{Attempts: e.attempts, err: fmt.Errorf("%w: test", attempt.ErrRecordedWithAnotherTicket), fails: 1}
	e.d.cfg.Attempts = recorded
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.accept()
	if n := len(e.recorder.recorded()); n != 1 {
		t.Fatalf("%d entries handed to the recorder", n)
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if _, ok := e.attempts.Current(o.TaskID); ok {
		t.Fatal("the book was asked again")
	}
}
