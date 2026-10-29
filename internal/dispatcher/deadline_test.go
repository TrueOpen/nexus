package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/handraise"
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
