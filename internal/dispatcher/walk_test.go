package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
)

func digestOf(t *testing.T, name string, m proto.Message) [32]byte {
	t.Helper()
	raw, err := marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// checkRecordable applies the Keeper's record-time checks of a dispatch entry that do not read
// chain state beyond the session's bound_change_height: the four parts name the same order, record
// and winner ticket are signed by this Builder and agree byte for byte where they must, the rounds
// and attempts are well formed with the winner last, the skips are within max_skips, and the accept
// names the winner ticket and its target.
func checkRecordable(t *testing.T, e *env, b *Bundle, boundChange uint64) *taskv1.DispatchRecordV1 {
	t.Helper()
	entry := b.Entry
	rec, win, acc, order := entry.GetRecord(), entry.GetWinnerTicket(), entry.GetAccept(), entry.GetSignedOrder().GetOrder()
	same := func(what string, a, b []byte) {
		t.Helper()
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs: %x vs %x", what, a, b)
		}
	}
	same("task_id record/ticket", rec.GetTaskId(), win.GetTaskId())
	same("task_id record/accept", rec.GetTaskId(), acc.GetTaskId())
	same("task_hash record/ticket", rec.GetTaskHash(), win.GetTaskHash())
	same("task_hash record/accept", rec.GetTaskHash(), acc.GetTaskHash())
	same("session_id", rec.GetSessionId(), order.GetSessionId())
	same("ticket session_id", win.GetSessionId(), order.GetSessionId())
	same("input_hash", win.GetInputHash(), order.GetInputHash())
	if rec.GetOrderSequence() != order.GetOrderSequence() || win.GetOrderSequence() != order.GetOrderSequence() {
		t.Fatal("order_sequence differs")
	}
	if rec.GetBuilderAddress() != e.builder || win.GetBuilderAddress() != e.builder {
		t.Fatal("builder_address is not this Builder")
	}
	ticketHash := digestOf(t, ticketName, win)
	recordHash := digestOf(t, recordName, rec)
	if err := dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), ticketHash[:], win.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("winner ticket signature: %v", err)
	}
	if err := dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), recordHash[:], rec.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("record signature: %v", err)
	}
	if rec.GetReferenceHeight() != win.GetReferenceHeight() || !bytes.Equal(rec.GetCandidatePoolSnapshotId(), win.GetCandidatePoolSnapshotId()) ||
		rec.GetVrfEpoch() != win.GetVrfEpoch() || !bytes.Equal(rec.GetVrfOutput(), win.GetVrfOutput()) || !bytes.Equal(rec.GetVrfProof(), win.GetVrfProof()) ||
		rec.GetRandomnessScheme() != win.GetRandomnessScheme() || rec.GetBoundChangeHeight() != win.GetBoundChangeHeight() ||
		rec.GetStickyAnchorSequence() != win.GetStickyAnchorSequence() || rec.GetStickyRunCount() != win.GetStickyRunCount() {
		t.Fatal("record and winner ticket disagree on a shared field")
	}
	if win.GetRandomnessScheme() != taskv1.DispatchRandomnessSchemeV1_DISPATCH_RANDOMNESS_SCHEME_V1_BUILDER_VRF {
		t.Fatal("randomness scheme")
	}
	if win.GetBoundChangeHeight() != boundChange {
		t.Fatalf("winner bound_change_height = %d, want %d", win.GetBoundChangeHeight(), boundChange)
	}
	rounds := rec.GetRounds()
	if len(rounds) == 0 {
		t.Fatal("record has no round")
	}
	accepted, skips := 0, uint32(0)
	lastRank := int64(-1)
	for i, r := range rounds {
		if r.GetDispatchRound() != uint32(i) {
			t.Fatalf("round %d numbered %d", i, r.GetDispatchRound())
		}
		if len(r.GetAttempts()) == 0 {
			t.Fatalf("round %d has no attempt", i)
		}
		for _, a := range r.GetAttempts() {
			if int64(a.GetRank()) <= lastRank {
				t.Fatalf("rank %d after %d", a.GetRank(), lastRank)
			}
			lastRank = int64(a.GetRank())
			switch a.GetOutcome() {
			case outcomeAccepted:
				accepted++
			case outcomeRejected:
				skips++
				if bytes.Equal(a.GetRejectDigestOrZero32(), make([]byte, 32)) {
					t.Fatal("REJECTED attempt without a reject digest")
				}
			case outcomeTimeout:
				skips++
				if a.GetTimeoutTierOrZero() == 0 {
					t.Fatal("TIMEOUT attempt without a tier")
				}
			case outcomeVoided, taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REVOKED:
			default:
				t.Fatalf("attempt outcome %v", a.GetOutcome())
			}
		}
	}
	last := rounds[len(rounds)-1]
	winner := last.GetAttempts()[len(last.GetAttempts())-1]
	if accepted != 1 || winner.GetOutcome() != outcomeAccepted {
		t.Fatal("the winner must be the only ACCEPTED attempt and the last one")
	}
	same("winner hash", winner.GetDispatchTicketHash(), ticketHash[:])
	same("record dispatch_ticket_hash", rec.GetDispatchTicketHash(), ticketHash[:])
	if !proto.Equal(winner.GetMember(), win.GetTarget()) || winner.GetRank() != win.GetRank() {
		t.Fatal("winner attempt does not match the winner ticket")
	}
	if win.GetDispatchRound() != last.GetDispatchRound() || !bytes.Equal(win.GetRosterHash(), last.GetRosterHash()) ||
		!bytes.Equal(win.GetHandraiseRootDigest(), last.GetHandraiseRootDigest()) {
		t.Fatal("winner ticket does not bind the last round")
	}
	if skips > e.params.MaxSkips {
		t.Fatalf("%d skips > max_skips %d", skips, e.params.MaxSkips)
	}
	same("accept ticket hash", acc.GetDispatchTicketHash(), ticketHash[:])
	if !proto.Equal(acc.GetMember(), win.GetTarget()) {
		t.Fatal("accept member is not the winner target")
	}
	return rec
}

func outcomes(rec *taskv1.DispatchRecordV1) []string {
	var out []string
	for _, r := range rec.GetRounds() {
		for _, a := range r.GetAttempts() {
			out = append(out, fmt.Sprintf("%d:%d:%s", r.GetDispatchRound(), a.GetRank(), a.GetOutcome().String()[len("DISPATCH_ATTEMPT_OUTCOME_V1_"):]))
		}
	}
	return out
}

// The first member of the drawn order gets one ticket; its accept ends the walk. The ticket binds
// the round's root and roster, the order's draw and the session's bound_change_height, with the
// slowest tier's deadline for a Worker whose RTT is not measured.
func TestAcceptStopsTheWalk(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)

	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7}) {
		t.Fatalf("offers = %v, want [op7]", got)
	}
	_, ticket, _ := e.lastOffer()
	offer := e.streams.offers()[0].frame.GetOffer()
	if !bytes.Equal(offer.GetSignedOrder().GetUserSignature(), bytes.Repeat([]byte{1}, 65)) {
		t.Fatal("the offer does not carry the signed order")
	}
	roster, err := dispatchdraw.BuildRoster(testChainID, [32]byte(mustHex(o.TaskID)), e.handraises.root,
		dispatchdraw.NewPool(testEpoch, testProfile, poolMembers), testESH, testRosterCap)
	if err != nil {
		t.Fatal(err)
	}
	wantDeadline := uint64(e.clock.Now().UnixMilli()) + 500
	if ticket.GetRank() != 0 || ticket.GetDispatchRound() != 0 || ticket.GetTarget().GetSlot() != 7 ||
		ticket.GetAcceptDeadlineMs() != wantDeadline || ticket.GetBoundChangeHeight() != testBound ||
		!bytes.Equal(ticket.GetRosterHash(), roster.Hash[:]) || !bytes.Equal(ticket.GetHandraiseRootDigest(), bytes.Repeat([]byte{0xd1}, 32)) ||
		ticket.GetReferenceHeight() != testEpoch.ReferenceHeight || ticket.GetVrfEpoch() != testEpoch.Number ||
		!bytes.Equal(ticket.GetCandidatePoolSnapshotId(), testSnapshot[:]) || ticket.GetStickyAnchorSequence() != 0 || ticket.GetStickyRunCount() != 1 {
		t.Fatalf("ticket = %v", ticket)
	}
	if state := e.ledgerState(o); state != inflight.StateDispatching {
		t.Fatalf("ledger = %v", state)
	}

	worker, hash := e.accept()
	if state := e.ledgerState(o); state != inflight.StateAccepted {
		t.Fatalf("ledger after accept = %v", state)
	}
	if got := e.observer.snapshot(); !reflect.DeepEqual(got.accepted, []string{op7}) || got.tickets[0] != hash || worker != op7 {
		t.Fatalf("observed %+v", got)
	}
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	if b := e.onlyBundle(); b.Deadline != testDeadline || b.Sequence != 0 || b.SessionID != s {
		t.Fatalf("bundle = %+v", b)
	}
	e.clock.advance(time.Second)
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers after the accept", n)
	}
	header, ok := e.d.DispatchResult(s, o.TaskID)
	if !ok || digestOf(t, ticketName, header.GetWinnerTicket()) != hash || !bytes.Equal(header.GetAccept().GetDispatchTicketHash(), hash[:]) ||
		header.GetRecordStatus() != taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_PENDING {
		t.Fatalf("result header = %v %v", header, ok)
	}
	digest := digestOf(t, resultHeaderName, header)
	if err := dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), digest[:], header.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("result header signature: %v", err)
	}
	// Outcomes feed the reject rate: the accepting Worker counts as not rejecting.
	if got := e.handraises.outcomeCalls(); !reflect.DeepEqual(got, []outcomeCall{{op7, false}}) {
		t.Fatalf("outcomes = %v", got)
	}
}

// Every reject moves to the next roster member; the record lists them with their digests. Each
// counts in the Worker's reject rate while it advertised a free slot.
func TestRejectsWalkOnAndFeedTheRejectRate(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.reject() // op7, rank 0
	e.reject() // op1, rank 1
	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7, op1, op3}) {
		t.Fatalf("offers = %v", got)
	}
	e.accept()
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:REJECTED", "0:1:REJECTED", "0:2:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	want := []outcomeCall{{op7, true}, {op1, true}, {op3, false}}
	if got := e.handraises.outcomeCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
}

// A reject from a Worker whose local free slot count is 0 (its accepted tickets used up the slots
// its handraise advertised) does not count as a reject.
func TestRejectWithoutFreeSlotIsNotCounted(t *testing.T) {
	e := newEnv(t)
	e.handraises.setRoot(0xd1, 1, op1, op3, op7)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.accept()                            // op7 takes its one slot
	e.sessions.ObserveHeight(testESH + 1) // past the unknown sticky anchor's possible height
	e.dispatch(e.order(s, 1, 1))
	if op, _, _ := e.lastOffer(); op != op7 {
		t.Fatalf("second order offered to %s", op)
	}
	e.reject()
	got := e.handraises.outcomeCalls()
	if last := got[len(got)-1]; last != (outcomeCall{op7, false}) {
		t.Fatalf("reject at 0 free slots counted: %v", got)
	}
	// A re-signed handraise restores the advertised slots.
	e.handraises.setRoot(0xd2, 1, op1, op3, op7)
	if free := e.d.slots.free(op7, e.handraises.current[op7]); free != 1 {
		t.Fatalf("free after re-sign = %d", free)
	}
}

// More rejects and timeouts than max_skips end the order as NO_CAPACITY: its ledger entry fails and
// its sequence stays unused.
func TestSkipLimitIsNoCapacity(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 1, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	e.reject()
	if n := len(e.streams.offers()); n != 2 {
		t.Fatalf("%d offers, want 2", n)
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], dispatchdraw.ErrNoCapacity) {
		t.Fatalf("failed = %v", got)
	}
	if state := e.ledgerState(o); state != inflight.StateFailed {
		t.Fatalf("ledger = %v", state)
	}
	if len(e.recorder.recorded()) != 0 {
		t.Fatal("a failed order was recorded")
	}
}

// With max_skips skips already, one more ticket may still win: the record stays within the limit.
func TestTicketAtTheSkipLimitMayStillWin(t *testing.T) {
	e := newEnv(t) // max_skips 2
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.reject()
	e.reject()
	e.accept()
	checkRecordable(t, e, e.onlyBundle(), testBound)
}

// A ticket unanswered at its deadline times out; the deadline comes from the Worker's RTT tier and
// the TIMEOUT attempt records that tier. A timeout counts in the reject-rate denominator only.
func TestTimeoutsPerRTTTier(t *testing.T) {
	e := newEnv(t)
	e.streams.rtt[op7] = 30 * time.Millisecond  // tier 1: 300 ms
	e.streams.rtt[op1] = 120 * time.Millisecond // tier 2: 500 ms
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, first, _ := e.lastOffer()
	if first.GetAcceptDeadlineMs() != uint64(e.clock.Now().UnixMilli())+300 {
		t.Fatalf("tier 1 deadline = %d", first.GetAcceptDeadlineMs())
	}
	e.clock.advance(299 * time.Millisecond)
	if n := len(e.streams.offers()); n != 1 {
		t.Fatal("timed out before the deadline")
	}
	e.clock.advance(time.Millisecond)
	op, second, _ := e.lastOffer()
	if op != op1 || second.GetAcceptDeadlineMs() != uint64(e.clock.Now().UnixMilli())+500 {
		t.Fatalf("after the timeout: %s deadline %d", op, second.GetAcceptDeadlineMs())
	}
	e.clock.advance(500 * time.Millisecond)
	e.accept() // op3
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:TIMEOUT", "0:1:TIMEOUT", "0:2:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	attempts := rec.GetRounds()[0].GetAttempts()
	if attempts[0].GetTimeoutTierOrZero() != 1 || attempts[1].GetTimeoutTierOrZero() != 2 {
		t.Fatalf("tiers = %d, %d", attempts[0].GetTimeoutTierOrZero(), attempts[1].GetTimeoutTierOrZero())
	}
	want := []outcomeCall{{op7, false}, {op1, false}, {op3, false}}
	if got := e.handraises.outcomeCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %v", got)
	}
}

// An accept arriving after its ticket's deadline is DISPATCH_TICKET_CLOSED: the ticket timed out
// and the walk went on. An accept of a ticket that is no longer out is closed too.
func TestLateAcceptIsTicketClosed(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	// The clock passes the deadline before the timer fires.
	e.clock.mu.Lock()
	e.clock.now = e.clock.now.Add(501 * time.Millisecond)
	e.clock.mu.Unlock()
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("late accept = %v, want DISPATCH_TICKET_CLOSED", err)
	}
	if op, _, _ := e.lastOffer(); op != op1 {
		t.Fatalf("after a late accept the next offer went to %s", op)
	}
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept of a timed-out ticket = %v", err)
	}
	if got := e.observer.snapshot(); len(got.accepted) != 0 {
		t.Fatal("a late accept won")
	}
}

// Answers that are not their ticket's (another member, another task) are refused and change
// nothing.
func TestAnswersMustMatchTheirTicket(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	m, from := e.acceptMsg(ticket, hash)
	from.Operator = op1
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrAnswerInvalid) {
		t.Fatalf("accept from another stream = %v", err)
	}
	m, from = e.acceptMsg(ticket, hash)
	m.TaskHash = bytes.Repeat([]byte{9}, 32)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrAnswerInvalid) {
		t.Fatalf("accept of another order version = %v", err)
	}
	m, from = e.acceptMsg(ticket, fill32(0x99))
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrUnknownTicket) {
		t.Fatalf("accept of an unknown ticket = %v", err)
	}
	if len(e.streams.offers()) != 1 || len(e.observer.snapshot().accepted) != 0 {
		t.Fatal("a refused answer changed the walk")
	}
}

// Stickiness promotes the previous recorded winner to rank 0 with a continuation commitment. When
// it rejects, the walk goes on in draw order with new-run commitments, and the record still says
// sticky_applied.
func TestStickyPromotionStaysOnTheRecordWhenThePromotedWorkerRejects(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 6)
	e.chain.update(s, func(st *chaincli.SessionState) {
		st.LastRecordWinner, st.StickyAnchorSequence, st.StickyAnchorHeight, st.StickyRunCount = op3, 5, 80, 1
	})
	e.dispatch(e.order(s, 6, 1))
	op, first, _ := e.lastOffer()
	if op != op3 || first.GetRank() != 0 || first.GetStickyAnchorSequence() != 5 || first.GetStickyRunCount() != 2 {
		t.Fatalf("first ticket to %s rank %d sticky (%d, %d)", op, first.GetRank(), first.GetStickyAnchorSequence(), first.GetStickyRunCount())
	}
	e.reject()
	op, second, _ := e.lastOffer()
	if op != op7 || second.GetRank() != 1 || second.GetStickyAnchorSequence() != 6 || second.GetStickyRunCount() != 1 {
		t.Fatalf("second ticket to %s rank %d sticky (%d, %d)", op, second.GetRank(), second.GetStickyAnchorSequence(), second.GetStickyRunCount())
	}
	e.accept()
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if !rec.GetStickyApplied() || rec.GetStickyAnchorSequence() != 6 || rec.GetStickyRunCount() != 1 {
		t.Fatalf("record sticky = %v (%d, %d)", rec.GetStickyApplied(), rec.GetStickyAnchorSequence(), rec.GetStickyRunCount())
	}
}

// An order dispatched while an earlier order of the session is accepted but unrecorded predicts the
// sticky state from that order's winner ticket: a new run started by it has no known anchor height
// yet. While the head is still at the order's earliest_submit_height that anchor (the earlier
// order's record height) could equal it, so the order waits; once the head is past it, an anchor
// recorded later lies above earliest_submit_height, outside the window, and the order is not
// promoted. While the earlier order still dispatches, the next waits.
func TestStickyPredictionFromAnEarlierUnrecordedOrder(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.dispatch(e.order(s, 1, 1))
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers: the second order must wait for the first", n)
	}
	e.accept() // order 0 won by op7, a new run
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers: at earliest_submit_height the second order must wait for the anchor", n)
	}
	e.sessions.ObserveHeight(testESH + 1)
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	offers := e.streams.offers()
	if len(offers) != 2 {
		t.Fatalf("%d offers once the head passed earliest_submit_height", len(offers))
	}
	second := offers[1].frame.GetOffer().GetTicket()
	if offers[1].operator != op7 || second.GetOrderSequence() != 1 || second.GetStickyAnchorSequence() != 1 || second.GetStickyRunCount() != 1 {
		t.Fatalf("second order ticket to %s: %v", offers[1].operator, second)
	}
}

// A change of the session's bound_change_height voids the ticket out and an accepted, unrecorded
// winner; each time a new round commits the new height and continues after the last rank.
func TestBindingChangeVoidsAndOpensANewRound(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	rebind := func(height uint64) {
		e.chain.update(s, func(st *chaincli.SessionState) { st.BoundChangeHeight = height })
		e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: height}})
	}
	rebind(60)
	op, ticket, _ := e.lastOffer()
	if op != op1 || ticket.GetDispatchRound() != 1 || ticket.GetRank() != 1 || ticket.GetBoundChangeHeight() != 60 {
		t.Fatalf("after the first change: %s %v", op, ticket)
	}
	_, firstWin := e.accept()
	rebind(70)
	if state := e.ledgerState(o); state != inflight.StateDispatching {
		t.Fatalf("ledger after a voided accept = %v", state)
	}
	if w := e.recorder.withdrawn; len(w) != 1 || w[0] != firstWin {
		t.Fatalf("withdrawn = %x", w)
	}
	op, ticket, _ = e.lastOffer()
	if op != op3 || ticket.GetDispatchRound() != 2 || ticket.GetBoundChangeHeight() != 70 {
		t.Fatalf("after the second change: %s %v", op, ticket)
	}
	e.accept()
	bundles := e.recorder.recorded()
	rec := checkRecordable(t, e, bundles[len(bundles)-1], 70)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:VOIDED", "1:1:VOIDED", "2:2:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	// Bound to another Builder, the session's orders fail, the accepted one included.
	e.dispatch(e.order(s, 1, 1))
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: op1, BoundChangeHeight: 80}})
	got := e.observer.snapshot().failed
	if len(got) != 2 || !errors.Is(got[0], ErrBoundElsewhere) || !errors.Is(got[1], ErrBoundElsewhere) {
		t.Fatalf("failed = %v", got)
	}
	if len(e.recorder.withdrawn) != 2 || e.ledgerState(o) != inflight.StateFailed {
		t.Fatalf("withdrawn %d, ledger %v", len(e.recorder.withdrawn), e.ledgerState(o))
	}
}

// While this Builder's own service key rotation is pending no ticket is issued and new orders are
// refused before their input is stored; once it clears the parked order goes on.
func TestOwnRotationPendingIssuesNoTickets(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.keys.builderErr = fmt.Errorf("%w: nonce 5", handraise.ErrBuilderRotationPending)
	if err := e.d.Probe(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe = %v", err)
	}
	e.dispatch(o)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers while the rotation is pending", n)
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if n := len(e.streams.offers()); n != 0 {
		t.Fatal("offered while still pending")
	}
	e.keys.mu.Lock()
	e.keys.builderErr = nil
	e.keys.mu.Unlock()
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 2})
	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7}) {
		t.Fatalf("offers after the rotation cleared = %v", got)
	}
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe = %v", err)
	}
}

// A Cortex with a pending key rotation stays in the roster, which holds exactly the members the
// bound root admits (anything less loses an omission challenge): it, like a member that becomes
// pending or disconnects later, gets a ticket that times out unsent, so the round still has an
// attempt for every roster member before the winner.
func TestUnreachableMembers(t *testing.T) {
	e := newEnv(t)
	e.keys.cortexPended[op7] = true
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	op, ticket, _ := e.lastOffer()
	if op != op1 || ticket.GetRank() != 1 {
		t.Fatalf("first offer to %s rank %d, want op1 rank 1", op, ticket.GetRank())
	}
	full, err := dispatchdraw.BuildRoster(testChainID, [32]byte(mustHex(o.TaskID)), e.handraises.root,
		dispatchdraw.NewPool(testEpoch, testProfile, poolMembers), testESH, testRosterCap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ticket.GetRosterHash(), full.Hash[:]) {
		t.Fatal("the pending member was left out of the roster")
	}
	e.keys.mu.Lock()
	e.keys.cortexPended[op3] = true
	e.keys.mu.Unlock()
	e.reject()
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers: the pending members must not be offered", n)
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], dispatchdraw.ErrNoCapacity) {
		t.Fatalf("failed = %v", got)
	}

	e2 := newEnv(t)
	e2.streams.disconnected[op7] = true
	s2 := e2.session(0xbb, 0)
	e2.dispatch(e2.order(s2, 0, 1))
	if op, _, _ := e2.lastOffer(); op != op1 {
		t.Fatalf("offer to %s, want op1 after the disconnected op7", op)
	}
	e2.accept()
	rec := checkRecordable(t, e2, e2.onlyBundle(), testBound)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:TIMEOUT", "0:1:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
	if got := e2.handraises.outcomeCalls(); !reflect.DeepEqual(got, []outcomeCall{{op1, false}}) {
		t.Fatalf("an unsent ticket fed the reject rate: %v", got)
	}
}

// An order whose earliest_submit_height is above the local head waits for that height.
func TestOrderWaitsForItsEarliestSubmitHeight(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.orderAt(s, 0, 1, testESH+1)
	e.dispatch(o)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers before the head reached earliest_submit_height", n)
	}
	e.sessions.ObserveHeight(testESH + 1)
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7}) {
		t.Fatalf("offers = %v", got)
	}
}

// A retry of a failed sequence in the same epoch is a new round: it binds the latest root and
// continues after the last rank with the skip count kept.
func TestRetryIsANewRound(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	e.params.MaxSkips = 1
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("not failed")
	}
	e.d.SetParams(e.params)
	e.handraises.setRoot(0xd2, 2, op1, op3, op7)
	retry := e.order(s, 0, 2) // re-signed, another task_hash
	e.dispatch(retry)
	op, ticket, _ := e.lastOffer()
	if op != op1 || ticket.GetDispatchRound() != 1 || ticket.GetRank() != 1 ||
		!bytes.Equal(ticket.GetHandraiseRootDigest(), bytes.Repeat([]byte{0xd2}, 32)) || ticket.GetTaskHash()[0] != 2 {
		t.Fatalf("retry ticket to %s: %v", op, ticket)
	}
	e.accept()
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if got := outcomes(rec); !reflect.DeepEqual(got, []string{"0:0:REJECTED", "1:1:ACCEPTED"}) {
		t.Fatalf("attempts = %v", got)
	}
}

// The input goes only to the winner, and only for the accept this Builder holds.
func TestInputRequest(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, ticket, hash := e.lastOffer()
	accept, from := e.acceptMsg(ticket, hash)
	request := &nexusv1InputRequest{ticket: ticket, hash: hash}
	if err := e.d.HandleDispatchInputRequest(context.Background(), from, request.msg(from.Digest[:])); !errors.Is(err, ErrInputRefused) {
		t.Fatalf("input before the accept = %v", err)
	}
	if err := e.d.HandleDispatchAccept(context.Background(), from, accept); err != nil {
		t.Fatal(err)
	}
	if err := e.d.HandleDispatchInputRequest(context.Background(), from, request.msg(bytes.Repeat([]byte{7}, 32))); !errors.Is(err, ErrInputRefused) {
		t.Fatalf("input with another accept digest = %v", err)
	}
	other := from
	other.Operator = op1
	if err := e.d.HandleDispatchInputRequest(context.Background(), other, request.msg(from.Digest[:])); !errors.Is(err, ErrInputRefused) {
		t.Fatalf("input for another Worker = %v", err)
	}
	if n := len(e.streams.inputResponses()); n != 0 {
		t.Fatalf("%d input chunks sent to refused requests", n)
	}
	if err := e.d.HandleDispatchInputRequest(context.Background(), from, request.msg(from.Digest[:])); err != nil {
		t.Fatal(err)
	}
	chunks := e.streams.inputResponses()
	var got []byte
	for i, c := range chunks {
		digest := digestOf(t, inputResponseName, c)
		if err := dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), digest[:], c.GetBuilderServiceSignature()); err != nil {
			t.Fatalf("chunk %d signature: %v", i, err)
		}
		if c.GetChunkIndex() != uint32(i) || c.GetChunkCount() != 3 || c.GetInputSizeBytes() != 11 ||
			!bytes.Equal(c.GetDispatchTicketHash(), hash[:]) || !bytes.Equal(c.GetInputHash(), ticket.GetInputHash()) {
			t.Fatalf("chunk %d = %v", i, c)
		}
		got = append(got, c.GetInput()...)
	}
	if string(got) != "hello world" {
		t.Fatalf("input = %q", got)
	}
}

type nexusv1InputRequest struct {
	ticket *taskv1.DispatchTicketV1
	hash   [32]byte
}

func (r *nexusv1InputRequest) msg(acceptDigest []byte) *nexusv1.DispatchInputRequestV1 {
	return &nexusv1.DispatchInputRequestV1{
		TaskId: r.ticket.GetTaskId(), DispatchTicketHash: r.hash[:], Member: r.ticket.GetTarget(),
		ServiceAuthorizationNonce: 3, DispatchAcceptDigest: acceptDigest,
	}
}

func TestOfferLive(t *testing.T) {
	now := time.UnixMilli(1_000)
	offer := func(deadline uint64) *nexusv1.DispatchStreamFrameV1 {
		return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{
			Ticket: &taskv1.DispatchTicketV1{AcceptDeadlineMs: deadline}}}}
	}
	if !OfferLive(offer(1_000), now) || OfferLive(offer(999), now) {
		t.Fatal("offer deadline filter")
	}
	if !OfferLive(&nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Revoke{Revoke: &nexusv1.DispatchRevokeV1{}}}, now) {
		t.Fatal("other frames are kept")
	}
}

// roundFailingStore refuses, while fail is set, to write an order state that holds a round: the
// first ticket of an order is then not issued and the order parks with its draw kept.
type roundFailingStore struct {
	kv.Store
	mu   sync.Mutex
	fail bool
}

func (s *roundFailingStore) setFail(v bool) {
	s.mu.Lock()
	s.fail = v
	s.mu.Unlock()
}

func (s *roundFailingStore) Set(ns kv.Namespace, key string, val []byte) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail && ns == kv.NSDispatch {
		var st orderState
		if json.Unmarshal(val, &st) == nil && len(st.Rounds) > 0 {
			return errors.New("disk full")
		}
	}
	return s.Store.Set(ns, key, val)
}

// Stickiness is decided from the roster round 0 actually binds: a first ticket that could not be
// issued leaves the draw without a round, and the next attempt decides again against the then
// latest root. Here the sticky Worker's handraise is gone by then, so the order is not promoted.
func TestStickyIsDecidedFromTheRosterRoundZeroBinds(t *testing.T) {
	e := newEnv(t)
	store := &roundFailingStore{Store: kv.NewMemStore()}
	e.store = store
	e.open(store)
	s := e.session(0xaa, 6)
	e.chain.update(s, func(st *chaincli.SessionState) {
		st.LastRecordWinner, st.StickyAnchorSequence, st.StickyAnchorHeight, st.StickyRunCount = op3, 5, 80, 1
	})
	store.setFail(true)
	e.dispatch(e.order(s, 6, 1))
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers while the round could not be written", n)
	}
	store.setFail(false)
	e.handraises.setRoot(0xd2, 2, op1, op7) // op3's handraise is gone
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH})
	op, ticket, _ := e.lastOffer()
	if op != op7 || ticket.GetRank() != 0 || ticket.GetStickyAnchorSequence() != 6 || ticket.GetStickyRunCount() != 1 ||
		!bytes.Equal(ticket.GetHandraiseRootDigest(), bytes.Repeat([]byte{0xd2}, 32)) {
		t.Fatalf("first ticket to %s rank %d sticky (%d, %d)", op, ticket.GetRank(), ticket.GetStickyAnchorSequence(), ticket.GetStickyRunCount())
	}
	e.accept()
	rec := checkRecordable(t, e, e.onlyBundle(), testBound)
	if rec.GetStickyApplied() {
		t.Fatal("promoted to a Worker the bound roster does not hold")
	}
}

// A binding change seen while an order waits for its first ticket is committed by that ticket even
// when the session state read still shows the old bound_change_height.
func TestBindingChangeBeforeTheFirstTicket(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.orderAt(s, 0, 1, testESH+1)
	e.dispatch(o)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers before earliest_submit_height", n)
	}
	e.d.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.SessionBuilderBound{SessionID: s, NewBuilder: e.builder, BoundChangeHeight: testBound + 5}})
	e.sessions.ObserveHeight(testESH + 1)
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	_, ticket, _ := e.lastOffer()
	if ticket.GetBoundChangeHeight() != testBound+5 || ticket.GetDispatchRound() != 0 {
		t.Fatalf("first ticket commits bound_change_height %d round %d, want %d round 0",
			ticket.GetBoundChangeHeight(), ticket.GetDispatchRound(), testBound+5)
	}
}

// An accept that arrives once the head passed the order's record deadline cannot be recorded in
// time (a late record is charged to the Builder): it is refused as DISPATCH_TICKET_CLOSED and the
// order fails.
func TestAcceptAfterTheRecordDeadlineFailsTheOrder(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, ticket, hash := e.lastOffer()
	e.sessions.ObserveHeight(testDeadline + 1)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept after the record deadline = %v, want DISPATCH_TICKET_CLOSED", err)
	}
	if got := e.observer.snapshot(); len(got.accepted) != 0 || len(got.failed) != 1 || !errors.Is(got.failed[0], ErrRecordDeadline) {
		t.Fatalf("observed %+v", got)
	}
	if n := len(e.recorder.recorded()); n != 0 {
		t.Fatalf("%d entries handed to the recorder", n)
	}
	if e.ledgerState(o) != inflight.StateFailed {
		t.Fatal("the order is not failed")
	}
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers after the deadline", n)
	}
}

// While another Builder's takeover of the session is registered, an order is recorded only if its
// record lands by the activation block (the Keeper admits records of that block before EndBlock
// moves the binding): a later record is refused and its Worker claims compensation. An accept
// too close to the activation height is refused and the order fails; one in time is recorded,
// which voids the takeover.
func TestRegisteredTakeoverBoundsTheRecordDeadline(t *testing.T) {
	for _, tc := range []struct {
		activation uint64
		accepted   bool
	}{{testESH + 1, false}, {testESH + 2, true}} {
		e := newEnv(t)
		s := e.session(0xaa, 0)
		o := e.order(s, 0, 1)
		e.dispatch(o)
		_, ticket, hash := e.lastOffer()
		e.chain.update(s, func(st *chaincli.SessionState) {
			st.PendingTakeover = &chaincli.PendingTakeover{CandidateBuilder: op1, OrderSequence: 0, ActivationHeight: tc.activation}
		})
		m, from := e.acceptMsg(ticket, hash)
		err := e.d.HandleDispatchAccept(context.Background(), from, m)
		got := e.observer.snapshot()
		if tc.accepted {
			if err != nil || len(got.accepted) != 1 || len(e.recorder.recorded()) != 1 {
				t.Fatalf("activation %d: accept = %v, observed %+v", tc.activation, err, got)
			}
			continue
		}
		if !errors.Is(err, ErrTicketClosed) || len(got.failed) != 1 || !errors.Is(got.failed[0], ErrRecordDeadline) {
			t.Fatalf("activation %d: accept = %v, observed %+v", tc.activation, err, got)
		}
		if e.ledgerState(o) != inflight.StateFailed {
			t.Fatal("the order is not failed")
		}
	}
}
