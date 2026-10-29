package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

// evidenceOf returns the evidence and attempt of a ticket, failing when there is none.
func (e *env) evidenceOf(hash [32]byte) (*dispatchevidence.Order, *dispatchevidence.Attempt) {
	e.t.Helper()
	o, a, found, err := e.evidence.ByTicket(hash[:])
	if err != nil || !found {
		e.t.Fatalf("no evidence of ticket %x: %v", hash[:4], err)
	}
	return o, a
}

// checkRecordSigned decodes a stored evidence record and checks this Builder signed it.
func checkRecordSigned(t *testing.T, e *env, raw []byte) *taskv1.DispatchRecordV1 {
	t.Helper()
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	digest := digestOf(t, recordName, &rec)
	if err := dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), digest[:], rec.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("record signature: %v", err)
	}
	return &rec
}

func recordAttempt(rec *taskv1.DispatchRecordV1, hash [32]byte) *taskv1.DispatchAttemptV1 {
	for _, r := range rec.GetRounds() {
		for _, a := range r.GetAttempts() {
			if bytes.Equal(a.GetDispatchTicketHash(), hash[:]) {
				return a
			}
		}
	}
	return nil
}

// An order that ends without a winner keeps its evidence: every ticket as signed and whether it
// reached its target, the rejects as received, the round's roster and root, and a record with no
// winner signed by this Builder that lists every attempt with its outcome.
func TestFailedOrderKeepsItsEvidence(t *testing.T) {
	e := newEnv(t) // max_skips 2; order op7, op1, op3
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	_, _, rejectedHash := e.lastOffer()
	_, rejectedTicket, _ := e.lastOffer()
	_, from := e.rejectMsg(rejectedTicket, rejectedHash)
	e.reject()
	_, _, timedOutHash := e.lastOffer()
	e.clock.advance(time.Second)
	_, _, lastHash := e.lastOffer()
	e.reject()
	if got := e.observer.snapshot().failed; len(got) != 1 {
		t.Fatalf("failed = %v", got)
	}

	ev, rejected := e.evidenceOf(rejectedHash)
	if ev.TaskID != o.TaskID || ev.SessionID != s || ev.Sequence != 0 || !bytes.Equal(ev.SignedOrder, o.SignedOrder) || ev.Recorded {
		t.Fatalf("evidence = %+v", ev)
	}
	if !rejected.Sent || rejected.Outcome != outcomeRejected || !bytes.Equal(rejected.Reject, from.Raw) || !rejected.Rebuttable() {
		t.Fatalf("rejected attempt = %+v", rejected)
	}
	if _, timedOut := e.evidenceOf(timedOutHash); !timedOut.Sent || timedOut.Outcome != outcomeTimeout || !timedOut.Rebuttable() {
		t.Fatalf("timed out attempt = %+v", timedOut)
	}
	if len(ev.Rounds) != 1 || len(ev.Rounds[0].Attempts) != 3 || !bytes.Equal(ev.Rounds[0].RootDigest, bytes.Repeat([]byte{0xd1}, 32)) {
		t.Fatalf("rounds = %+v", ev.Rounds)
	}
	var roster taskv1.DispatchRosterV1
	if err := proto.Unmarshal(ev.Rounds[0].Roster, &roster); err != nil || len(roster.GetMembers()) != 3 {
		t.Fatalf("roster = %v %v", &roster, err)
	}
	var ticket taskv1.DispatchTicketV1
	if err := proto.Unmarshal(ev.Rounds[0].Attempts[0].Ticket, &ticket); err != nil || !bytes.Equal(ev.Rounds[0].RosterHash, ticket.GetRosterHash()) {
		t.Fatal("round roster hash is not the tickets' roster_hash")
	}
	if ev.DeadlineBase != testESH {
		t.Fatalf("deadline base %d", ev.DeadlineBase)
	}

	rec := checkRecordSigned(t, e, ev.Record)
	if !bytes.Equal(rec.GetDispatchTicketHash(), make([]byte, 32)) {
		t.Fatal("a record without a winner names a winner ticket")
	}
	for hash, want := range map[[32]byte]taskv1.DispatchAttemptOutcomeV1{rejectedHash: outcomeRejected, timedOutHash: outcomeTimeout, lastHash: outcomeRejected} {
		a := recordAttempt(rec, hash)
		if a == nil || a.GetOutcome() != want {
			t.Fatalf("record attempt %x = %v, want %s", hash[:4], a, want)
		}
	}
	if a := recordAttempt(rec, rejectedHash); !bytes.Equal(a.GetRejectDigestOrZero32(), from.Digest[:]) {
		t.Fatal("record reject digest is not the reject's")
	}
	if rec.GetOrderSequence() != 0 || hexOf(rec.GetTaskId()) != o.TaskID || !bytes.Equal(rec.GetSessionId(), mustHex(s)) {
		t.Fatal("record names another order")
	}
}

// A ticket that could not reach its Worker is kept as unsent: a claim on it is owed.
func TestUnsentTicketEvidenceIsNotRebuttable(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	e.streams.mu.Lock()
	e.streams.disconnected[op7] = true
	e.streams.mu.Unlock()
	e.dispatch(e.order(s, 0, 1))
	_, st := e.phaseOf(s, 0)
	unsent := st.Rounds[0].Attempts[0]
	if unsent.Sent {
		t.Fatal("ticket to a disconnected Worker sent")
	}
	_, a := e.evidenceOf([32]byte(unsent.Hash))
	if a.Sent || a.Outcome != outcomeTimeout || a.Rebuttable() {
		t.Fatalf("unsent attempt = %+v", a)
	}
}

// The accepted order's evidence holds the record handed to the Recorder; once recorded it is
// marked with the recorded height and the dispatch state goes in the same write.
func TestRecordedOrderEvidence(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.reject()
	_, hash := e.accept()
	b := e.onlyBundle()
	ev, w := e.evidenceOf(hash)
	if w.Outcome != outcomeAccepted || w.Rebuttable() {
		t.Fatalf("winner attempt = %+v", w)
	}
	want, err := marshal(b.Entry.GetRecord())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.Record, want) || len(ev.Accept) == 0 || ev.Recorded {
		t.Fatal("accepted evidence does not hold the entry's record and accept")
	}
	if err := e.d.Recorded(s, 0, 117); err != nil {
		t.Fatal(err)
	}
	ev, _ = e.evidenceOf(hash)
	if !ev.Recorded || ev.RecordedHeight != 117 || !bytes.Equal(ev.Record, want) {
		t.Fatalf("recorded evidence = recorded %v at %d", ev.Recorded, ev.RecordedHeight)
	}
	if states, _ := loadStates(e.store); len(states) != 0 {
		t.Fatal("dispatch state kept after the record")
	}
}

// A refused record voids the winner: the evidence then shows it VOIDED (its Worker is owed) in a
// new record without a winner.
func TestRecordRejectedEvidenceVoidsTheWinner(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, hash := e.accept()
	if err := e.d.RecordRejected(s, 0, ErrRecordRejected); err != nil {
		t.Fatal(err)
	}
	ev, w := e.evidenceOf(hash)
	if w.Outcome != outcomeVoided || w.Rebuttable() {
		t.Fatalf("voided winner = %+v", w)
	}
	rec := checkRecordSigned(t, e, ev.Record)
	if a := recordAttempt(rec, hash); a == nil || a.GetOutcome() != outcomeVoided {
		t.Fatalf("record attempt = %v", a)
	}
}

// An on-time accept too late to record is kept with the attempt VOIDED.
func TestLateAcceptEvidence(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	e.sessions.ObserveHeight(testDeadline - 1)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept = %v", err)
	}
	_, a := e.evidenceOf(hash)
	if a.Outcome != outcomeVoided || !bytes.Equal(a.LateAccept, from.Raw) || a.Rebuttable() {
		t.Fatalf("late accept attempt = %+v", a)
	}
}

// A retry in the same epoch adds a round to the same evidence.
func TestRetryExtendsTheEvidence(t *testing.T) {
	e := newEnv(t)
	e.d.SetParams(Params{MaxSkips: 0, Sticky: e.params.Sticky, MaxRosterBytes: testRosterCap, MaxDrawAttempts: 64})
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, _, first := e.lastOffer()
	e.reject()
	e.d.SetParams(e.params)
	e.dispatch(e.order(s, 0, 2))
	_, hash := e.accept()
	ev, _ := e.evidenceOf(hash)
	if len(ev.Rounds) != 2 {
		t.Fatalf("%d rounds", len(ev.Rounds))
	}
	if _, a := e.evidenceOf(first); a.Outcome != outcomeRejected {
		t.Fatal("first round's attempt lost")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
