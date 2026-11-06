package recorder

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/coordinator"
)

// Outbox counts the unresolved entries, those waiting for the next block and the transactions.
func TestOutboxCounts(t *testing.T) {
	e := newEnv(t)
	a0, b0 := bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50)
	e.record(a0, b0)
	if got := e.r.Outbox(); got != (OutboxState{Entries: 2, Waiting: 2}) {
		t.Fatalf("before the block = %+v", got)
	}
	e.block(10)
	if got := e.r.Outbox(); got != (OutboxState{Entries: 2, Transactions: 1}) {
		t.Fatalf("after the block = %+v", got)
	}
	msg, raw := e.lastSent()
	e.chain.execute(raw, executed(t, msg, 11, ok(), ok()))
	e.block(11)
	if got := e.r.Outbox(); got != (OutboxState{}) {
		t.Fatalf("after the records = %+v", got)
	}
}

// A takeover entry not sent yet is withdrawn and gone; one carried by a transaction stays.
func TestWithdrawUnsentTakeover(t *testing.T) {
	e := newEnv(t)
	tb := takeover(t, 0xaa, 5, 50)
	if err := e.r.RecordTakeover(context.Background(), tb); err != nil {
		t.Fatal(err)
	}
	if e.r.WithdrawUnsentTakeover(tb.SessionID, 6) {
		t.Fatal("withdrew another sequence")
	}
	if !e.r.WithdrawUnsentTakeover(tb.SessionID, 5) || e.r.Outbox().Entries != 0 || len(e.outboxKeys()) != 0 {
		t.Fatalf("unsent entry not withdrawn: %+v", e.r.Outbox())
	}
	if err := e.r.RecordTakeover(context.Background(), tb); err != nil {
		t.Fatal(err)
	}
	e.block(10)
	if e.r.WithdrawUnsentTakeover(tb.SessionID, 5) || e.r.Outbox().Entries != 1 {
		t.Fatalf("sent entry withdrawn: %+v", e.r.Outbox())
	}
}

// WithdrawTakeoverUnlessSent reports whether no transaction carries the takeover entry, withdrawing
// an unsent one: true for an entry not sent yet (now gone) and for no entry at all (never recorded,
// or already resolved, as a refused one is), false only while a transaction carries it.
func TestWithdrawTakeoverUnlessSent(t *testing.T) {
	e := newEnv(t)
	e.takeovers()
	tb := takeover(t, 0xaa, 5, 50)
	if !e.r.WithdrawTakeoverUnlessSent(tb.SessionID, 5) {
		t.Fatal("no entry reported as carried by a transaction")
	}
	if err := e.r.RecordTakeover(context.Background(), tb); err != nil {
		t.Fatal(err)
	}
	if !e.r.WithdrawTakeoverUnlessSent(tb.SessionID, 5) || e.r.Outbox().Entries != 0 || len(e.outboxKeys()) != 0 {
		t.Fatalf("unsent entry not withdrawn: %+v", e.r.Outbox())
	}
	if err := e.r.RecordTakeover(context.Background(), tb); err != nil {
		t.Fatal(err)
	}
	e.block(10)
	if e.r.WithdrawTakeoverUnlessSent(tb.SessionID, 5) || e.r.Outbox().Entries != 1 {
		t.Fatalf("sent entry withdrawn: %+v", e.r.Outbox())
	}
	msg, raw := e.lastSent()
	e.chain.execute(raw, executed(t, msg, 11, refused(codeSequenceNotNext)))
	e.block(11)
	if !e.r.WithdrawTakeoverUnlessSent(tb.SessionID, 5) {
		t.Fatal("a refused entry is still reported as carried by a transaction")
	}
}

// A takeover entry chosen for a transaction is not withdrawn as unsent while the transaction is
// signed: the transaction carries it whatever happens to the entry then. Once the send failed the
// entry is unsent again and can be withdrawn.
func TestTakeoverEntryBeingPackedIsNotWithdrawnAsUnsent(t *testing.T) {
	e := newEnv(t)
	tb := takeover(t, 0xaa, 5, 50)
	if err := e.r.RecordTakeover(context.Background(), tb); err != nil {
		t.Fatal(err)
	}
	withdrawn := true
	e.tx.beforeSign = func() {
		e.tx.beforeSign = nil
		withdrawn = e.r.WithdrawUnsentTakeover(tb.SessionID, 5)
	}
	e.tx.next = []error{&coordinator.SubmissionError{Phase: coordinator.SubmissionBroadcast, Definitive: true, Err: errors.New("refused")}}
	e.block(10)
	if withdrawn {
		t.Fatal("an entry chosen for a transaction was withdrawn as unsent")
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 1 || len(msgs[0].GetEntries()) != 1 {
		t.Fatalf("sent = %v", msgs)
	}
	if !e.r.WithdrawUnsentTakeover(tb.SessionID, 5) {
		t.Fatal("an entry whose send failed cannot be withdrawn")
	}
}

// A dispatch entry withdrawn while its transaction is signed is marked, so the transaction it
// rides in changes nothing on its refusal; withdrawn and not carried after all, it is dropped.
func TestEntryWithdrawnWhileBeingPacked(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.tx.beforeSign = func() {
		e.tx.beforeSign = nil
		e.r.Withdraw(context.Background(), b.SessionID, 0, [32]byte(b.Entry.GetRecord().GetDispatchTicketHash()))
	}
	e.tx.next = []error{&coordinator.SubmissionError{Phase: coordinator.SubmissionBroadcast, Definitive: true, Err: errors.New("refused")}}
	e.block(10)
	if got := e.r.Outbox(); got.Entries != 0 || len(e.outboxKeys()) != 0 {
		t.Fatalf("withdrawn entry kept after its send failed: %+v %v", got, e.outboxKeys())
	}
}
