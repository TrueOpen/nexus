package recorder

import (
	"context"
	"testing"
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
