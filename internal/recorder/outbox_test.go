package recorder

import "testing"

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
