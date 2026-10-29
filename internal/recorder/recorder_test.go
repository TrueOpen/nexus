package recorder

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatcher"
)

// Every block packs the entries accepted since the last one, sorted by (session_id,
// order_sequence), into as few transactions as max_dispatch_entries_per_record and
// max_dispatch_record_bytes allow; an entry is persisted before its transaction is broadcast and
// a second Record of the same bytes is the same entry.
func TestPackingOrderAndSplitLimits(t *testing.T) {
	e := newEnv(t)
	e.params.MaxEntries = 2
	e.r.SetParams(e.params)
	e.record(bundle(0xbb, 0, 1, 50), bundle(0xaa, 1, 1, 50), bundle(0xaa, 0, 1, 50), bundle(0xaa, 0, 1, 50))
	if got := e.outboxKeys(); !reflect.DeepEqual(got, []string{"entry/", "entry/", "entry/"}) {
		t.Fatalf("outbox before the block = %v", got)
	}
	e.block(10)
	msgs, _ := e.tx.sent()
	if len(msgs) != 2 || !reflect.DeepEqual(entriesOf(msgs[0]), []string{"aa/0", "aa/1"}) || !reflect.DeepEqual(entriesOf(msgs[1]), []string{"bb/0"}) {
		t.Fatalf("packed %d: %v", len(msgs), msgs)
	}
	if msgs[0].GetSubmitterAddress() != e.signer.Address() {
		t.Fatalf("submitter = %s", msgs[0].GetSubmitterAddress())
	}
	if got := e.outboxKeys(); !reflect.DeepEqual(got, []string{"entry/", "entry/", "entry/", "tx/", "tx/"}) {
		t.Fatalf("outbox after the block = %v", got)
	}
	// Sent entries are not packed again while their transaction may still land.
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(11)
	if msgs, _ := e.tx.sent(); len(msgs) != 2 {
		t.Fatalf("resent: %d messages", len(msgs))
	}

	// The byte limit: two entries fit exactly; one byte less splits them.
	two := []*dispatcher.Bundle{bundle(0xcc, 0, 1, 50), bundle(0xcc, 1, 1, 50)}
	size := proto.Size(&taskv1.MsgRecordDispatch{SubmitterAddress: e.signer.Address(), Entries: []*taskv1.DispatchRecordEntryV1{
		{Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: two[0].Entry}}, {Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: two[1].Entry}},
	}})
	for _, tc := range []struct {
		limit uint64
		want  int
	}{{uint64(size), 1}, {uint64(size) - 1, 2}} {
		e := newEnv(t)
		e.params.MaxBytes = tc.limit
		e.r.SetParams(e.params)
		e.record(two...)
		e.block(10)
		if msgs, _ := e.tx.sent(); len(msgs) != tc.want {
			t.Fatalf("limit %d of %d: %d messages, want %d", tc.limit, size, len(msgs), tc.want)
		}
	}
}

// Results are read per entry: accepted entries are recorded (ledger, dispatcher, task, RECORDED
// notice); a refused one is RECORD_REJECTED with its code, suspends its session from its sequence
// and fails the later orders of the session; the other sessions go on.
func TestPartialRejection(t *testing.T) {
	e := newEnv(t)
	a0, a1, b0 := bundle(0xaa, 0, 1, 50), bundle(0xaa, 1, 2, 50), bundle(0xbb, 0, 3, 50)
	e.record(a0, a1, b0)
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.execute(raw, executed(t, msg, 11, ok(), refused(codeBalance), result{status: noop}))
	e.block(11)

	wantRecorded := []orderKey{{a0.SessionID, 0}, {b0.SessionID, 0}}
	if !reflect.DeepEqual(e.ledger.recorded, wantRecorded) || !reflect.DeepEqual(e.orders.recorded, wantRecorded) {
		t.Fatalf("recorded: ledger %v, orders %v", e.ledger.recorded, e.orders.recorded)
	}
	if !reflect.DeepEqual(e.orders.heights, []uint64{11, 11}) {
		t.Fatalf("dispatcher told recorded heights %v", e.orders.heights)
	}
	if want := []taskReport{{taskID: a0.TaskID, height: 11}, {taskID: b0.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("tasks recorded = %v", e.tasks.recorded)
	}
	if want := []taskReport{{taskID: a1.TaskID, code: codeBalance}}; !reflect.DeepEqual(e.tasks.rejected, want) {
		t.Fatalf("tasks rejected = %v", e.tasks.rejected)
	}
	ticketOf := func(b *dispatcher.Bundle) [32]byte { return [32]byte(b.Entry.GetRecord().GetDispatchTicketHash()) }
	wantAttempts := []attemptReport{{a0.TaskID, ticketOf(a0), true}, {a1.TaskID, ticketOf(a1), false}, {b0.TaskID, ticketOf(b0), true}}
	if !reflect.DeepEqual(e.attempts.reports, wantAttempts) {
		t.Fatalf("attempt outcomes = %v, want %v", e.attempts.reports, wantAttempts)
	}
	if want := []orderKey{{a1.SessionID, 1}}; !reflect.DeepEqual(e.ledger.suspended, want) {
		t.Fatalf("ledger suspended = %v", e.ledger.suspended)
	}
	if s := e.orders.suspended; len(s) != 1 || s[0].session != a1.SessionID || s[0].from != 1 || !errors.Is(s[0].reason, dispatcher.ErrRecordRejected) {
		t.Fatalf("orders suspended = %v", s)
	}
	got := e.notices()
	if len(got) != 3 {
		t.Fatalf("%d notices", len(got))
	}
	for i, want := range []struct {
		ticket byte
		status taskv1.DispatchRecordStatusV1
		code   taskv1.DispatchRejectCodeV1
		height uint64
	}{
		{1, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED, 0, 11},
		{2, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED, codeBalance, 0},
		{3, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED, 0, 11},
	} {
		n := got[i].n
		if got[i].operator != worker || !bytes.Equal(n.GetDispatchTicketHash(), fill(want.ticket)) || n.GetStatus() != want.status ||
			n.GetRejectCode() != want.code || n.GetRecordedHeight() != want.height {
			t.Fatalf("notice %d = %v", i, n)
		}
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
}

// A refused sequence fails every later entry of the session, sent or not: each is RECORD_REJECTED
// with the code the chain gives an order past a gap, none is submitted again and their own later
// results change nothing.
func TestRejectionCascadesToLaterEntries(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 1, 1, 50))
	e.block(10)
	msg1, raw1 := e.lastSent()
	e.record(bundle(0xaa, 2, 2, 50), bundle(0xbb, 0, 3, 50))
	e.block(11)
	msg2, raw2 := e.lastSent()
	e.record(bundle(0xaa, 3, 4, 50))
	e.chain.execute(raw1, executed(t, msg1, 12, refused(codeBalance)))
	e.block(12)

	codes := map[string]taskv1.DispatchRejectCodeV1{}
	for _, r := range e.tasks.rejected {
		codes[r.taskID] = r.code
	}
	want := map[string]taskv1.DispatchRejectCodeV1{taskIDOf(0xaa, 1): codeBalance, taskIDOf(0xaa, 2): codeConsumed, taskIDOf(0xaa, 3): codeConsumed}
	if !reflect.DeepEqual(codes, want) || len(e.tasks.rejected) != 3 {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
	if len(e.ledger.suspended) != 1 || len(e.orders.suspended) != 1 || e.orders.suspended[0].from != 1 {
		t.Fatalf("suspended: ledger %v, orders %v", e.ledger.suspended, e.orders.suspended)
	}
	if n := len(e.notices()); n != 3 {
		t.Fatalf("%d notices", n)
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 2 {
		t.Fatalf("a cancelled entry was submitted: %d messages", len(msgs))
	}
	e.chain.execute(raw2, executed(t, msg2, 13, refused(codeConsumed), ok()))
	e.block(13)
	if len(e.tasks.rejected) != 3 || len(e.notices()) != 4 || len(e.ledger.recorded) != 1 {
		t.Fatalf("after the later result: rejected %d, notices %d, recorded %v", len(e.tasks.rejected), len(e.notices()), e.ledger.recorded)
	}
}

// Results whose object_id is not the key of the entry sent at that index are not attributed: each
// entry is checked with the dispatch record query, a recorded one is recorded, the others go out
// again with the same bytes.
func TestObjectIDMismatch(t *testing.T) {
	e := newEnv(t)
	a, b := bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50)
	e.record(a, b)
	e.block(10)
	msg, raw := e.lastSent()
	swapped := proto.Clone(msg).(*taskv1.MsgRecordDispatch)
	swapped.Entries[0], swapped.Entries[1] = swapped.Entries[1], swapped.Entries[0]
	e.chain.execute(raw, executed(t, swapped, 11, ok(), ok()))
	e.chain.records[orderKey{a.SessionID, 0}] = &taskv1.DispatchRecordState{DispatchTicketHash: fill(1), RecordedHeight: 11}
	e.block(12)
	if want := []orderKey{{a.SessionID, 0}}; !reflect.DeepEqual(e.ledger.recorded, want) {
		t.Fatalf("recorded = %v", e.ledger.recorded)
	}
	if want := []taskReport{{taskID: a.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("tasks recorded = %v", e.tasks.recorded)
	}
	again, _ := e.lastSent()
	if msgs, _ := e.tx.sent(); len(msgs) != 2 || !reflect.DeepEqual(entriesOf(again), []string{"bb/0"}) || !proto.Equal(again.Entries[0], msg.Entries[1]) {
		t.Fatalf("resubmitted %v", entriesOf(again))
	}
	if len(e.tasks.rejected) != 0 {
		t.Fatalf("rejected %v", e.tasks.rejected)
	}
}

// After a restart the stored transaction is checked on chain and broadcast again as the exact
// bytes stored; the dispatcher's Record of the same entry is the stored one. Once the chain shows
// the transaction can no longer land, the entry goes out in a new transaction with the same entry
// bytes.
func TestRestartReplaysTheSameBytes(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()

	e.open()
	e.record(b)
	e.tx.rebroadcast = []chaincli.TxResult{{}, {Code: 32, Codespace: "sdk", RawLog: "account sequence mismatch"}}
	e.block(11)
	if len(e.tx.resent) != 1 || !bytes.Equal(e.tx.resent[0], raw) {
		t.Fatalf("replayed %d txs", len(e.tx.resent))
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("re-signed after the restart: %d messages", len(msgs))
	}
	e.block(12)
	if len(e.tx.resent) != 1 {
		t.Fatal("rebroadcast before its wait")
	}
	e.block(13)
	if len(e.tx.resent) != 2 {
		t.Fatalf("not rebroadcast after its wait: %d", len(e.tx.resent))
	}
	msgs, raws := e.tx.sent()
	if len(msgs) != 2 || bytes.Equal(raws[1], raw) {
		t.Fatalf("lost tx not repacked: %d messages", len(msgs))
	}
	first, _ := proto.MarshalOptions{Deterministic: true}.Marshal(msg.Entries[0])
	second, _ := proto.MarshalOptions{Deterministic: true}.Marshal(msgs[1].Entries[0])
	if !bytes.Equal(first, second) {
		t.Fatal("the entry bytes changed")
	}
}

// Past its record deadline an entry the chain did not record is RECORD_LATE: its session is
// suspended and its later orders fail. An entry whose deadline is before the next block is not
// submitted. A record found by the query is recorded instead, and an unreadable chain decides
// nothing.
func TestDeadlinePassed(t *testing.T) {
	e := newEnv(t)
	a1, a2 := bundle(0xaa, 1, 1, 20), bundle(0xaa, 2, 2, 25)
	e.record(a1)
	e.block(10)
	e.record(a2, bundle(0xbb, 0, 3, 21), bundle(0xcc, 0, 4, 21))
	e.chain.records[orderKey{sessionHex(0xcc), 0}] = &taskv1.DispatchRecordState{DispatchTicketHash: fill(4), RecordedHeight: 21}
	e.block(21)
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("submitted a cancelled or late entry: %v", entriesOf(msgs[len(msgs)-1]))
	}
	want := []taskReport{{taskID: a1.TaskID, code: codeLate}, {taskID: a2.TaskID, code: codeConsumed}}
	if !reflect.DeepEqual(e.tasks.rejected, want) {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
	if want := []orderKey{{a1.SessionID, 1}}; !reflect.DeepEqual(e.ledger.suspended, want) {
		t.Fatalf("suspended = %v", e.ledger.suspended)
	}
	e.chain.recordErr = errUnreadable
	e.block(22)
	if len(e.tasks.rejected) != 2 || len(e.tasks.recorded) != 0 {
		t.Fatalf("decided on an unreadable chain: %v %v", e.tasks.rejected, e.tasks.recorded)
	}
	e.chain.recordErr = nil
	e.block(23)
	if want := []taskReport{{taskID: taskIDOf(0xcc, 0), height: 21}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("recorded = %v", e.tasks.recorded)
	}
	if len(e.tasks.rejected) != 3 || e.tasks.rejected[2].taskID != taskIDOf(0xbb, 0) {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
}

// A dispatch_recorded event of the entry's winner ticket records it without waiting for the
// transaction result, which then changes nothing; an event of another ticket is not this entry.
func TestReconcileViaEvent(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()
	e.r.HandleChainEvent(chaincli.ChainEvent{Height: 11, Typed: chaincli.DispatchRecorded{SessionID: b.SessionID, OrderSequence: 0, TicketHash: fill(9)}})
	if len(e.tasks.recorded) != 0 {
		t.Fatal("recorded by another ticket's event")
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Height: 11, Typed: chaincli.DispatchRecorded{SessionID: b.SessionID, OrderSequence: 0, TicketHash: fill(1)}})
	if want := []taskReport{{taskID: b.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) || len(e.ledger.recorded) != 1 {
		t.Fatalf("recorded = %v, ledger %v", e.tasks.recorded, e.ledger.recorded)
	}
	e.chain.execute(raw, executed(t, msg, 11, ok()))
	e.block(12)
	if len(e.tasks.recorded) != 1 || len(e.notices()) != 1 || len(e.outboxKeys()) != 0 {
		t.Fatalf("after the result: recorded %d, notices %d, outbox %v", len(e.tasks.recorded), len(e.notices()), e.outboxKeys())
	}
}

// A withdrawn entry is not submitted; one withdrawn after it was sent is dropped when refused,
// without suspending its session.
func TestWithdrawnEntries(t *testing.T) {
	e := newEnv(t)
	queued, sent := bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50)
	e.record(queued)
	e.r.Withdraw(context.Background(), queued.SessionID, 0, [32]byte(fill(1)))
	e.record(sent)
	e.block(10)
	msg, raw := e.lastSent()
	if !reflect.DeepEqual(entriesOf(msg), []string{"bb/0"}) {
		t.Fatalf("submitted %v", entriesOf(msg))
	}
	e.r.Withdraw(context.Background(), sent.SessionID, 0, [32]byte(fill(2)))
	e.chain.execute(raw, executed(t, msg, 11, refused(taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_BOUND_CHANGE_HEIGHT_MISMATCH)))
	e.block(11)
	if len(e.tasks.rejected) != 0 || len(e.ledger.suspended) != 0 || len(e.orders.suspended) != 0 || len(e.notices()) != 0 {
		t.Fatalf("a withdrawn entry failed its session: %v %v", e.tasks.rejected, e.ledger.suspended)
	}
	if len(e.outboxKeys()) != 0 {
		t.Fatalf("outbox keeps %v", e.outboxKeys())
	}
}

// SEQUENCE_CONSUMED while an earlier entry of the session is still unresolved is not final: the
// entry is held and submitted again once the earlier one is recorded.
func TestSequenceConsumedBehindAnUnresolvedEntryIsRetried(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(10)
	msg0, raw0 := e.lastSent()
	e.record(bundle(0xaa, 1, 2, 50))
	e.block(11)
	msg1, raw1 := e.lastSent()
	e.chain.execute(raw1, executed(t, msg1, 12, refused(codeConsumed)))
	e.block(12)
	if len(e.tasks.rejected) != 0 || len(e.ledger.suspended) != 0 {
		t.Fatalf("held entry failed: %v", e.tasks.rejected)
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 2 {
		t.Fatal("held entry resubmitted before the earlier one resolved")
	}
	e.chain.execute(raw0, executed(t, msg0, 13, ok()))
	e.block(13)
	again, _ := e.lastSent()
	if msgs, _ := e.tx.sent(); len(msgs) != 3 || !reflect.DeepEqual(entriesOf(again), []string{"aa/1"}) {
		t.Fatalf("held entry not resubmitted: %v", entriesOf(again))
	}
}

// A transaction the chain executed and refused as a whole leaves its entries unresolved: they go
// out again, and the compensation account is read again first.
func TestFailedTransactionIsRetried(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(10)
	_, raw := e.lastSent()
	reads := e.account.reads
	e.chain.execute(raw, chaincli.TxResult{Height: 11, Code: 7, Codespace: "task", RawLog: "builder compensation below min"})
	e.block(11)
	if msgs, _ := e.tx.sent(); len(msgs) != 2 {
		t.Fatalf("failed tx not retried: %d messages", len(msgs))
	}
	if e.account.reads == reads {
		t.Fatal("compensation account not read again")
	}
	if len(e.tasks.rejected) != 0 {
		t.Fatalf("rejected %v", e.tasks.rejected)
	}
	// A broadcast whose outcome is unknown keeps its transaction; one refused before it was sent
	// does not.
	e.record(bundle(0xbb, 0, 2, 50))
	e.tx.next = []error{&coordinator.SubmissionError{Phase: coordinator.SubmissionBroadcast, Err: errUnreadable}}
	e.block(12)
	e.record(bundle(0xcc, 0, 3, 50))
	e.tx.next = []error{&coordinator.SubmissionError{Phase: coordinator.SubmissionBroadcast, Definitive: true, Err: errors.New("rejected by CheckTx")}}
	e.block(13)
	msgs, _ := e.tx.sent()
	if len(msgs) != 4 || !reflect.DeepEqual(entriesOf(msgs[3]), []string{"cc/0"}) {
		t.Fatalf("messages = %d", len(msgs))
	}
	e.block(14)
	msgs, _ = e.tx.sent()
	if !reflect.DeepEqual(entriesOf(msgs[len(msgs)-1]), []string{"cc/0"}) || len(msgs) != 5 {
		t.Fatalf("refused tx's entry not resubmitted: %v", entriesOf(msgs[len(msgs)-1]))
	}
}

// Started, the Recorder works at every NewBlock event; the dispatcher must be wired first.
func TestBlocksDriveTheRecorder(t *testing.T) {
	e := newEnv(t)
	idle, err := New(Config{
		ChainID: testChainID, Builder: builder, Signer: e.signer, Store: e.store, Ledger: e.ledger, Chain: e.chain, Tx: e.tx,
		Tasks: e.tasks, Attempts: e.attempts, Streams: e.streams, Gate: e.gate, GasBase: testGasBase, GasPerEntry: testGasPerEntry,
	}, e.params)
	if err != nil {
		t.Fatal(err)
	}
	if err := idle.Start(context.Background()); err == nil {
		t.Fatal("started without the dispatcher")
	}
	if err := e.r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.r.Stop(context.Background()) })
	e.record(bundle(0xaa, 0, 1, 50))
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 10})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if msgs, _ := e.tx.sent(); len(msgs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no record sent at the block")
		}
		time.Sleep(time.Millisecond)
	}
}

// A Withdraw that arrives before the Record of its winner ticket drops that Record.
func TestWithdrawBeforeRecord(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.r.Withdraw(context.Background(), b.SessionID, 0, [32]byte(fill(1)))
	e.record(b, bundle(0xbb, 0, 2, 50))
	e.block(10)
	if msg, _ := e.lastSent(); !reflect.DeepEqual(entriesOf(msg), []string{"bb/0"}) {
		t.Fatalf("submitted %v", entriesOf(msg))
	}
	// The same order accepted again with another ticket is recorded.
	e.record(bundle(0xaa, 0, 3, 50))
	e.block(11)
	if msg, _ := e.lastSent(); !reflect.DeepEqual(entriesOf(msg), []string{"aa/0"}) {
		t.Fatalf("submitted %v", entriesOf(msg))
	}
}

// A session's first order has sequence 0: past its deadline it is resolved by the dispatch record
// query like any other.
func TestSequenceZeroPastTheDeadlineIsResolvedByQuery(t *testing.T) {
	e := newEnv(t)
	recorded, late := bundle(0xaa, 0, 1, 20), bundle(0xbb, 0, 2, 20)
	e.record(recorded, late)
	e.block(10)
	e.chain.records[orderKey{recorded.SessionID, 0}] = &taskv1.DispatchRecordState{DispatchTicketHash: fill(1), RecordedHeight: 12}
	e.block(21)
	if want := []taskReport{{taskID: recorded.TaskID, height: 12}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("recorded = %v", e.tasks.recorded)
	}
	if want := []taskReport{{taskID: late.TaskID, code: codeLate}}; !reflect.DeepEqual(e.tasks.rejected, want) {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
}

// Results whose batch_digest does not commit to them are not attributed, although each echoes its
// entry's key: every entry is checked with the dispatch record query instead.
func TestBatchDigestMismatchIsCheckedOnChain(t *testing.T) {
	e := newEnv(t)
	a, b := bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50)
	e.record(a, b)
	e.block(10)
	msg, raw := e.lastSent()
	res := executed(t, msg, 11, ok(), refused(codeBalance))
	resp := &taskv1.MsgRecordDispatchResponse{}
	if err := chaincli.DecodeMsgResponse(res, 0, resp); err != nil {
		t.Fatal(err)
	}
	resp.BatchDigest = fill(0xee)
	e.chain.execute(raw, txWith(t, 11, resp))
	e.chain.records[orderKey{a.SessionID, 0}] = &taskv1.DispatchRecordState{DispatchTicketHash: fill(1), RecordedHeight: 11}
	e.block(12)
	if want := []taskReport{{taskID: a.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("recorded = %v", e.tasks.recorded)
	}
	if len(e.tasks.rejected) != 0 {
		t.Fatalf("a result under a mismatched batch_digest was taken: rejected %v", e.tasks.rejected)
	}
	if e.chain.queries == 0 {
		t.Fatal("entries were not checked on chain")
	}
	again, _ := e.lastSent()
	if !reflect.DeepEqual(entriesOf(again), []string{"bb/0"}) {
		t.Fatalf("resubmitted %v", entriesOf(again))
	}
}
