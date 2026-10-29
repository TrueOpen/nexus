package recorder

import (
	"errors"
	"reflect"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
)

func four() []string { return []string{"aa/0", "bb/0", "cc/0", "dd/0"} }

func (e *env) recordFour() {
	e.record(bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50), bundle(0xcc, 0, 3, 50), bundle(0xdd, 0, 4, 50))
}

func (e *env) fail(raw []byte, height int64, codespace string, code uint32) {
	e.chain.execute(raw, chaincli.TxResult{Height: height, Code: code, Codespace: codespace, RawLog: "refused"})
}

// A record transaction gets gas for its entries: base plus a share per entry.
func TestRecordGasFollowsTheEntryCount(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	e.block(10)
	if got := e.tx.gas; !reflect.DeepEqual(got, []uint64{testGasBase + 4*testGasPerEntry}) {
		t.Fatalf("gas = %v", got)
	}
}

// Out of gas is deterministic for a batch that size: its entries go out again in halves with
// twice the gas share, and the limits come back as transactions succeed.
func TestOutOfGasHalvesTheBatch(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	e.block(10)
	_, raw := e.lastSent()
	e.fail(raw, 11, "sdk", 11)
	e.block(11)
	msgs, raws := e.tx.sent()
	if len(msgs) != 3 || !reflect.DeepEqual(entriesOf(msgs[1]), four()[:2]) || !reflect.DeepEqual(entriesOf(msgs[2]), four()[2:]) {
		t.Fatalf("resent %d messages", len(msgs))
	}
	if e.tx.gas[1] != 2*(testGasBase+2*testGasPerEntry) {
		t.Fatalf("gas after out of gas = %d", e.tx.gas[1])
	}
	e.chain.execute(raws[1], executed(t, msgs[1], 12, ok(), ok()))
	e.chain.execute(raws[2], executed(t, msgs[2], 12, ok(), ok()))
	e.block(12)
	e.record(bundle(0xee, 0, 5, 50), bundle(0xef, 0, 6, 50), bundle(0xf0, 0, 7, 50), bundle(0xf1, 0, 8, 50))
	e.block(13)
	msgs, _ = e.tx.sent()
	if len(msgs) != 4 || len(msgs[3].GetEntries()) != 4 || e.tx.gas[3] != testGasBase+4*testGasPerEntry {
		t.Fatalf("limits not restored: %d messages, last of %d entries, gas %d", len(msgs), len(msgs[len(msgs)-1].GetEntries()), e.tx.gas[len(e.tx.gas)-1])
	}
}

// The same unexplained refusal three times running halves the batch; down to one entry, it stops
// the records until an event of this Builder's key (or a later retry) and is reported.
func TestRepeatedRefusalHalvesThenStops(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 500), bundle(0xbb, 0, 2, 500))
	height := uint64(10)
	e.block(height)
	refuse := func() {
		t.Helper()
		msgs, raws := e.tx.sent()
		n := len(msgs)
		for i := n - 1; i >= 0 && i >= n-2; i-- {
			if _, done := e.chain.txs[sha(raws[i])]; !done {
				e.fail(raws[i], int64(height+1), "task", 1107)
			}
		}
		height++
		e.block(height)
	}
	refuse()
	refuse()
	if msgs, _ := e.tx.sent(); len(msgs) != 3 || len(msgs[2].GetEntries()) != 2 {
		t.Fatalf("before the third refusal: %d messages", len(msgs))
	}
	refuse()
	msgs, _ := e.tx.sent()
	if len(msgs) != 5 || len(msgs[3].GetEntries()) != 1 || len(msgs[4].GetEntries()) != 1 {
		t.Fatalf("after three refusals: %d messages", len(msgs))
	}
	refuse()
	refuse()
	refuse()
	sent := len(e.tx.msgs)
	e.block(height + 1)
	e.block(height + 2)
	if len(e.tx.msgs) != sent {
		t.Fatal("records sent while stopped")
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.ServiceKeyRotated{ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, Operator: builder}})
	e.block(height + 3)
	if len(e.tx.msgs) == sent {
		t.Fatal("records not resumed after a key event of this Builder")
	}
	if len(e.tasks.rejected) != 0 {
		t.Fatalf("rejected %v", e.tasks.rejected)
	}
}

// An unauthorized or unfunded submitter is not fixed by sending again: records stop at once and
// are retried after fatalRetryBlocks, or on a key event of this Builder; a refusal at CheckTx
// counts the same.
func TestFatalRefusalStopsRecords(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 500))
	e.block(10)
	_, raw := e.lastSent()
	e.fail(raw, 11, "sdk", 4)
	e.block(11)
	e.block(12)
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("resent after unauthorized: %d", len(msgs))
	}
	e.block(11 + fatalRetryBlocks)
	if msgs, _ := e.tx.sent(); len(msgs) != 2 {
		t.Fatalf("not retried after %d blocks", fatalRetryBlocks)
	}
	// Refused at CheckTx with insufficient funds.
	e.tx.next = []error{&coordinator.SubmissionError{Phase: coordinator.SubmissionBroadcast, Definitive: true,
		Result: chaincli.TxResult{Code: 5, Codespace: "sdk"}, Err: errors.New("insufficient funds")}}
	e.record(bundle(0xbb, 0, 2, 500))
	_, raw = e.lastSent()
	e.chain.execute(raw, executed(t, e.tx.msgs[1], int64(12+fatalRetryBlocks), ok()))
	e.block(12 + fatalRetryBlocks)
	sent := len(e.tx.msgs)
	e.block(13 + fatalRetryBlocks)
	if len(e.tx.msgs) != sent {
		t.Fatal("resent after a fatal CheckTx refusal")
	}
}

// badDigest is the executed result of msg with every entry applied under a batch_digest that does
// not commit to the results.
func badDigest(t *testing.T, msg *taskv1.MsgRecordDispatch, height int64) chaincli.TxResult {
	t.Helper()
	results := make([]result, len(msg.GetEntries()))
	for i := range results {
		results[i] = ok()
	}
	res := executed(t, msg, height, results...)
	resp := &taskv1.MsgRecordDispatchResponse{}
	if err := chaincli.DecodeMsgResponse(res, 0, resp); err != nil {
		t.Fatal(err)
	}
	resp.BatchDigest = fill(0xee)
	return txWith(t, height, resp)
}

// Results that keep failing their batch_digest count as refusals of the same kind: they do not
// send a transaction every block until the record deadline, but halve the batch and then stop the
// records like any other repeated refusal.
func TestRepeatedUnattributableResultsStopRecords(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 500))
	height := uint64(10)
	e.block(height)
	executedCount := 0
	for i := 0; i < 2*sameRefusalLimit; i++ {
		msgs, raws := e.tx.sent()
		if len(msgs) > executedCount {
			e.chain.execute(raws[len(raws)-1], badDigest(t, msgs[len(msgs)-1], int64(height+1)))
			executedCount = len(msgs)
		}
		height++
		e.block(height)
	}
	if msgs, _ := e.tx.sent(); len(msgs) != sameRefusalLimit {
		t.Fatalf("%d record transactions sent, want records stopped after %d unattributable results", len(msgs), sameRefusalLimit)
	}
}

// An entry checked on chain because its results could not be attributed, whose order the chain
// recorded with another ticket of this Builder, is resolved like a CONFLICT with that record: the
// order is recorded and the entry is not sent again.
func TestUnattributableResultOfAnOrderRecordedWithAnotherOwnTicket(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.records[orderKey{b.SessionID, 0}] = &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(7), RecordedHeight: 9}
	e.chain.execute(raw, badDigest(t, msg, 11))
	e.block(11)
	e.block(12)
	if want := []taskReport{{taskID: b.TaskID, height: 9}}; !reflect.DeepEqual(e.tasks.recorded, want) || len(e.ledger.recorded) != 1 {
		t.Fatalf("recorded: tasks %v, ledger %v", e.tasks.recorded, e.ledger.recorded)
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("entry sent again: %d messages", len(msgs))
	}
}
