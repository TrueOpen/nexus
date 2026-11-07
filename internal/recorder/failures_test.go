package recorder

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatcher"
)

func four() []string { return []string{"aa/0", "bb/0", "cc/0", "dd/0"} }

func (e *env) recordFour() {
	e.record(bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50), bundle(0xcc, 0, 3, 50), bundle(0xdd, 0, 4, 50))
}

func (e *env) fail(raw []byte, height int64, codespace string, code uint32) {
	e.chain.execute(raw, chaincli.TxResult{Height: height, Code: code, Codespace: codespace, RawLog: "refused"})
}

// recordGas is the gas the test formula gives msg.
func recordGas(msg *taskv1.MsgRecordDispatch) uint64 {
	return testGasBase + testGasPerEntry*uint64(len(msg.GetEntries())) + testGasPerByte*uint64(proto.Size(msg))
}

// A record transaction gets gas for its entries and its bytes: base, a share per entry and a
// share per encoded byte of the message.
func TestRecordGasFollowsTheEntryCountAndSize(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	e.block(10)
	msg, _ := e.lastSent()
	if got := e.tx.gas; !reflect.DeepEqual(got, []uint64{recordGas(msg)}) || got[0] <= testGasBase+4*testGasPerEntry {
		t.Fatalf("gas = %v, want %d", got, recordGas(msg))
	}
}

// realisticBundle is a dispatch entry whose one-entry record message is about the size of a
// normal one on chain (some 2300 bytes).
func realisticBundle(t *testing.T) *dispatcher.Bundle {
	t.Helper()
	b := bundle(0xaa, 0, 1, 50)
	b.Entry.SignedOrder.UserSignature = bytes.Repeat([]byte{0x01}, 65)
	entry := &taskv1.DispatchRecordEntryV1{Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: b.Entry}}
	pad := 2300 - proto.Size(&taskv1.MsgRecordDispatch{SubmitterAddress: builder, Entries: []*taskv1.DispatchRecordEntryV1{entry}})
	if pad <= 0 {
		t.Fatalf("test entry already above the realistic size")
	}
	b.Entry.SignedOrder.Order.ModelId = bytes.Repeat([]byte{0x6d}, pad)
	return b
}

// With the default gas settings a one-entry record of a realistic size gets enough gas the first
// time: on chain such a record uses some 556k gas, most of it per stored byte.
func TestDefaultRecordGasCoversARealisticEntry(t *testing.T) {
	e := newEnv(t)
	d := config.Load().Dispatch
	e.gasBase, e.gasPerEntry, e.gasPerByte = d.RecordGasBase, d.RecordGasPerEntry, d.RecordGasPerByte
	e.open()
	e.record(realisticBundle(t))
	e.block(10)
	msg, _ := e.lastSent()
	if size := proto.Size(msg); size < 2250 || size > 2400 {
		t.Fatalf("record message of %d bytes, want about 2300", size)
	}
	if gas := e.tx.gas[0]; gas < 650_000 {
		t.Fatalf("gas = %d for a realistic one-entry record, want at least 650000", gas)
	}
}

// Out of gas asks for more gas, not a smaller batch: the same entries go out again together with
// twice the gas, and the gas comes back as transactions succeed.
func TestOutOfGasRaisesTheGasOfTheSameBatch(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	e.block(10)
	_, raw := e.lastSent()
	e.fail(raw, 11, "sdk", 11)
	e.block(11)
	msgs, raws := e.tx.sent()
	if len(msgs) != 2 || !reflect.DeepEqual(entriesOf(msgs[1]), four()) {
		t.Fatalf("resent %d messages, last %v", len(msgs), entriesOf(msgs[len(msgs)-1]))
	}
	if e.tx.gas[1] != 2*recordGas(msgs[1]) {
		t.Fatalf("gas after out of gas = %d, want %d", e.tx.gas[1], 2*recordGas(msgs[1]))
	}
	e.chain.execute(raws[1], executed(t, msgs[1], 12, ok(), ok(), ok(), ok()))
	e.block(12)
	e.record(bundle(0xee, 0, 5, 50), bundle(0xef, 0, 6, 50), bundle(0xf0, 0, 7, 50), bundle(0xf1, 0, 8, 50))
	e.block(13)
	msgs, _ = e.tx.sent()
	if len(msgs) != 3 || len(msgs[2].GetEntries()) != 4 || e.tx.gas[2] != recordGas(msgs[2]) {
		t.Fatalf("limits not restored: %d messages, last of %d entries, gas %d", len(msgs), len(msgs[len(msgs)-1].GetEntries()), e.tx.gas[len(e.tx.gas)-1])
	}
}

// Only a batch still out of gas at the highest gas factor is halved.
func TestOutOfGasAtTheHighestFactorHalvesTheBatch(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	height := uint64(10)
	e.block(height)
	for factor := uint64(2); factor <= maxGasFactor; factor *= 2 {
		_, raw := e.lastSent()
		e.fail(raw, int64(height+1), "sdk", 11)
		height++
		e.block(height)
		msg, _ := e.lastSent()
		if len(msg.GetEntries()) != 4 || e.tx.gas[len(e.tx.gas)-1] != factor*recordGas(msg) {
			t.Fatalf("factor %d: batch of %d entries with gas %d", factor, len(msg.GetEntries()), e.tx.gas[len(e.tx.gas)-1])
		}
	}
	_, raw := e.lastSent()
	e.fail(raw, int64(height+1), "sdk", 11)
	e.block(height + 1)
	msgs, _ := e.tx.sent()
	n := len(msgs)
	if !reflect.DeepEqual(entriesOf(msgs[n-2]), four()[:2]) || !reflect.DeepEqual(entriesOf(msgs[n-1]), four()[2:]) ||
		e.tx.gas[n-1] != maxGasFactor*recordGas(msgs[n-1]) {
		t.Fatalf("at the highest factor: %v then %v, gas %d", entriesOf(msgs[n-2]), entriesOf(msgs[n-1]), e.tx.gas[n-1])
	}
}

// The raised gas and the lowered batch come back also when the chain's dispatch_recorded event
// resolves the entries of the transaction that carried them before its result is read (the
// transaction then never gets a result read).
func TestSizingComesBackWhenTheRecordedEventResolvesTheEntries(t *testing.T) {
	e := newEnv(t)
	e.recordFour()
	height := uint64(10)
	e.block(height)
	// Out of gas up to the highest factor and once more: the batch is halved too.
	for i := 0; i < 4; i++ {
		msgs, raws := e.tx.sent()
		for j := len(msgs) - 1; j >= 0; j-- {
			if _, done := e.chain.txs[sha(raws[j])]; !done {
				e.fail(raws[j], int64(height+1), "sdk", 11)
			}
		}
		height++
		e.block(height)
	}
	if max, factor := e.r.limits(e.params.MaxEntries); max != 2 || factor != maxGasFactor {
		t.Fatalf("before the events: max entries %d, gas factor %d", max, factor)
	}
	// The chain records every entry; its events come before the next block reads the results.
	for _, b := range []*dispatcher.Bundle{bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50), bundle(0xcc, 0, 3, 50), bundle(0xdd, 0, 4, 50)} {
		e.r.HandleChainEvent(chaincli.ChainEvent{Height: int64(height + 1), Typed: chaincli.DispatchRecorded{
			SessionID: b.SessionID, OrderSequence: b.Sequence, TicketHash: b.Entry.GetRecord().GetDispatchTicketHash()}})
	}
	if len(e.tasks.recorded) != 4 {
		t.Fatalf("recorded %d entries by event", len(e.tasks.recorded))
	}
	// Each of the two transactions counts once: 8 -> 2, cap 2 -> 8.
	if max, factor := e.r.limits(e.params.MaxEntries); max != 8 || factor != 2 {
		t.Fatalf("after the events: max entries %d, gas factor %d", max, factor)
	}
	// Their results, read at the next block, do not count again.
	msgs, raws := e.tx.sent()
	n := len(msgs)
	e.chain.execute(raws[n-2], executed(t, msgs[n-2], int64(height+1), ok(), ok()))
	e.chain.execute(raws[n-1], executed(t, msgs[n-1], int64(height+1), ok(), ok()))
	e.block(height + 1)
	if max, factor := e.r.limits(e.params.MaxEntries); max != 8 || factor != 2 {
		t.Fatalf("after the results: max entries %d, gas factor %d", max, factor)
	}
}

// A single-entry record out of gas that the event resolves leaves the next record at the normal
// gas, the case seen on chain: the retry with doubled gas lands, its event comes first.
func TestOutOfGasRetryResolvedByEventRestoresNormalGas(t *testing.T) {
	e := newEnv(t)
	a := bundle(0xaa, 0, 1, 50)
	e.record(a)
	e.block(10)
	_, raw := e.lastSent()
	e.fail(raw, 11, "sdk", 11)
	e.block(11)
	msg, _ := e.lastSent()
	if e.tx.gas[1] != 2*recordGas(msg) {
		t.Fatalf("retry gas = %d, want %d", e.tx.gas[1], 2*recordGas(msg))
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Height: 12, Typed: chaincli.DispatchRecorded{
		SessionID: a.SessionID, OrderSequence: a.Sequence, TicketHash: a.Entry.GetRecord().GetDispatchTicketHash()}})
	e.block(12)
	e.record(bundle(0xbb, 0, 2, 50), bundle(0xcc, 0, 3, 50))
	e.block(13)
	msg, _ = e.lastSent()
	if len(msg.GetEntries()) != 2 || e.tx.gas[len(e.tx.gas)-1] != recordGas(msg) {
		t.Fatalf("after the event: batch of %d entries, gas %d, want %d", len(msg.GetEntries()), e.tx.gas[len(e.tx.gas)-1], recordGas(msg))
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

// Results that cannot be attributed while the chain check finds every entry recorded with its own
// ticket (the chain executed the batch; only the result encoding drifted) are not a refusal: they
// never halve the batch or stop the records.
func TestUnattributableResultsOfRecordedEntriesAreNoRefusal(t *testing.T) {
	e := newEnv(t)
	height := uint64(10)
	for i := 0; i < 2*sameRefusalLimit; i++ {
		a, b := bundle(byte(0x10+2*i), 0, 1, 500), bundle(byte(0x11+2*i), 0, 1, 500)
		e.record(a, b)
		e.block(height)
		msgs, raws := e.tx.sent()
		msg := msgs[len(msgs)-1]
		if len(msg.GetEntries()) != 2 {
			t.Fatalf("round %d: batch of %d entries, want 2 (no halving)", i, len(msg.GetEntries()))
		}
		for _, bd := range []*dispatcher.Bundle{a, b} {
			e.chain.records[orderKey{bd.SessionID, 0}] = &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(1), RecordedHeight: height + 1}
		}
		e.chain.execute(raws[len(raws)-1], badDigest(t, msg, int64(height+1)))
		height++
		e.block(height)
	}
	if len(e.tasks.recorded) != 4*sameRefusalLimit {
		t.Fatalf("recorded %d entries, want %d", len(e.tasks.recorded), 4*sameRefusalLimit)
	}
}
