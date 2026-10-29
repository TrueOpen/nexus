package recorder

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// testBoundChange is the bound_change_height the test takeover entries are registered under.
const testBoundChange = 40

var (
	codeTakeoverConsumed = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_SEQUENCE_CONSUMED
	codeTakeoverPending  = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING
)

// takeover is the takeover entry of order seq of session, valid until deadline.
func takeover(t *testing.T, session byte, seq, deadline uint64) *TakeoverBundle {
	t.Helper()
	order := wirefixture.TaskOrderV3(t, wirefixture.Load(t, "task/task_order_v3.json").Vector(t, "task_order_v3_core", 0))
	order.SessionId, order.OrderSequence = fill(session), seq
	return &TakeoverBundle{
		SessionID: sessionHex(session), Sequence: seq, TaskID: taskIDOf(session, seq), BoundChangeHeight: testBoundChange,
		Deadline: deadline, Entry: &taskv1.TakeoverEntryV1{SignedOrder: &taskv1.SignedOrderV2{Order: order, UserSignature: []byte{1}}},
	}
}

type takeoverReport struct {
	session   string
	seq       uint64
	height    uint64
	code      taskv1.DispatchRejectCodeV1
	lapsed    bool
	unsettled bool
}

type fakeTakeovers struct {
	mu      sync.Mutex
	reports []takeoverReport
}

func (f *fakeTakeovers) TakeoverRegistered(sessionID string, seq, height uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, takeoverReport{session: sessionID, seq: seq, height: height})
}

func (f *fakeTakeovers) TakeoverRefused(sessionID string, seq uint64, code taskv1.DispatchRejectCodeV1) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, takeoverReport{session: sessionID, seq: seq, code: code})
}

func (f *fakeTakeovers) TakeoverLapsed(sessionID string, seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, takeoverReport{session: sessionID, seq: seq, lapsed: true})
}

func (f *fakeTakeovers) TakeoverUnsettled(sessionID string, seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, takeoverReport{session: sessionID, seq: seq, unsettled: true})
}

func (f *fakeTakeovers) got() []takeoverReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]takeoverReport(nil), f.reports...)
}

func (e *env) takeovers() *fakeTakeovers {
	f := &fakeTakeovers{}
	e.r.SetTakeovers(f)
	return f
}

func (e *env) recordTakeover(b *TakeoverBundle) {
	e.t.Helper()
	if err := e.r.RecordTakeover(context.Background(), b); err != nil {
		e.t.Fatal(err)
	}
}

// A takeover entry goes out with the next block's record transaction, sorted with the dispatch
// entries by (session_id, order_sequence), as the takeover oneof carrying the signed order; the
// same takeover again is the same entry.
func TestTakeoverEntryIsPackedWithTheDispatchEntries(t *testing.T) {
	e := newEnv(t)
	e.takeovers()
	tk := takeover(t, 0xbb, 3, 50)
	e.record(bundle(0xcc, 0, 1, 50), bundle(0xaa, 0, 2, 50))
	e.recordTakeover(tk)
	e.recordTakeover(takeover(t, 0xbb, 3, 50))
	e.block(10)
	msg, _ := e.lastSent()
	if got := entriesOf(msg); !reflect.DeepEqual(got, []string{"aa/0", "bb/3T", "cc/0"}) {
		t.Fatalf("packed %v", got)
	}
	if !proto.Equal(msg.GetEntries()[1].GetTakeover(), tk.Entry) {
		t.Fatalf("takeover entry = %v", msg.GetEntries()[1])
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
}

// The result of a takeover entry, keyed by its takeover_entry_digest, goes to the takeovers:
// registered (also as an exact replay) or refused with its code. A refused takeover suspends
// nothing, fails no dispatch entry and sends no notice.
func TestTakeoverResults(t *testing.T) {
	e := newEnv(t)
	tk := e.takeovers()
	a0 := bundle(0xaa, 0, 1, 50)
	e.record(a0)
	e.recordTakeover(takeover(t, 0xaa, 1, 50))
	e.recordTakeover(takeover(t, 0xbb, 4, 50))
	e.recordTakeover(takeover(t, 0xcc, 2, 50))
	e.block(10)
	msg, raw := e.lastSent()
	if got := entriesOf(msg); !reflect.DeepEqual(got, []string{"aa/0", "aa/1T", "bb/4T", "cc/2T"}) {
		t.Fatalf("packed %v", got)
	}
	e.chain.execute(raw, executed(t, msg, 11, ok(), refused(codeTakeoverConsumed), ok(), result{status: noop}))
	e.block(11)
	want := []takeoverReport{
		{session: sessionHex(0xaa), seq: 1, code: codeTakeoverConsumed},
		{session: sessionHex(0xbb), seq: 4, height: 11},
		{session: sessionHex(0xcc), seq: 2, height: 11},
	}
	if got := tk.got(); !reflect.DeepEqual(got, want) {
		t.Fatalf("takeover reports = %v, want %v", got, want)
	}
	if len(e.ledger.suspended) != 0 || len(e.orders.suspended) != 0 || len(e.tasks.rejected) != 0 {
		t.Fatalf("a takeover refusal suspended: ledger %v, orders %v, tasks %v", e.ledger.suspended, e.orders.suspended, e.tasks.rejected)
	}
	if n := e.notices(); len(n) != 1 || !bytes.Equal(n[0].n.GetDispatchTicketHash(), fill(1)) {
		t.Fatalf("notices = %v", n)
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
	// Another takeover of the session may be pending.
	e.recordTakeover(takeover(t, 0xdd, 0, 50))
	e.block(12)
	msg, raw = e.lastSent()
	e.chain.execute(raw, executed(t, msg, 13, refused(codeTakeoverPending)))
	e.block(13)
	if got := tk.got(); got[len(got)-1] != (takeoverReport{session: sessionHex(0xdd), code: codeTakeoverPending}) {
		t.Fatalf("last report = %v", got[len(got)-1])
	}
}

// A takeover entry is not sent once its order would be expired at the next block, and one still
// unresolved past its deadline lapses: the takeovers read the session to learn what happened. No
// dispatch record is queried for it.
func TestTakeoverEntryLapsesAtItsDeadline(t *testing.T) {
	e := newEnv(t)
	tk := e.takeovers()
	e.recordTakeover(takeover(t, 0xaa, 1, 12))
	e.block(12)
	if msgs, _ := e.tx.sent(); len(msgs) != 0 {
		t.Fatalf("an entry at its deadline was sent: %v", msgs)
	}
	e.block(13)
	if got := tk.got(); !reflect.DeepEqual(got, []takeoverReport{{session: sessionHex(0xaa), seq: 1, lapsed: true}}) {
		t.Fatalf("reports = %v", got)
	}
	if e.chain.queries != 0 {
		t.Fatalf("%d dispatch record queries", e.chain.queries)
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
}

// A takeover entry survives a restart and goes out as stored.
func TestTakeoverEntrySurvivesARestart(t *testing.T) {
	e := newEnv(t)
	tk := takeover(t, 0xaa, 1, 50)
	e.recordTakeover(tk)
	e.open()
	reports := e.takeovers()
	e.block(10)
	msg, raw := e.lastSent()
	if !proto.Equal(msg.GetEntries()[0].GetTakeover(), tk.Entry) {
		t.Fatalf("sent %v", msg)
	}
	e.chain.execute(raw, executed(t, msg, 11, ok()))
	e.block(11)
	if got := reports.got(); !reflect.DeepEqual(got, []takeoverReport{{session: sessionHex(0xaa), seq: 1, height: 11}}) {
		t.Fatalf("reports = %v", got)
	}
}

// A takeover result whose object_id is not the entry's key (the chain keyed it under a newer
// bound_change_height) is not attributed: the entry is dropped and the takeovers settle it with
// the chain. The dispatch entries of the same transaction keep their own results.
func TestTakeoverKeyMismatchKeepsTheOtherResults(t *testing.T) {
	e := newEnv(t)
	tk := e.takeovers()
	a0 := bundle(0xaa, 0, 1, 50)
	e.record(a0)
	e.recordTakeover(takeover(t, 0xbb, 1, 50))
	e.block(10)
	msg, raw := e.lastSent()
	res := executed(t, msg, 11, ok(), ok())
	resp := &taskv1.MsgRecordDispatchResponse{}
	if err := chaincli.DecodeMsgResponse(res, 0, resp); err != nil {
		t.Fatal(err)
	}
	resp.Results[1].ObjectId = fill(9)
	digest := chaincli.RecordDispatchBatchDigest(testChainID, resp.GetResults())
	resp.BatchDigest = digest[:]
	e.chain.execute(raw, txWith(t, 11, resp))
	e.block(11)
	if got := tk.got(); !reflect.DeepEqual(got, []takeoverReport{{session: sessionHex(0xbb), seq: 1, unsettled: true}}) {
		t.Fatalf("reports = %v", got)
	}
	if want := []taskReport{{taskID: a0.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("tasks recorded = %v", e.tasks.recorded)
	}
	if e.chain.queries != 0 {
		t.Fatalf("%d record queries", e.chain.queries)
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
	// Results that cannot be attributed at all: the takeover is settled with the chain as well.
	e.recordTakeover(takeover(t, 0xcc, 1, 50))
	e.block(12)
	_, raw = e.lastSent()
	e.chain.execute(raw, txWith(t, 13, &taskv1.MsgRecordDispatchResponse{}))
	e.block(13)
	if got := tk.got(); got[len(got)-1] != (takeoverReport{session: sessionHex(0xcc), seq: 1, unsettled: true}) {
		t.Fatalf("reports = %v", got)
	}
}

// A withdrawn takeover entry is not sent; one already sent has its result ignored.
func TestWithdrawTakeover(t *testing.T) {
	e := newEnv(t)
	tk := e.takeovers()
	e.recordTakeover(takeover(t, 0xaa, 1, 50))
	e.r.WithdrawTakeover(context.Background(), sessionHex(0xaa), 1)
	e.block(10)
	if msgs, _ := e.tx.sent(); len(msgs) != 0 {
		t.Fatalf("a withdrawn entry was sent: %v", msgs)
	}
	e.recordTakeover(takeover(t, 0xbb, 1, 50))
	e.block(11)
	msg, raw := e.lastSent()
	e.r.WithdrawTakeover(context.Background(), sessionHex(0xbb), 1)
	e.chain.execute(raw, executed(t, msg, 12, refused(codeTakeoverPending)))
	e.block(12)
	if got := tk.got(); len(got) != 0 {
		t.Fatalf("reports = %v", got)
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
}

// The takeover key is the candidate's (this Builder's operator address) takeover_entry_digest.
func TestTakeoverEntryKey(t *testing.T) {
	e := newEnv(t)
	tk := takeover(t, 0xaa, 1, 50)
	e.recordTakeover(tk)
	want, err := chaincli.TakeoverEntryObjectID(testChainID, builder, tk.Entry, testBoundChange)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.r.entries[hexID(want)]; !ok {
		t.Fatalf("outbox keys %v", e.r.entries)
	}
}

func hexID(id [32]byte) string { return hex.EncodeToString(id[:]) }

// A withdrawn takeover entry whose transaction is refused as a whole is not sent again: it is
// dropped when the transaction is.
func TestWithdrawnTakeoverIsNotSentAfterARequeue(t *testing.T) {
	e := newEnv(t)
	tk := e.takeovers()
	e.recordTakeover(takeover(t, 0xaa, 1, 50))
	e.block(10)
	_, raw := e.lastSent()
	e.r.WithdrawTakeover(context.Background(), sessionHex(0xaa), 1)
	e.chain.execute(raw, chaincli.TxResult{Height: 11, Code: 5, Codespace: "task"})
	e.block(11)
	e.block(12)
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatalf("%d messages: the withdrawn entry was sent again", len(msgs))
	}
	if got := tk.got(); len(got) != 0 {
		t.Fatalf("reports = %v", got)
	}
	if keys := e.outboxKeys(); len(keys) != 0 {
		t.Fatalf("outbox keeps %v", keys)
	}
}
