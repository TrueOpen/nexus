package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// stagingFixture is a Pending task this Builder dispatched, its winning attempt in the book and
// the Worker's signed receipt naming the winner ticket.
type stagingFixture struct {
	c       *Coordinator
	store   kv.Store
	book    *attempt.Book
	submit  *fakeSubmitter
	session string
	task    string
	worker  string
	ticket  [32]byte
	receipt types.InferReceiptSubmission
}

func newStagingFixture(t *testing.T) *stagingFixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), store, testBuilderSelf, testChainID)
	enableTestBuilderMessages(c)
	submit := &fakeSubmitter{}
	c.submit = submit
	workerService, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	f := &stagingFixture{
		c: c, store: store, submit: submit, worker: workerService.Address(),
		session: "sess-staging", task: "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e",
	}
	if err := trackTestOrder(c, testCurrentOrder(f.session, f.task, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	f.book = newTestBook(t, kv.NewMemStore())
	c.SetAttempts(f.book)
	w, ticket := testWinner(t, strings.Repeat("cd", 32), f.task, f.worker, 0)
	w.SessionID = f.session
	if err := f.book.Accepted(w); err != nil {
		t.Fatal(err)
	}
	f.ticket = ticket
	output := sha256.Sum256([]byte("output"))
	f.receipt = testInferReceipt(f.session, f.task, f.worker, output[:])
	f.receipt.TaskHash = hex.EncodeToString(w.Ticket.GetTaskHash())
	f.receipt.DispatchTicketHash = ticket[:]
	f.sign(t, workerService)
	return f
}

func (f *stagingFixture) sign(t *testing.T, s signer.Signer) {
	t.Helper()
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receipt.InferReceiptHash = digest[:]
	if f.receipt.WorkerServiceSignature, err = s.Sign(digest[:]); err != nil {
		t.Fatal(err)
	}
}

func (f *stagingFixture) staged() bool {
	_, found := f.store.Get(kv.NSReceiptStaging, taskKey(f.session, f.task))
	return found
}

func (f *stagingFixture) submitted() int {
	f.submit.mu.Lock()
	defer f.submit.mu.Unlock()
	return len(f.submit.openVerify)
}

// A receipt that arrives before the dispatch is recorded is staged, not relayed; when the chain
// shows the task recorded it goes through the normal path and leaves the staging.
func TestReceiptStagedUntilTheRecord(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatalf("receipt before the record: %v", err)
	}
	if !f.staged() || f.submitted() != 0 {
		t.Fatalf("staged %t, submitted %d", f.staged(), f.submitted())
	}
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatalf("the same receipt again: %v", err)
	}
	f.book.Recorded(f.task, f.ticket)
	fsm, _ := f.c.getFSM(f.session, f.task)
	f.c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{SessionID: f.session, TaskID: f.task, State: types.Assigned, Winner: f.worker}, 101)
	if f.staged() || f.submitted() != 1 {
		t.Fatalf("after the record: staged %t, submitted %d", f.staged(), f.submitted())
	}
}

// A refused record drops the staged receipt with the task.
func TestReceiptStagingDroppedOnRejection(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatal(err)
	}
	f.book.Rejected(f.task, f.ticket)
	f.c.RecordRejected(f.session, f.task, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_BALANCE_INSUFFICIENT)
	if f.staged() || f.submitted() != 0 {
		t.Fatalf("after the rejection: staged %t, submitted %d", f.staged(), f.submitted())
	}
}

// The receipt's dispatch_ticket_hash must be the task's live winner ticket; anything else is
// refused and nothing is staged.
func TestReceiptMustNameTheWinnerTicket(t *testing.T) {
	f := newStagingFixture(t)
	workerService, _ := signer.NewFromHex(testKeyHex, "trueopen")
	f.receipt.DispatchTicketHash = make([]byte, 32)
	f.sign(t, workerService)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); !errors.Is(err, types.ErrReceiptDispatchMismatch) {
		t.Fatalf("another ticket: %v", err)
	}
	f.receipt.DispatchTicketHash = f.ticket[:]
	f.sign(t, workerService)
	f.book.Rejected(f.task, f.ticket)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("rejected attempt: %v", err)
	}
	if f.staged() {
		t.Fatal("a refused receipt was staged")
	}
}

// failingCustodian refuses the first fails holds with a storage error.
type failingCustodian struct {
	relay.Custodian
	fails int
}

func (f *failingCustodian) Hold(receipt types.InferReceiptSubmission, ttl time.Duration) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("relay store unavailable")
	}
	return f.Custodian.Hold(receipt, ttl)
}

// A staged receipt the normal path cannot take when the record shows up stays staged and the
// reconcile reports the task unfinished; the next reconcile of the Assigned task relays it.
func TestStagedReceiptRetriedAfterAFailedRelease(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatal(err)
	}
	f.book.Recorded(f.task, f.ticket)
	f.c.relay = &failingCustodian{Custodian: f.c.relay, fails: 1}
	fsm, _ := f.c.getFSM(f.session, f.task)
	recorded := chaincli.OnChainTask{SessionID: f.session, TaskID: f.task, State: types.Assigned, Winner: f.worker}
	if done := f.c.applyAuthoritativeTask(fsm, recorded, 101); done || !f.staged() || f.submitted() != 0 {
		t.Fatalf("failed release: done %t, staged %t, submitted %d", done, f.staged(), f.submitted())
	}
	if done := f.c.applyAuthoritativeTask(fsm, recorded, 102); !done || f.staged() || f.submitted() != 1 {
		t.Fatalf("next reconcile: done %t, staged %t, submitted %d", done, f.staged(), f.submitted())
	}
}

// A restart between saving the task Assigned and releasing its staged receipt does not orphan
// the receipt: the reconcile after the restart finds the task Assigned and relays it.
func TestStagedReceiptReleasedAfterARestart(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatal(err)
	}
	f.book.Recorded(f.task, f.ticket)
	fsm, _ := f.c.getFSM(f.session, f.task)
	fsm.onWinnerRecorded(f.worker, nil, 101, 0) // saved Assigned; the process stops here

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), f.store, testBuilderSelf, testChainID)
	enableTestBuilderMessages(c)
	submit := &fakeSubmitter{}
	c.submit = submit
	c.SetAttempts(f.book)
	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(f.session, f.task)
	if !ok {
		t.Fatal("task not recovered")
	}
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{SessionID: f.session, TaskID: f.task, State: types.Assigned, Winner: f.worker}, 102)
	submit.mu.Lock()
	n := len(submit.openVerify)
	submit.mu.Unlock()
	if f.staged() || n != 1 {
		t.Fatalf("after the restart: staged %t, submitted %d", f.staged(), n)
	}
}

// Once the chain holds a receipt for the task a staged one has nothing left to do and is dropped.
func TestStagedReceiptDroppedOnceTheChainHasAReceipt(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatal(err)
	}
	f.book.Recorded(f.task, f.ticket)
	fsm, _ := f.c.getFSM(f.session, f.task)
	fsm.onWinnerRecorded(f.worker, nil, 101, 0)
	f.c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{SessionID: f.session, TaskID: f.task, State: types.Verifying, Winner: f.worker, ReceiptAccepted: true}, 102)
	if f.staged() {
		t.Fatal("staged receipt kept after the chain accepted a receipt")
	}
}

// fakePayloads records the output streams retired.
type fakePayloads struct {
	mu      sync.Mutex
	retired []string
}

func (*fakePayloads) Delete(context.Context, payloadstore.Input) error { return nil }
func (*fakePayloads) Sweep(context.Context, uint64) error              { return nil }
func (f *fakePayloads) RetireOutput(_ context.Context, sessionID, taskID string, ticket []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retired = append(f.retired, sessionID+"|"+taskID+"|"+hex.EncodeToString(ticket))
	return nil
}

// A task dropped after its record was refused retires the refused attempt's output stream; the
// attempt stays in the book (its REJECTED header for a late subscriber) until its retention ends.
func TestRefusedAttemptRetiredWithItsTask(t *testing.T) {
	f := newStagingFixture(t)
	payloads := &fakePayloads{}
	f.c.payloads = payloads
	f.c.SetAttemptRetention(50)
	f.book.Rejected(f.task, f.ticket)
	f.c.RecordRejected(f.session, f.task, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_BALANCE_INSUFFICIENT)
	if want := []string{f.session + "|" + f.task + "|" + hex.EncodeToString(f.ticket[:])}; !reflect.DeepEqual(payloads.retired, want) {
		t.Fatalf("retired = %v", payloads.retired)
	}
	a, ok := f.book.Current(f.task)
	if !ok || a.Status != attempt.Rejected || a.ExpireHeight == 0 || a.ExpireHeight > 50 {
		t.Fatalf("attempt = %+v, %v", a, ok)
	}
}

// After the record the attempt takes uploads up to the task's infer deadline; once the task is
// terminal it takes none, and it expires after the retention.
func TestRecordedAttemptUploadsEndWithTheTask(t *testing.T) {
	f := newStagingFixture(t)
	f.c.SetAttemptRetention(50)
	f.book.Recorded(f.task, f.ticket)
	fsm, _ := f.c.getFSM(f.session, f.task)
	recorded := chaincli.OnChainTask{SessionID: f.session, TaskID: f.task, State: types.Assigned, Winner: f.worker}
	recorded.Assignment.InferDeadlineHeight = 500
	f.c.applyAuthoritativeTask(fsm, recorded, 101)
	if a, _ := f.book.Current(f.task); a.UploadUntil != 500 || !a.AcceptsUploads(500) || a.AcceptsUploads(501) {
		t.Fatalf("attempt after the record = %+v", a)
	}
	f.c.removeTask(taskKey(f.session, f.task))
	if a, _ := f.book.Current(f.task); a.AcceptsUploads(100) || a.ExpireHeight == 0 {
		t.Fatalf("attempt of the terminal task = %+v", a)
	}
}

// A dispatch failure for a task whose attempt the chain recorded (a voided winner recorded after
// all, its new round without a taker) does not drop the task: the chain assigned it, so it is
// reconciled instead and its staged receipt stays.
func TestDispatchFailureOfARecordedTaskKeepsIt(t *testing.T) {
	f := newStagingFixture(t)
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); err != nil {
		t.Fatal(err)
	}
	f.book.Recorded(f.task, f.ticket)
	f.c.DispatchFailed(f.session, f.task, fmt.Errorf("%w: no member left", dispatchdraw.ErrNoCapacity))
	if _, ok := f.c.getFSM(f.session, f.task); !ok {
		t.Fatal("the recorded task was dropped")
	}
	if !f.staged() {
		t.Fatal("the staged receipt was dropped")
	}
}

// A task dropped while its attempt is recorded keeps the attempt's output stream; the attempt
// still expires after the retention.
func TestAbandonedRecordedAttemptExpiresAndKeepsItsStream(t *testing.T) {
	f := newStagingFixture(t)
	payloads := &fakePayloads{}
	f.c.payloads = payloads
	f.book.Recorded(f.task, f.ticket)
	fsm, _ := f.c.getFSM(f.session, f.task)
	f.c.abandonTask(taskKey(f.session, f.task), fsm)
	if len(payloads.retired) != 0 {
		t.Fatalf("retired = %v", payloads.retired)
	}
	if a, ok := f.book.Current(f.task); !ok || a.ExpireHeight == 0 {
		t.Fatalf("attempt = %+v, %v", a, ok)
	}
}

// A receipt for a task in flight whose attempt the book does not hold yet (it is still taking
// the winner) is retryable, not refused, and nothing is staged.
func TestReceiptBeforeTheBookHoldsTheAttemptIsRetryable(t *testing.T) {
	f := newStagingFixture(t)
	f.c.SetAttempts(newTestBook(t, kv.NewMemStore()))
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); !errors.Is(err, types.ErrUnavailable) {
		t.Fatalf("receipt = %v", err)
	}
	if f.staged() {
		t.Fatal("receipt staged")
	}
}
