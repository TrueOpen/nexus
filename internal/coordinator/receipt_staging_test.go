package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
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
	if err := f.c.OnInferReceipt(context.Background(), f.receipt); !errors.Is(err, types.ErrInvalidArgument) {
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
