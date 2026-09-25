package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// acceptedReceiptFake answers QueryTask from chainFactsFake and QueryInferReceipt with the
// chain's accepted receipt hashes.
type acceptedReceiptFake struct {
	*chainFactsFake
	receipt chaincli.AcceptedInferReceipt
	err     error
	calls   int
}

func (f *acceptedReceiptFake) QueryInferReceipt(context.Context, string) (chaincli.AcceptedInferReceipt, error) {
	f.calls++
	return f.receipt, f.err
}

// The Worker hands its signed receipt to one Builder only. Once the chain has accepted it, the
// other Builders take output_hash and infer_receipt_hash from the chain, so they accept Verifier
// handraises that bind them instead of dropping every one.
func TestBuilderWithoutReceiptUsesChainAcceptedHashes(t *testing.T) {
	const (
		session = "sess-accepted-receipt"
		task    = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"
		winner  = "trueopen1winnerworker"
	)
	outputSum, receiptSum := sha256.Sum256([]byte("output")), sha256.Sum256([]byte("receipt"))
	query := &acceptedReceiptFake{
		chainFactsFake: &chainFactsFake{height: 150},
		receipt:        chaincli.AcceptedInferReceipt{OutputHash: outputSum[:], InferReceiptHash: receiptSum[:]},
	}
	c, _ := newTestCoordinator(t, WithTaskQuerier(query))
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{
		SessionID: session, TaskID: task,
		AssignedSet: []types.BuilderRef{{Address: testBuilderSelf, Endpoint: "https://b/1"}}, Height: 100,
	})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: winner, Height: 101})
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}
	accepted := func() int {
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return len(fsm.verifierHR)
	}

	fsm.onVerifierHandraise(testVerifierHandraise(session, task, testOperator("verifier-1"), outputSum[:], receiptSum[:]))
	if accepted() != 0 {
		t.Fatal("handraise accepted before any accepted receipt was known")
	}

	onChain := chaincli.OnChainTask{
		SessionID: session, TaskID: task, State: types.Verifying, Winner: winner,
		Assignment: chaincli.TaskAssignmentState{WinnerConfirmHeight: 101}, ReceiptAccepted: true,
	}
	c.applyAuthoritativeTask(fsm, onChain, 150)
	c.applyAuthoritativeTask(fsm, onChain, 151)
	if query.calls != 1 {
		t.Fatalf("accepted receipt queried %d times, want once", query.calls)
	}

	otherSum := sha256.Sum256([]byte("other output"))
	fsm.onVerifierHandraise(testVerifierHandraise(session, task, testOperator("verifier-2"), otherSum[:], receiptSum[:]))
	if accepted() != 0 {
		t.Fatal("handraise with a different output_hash accepted")
	}
	fsm.onVerifierHandraise(testVerifierHandraise(session, task, testOperator("verifier-1"), outputSum[:], receiptSum[:]))
	if accepted() != 1 {
		t.Fatal("handraise binding the chain's accepted hashes was dropped")
	}

	// The chain hashes do not stand in for the output itself: this Builder never received the
	// finalized output, so it must not declare itself data-ready by sending OPEN_VERIFY or
	// proposing the handraises it keeps.
	if c.HasAcceptedOutput(session, task, outputSum[:]) {
		t.Fatal("chain-accepted hashes reported as locally accepted output")
	}
	fsm.mu.Lock()
	payload, published := fsm.openVerifyPayload(), fsm.openVerifyPublished
	fsm.scheduleVerifierProposalLocked()
	fsm.submitVerifierProposalLocked()
	fsm.mu.Unlock()
	if payload != nil || published {
		t.Fatal("a Builder without the signed receipt would send OPEN_VERIFY")
	}
	if submit := c.submit.(*fakeSubmitter); len(submit.verifierHandraises) != 0 {
		t.Fatalf("a Builder without the signed receipt proposed handraises: %d", len(submit.verifierHandraises))
	}

	// A signed receipt that differs from the accepted one is refused.
	conflicting := testInferReceipt(session, task, winner, otherSum[:])
	conflicting.InferReceiptHash = receiptSum[:]
	fsm.mu.Lock()
	err := fsm.validateInferReceiptLocked(conflicting)
	fsm.mu.Unlock()
	if !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("conflicting receipt error = %v", err)
	}

	// The hashes survive a restart.
	raw, ok := c.kv.Get(kv.NSTask, taskKey(session, task))
	if !ok {
		t.Fatal("task snapshot not persisted")
	}
	var snapshot taskSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.AcceptedOutputHash, outputSum[:]) || !bytes.Equal(snapshot.AcceptedReceiptHash, receiptSum[:]) {
		t.Fatalf("snapshot hashes = %x / %x", snapshot.AcceptedOutputHash, snapshot.AcceptedReceiptHash)
	}
}

// A failed chain query leaves the Builder as it was; the next reconciliation retries.
func TestAcceptedReceiptQueryFailureRetries(t *testing.T) {
	const (
		session = "sess-accepted-receipt-retry"
		task    = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e"
	)
	query := &acceptedReceiptFake{chainFactsFake: &chainFactsFake{height: 150}, err: errors.New("unavailable")}
	c, _ := newTestCoordinator(t, WithTaskQuerier(query))
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "trueopen1winner", Height: 101})
	fsm, _ := c.getFSM(session, task)
	onChain := chaincli.OnChainTask{SessionID: session, TaskID: task, State: types.Verifying, Winner: "trueopen1winner", ReceiptAccepted: true}
	c.applyAuthoritativeTask(fsm, onChain, 150)
	c.applyAuthoritativeTask(fsm, onChain, 151)
	if query.calls != 2 || !fsm.needsAcceptedReceipt() {
		t.Fatalf("calls = %d, needs = %v", query.calls, fsm.needsAcceptedReceipt())
	}
}
