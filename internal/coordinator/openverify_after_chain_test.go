package coordinator

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// OPEN_VERIFY must be sent only after the chain has accepted the receipt, and the assignment notice
// must be sent only after the chain has decided the verifiers.
//
// In integration both were sent too early:
//
//   - OPEN_VERIFY was sent as soon as the receipt was accepted locally. The receipt transaction only
//     reaches the chain in the next block, so a Verifier that received the message and queried the
//     chain immediately did not find the receipt yet and reported "receipt is not available";
//     OPEN_VERIFY is Core-tier and sent once, so that error was the end of the line and the verify
//     window expired and was swept as INSUFFICIENT. Contract §5.8 says it is "published only after
//     the InferReceipt has been accepted by the keeper".
//   - Reconcile treated "the verify window is open" (RECEIPT_COMMITTED on chain) as "the verifiers
//     are decided", sent an assignment notice with 0 verifiers, and advanced the local state to
//     Verifying.
func TestOpenVerifyWaitsForChainAcceptedReceipt(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	fake := &fakeSubmitter{}

	workerService, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("worker service signer: %v", err)
	}
	winner := workerService.Address()

	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	enableTestBusEnvelopes(c)
	c.submit = fake

	const (
		session = "sess-open-verify-after-chain"
		task    = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
	)
	openVerify, verifySelect := &captured{}, &captured{}
	mustSub(t, bus, msgbus.SubjectVerifyOpen(task), openVerify)
	mustSub(t, bus, msgbus.SubjectVerifierAssignment(task), verifySelect)

	outputHashSum := sha256.Sum256([]byte("canonical output"))
	outputHash := outputHashSum[:]

	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{
		SessionID: session, TaskID: task,
		AssignedSet: []types.BuilderRef{{Address: testBuilderSelf, Endpoint: "https://b/1"}},
		Height:      100,
	})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
		SessionID: session, TaskID: task, Winner: winner, AssignSeed: []byte("assign-seed"), Height: 101,
	})

	receipt := testInferReceipt(session, task, winner, outputHash)
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(receipt)
	if err != nil {
		t.Fatalf("derive receipt digest: %v", err)
	}
	receipt.InferReceiptHash = digest[:]
	signature, err := workerService.Sign(digest[:])
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	receipt.WorkerServiceSignature = signature
	if err := c.OnInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	if openVerify.count() != 0 {
		t.Fatalf("OPEN_VERIFY was sent before the chain accepted the receipt: %d", openVerify.count())
	}

	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}

	// The chain accepted the receipt and the verify window is open, but the verifiers are not decided
	// yet (RECEIPT_COMMITTED -> Verifying, with Verifiers empty).
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: session, TaskID: task, State: types.Verifying, Winner: winner,
		Assignment: chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		// QueryTask carries only the receipt_status bit; the receipt itself comes from
		// QueryInferReceipt and is empty in the snapshot.
		ReceiptAccepted: true,
	}, 150)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY must be sent exactly once after the chain accepts the receipt, got %d", openVerify.count())
	}
	if verifySelect.count() != 0 {
		t.Fatalf("the assignment notice was sent before the verifiers were decided: %d", verifySelect.count())
	}
	assertState(t, c, session, task, types.Assigned)

	// Verifier hand-raises must still be accepted while the verify window is open -- they are only
	// accepted in the Assigned state.
	fsm.onVerifierHandraise(testVerifierHandraise(session, task, testOperator("verifier-1"), outputHash, digest[:]))
	fsm.mu.Lock()
	accepted := len(fsm.verifierHR)
	fsm.mu.Unlock()
	if accepted != 1 {
		t.Fatalf("a hand-raise during the open verify window was dropped: accepted = %d", accepted)
	}

	// Reconcile once more: OPEN_VERIFY must not be sent again.
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: session, TaskID: task, State: types.Verifying, Winner: winner,
		Assignment: chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		// QueryTask carries only the receipt_status bit; the receipt itself comes from
		// QueryInferReceipt and is empty in the snapshot.
		ReceiptAccepted: true,
	}, 151)
	if openVerify.count() != 1 {
		t.Fatalf("a repeated reconcile resent OPEN_VERIFY: %d", openVerify.count())
	}

	// The assignment notice is sent only after the chain has decided the verifiers.
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: session, TaskID: task, State: types.Verifying, Winner: winner,
		Assignment: chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		// QueryTask carries only the receipt_status bit; the receipt itself comes from
		// QueryInferReceipt and is empty in the snapshot.
		ReceiptAccepted:    true,
		Verifiers:          []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")},
		Deadlines:          types.Deadlines{Commit: 200, Reveal: 210, Verify: 220},
		VerifierAssignment: chaincli.VerifierAssignmentState{OpenVerifyHeight: 160},
	}, 161)
	if verifySelect.count() != 1 {
		t.Fatalf("the assignment notice must be sent exactly once after the verifiers are decided, got %d", verifySelect.count())
	}
	assertState(t, c, session, task, types.Verifying)
}
