package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

func testVerifyCommit(task, verifier string) *taskv1.VerifyCommitV1 {
	commitHash := sha256.Sum256([]byte("commit|" + task + "|" + verifier))
	return &taskv1.VerifyCommitV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: mustHex32(task),
		VerifyRound: uint32(nodecontract.SupportedVerifyRoundV1), VerifierOperatorAddress: verifier,
		ServiceAuthorizationNonce: 7, CommitHash: commitHash[:], ExpiryHeight: 1000,
		ServiceSignature: testSignatureBytes64("verify-commit-signature", task, verifier),
	}
}

// verifyingTask pushes a task to Verifying: order -> assignment -> receipt -> on-chain open-verify with verifiers selected.
func verifyingTask(t *testing.T, c *Coordinator, session, task string, verifiers []string) {
	t.Helper()
	workerService, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("worker service signer: %v", err)
	}
	winner := workerService.Address()
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{
		SessionID: session, TaskID: task,
		AssignedSet: []types.BuilderRef{{Address: testBuilderSelf, Endpoint: "https://b/1"}}, Height: 100,
	})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
		SessionID: session, TaskID: task, Winner: winner, AssignSeed: []byte("assign-seed"), Height: 101,
	})
	outputHashSum := sha256.Sum256([]byte("canonical output"))
	receipt := testInferReceipt(session, task, winner, outputHashSum[:])
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
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: 3, Verify: 4}, Height: 200,
	})
	assertState(t, c, session, task, types.Verifying)
}

// Phase-1 Builder relay: the selected Verifier's commit is relayed verbatim as one batch; re-sending
// the same one is idempotent; a second one with different content, a non-selected Verifier, a task
// not in the verification phase, and an unknown task are each rejected by their sentinel.
func TestVerifyCommitRelay(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sub := &fakeSubmitter{}
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	enableTestBusEnvelopes(c)
	c.submit = sub

	const (
		session = "sess-verify-relay"
		task    = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
	)
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	ctx := context.Background()

	commit := testVerifyCommit(task, verifiers[0])
	ack, err := c.OnVerifyCommit(ctx, session, task, commit)
	if err != nil || ack.Idempotent || string(ack.TxHash) != "commit-tx" {
		t.Fatalf("relay = %+v, %v", ack, err)
	}
	if len(sub.verifyCommits) != 1 || sub.verifyCommits[0].Submitter != testBuilderSelf ||
		!proto.Equal(sub.verifyCommits[0].Commit, commit) {
		t.Fatalf("commit was not relayed verbatim as one batch: %+v", sub.verifyCommits)
	}

	ack, err = c.OnVerifyCommit(ctx, session, task, proto.Clone(commit).(*taskv1.VerifyCommitV1))
	if err != nil || !ack.Idempotent || len(sub.verifyCommits) != 1 {
		t.Fatalf("same commit again: ack = %+v, err = %v, relayed = %d", ack, err, len(sub.verifyCommits))
	}

	changed := testVerifyCommit(task, verifiers[0])
	changed.ExpiryHeight = 1001
	if _, err := c.OnVerifyCommit(ctx, session, task, changed); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("a different second commit must be refused: %v", err)
	}
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, testOperator("stranger"))); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("non-selected verifier: %v", err)
	}
	if _, err := c.OnVerifyCommit(ctx, session, "0000000000000000000000000000000000000000000000000000000000000001", commit); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("unknown task: %v", err)
	}

	// On-chain verdict rejection: report InvalidArgument, do not record locally.
	sub.verifyCommitErr = &SubmissionError{Phase: SubmissionBroadcast, Definitive: true, Err: errors.New("code 5: rejected")}
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("definitive chain rejection: %v", err)
	}
	// Transient failure: returned as is, retryable next time.
	sub.verifyCommitErr = errors.New("connection refused")
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); err == nil || errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("transient failure: %v", err)
	}
	sub.verifyCommitErr = nil
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); err != nil || len(sub.verifyCommits) != 2 {
		t.Fatalf("retry after transient failure: %v, relayed = %d", err, len(sub.verifyCommits))
	}

	// Task not in the verification phase: FailedPrecondition.
	const pending = "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b"
	if err := c.OnOrder(ctx, testCurrentOrder("sess-pending", pending, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	if _, err := c.OnVerifyCommit(ctx, "sess-pending", pending, testVerifyCommit(pending, verifiers[0])); !errors.Is(err, types.ErrFailedPrecondition) {
		t.Fatalf("pending task: %v", err)
	}
}

// The Ingress-path result goes through the same relay as the JetStream path: one batch, idempotent, non-selected rejected.
func TestVerifyResultRelayViaIngress(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sub := &fakeSubmitter{}
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	enableTestBusEnvelopes(c)
	c.submit = sub

	const (
		session = "sess-verify-result-relay"
		task    = "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
	)
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	ctx := context.Background()

	vr := testVerifyResult(task, verifiers[0], [][]byte{[]byte("v0"), []byte("v1")})
	ack, err := c.OnVerifyResult(ctx, session, task, vr)
	if err != nil || ack.Idempotent {
		t.Fatalf("relay = %+v, %v", ack, err)
	}
	if len(sub.verifyResults) != 1 || sub.verifyResults[0].Submitter != testBuilderSelf || !proto.Equal(sub.verifyResults[0].Receipt, vr) {
		t.Fatalf("receipt was not relayed verbatim: %+v", sub.verifyResults)
	}
	ack, err = c.OnVerifyResult(ctx, session, task, proto.Clone(vr).(*taskv1.ResultReceiptV2))
	if err != nil || !ack.Idempotent || len(sub.verifyResults) != 1 {
		t.Fatalf("same receipt again: ack = %+v, err = %v, relayed = %d", ack, err, len(sub.verifyResults))
	}
	if _, err := c.OnVerifyResult(ctx, session, task, testVerifyResult(task, testOperator("stranger"), nil)); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("non-selected verifier: %v", err)
	}
	broken := testVerifyResult(task, verifiers[1], nil)
	broken.MetricRoot = nil
	if _, err := c.OnVerifyResult(ctx, session, task, broken); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("receipt without metric root: %v", err)
	}
}
