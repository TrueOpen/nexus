package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	wirebus "github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
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

// TestInferReceiptReachesChainAsMsgSubmitInferReceipt is the end-to-end gate of the receipt submit bridge:
// Worker-signed receipt -> coordinator FSM -> chaincli.OpenVerifyTx.InferReceipt ->
// real defaultSubmitter -> MsgSubmitInferReceipt inside the signed tx.
//
// It pins exactly the link that was broken before the fix: taskfsm built OpenVerifyTx without
// InferReceipt, the submitter rejected nil before broadcast, so the Builder could answer the Worker
// with relay_accepted=true while MsgSubmitInferReceipt could never be submitted.
//
// The last step recomputes the H_FIELDS_V1 digest of the receipt in the broadcast message and
// verifies the signature with the Worker's service key: the on-chain Keeper does the same, so this
// assertion is equivalent to "this tx carries a signature the Keeper would accept" -- actual
// inclusion still needs the Node-side Task slice to switch the handler to InferReceiptV2.
func TestInferReceiptReachesChainAsMsgSubmitInferReceipt(t *testing.T) {
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
	keys := enableTestBusEnvelopes(c)
	c.submit = fake

	const (
		session = "sess-bridge"
		task    = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
	)
	outputBody := []byte("canonical output")
	outputHashSum := sha256.Sum256(outputBody)
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

	for _, candidate := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		handraise := testVerifierHandraise(session, task, candidate, outputHash, digest[:])
		publishEnvelope(t, bus, keys, candidate, msgbus.SubjectVerifierHandraiseV1(task),
			wirebus.KindVerifierHandraise, handraise)
	}
	if len(fake.openVerify) != 1 {
		t.Fatalf("expected 1 OpenVerifyTx, got %d", len(fake.openVerify))
	}
	tx := fake.openVerify[0]
	if tx.InferReceipt == nil {
		t.Fatal("OpenVerifyTx.InferReceipt is nil: MsgSubmitInferReceipt could never be built")
	}

	// Real submitter: validateInferReceipt checks the §5.14 structure item by item, then signs and broadcasts.
	// The Builder's Cosmos signing key and the Worker's service key must be two different keys.
	builder, err := signer.NewFromHex(
		"4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d", "trueopen")
	if err != nil {
		t.Fatalf("builder signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	submitter := NewSignedSubmitter(log, chain, chain, builder, builder, config.ChainConfig{
		ChainID: testChainID, GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})
	tx.Submitter = builder.Address()
	result, err := submitter.SubmitOpenVerify(ctx, tx)
	if err != nil {
		t.Fatalf("SubmitOpenVerify: %v", err)
	}
	if result.Code != 0 || len(chain.broadcast) != 1 {
		t.Fatalf("broadcast: code=%d n=%d", result.Code, len(chain.broadcast))
	}

	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgSubmitInferReceipt {
		t.Fatalf("type_url = %q", body.Messages[0].TypeUrl)
	}
	var msg taskv1.MsgSubmitInferReceipt
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal MsgSubmitInferReceipt: %v", err)
	}
	onChain := msg.GetReceipt()
	if msg.GetSubmitterAddress() != builder.Address() || onChain == nil {
		t.Fatalf("MsgSubmitInferReceipt mismatch: %+v", &msg)
	}
	wantTaskID, err := nodecontract.Hash32Bytes("task_id", task)
	if err != nil {
		t.Fatal(err)
	}
	if onChain.GetSchemaVersion() != nodecontract.InferReceiptSchemaVersionV2 ||
		onChain.GetChainId() != testChainID || !bytes.Equal(onChain.GetTaskId(), wantTaskID) ||
		onChain.GetWorkerOperatorAddress() != winner ||
		!bytes.Equal(onChain.GetOutputHash(), outputHash) ||
		onChain.GetServiceAuthorizationNonce() == 0 || onChain.GetExpiryHeight() == 0 ||
		len(onChain.GetTaskHash()) != 32 || len(onChain.GetGenerationParamsDigest()) != 32 ||
		len(onChain.GetRequiredEvidenceCommitments()) != 1 ||
		onChain.GetRequiredEvidenceCommitments()[0].GetEvidenceKind() !=
			sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING ||
		!bytes.Equal(onChain.GetServiceSignature(), signature) {
		t.Fatalf("on-chain receipt is not the Worker-signed InferReceiptV2: %+v", onChain)
	}

	// The step the Keeper recomputes: the digest must match exactly what the Worker signed, and the signature must verify.
	onChainDigest, err := nodecontract.InferReceiptSigningDigest(onChain)
	if err != nil {
		t.Fatalf("recompute on-chain digest: %v", err)
	}
	if onChainDigest != digest {
		t.Fatalf("on-chain digest %x != signed digest %x", onChainDigest, digest)
	}
	if !signer.VerifySig(workerService.PubKeyCompressed(), onChainDigest[:], onChain.GetServiceSignature()) {
		t.Fatal("Worker service signature does not verify against the on-chain receipt digest")
	}
}
