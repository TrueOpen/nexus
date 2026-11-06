package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// fakeSubmitter records the three phases of submitted Tx for assertions.
type fakeSubmitter struct {
	mu         sync.Mutex
	settleErr  error
	openVerify []chaincli.OpenVerifyTx
	settle     []chaincli.SettleTx
	sweep      []chaincli.SweepDeadlineTx
	sweepErr   error

	verifierHandraises    []chaincli.OpenVerifyTx
	verifierHandraisesErr error
	// verifierHandraiseAttempts counts every submission, including refused ones.
	verifierHandraiseAttempts int
	verifyResults             []chaincli.VerifyResultTx
	verifyCommits             []chaincli.VerifyCommitTx
	verifyCommitErr           error
	verifyResultErr           error

	// verifierExcluded is reported as left out of every verifier handraise proposal.
	verifierExcluded []ExcludedHandraise
}

func (s *fakeSubmitter) SubmitOpenVerify(_ context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	s.openVerify = append(s.openVerify, tx)
	s.mu.Unlock()
	return chaincli.TxResult{Code: 0}, nil
}

func (s *fakeSubmitter) SubmitVerifierHandraises(_ context.Context, tx chaincli.OpenVerifyTx) (ProposalResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifierHandraiseAttempts++
	if s.verifierHandraisesErr != nil {
		return ProposalResult{}, s.verifierHandraisesErr
	}
	s.verifierHandraises = append(s.verifierHandraises, tx)
	return ProposalResult{Excluded: s.verifierExcluded}, nil
}

func (s *fakeSubmitter) SubmitVerifyCommit(_ context.Context, tx chaincli.VerifyCommitTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyCommitErr != nil {
		return chaincli.TxResult{}, s.verifyCommitErr
	}
	s.verifyCommits = append(s.verifyCommits, tx)
	return chaincli.TxResult{Code: 0, TxHash: []byte("commit-tx")}, nil
}

func (s *fakeSubmitter) SubmitVerifyResult(_ context.Context, tx chaincli.VerifyResultTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyResultErr != nil {
		return chaincli.TxResult{}, s.verifyResultErr
	}
	s.verifyResults = append(s.verifyResults, tx)
	return chaincli.TxResult{Code: 0}, nil
}

func (s *fakeSubmitter) SubmitSettle(_ context.Context, tx chaincli.SettleTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settleErr != nil {
		return chaincli.TxResult{}, s.settleErr
	}
	s.settle = append(s.settle, tx)
	return chaincli.TxResult{Code: 0}, nil
}

func (s *fakeSubmitter) SubmitSweepDeadline(_ context.Context, tx chaincli.SweepDeadlineTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	s.sweep = append(s.sweep, tx)
	err := s.sweepErr
	s.mu.Unlock()
	if err != nil {
		return chaincli.TxResult{}, err
	}
	return chaincli.TxResult{Code: 0}, nil
}

func (s *fakeSubmitter) sweepTxs() []chaincli.SweepDeadlineTx {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]chaincli.SweepDeadlineTx(nil), s.sweep...)
}

// testInferReceipt builds a signed InferReceipt in the wire InferReceipt shape. The field set is
// exactly that one:
// token_count / work_unit were removed from the wire and are now carried by typed evidence commitments.
//
// task must be a canonical lowercase 64-hex Hash32: when the coordinator assembles
// MsgSubmitInferReceipt it decodes task_id / task_hash into raw 32 bytes.
func testInferReceipt(session, task, worker string, outputHash []byte) types.InferReceiptSubmission {
	taskHash := sha256.Sum256([]byte("task-hash-" + task))
	paramsDigest := sha256.Sum256([]byte("generation-params-" + task))
	evidenceHash := sha256.Sum256([]byte("worker-value-opening-" + task))
	ticketHash := sha256.Sum256([]byte("dispatch-ticket-" + task))
	return types.InferReceiptSubmission{
		SessionID:                 session,
		SchemaVersion:             nodecontract.InferReceiptSchemaVersionV3,
		ChainID:                   testChainID,
		TaskID:                    task,
		TaskHash:                  hex.EncodeToString(taskHash[:]),
		WorkerAddress:             worker,
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    paramsDigest[:],
		OutputHash:                outputHash,
		OutputSizeBytes:           6,
		EvidenceCommitments: []types.EvidenceCommitment{{
			Kind:             uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING),
			HashOrRoot:       evidenceHash[:],
			EncodedSizeBytes: 4096,
		}},
		ExpiryHeight:           1200,
		DispatchTicketHash:     ticketHash[:],
		WorkerServiceSignature: []byte("worker-service-signature"),
		InferReceiptHash:       []byte("infer-receipt"),
	}
}

// testTaskID builds a task_id in its real shape. On the wire task_id / task_hash
// are both Hash32 and only 64 lowercase hex characters pass wire validation; in production it
// comes from nodecontract.DeriveTaskIDFromRawSession, and tests can no longer run the
// submission path with a fake ID like "task-1".
func testTaskID(name string) string {
	sum := sha256.Sum256([]byte("test-task-id|" + name))
	return hex.EncodeToString(sum[:])
}

// testUserAddress is the test address of the ordering user. It must be **canonical bech32**:
// the preimage framing of task_hash frames the address-codec bytes of user_address
// (H_FIELDS_V1 address rule), and task_hash cannot be computed if they cannot be decoded. The
// testUserAddress of the old fixture was not valid bech32, which did not matter earlier
// (the order identity was sha256(envelope) then and ignored the address); now it gets the
// whole order rejected at ingress.
// Value = bech32("trueopen", 20 × 0x11).
const testUserAddress = "trueopen1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rsxm9a"

func testHash32(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// testPlaceholderTaskHash gives the cases that "only need a task to exist" (event reconcile,
// snapshot recovery, etc.) a candidate task_hash of valid shape. An order must
// carry it to be broadcast at all -- an order whose canonical task_hash cannot be computed is
// certain to be rejected on-chain, and Nexus no longer lets it into the flow.
// Cases that run the real hand-raise/submission path should use testCurrentOrder, whose value
// is derived from the signed order.
var testPlaceholderTaskHash = testHash32("placeholder-task-hash")

// testPlaceholderOrder gives the cases that "only need a task to exist" a minimal broadcastable
// order: a task_hash of valid shape plus a frozen SignedOrderV2 (onOrder fails closed on both).
func testPlaceholderOrder(session, task string) types.Order {
	return types.Order{
		TaskHash: testPlaceholderTaskHash, SessionID: session, TaskID: task,
		ModelID: testModelIDHex, PayloadCID: "cid", SignedOrder: testSignedOrderBytes(testUserAddress),
	}
}

// testCanonicalTaskHash is the canonical task_hash of the frozen TaskOrderV2 in
// testSignedOrder. Any case that has to run "broadcast → hand-raise → on-chain" must use it for
// the order, the hand-raise and the proposal scope alike -- a mismatch between the three means
// fail-closed took effect, not a fixture coincidence.
func testCanonicalTaskHash(user string) string {
	hash, err := nodecontract.TaskOrderHashHexV3(testSignedOrder(user).GetOrder())
	if err != nil {
		panic(err)
	}
	return hash
}

// testSignature64 builds a 64-byte compact signature placeholder. Nexus only checks
// length/encoding and passes it through; signature verification is in the Keeper, and digest
// framing is covered by the nodecontract golden tests.
func testSignature64(parts ...string) string {
	return testHash32(append([]string{"lo"}, parts...)...) + testHash32(append([]string{"hi"}, parts...)...)
}

// testSignedOrderBytes reuses the SignedOrderV2 fixture of submitter_test to give the proto-encoded
// SignedOrderV2 that the SDK side submits; in production only the SDK can supply it, because the
// user signs the order and Nexus has no right to reconstruct it.
func testSignedOrderBytes(user string) []byte {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(testSignedOrder(user))
	if err != nil {
		panic(err)
	}
	return raw
}

func testCurrentOrder(session, task, user string) types.Order {
	envelope := nodecontract.AssignmentOrderEnvelopeV1{
		SchemaVersion: nodecontract.OrderEnvelopeSchemaV1, ModelID: testModelIDHex, ProfileVersion: 2, TaskType: "inference",
		RewardBucket: 1, ProfileResourceTier: 2, InferInputUnitPriceBid: 2, InferOutputUnitPriceBid: 3,
		VerifyUnitPriceBid: 4, MaxFee: 100, TxFeeReserve: 0, InferFeeCap: 70, VerifyFeeCap: 10, OrderValue: 80,
		DeadlineHeight: 1000, PayloadHash: strings.Repeat("a", 64),
		InferTimeoutBlocks: 20, ReferenceBucketKey: "reference-v1", TimeoutBucketKey: "standard",
	}
	raw, err := nodecontract.CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		panic(err)
	}
	// task_hash must match the one derived from the TaskOrderV2 inside SignedOrder -- that is
	// how ingress computes it in production, and both the hand-raise and the on-chain scope are
	// compared against it.
	// This used to hold sha256(order_envelope), which is an envelope byte digest, not the order identity.
	taskHash := testCanonicalTaskHash(user)
	return types.Order{
		SessionID: session, TaskID: task, OrderSequence: 1, ModelID: envelope.ModelID, ProfileVersion: envelope.ProfileVersion,
		TaskType: envelope.TaskType, PayloadCID: "cid-in", User: user, Deadline: int64(envelope.DeadlineHeight),
		OrderEnvelope: raw, TaskHash: taskHash, SignatureScheme: "secp256k1", UserSignature: "user-signature",
		RewardBucket: envelope.RewardBucket, ProfileResourceTier: envelope.ProfileResourceTier,
		InferInputUnitPriceBid: envelope.InferInputUnitPriceBid, InferOutputUnitPriceBid: envelope.InferOutputUnitPriceBid,
		VerifyUnitPriceBid: envelope.VerifyUnitPriceBid, MaxFee: envelope.MaxFee, TxFeeReserve: envelope.TxFeeReserve,
		InferFeeCap: envelope.InferFeeCap, VerifyFeeCap: envelope.VerifyFeeCap, OrderValue: envelope.OrderValue,
		DeadlineHeight: envelope.DeadlineHeight, PayloadHash: envelope.PayloadHash,
		InferTimeoutBlocks: envelope.InferTimeoutBlocks, ReferenceBucketKey: envelope.ReferenceBucketKey, TimeoutBucketKey: envelope.TimeoutBucketKey,
		SignedOrder: testSignedOrderBytes(user),
	}
}

// testWorkerSlots gives candidate addresses a stable slot. The Keeper requires handraises within
// one proposal to be strictly ascending and unique by member.slot, so tests cannot let everyone
// share one slot.
var testWorkerSlots = map[string]uint32{}
var testWorkerSlotsMu sync.Mutex

func testWorkerSlot(candidate string) uint32 {
	testWorkerSlotsMu.Lock()
	defer testWorkerSlotsMu.Unlock()
	if slot, ok := testWorkerSlots[candidate]; ok {
		return slot
	}
	slot := uint32(len(testWorkerSlots) + 1)
	testWorkerSlots[candidate] = slot
	return slot
}

// mustHex32 decodes canonical 64-hex back into 32 bytes (for test fixtures).
func mustHex32(value string) []byte {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		panic("fixture is not canonical 64-hex: " + value)
	}
	return raw
}

// testSignatureBytes64 builds a 64-byte compact signature placeholder. Nexus only checks the
// length and passes it through; signature verification is in the Keeper.
func testSignatureBytes64(parts ...string) []byte {
	lo := sha256.Sum256([]byte(strings.Join(append([]string{"lo"}, parts...), "|")))
	hi := sha256.Sum256([]byte(strings.Join(append([]string{"hi"}, parts...), "|")))
	return append(lo[:], hi[:]...)
}

// testVerifierHandraise builds a Verifier hand-raise in the frozen wire shape (proto body).
// The output/infer receipt commitments must match the local authoritative values, or
// validVerifierHandraise drops it.
func testVerifierHandraise(session, task, candidate string, outputHash, inferReceiptHash []byte) *taskv1.VerifierHandraiseV1 {
	snapshotID := sha256.Sum256([]byte("candidate-pool-snapshot|" + session + "|" + task))
	return &taskv1.VerifierHandraiseV1{
		SchemaVersion:    1,
		ChainId:          testChainID,
		TaskId:           mustHex32(task),
		VerifyRound:      uint32(nodecontract.SupportedVerifyRoundV1),
		InferReceiptHash: append([]byte(nil), inferReceiptHash...),
		OutputHash:       append([]byte(nil), outputHash...),
		ModelId:          testModelIDBytes,
		ProfileVersion:   2,
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: snapshotID[:],
			Slot:                    testWorkerSlot(candidate),
			SlotVersion:             1,
			OperatorAddress:         candidate,
		},
		Duty:                      sharedv1.Duty_DUTY_VERIFIER,
		ServiceAuthorizationNonce: 7,
		ExpiryHeight:              1000,
		ServiceSignature:          testSignatureBytes64("verifier-service-signature", task, candidate),
	}
}

// testVerifyResult builds a verification result receipt in the frozen wire shape.
// The metric fields are derived deterministically from vals: same vals → same metric_root /
// summary (consistent), otherwise inconsistent; result_reveal_hash, by contrast, always differs
// per node.
func testVerifyResult(task, verifier string, vals [][]byte) *taskv1.ResultReceiptV3 {
	material := sha256.New()
	for _, v := range vals {
		material.Write(v)
		material.Write([]byte{0})
	}
	metricRoot := sha256.Sum256(append([]byte("metric-root|"), material.Sum(nil)...))
	// The reveal hash is salted per Verifier: the commit/reveal scheme requires a different salt
	// per node (cortex's salt includes the Verifier address), so the reveal hashes of the same
	// re-execution results on three Verifiers are necessarily unequal.
	revealHash := sha256.Sum256(append([]byte("result-reveal|"+verifier+"|"), material.Sum(nil)...))
	paramsDigest := sha256.Sum256([]byte("generation-params|" + task))
	return &taskv1.ResultReceiptV3{
		SchemaVersion:             nodecontract.ResultReceiptSchemaVersionV3,
		ChainId:                   testChainID,
		TaskId:                    mustHex32(task),
		VerifyRound:               uint32(nodecontract.SupportedVerifyRoundV1),
		VerifierOperatorAddress:   verifier,
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    paramsDigest[:],
		MetricRoot:                metricRoot[:],
		MetricSummary:             &taskv1.MetricSummaryV1{FiniteCount: uint32(len(vals))},
		// V2: V1's result_reveal_hash is replaced by the evidence bundle hash + manifest size + salt.
		// Each Verifier's salt differs, so this hash is inherently different per node; the fixture keeps the original value.
		VerifierEvidenceBundleHash:        revealHash[:],
		VerifierEvidenceManifestSizeBytes: 145,
		Salt:                              revealHash[:],
		ExpiryHeight:                      1000,
		ServiceSignature:                  testSignatureBytes64("verify-result-signature", task, verifier),
	}
}

// TestHappyPath walks the verify and settle half of one task's happy path:
// dispatch recorded on chain (winner known → Assigned) → InferReceipt → InferReceipt accepted on
// chain → Worker result finalized here → signed OPEN_VERIFY → 3×verifier handraise → verifier
// handraise proposal → OpenVerifyAccepted (signed VERIFIER_ASSIGNMENT_NOTIFY) → SampleReady →
// relayed verify results → SettleTx → SettleAccepted → Closed.
func TestHappyPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	sub := &fakeSubmitter{}

	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_, link := enableTestBuilderMessages(c)
	c.submit = sub // inject the fake submitter
	c.SetResultReadiness(&fakeResultReadiness{ready: true})

	const session = "sess-1"
	// Signed Builder messages project addresses and hashes strictly: the winner is a bech32
	// operator and the hashes are 32 bytes.
	winner := testOperator("worker-1")
	task := testTaskID("task-1")
	ctx := context.Background()

	// 1) The task is tracked as Pending until the chain records its dispatch.
	if err := trackTestOrder(c, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	assertState(t, c, session, task, types.Pending)

	// 2) The chain records the dispatch and its winner → Assigned. Nothing is sent: the Worker
	// learned of its win from the dispatch itself.
	recordTestWinner(c, session, task, winner, 101)
	assertState(t, c, session, task, types.Assigned)
	if len(link.frames) != 0 {
		t.Fatalf("recording the winner must send nothing, got %d frames", len(link.frames))
	}

	// 4) The Worker returns the result reference (→ escrow + record the three hash/cid values).
	outputSum := sha256.Sum256([]byte("output-root"))
	receiptSum := sha256.Sum256([]byte("infer-receipt"))
	outputHash, receiptHash := outputSum[:], receiptSum[:]
	receipt := testInferReceipt(session, task, winner, outputHash)
	receipt.InferReceiptHash = receiptHash
	if err := c.OnInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}

	// 5) 3 Verifiers hand-raise on their Cortex streams → trigger OpenVerifyTx (output_hash = outputHash).
	for _, cand := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		if err := c.HandleVerifierHandraise(ctx, cand,
			testVerifierHandraise(session, task, cand, outputHash, receiptHash)); err != nil {
			t.Fatalf("HandleVerifierHandraise(%s): %v", cand, err)
		}
	}
	if len(sub.openVerify) != 1 {
		t.Fatalf("expected 1 OpenVerifyTx, got %d", len(sub.openVerify))
	}
	// OpenVerifyTx carries only the InferReceipt body (MsgSubmitInferReceipt);
	// the string copies of the old MsgOpenVerify are gone.
	submitted := sub.openVerify[0].InferReceipt
	if submitted == nil {
		t.Fatal("OpenVerifyTx.InferReceipt must be populated")
	}
	if !bytes.Equal(submitted.GetOutputHash(), outputHash) {
		t.Fatalf("InferReceipt.output_hash mismatch: %x", submitted.GetOutputHash())
	}
	if hex.EncodeToString(submitted.GetTaskId()) != task ||
		submitted.GetSchemaVersion() != nodecontract.InferReceiptSchemaVersionV3 ||
		submitted.GetChainId() != testChainID || submitted.GetServiceAuthorizationNonce() == 0 ||
		submitted.GetExpiryHeight() == 0 || len(submitted.GetGenerationParamsDigest()) != 32 ||
		len(submitted.GetRequiredEvidenceCommitments()) != 1 {
		t.Fatalf("InferReceipt is not the frozen InferReceiptV2 shape: %+v", submitted)
	}

	// 5b) The chain accepts the receipt and the Worker result is finalized here → signed OPEN_VERIFY.
	acceptedFSM, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing after receipt")
	}
	acceptedFSM.onInferReceiptAccepted()
	c.OnResultFinalized(session, task)
	eventually(t, func() bool { return len(link.openVerifies()) == 1 })
	openVerify := link.openVerifies()[0]
	if !bytes.Equal(openVerify.GetTaskId(), mustHex32(task)) || !bytes.Equal(openVerify.GetOutputHash(), outputHash) ||
		openVerify.GetWorkerOperatorAddress() != winner {
		t.Fatalf("OPEN_VERIFY mismatch: %+v", openVerify)
	}
	assertBuilderSigned(t, c, "nexus.v1.OpenVerifyV1", openVerify, openVerify.GetBinding(), openVerify.GetBuilderServiceSignature())

	// 6a) On-chain open-verify included → Verifying + signed verifier assignment notification.
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	assertState(t, c, session, task, types.Verifying)
	assertPhase(t, c, session, task, types.PhaseOpenVerify)
	if len(link.verifierAssignments()) != 1 {
		t.Fatalf("expected 1 VERIFIER_ASSIGNMENT_NOTIFY, got %d", len(link.verifierAssignments()))
	}
	vs := link.verifierAssignments()[0]
	if len(vs.GetVerifiers()) != 3 || !bytes.Equal(vs.GetOutputHash(), outputHash) || vs.GetOpenVerifyHeight() != 200 {
		t.Fatalf("VERIFIER_ASSIGNMENT_NOTIFY mismatch: %+v", vs)
	}
	assertBuilderSigned(t, c, "nexus.v1.VerifierAssignmentNotifyV1", vs, vs.GetBinding(), vs.GetBuilderServiceSignature())
	// 6b) On-chain SampleReady: record only the seed and phase; nothing is sent to Cortex.
	seed := []byte("chain-sample-seed")
	c.OnSampleReady(chaincli.SampleReady{
		SessionID: session, TaskID: task, SampleSeed: seed, ReadyHeight: 210, Height: 211,
	})
	assertPhase(t, c, session, task, types.PhaseSampleReady)
	settleFSM, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing before settle selection")
	}
	settleFSM.mu.Lock()
	settleFSM.settleSelection = settleSelection(session, task, testBuilderSelf)
	settleFSM.settleGraceBlocks = rankGraceBlocks
	settleFSM.mu.Unlock()

	// 7) Verifier results are relayed to the chain verbatim. Normal verification has no Worker
	// reveal step; the Worker's commitment is already locked by the accepted InferReceipt.
	vi := [][]byte{[]byte("v0"), []byte("v1")}
	relayTestVerifyResult(t, c, session, task, testVerifyResult(task, verifiers[0], vi))
	relayTestVerifyResult(t, c, session, task, testVerifyResult(task, verifiers[1], vi))
	if len(sub.verifyResults) != 2 {
		t.Fatalf("expected 2 relayed MsgSubmitVerifyResult, got %d", len(sub.verifyResults))
	}
	if sub.verifyResults[0].Submitter != testBuilderSelf ||
		!proto.Equal(sub.verifyResults[0].Receipt, testVerifyResult(task, verifiers[0], vi)) {
		t.Fatalf("relayed receipt was not forwarded verbatim: %+v", sub.verifyResults[0])
	}
	// Settlement is sent once the chain reports the task ready to settle; the public request
	// carries only task_id + submitter_address, verdict/receipt references/evidence root are
	// derived by the chain.
	c.onNewBlock(4)
	if len(sub.settle) != 0 {
		t.Fatalf("SettleTx must wait for the chain to report the task ready, got %d", len(sub.settle))
	}
	markSettleReady(settleFSM, 0)
	if len(sub.settle) != 1 {
		t.Fatalf("expected 1 SettleTx once the chain reports the task ready, got %d", len(sub.settle))
	}
	// 8) The Worker reveal event does not exist on chain; even if it arrives it is only recorded and triggers no second transaction.
	c.OnWorkerRevealAccepted(chaincli.WorkerRevealAccepted{SessionID: session, TaskID: task, Height: 300})
	if len(sub.settle) != 1 {
		t.Fatalf("expected still 1 SettleTx, got %d", len(sub.settle))
	}
	if sub.settle[0].TaskID != task || sub.settle[0].Submitter != testBuilderSelf {
		t.Fatalf("SettleTx mismatch: %+v", sub.settle[0])
	}

	// 9) Settlement included → Settled + escrow available; wait for on-chain finality before wrapping up.
	c.OnSettleAccepted(chaincli.SettleAccepted{
		SessionID: session, TaskID: task, TaskVerdict: types.VerdictPass,
		Settlement: releasableSettlement(), Height: 400,
	})
	assertState(t, c, session, task, types.Settled)
	held, err := rl.Serve(session, task, types.AccessSealedKey)
	if err != nil {
		t.Fatalf("custody should be held after settle: %v", err)
	}
	if !bytes.Equal(held.InferReceiptHash, receiptHash) || held.WorkerAddress == "" {
		t.Fatalf("custody must hold the signed InferReceipt: %+v", held)
	}
	// Sealed key delivery was removed: tiers no longer change the returned content.
	pkg, err := rl.Serve(session, task, types.AccessPackage)
	if err != nil {
		t.Fatalf("PACKAGE serve: %v", err)
	}
	if string(pkg.InferReceiptHash) != string(held.InferReceiptHash) {
		t.Fatal("PACKAGE access must return the same receipt material")
	}

	// 10) Chain height reaches the finality/cleanup boundary → Closed + escrow released + removed from the task table.
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing before challenge expiry")
	}
	if !fsm.closeSettledAtHeight(120) {
		t.Fatal("settled task did not close at releasable height")
	}
	if _, err := rl.Serve(session, task, types.AccessSealedKey); err == nil {
		t.Fatal("custody should be released after challenge window")
	}
	if _, ok := c.getFSM(session, task); ok {
		t.Fatal("task should be removed from table after close")
	}
}

// TestSweepDeadlineConverges: timeout sweep: a non-SETTLE phase swept → Failed terminal state + escrow released + removed from the task table.
func TestSweepDeadlineConverges(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_, _ = enableTestBuilderMessages(c)
	c.submit = &fakeSubmitter{}

	const session, task = "sess-sw", "task-sw"
	ctx := context.Background()
	if err := trackTestOrder(c, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err == nil {
		t.Fatal("OnInferReceipt must reject output before assignment finalized")
	}

	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 500,
	})
	if _, err := rl.Serve(session, task, types.AccessSealedKey); err == nil {
		t.Fatal("custody must be released after sweep")
	}
	if _, ok := c.getFSM(session, task); ok {
		t.Fatal("task must be removed from table after sweep")
	}
}

// A non-terminal transition code (COMMIT_CLOSED is usually exactly the reveal phase starting)
// must not misclassify an in-flight task as failed: the task stays in the table, escrow must not be
// released, and state is left to Query reconcile.
func TestSweepDeadlineWindowAdvanceKeepsTaskLive(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_, _ = enableTestBuilderMessages(c)
	c.submit = &fakeSubmitter{}

	const session, task = "sess-sw-live", "task-sw-live"
	if err := trackTestOrder(c, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}

	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task,
		DeadlineKind:   taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT,
		TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_COMMIT_CLOSED,
		Height:         500,
	})
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("a window advance must not remove the task from the table")
	}
	fsm.mu.Lock()
	state, terminal := fsm.state, fsm.terminal
	fsm.mu.Unlock()
	if terminal || state == types.Failed {
		t.Fatalf("state=%v terminal=%v; a window advance must not converge the task", state, terminal)
	}
}

// The public deadline runner is off by default: without explicitly enabling it there must be no MsgSweepDeadline broadcast at all.
func TestSweepDueDeadlinesIsOffByDefault(t *testing.T) {
	sub := &fakeSubmitter{}
	f := newSweepTestFSM(sub)
	f.sweepDueDeadlines(DeadlineSweepPolicy{}, 100_000)
	if got := sub.sweepTxs(); len(got) != 0 {
		t.Fatalf("sweeps=%d, want 0 while the runner is disabled", len(got))
	}
}

// Once enabled: submit only after the grace period, once per kind, and move on to the next expired phase in protocol order.
func TestSweepDueDeadlinesSubmitsOncePerKind(t *testing.T) {
	sub := &fakeSubmitter{}
	f := newSweepTestFSM(sub)
	policy := DeadlineSweepPolicy{Enabled: true, GraceBlocks: 5}

	f.sweepDueDeadlines(policy, 104)
	if got := sub.sweepTxs(); len(got) != 0 {
		t.Fatalf("sweeps=%d at height 104, want 0 before the grace window closes", len(got))
	}

	f.sweepDueDeadlines(policy, 105)
	got := sub.sweepTxs()
	if len(got) != 1 || got[0].DeadlineKind != taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT {
		t.Fatalf("sweeps=%+v, want one VERIFY_COMMIT sweep", got)
	}
	if got[0].Submitter != f.self || got[0].TaskID != f.taskID {
		t.Fatalf("sweep tx=%+v, want the local builder and task", got[0])
	}

	f.sweepDueDeadlines(policy, 106)
	if got := sub.sweepTxs(); len(got) != 1 {
		t.Fatalf("sweeps=%d, want the same kind submitted only once", len(got))
	}

	f.sweepDueDeadlines(policy, 305)
	got = sub.sweepTxs()
	if len(got) != 2 || got[1].DeadlineKind != taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_FINAL {
		t.Fatalf("sweeps=%+v, want VERIFY_FINAL once its deadline passes", got)
	}
}

// A failed submission must allow a retry on the next block; it must not give up forever just because it was "recorded once".
func TestSweepDueDeadlinesRetriesAfterSubmitFailure(t *testing.T) {
	sub := &fakeSubmitter{sweepErr: errors.New("broadcast failed")}
	f := newSweepTestFSM(sub)
	policy := DeadlineSweepPolicy{Enabled: true}

	f.sweepDueDeadlines(policy, 100)
	sub.mu.Lock()
	sub.sweepErr = nil
	sub.mu.Unlock()
	f.sweepDueDeadlines(policy, 101)

	if got := sub.sweepTxs(); len(got) != 2 {
		t.Fatalf("sweeps=%d, want a retry on the next block after a failed submission", len(got))
	}
}

// newSweepTestFSM builds an FSM in Verifying for which the chain has already given commit/verify deadlines.
func newSweepTestFSM(sub Submitter) *taskFSM {
	return &taskFSM{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		self:      testBuilderSelf,
		submit:    sub,
		sessionID: "sess-sweep",
		taskID:    testTaskID("sweep"),
		state:     types.Verifying,
		deadlines: types.Deadlines{Commit: 100, Verify: 300},
	}
}

func TestOnInferReceiptRequiresFinalizedWinner(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_, _ = enableTestBuilderMessages(c)
	c.submit = &fakeSubmitter{}

	const session, task, winner = "sess-out", "task-out", "worker-1"
	ctx := context.Background()
	if err := trackTestOrder(c, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, winner, 101)

	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-2", []byte("h"))); err != ErrUnauthorized {
		t.Fatalf("wrong winner: want ErrUnauthorized, got %v", err)
	}
	if _, err := rl.Serve(session, task, types.AccessSealedKey); err == nil {
		t.Fatal("wrong-winner output ref must not be held in custody")
	}

	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, winner, []byte("h"))); err != nil {
		t.Fatalf("winner output ref: %v", err)
	}
	ref, err := rl.Serve(session, task, types.AccessSealedKey)
	if err != nil {
		t.Fatalf("winner output ref must be held: %v", err)
	}
	if ref.WorkerAddress != winner || string(ref.OutputHash) != "h" || len(ref.WorkerServiceSignature) == 0 {
		t.Fatalf("held receipt missing product fields: %+v", ref)
	}
}

func TestVerifierHandraiseMustMatchOutputMaterial(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sub := &fakeSubmitter{}
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	enableTestBuilderMessages(c)
	c.submit = sub

	const session, winner = "sess-bad-verifier", "worker-1"
	task := testTaskID("bad-verifier")
	ctx := context.Background()
	if err := trackTestOrder(c, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, winner, 101)
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, winner, []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	for _, cand := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		// The output commitment binds the wrong value: validVerifierHandraise must drop it at the entrance.
		hr := testVerifierHandraise(session, task, cand, []byte("wrong"), []byte("infer-receipt"))
		if err := c.HandleVerifierHandraise(ctx, cand, hr); err != nil {
			t.Fatalf("HandleVerifierHandraise: %v", err)
		}
	}
	// Putting the receipt on-chain is no longer triggered by hand-raises (it carries only receipt +
	// submitter, and waiting for hand-raises would deadlock), so what is guarded here is the
	// hand-raise itself: one binding the wrong output commitment must be dropped at the entrance,
	// not a single one accepted.
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}
	fsm.mu.Lock()
	accepted := len(fsm.verifierHR)
	fsm.mu.Unlock()
	if accepted != 0 {
		t.Fatalf("verifier handraises with wrong material were accepted: %d", accepted)
	}
	if len(sub.verifierHandraises) != 0 {
		t.Fatalf("verifier handraises with wrong material must not reach the chain, got %d", len(sub.verifierHandraises))
	}
}

func TestVerifyResultRequiresSelectedVerifierAndMaterial(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sub := &fakeSubmitter{}
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	_, _ = enableTestBuilderMessages(c)
	c.submit = sub

	const session = "sess-bad-result"
	task := testTaskID("bad-result")
	if err := trackTestOrder(c, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, "worker-1", 101)
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: []string{"verifier-1", "verifier-2"},
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	c.OnWorkerRevealAccepted(chaincli.WorkerRevealAccepted{SessionID: session, TaskID: task, Height: 300})
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing")
	}
	vals := [][]byte{[]byte("v0"), []byte("v1")}
	// Not a selected Verifier: refused as unauthorized.
	if _, err := fsm.relayVerifyResult(testVerifyResult(task, "stranger", vals)); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("stranger verify result: want ErrUnauthorized, got %v", err)
	}
	// Missing metric fields: refused as invalid.
	incomplete := testVerifyResult(task, "verifier-1", vals)
	incomplete.MetricRoot = nil
	if _, err := fsm.relayVerifyResult(incomplete); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("verify result without metric material: want ErrInvalidArgument, got %v", err)
	}
	// Unsupported verify round: refused as invalid.
	wrongRound := testVerifyResult(task, "verifier-1", vals)
	wrongRound.VerifyRound = 2
	if _, err := fsm.relayVerifyResult(wrongRound); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("verify result for an unsupported round: want ErrInvalidArgument, got %v", err)
	}
	if len(sub.verifyResults) != 0 {
		t.Fatalf("no invalid verify result may reach the chain, got %d", len(sub.verifyResults))
	}
	if len(fsm.verifyResults) != 0 {
		t.Fatalf("no invalid verify result may be recorded, got %d", len(fsm.verifyResults))
	}
	if len(sub.settle) != 0 {
		t.Fatalf("invalid verify results must not submit SettleTx, got %d", len(sub.settle))
	}
}

// TestSettleWaitsForChainNotResults: Verifier results are relayed but never gate settlement; the
// settlement waits for the chain to report the task ready. The public request carries only
// task_id + submitter_address, and no Worker reveal is needed.
func TestSettleWaitsForChainNotResults(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sub := &fakeSubmitter{}
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	enableTestBuilderMessages(c)
	c.submit = sub

	const session, task = "sess-fr", "4444444444444444444444444444444444444444444444444444444444444444"
	ctx := context.Background()
	if err := trackTestOrder(c, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	// Advance to Verifying.
	recordTestWinner(c, session, task, "worker-1", 101)
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	settleVerifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: settleVerifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	c.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("sample-seed"), Height: 210})
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing before settle selection")
	}
	fsm.mu.Lock()
	fsm.settleSelection = settleSelection(session, task, testBuilderSelf)
	fsm.settleGraceBlocks = rankGraceBlocks
	fsm.mu.Unlock()

	vi := [][]byte{[]byte("v0")}
	other := [][]byte{[]byte("v0-other")}
	relayTestVerifyResult(t, c, session, task, testVerifyResult(task, settleVerifiers[0], vi))
	relayTestVerifyResult(t, c, session, task, testVerifyResult(task, settleVerifiers[1], other))
	relayTestVerifyResult(t, c, session, task, testVerifyResult(task, settleVerifiers[2], vi))
	if len(sub.verifyResults) != 3 {
		t.Fatalf("expected 3 relayed MsgSubmitVerifyResult, got %d", len(sub.verifyResults))
	}
	c.onNewBlock(4)
	if len(sub.settle) != 0 {
		t.Fatalf("SettleTx must wait for the chain to report the task ready, got %d", len(sub.settle))
	}
	markSettleReady(fsm, 0)
	if len(sub.settle) != 1 {
		t.Fatalf("expected 1 SettleTx once the chain reports the task ready, got %d", len(sub.settle))
	}
	if sub.settle[0].TaskID != task || sub.settle[0].Submitter != testBuilderSelf {
		t.Fatalf("SettleTx mismatch: %+v", sub.settle[0])
	}
	fsm.mu.Lock()
	revealed := fsm.workerRevealed
	fsm.mu.Unlock()
	if revealed {
		t.Fatal("no worker reveal was observed; the flag must stay false and must not gate settlement")
	}
}

func assertState(t *testing.T, c *Coordinator, session, task string, want types.TaskState) {
	t.Helper()
	st, err := c.TaskStatus(context.Background(), session, task)
	if err != nil {
		t.Fatalf("TaskStatus: %v", err)
	}
	if st.State != want.String() {
		t.Fatalf("state = %s, want %s", st.State, want.String())
	}
}

func assertPhase(t *testing.T, c *Coordinator, session, task string, want types.TaskPhase) {
	t.Helper()
	st, err := c.TaskStatus(context.Background(), session, task)
	if err != nil {
		t.Fatalf("TaskStatus: %v", err)
	}
	if st.TaskPhase != want.String() {
		t.Fatalf("task_phase = %s, want %s", st.TaskPhase, want.String())
	}
}
