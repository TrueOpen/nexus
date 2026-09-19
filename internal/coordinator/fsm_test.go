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

	wirebus "github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// fakeSubmitter records the three phases of submitted Tx for assertions.
type fakeSubmitter struct {
	mu           sync.Mutex
	settleErr    error
	assign       []chaincli.AssignTx
	assignResult chaincli.TxResult
	assignErr    error
	openVerify   []chaincli.OpenVerifyTx
	settle       []chaincli.SettleTx
	sweep        []chaincli.SweepDeadlineTx
	sweepErr     error

	verifierHandraises    []chaincli.OpenVerifyTx
	verifierHandraisesErr error
	verifyResults         []chaincli.VerifyResultTx
	verifyCommits         []chaincli.VerifyCommitTx
	verifyCommitErr       error
	verifyResultErr       error
}

type jsHandlerCaptureBus struct {
	msgbus.Bus
	handler msgbus.MsgHandler
}

func (b *jsHandlerCaptureBus) JSSubscribe(_ string, _ string, h msgbus.MsgHandler) (msgbus.Unsubscribe, error) {
	b.handler = h
	return func() {}, nil
}

func TestJSSubscribeRejectsDeliveryAfterFSMShutdown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := &jsHandlerCaptureBus{Bus: msgbus.NewStub(log, nil)}
	fsm := &taskFSM{bus: bus}
	fsm.jsSubscribe("subject", "durable", func([]byte) error { return nil })
	fsm.shutdown()
	if err := bus.handler("subject", []byte("message")); err == nil {
		t.Fatal("JetStream handler acknowledged a message rejected during shutdown")
	}
}

// TestPublishRefusesFramesItCannotSign locks in the core constraint of gh #45: when a
// compliant frame cannot be signed, the only correct behaviour is not to send; there is no
// dev fallback of "send one without a signature first".
func TestPublishRefusesFramesItCannotSign(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	task := testTaskID("encode-refusal")

	t.Run("no service key", func(t *testing.T) {
		bus := msgbus.NewStub(log, nil)
		sent := &captured{}
		mustSub(t, bus, msgbus.SubjectVerifyOpen(task), sent)
		fsm := &taskFSM{
			log: log, bus: bus, chainID: testChainID, self: testBuilderSelf,
			sessionID: "session-1", taskID: task,
		}
		if err := fsm.publish(msgbus.SubjectVerifyOpen(task), wirebus.KindOpenVerify,
			&busv1.OpenVerifyV1{}, busadapter.TierCore); err != nil {
			t.Fatalf("missing service key must not fail the task, got %v", err)
		}
		if sent.count() != 0 {
			t.Fatal("an unsigned frame reached the bus")
		}
	})

	t.Run("prepare without service key", func(t *testing.T) {
		bus := msgbus.NewStub(log, nil)
		sent := &captured{}
		mustSub(t, bus, msgbus.SubjectBuilderPrepare(task), sent)
		fsm := &taskFSM{
			log: log, bus: bus, chainID: testChainID, self: testBuilderSelf,
			sessionID: "session-1", taskID: task,
			prepares: &prepareCodec{log: log, chainID: testChainID},
		}
		fsm.publishPrepare()
		if sent.count() != 0 {
			t.Fatal("an unsigned prepare notice reached the bus")
		}
	})
}

func (s *fakeSubmitter) SubmitAssign(_ context.Context, tx chaincli.AssignTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	s.assign = append(s.assign, tx)
	s.mu.Unlock()
	return s.assignResult, s.assignErr
}

func (s *fakeSubmitter) SubmitOpenVerify(_ context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	s.openVerify = append(s.openVerify, tx)
	s.mu.Unlock()
	return chaincli.TxResult{Code: 0}, nil
}

func (s *fakeSubmitter) SubmitVerifierHandraises(_ context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifierHandraisesErr != nil {
		return chaincli.TxResult{}, s.verifierHandraisesErr
	}
	s.verifierHandraises = append(s.verifierHandraises, tx)
	return chaincli.TxResult{Code: 0}, nil
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

// captured collects the messages a test subscribed to on some subject (payload decoded).
type captured struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (c *captured) add(data []byte) {
	c.mu.Lock()
	c.msgs = append(c.msgs, append([]byte(nil), data...))
	c.mu.Unlock()
}

func (c *captured) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func (c *captured) last() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return nil
	}
	return c.msgs[len(c.msgs)-1]
}

// testInferReceipt builds a signed InferReceipt in the frozen §5.14 shape. The field set is
// exactly that one:
// token_count / work_unit were removed from the wire and are now carried by typed evidence commitments.
//
// task must be a canonical lowercase 64-hex Hash32: when the coordinator assembles
// MsgSubmitInferReceipt it decodes task_id / task_hash into raw 32 bytes.
func testInferReceipt(session, task, worker string, outputHash []byte) types.InferReceiptSubmission {
	taskHash := sha256.Sum256([]byte("task-hash-" + task))
	paramsDigest := sha256.Sum256([]byte("generation-params-" + task))
	evidenceHash := sha256.Sum256([]byte("worker-value-opening-" + task))
	return types.InferReceiptSubmission{
		SessionID:                 session,
		SchemaVersion:             nodecontract.InferReceiptSchemaVersionV2,
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
		WorkerServiceSignature: []byte("worker-service-signature"),
		InferReceiptHash:       []byte("infer-receipt"),
	}
}

// testTaskID builds a task_id in its real shape. In the frozen contract task_id / task_hash
// are both Hash32 and only 64 lowercase hex characters pass wire validation; in production it
// comes from nodecontract.DeriveTaskIDFromRawSession, and tests can no longer run the
// submission path with a fake ID like "task-1".
func testTaskID(name string) string {
	sum := sha256.Sum256([]byte("test-task-id|" + name))
	return hex.EncodeToString(sum[:])
}

// testUserAddress is the test address of the ordering user. It must be **canonical bech32**:
// the preimage framing of task_hash frames the address-codec bytes of user_address
// (§1.2 / adjudication 24), and task_hash cannot be computed if they cannot be decoded. The
// testUserAddress of the old fixture was not valid bech32, which did not matter before gh #42
// (the order identity was sha256(envelope) then and ignored the address); now it gets the
// whole order rejected at ingress.
// Value = bech32("trueopen", 20 × 0x11).
const testUserAddress = "trueopen1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rsxm9a"

func testHash32(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// testPlaceholderTaskHash gives the cases that "only need a task to exist" (event reconcile,
// snapshot recovery, etc.) a candidate task_hash of valid shape. Since gh #42 an order must
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
		ModelID: "m", PayloadCID: "cid", SignedOrder: testSignedOrderBytes(testUserAddress),
	}
}

// testCanonicalTaskHash is the canonical task_hash (gh #42) of the frozen TaskOrderV2 in
// testSignedOrder. Any case that has to run "broadcast → hand-raise → on-chain" must use it for
// the order, the hand-raise and the proposal scope alike -- a mismatch between the three means
// fail-closed took effect, not a fixture coincidence.
func testCanonicalTaskHash(user string) string {
	hash, err := nodecontract.TaskOrderHashHexV2(testSignedOrder(user).GetOrder())
	if err != nil {
		panic(err)
	}
	return hash
}

// testSignature64 builds a 64-byte compact signature placeholder. Nexus only checks
// length/encoding and passes it through; signature verification is in the Keeper, and digest
// framing belongs to gh #24.
func testSignature64(parts ...string) string {
	return testHash32(append([]string{"lo"}, parts...)...) + testHash32(append([]string{"hi"}, parts...)...)
}

// testSignedOrderBytes reuses the §5.13 fixture of submitter_test to give the proto-encoded
// SignedOrderV2 that the SDK side should submit. It is the only legitimate carrier of the
// first-proposal scope branch of MsgSubmitWorkerHandraises, and in production it can only be
// supplied by the SDK (the user signs the frozen TaskOrderV2, which Nexus has no right to
// reconstruct).
func testSignedOrderBytes(user string) []byte {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(testSignedOrder(user))
	if err != nil {
		panic(err)
	}
	return raw
}

func testCurrentOrder(session, task, user string) types.Order {
	envelope := nodecontract.AssignmentOrderEnvelopeV1{
		SchemaVersion: nodecontract.OrderEnvelopeSchemaV1, ModelID: "model-1", ProfileVersion: 2, TaskType: "inference",
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
	// compared against it (gh #42).
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

// testWorkerSlots gives candidate addresses a stable slot. §4.2.2 requires handraises within
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

// testWorkerHandraise builds a Worker hand-raise in the frozen wire shape (proto body).
func testWorkerHandraise(session, task, candidate string) *taskv1.WorkerHandraiseV1 {
	order := testCurrentOrder(session, task, testUserAddress)
	snapshotID := sha256.Sum256([]byte("candidate-pool-snapshot|" + session + "|" + task))
	return &taskv1.WorkerHandraiseV1{
		SchemaVersion: 1,
		ChainId:       testChainID,
		TaskId:        mustHex32(task),
		// The hand-raise echoes the candidate task_hash from the broadcast verbatim: building a
		// different value gets it dropped on the spot by validWorkerHandraise (gh #42 acceptance 6).
		TaskHash:       mustHex32(order.TaskHash),
		ModelId:        order.ModelID,
		ProfileVersion: order.ProfileVersion,
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: snapshotID[:],
			Slot:                    testWorkerSlot(candidate),
			SlotVersion:             1,
			OperatorAddress:         candidate,
		},
		Duty:                      sharedv1.Duty_DUTY_WORKER,
		ServiceAuthorizationNonce: 7,
		ExpiryHeight:              1000,
		ServiceSignature:          testSignatureBytes64("service-signature", task, candidate),
	}
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
		ModelId:          "model-1",
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

// testVerifyResult builds a verification result receipt in the frozen wire shape (contract §5.11).
// The metric fields are derived deterministically from vals: same vals → same metric_root /
// summary (consistent), otherwise inconsistent; result_reveal_hash, by contrast, always differs
// per node.
func testVerifyResult(task, verifier string, vals [][]byte) *taskv1.ResultReceiptV2 {
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
	return &taskv1.ResultReceiptV2{
		SchemaVersion:             nodecontract.ResultReceiptSchemaVersionV2,
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

// TestHappyPath walks one order's complete happy path (v1.5 two-phase + seed afterwards):
// order → 3×worker handraise → AssignTx → AssignAccepted(randomness pending, no start-work) →
// AssignmentFinalized(winner determined → start-work notification) → result reference →
// 3×verifier handraise → OpenVerifyTx → OpenVerifyAccepted(no seed) →
// on-chain SampleReady (seed recorded only; v1 has no matching subject) → 2×consistent V_i →
// WorkerRevealReceiptAccepted → SettleTx → SettleAccepted → challenge window → Closed.
func TestHappyPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	rl := relay.NewMem(log)
	sub := &fakeSubmitter{}

	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub // inject the fake submitter

	const (
		session = "sess-1"
		model   = "model-1"
		winner  = "worker-1"
	)
	// task_id must have its real shape, or WorkerHandraiseV1 cannot be assembled.
	task := testTaskID("task-1")
	ctx := context.Background()

	// Observe the four contract subjects nexus will publish on.
	orders := &captured{}
	assign := &captured{}
	verifySelect := &captured{}
	openVerify := &captured{}
	mustSub(t, bus, msgbus.SubjectTaskOpen(model), orders)
	mustSub(t, bus, msgbus.SubjectWorkerAssignment(task), assign)
	mustSub(t, bus, msgbus.SubjectVerifierAssignment(task), verifySelect)
	mustSub(t, bus, msgbus.SubjectVerifyOpen(task), openVerify)

	// 1) Place the order → Pending + broadcast the order.
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	if orders.count() != 1 {
		t.Fatalf("expected 1 OrderBroadcast, got %d", orders.count())
	}
	orderEnvelope := decodeTestEnvelope(t, orders.last())
	assertContractEnvelope(t, orderEnvelope, msgbus.SubjectTaskOpen(model), wirebus.KindOrderBroadcast)
	ob := decodeTestPayload[busv1.OrderBroadcastV1](t, orders.last())
	// The broadcast carries only the complete user-signed order; task_hash is recomputed by the receiver from signed_order.order.
	rebroadcastHash, err := nodecontract.TaskOrderHashHexV2(ob.GetSignedOrder().GetOrder())
	if err != nil {
		t.Fatalf("recompute task_hash from broadcast: %v", err)
	}
	if rebroadcastHash != testCanonicalTaskHash(testUserAddress) {
		t.Fatalf("OrderBroadcast signed order does not derive the canonical task_hash")
	}
	if ob.GetSignedOrder().GetOrder().GetModelId() != model {
		t.Fatalf("OrderBroadcast model mismatch: %+v", ob)
	}
	assertState(t, c, session, task, types.Pending)

	// 2) 3 Workers hand-raise → trigger AssignTx.
	for _, cand := range []string{testOperator("worker-1"), testOperator("worker-2"), testOperator("worker-3")} {
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, cand))
	}
	if len(sub.assign) != 1 {
		t.Fatalf("expected 1 AssignTx, got %d", len(sub.assign))
	}
	// What goes on-chain is the Cortex-signed proto hand-raise body; there are no string copies any more.
	// §5.5: one proposal needs only 1 hand-raise: the first arrival proposes.
	if sub.assign[0].SessionID != session || sub.assign[0].TaskID != task ||
		len(sub.assign[0].WorkerHandraises) != proposalHandraiseMin {
		t.Fatalf("AssignTx mismatch: %+v", sub.assign[0])
	}

	// 3a) AssignTx included (first of two phases): winner undecided → still Pending, no start-work notification.
	c.OnAssignAccepted(chaincli.AssignAccepted{
		SessionID: session, TaskID: task,
		AssignedSet: []types.BuilderRef{{Address: testBuilderSelf, Endpoint: "https://b/1"}},
		Height:      100,
	})
	assertState(t, c, session, task, types.Pending)
	assertPhase(t, c, session, task, types.PhaseAssignRandomnessPending)
	if assign.count() != 0 {
		t.Fatalf("AssignNotify must NOT fire before AssignmentFinalized, got %d", assign.count())
	}

	// 3b) randomness settled (second of two phases) → Assigned + start-work notification (with winner/finalized_height).
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
		SessionID: session, TaskID: task, Winner: winner, AssignSeed: []byte("assign-seed"), Height: 101,
		InferDeadlineHeight: 260,
	})
	assertState(t, c, session, task, types.Assigned)
	if assign.count() != 1 {
		t.Fatalf("expected 1 AssignNotify, got %d", assign.count())
	}
	assignEnvelope := decodeTestEnvelope(t, assign.last())
	assertContractEnvelope(t, assignEnvelope, msgbus.SubjectWorkerAssignment(task),
		wirebus.KindWorkerAssignmentNotify)
	if assignEnvelope.GetMessageId() == orderEnvelope.GetMessageId() {
		t.Fatalf("reused message_id %q", assignEnvelope.GetMessageId())
	}
	if bytes.Equal(assignEnvelope.GetNonce(), orderEnvelope.GetNonce()) {
		t.Fatal("reused envelope nonce")
	}
	an := decodeTestPayload[busv1.WorkerAssignmentNotifyV1](t, assign.last())
	if an.GetWinnerOperatorAddress() != winner || an.GetFinalizedHeight() != 101 ||
		!bytes.Equal(an.GetAssignSeed(), []byte("assign-seed")) ||
		an.GetInferDeadlineHeight() != 260 {
		t.Fatalf("AssignNotify mismatch: %+v", an)
	}
	if !bytes.Equal(an.GetTaskId(), mustHex32(task)) {
		t.Fatalf("AssignNotify task binding mismatch: %+v", an)
	}

	// 4) The Worker returns the result reference (→ escrow + record the three hash/cid values).
	outputHash := []byte("output-root-hash")
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, winner, outputHash)); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}

	// 5) 3 Verifiers hand-raise → trigger OpenVerifyTx (output_hash = outputHash).
	for _, cand := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectVerifierHandraiseV1(task),
			wirebus.KindVerifierHandraise,
			testVerifierHandraise(session, task, cand, outputHash, []byte("infer-receipt")))
	}
	if len(sub.openVerify) != 1 {
		t.Fatalf("expected 1 OpenVerifyTx, got %d", len(sub.openVerify))
	}
	// OpenVerifyTx carries only the InferReceipt body (§10.3 MsgSubmitInferReceipt);
	// the string copies of the old MsgOpenVerify are gone.
	submitted := sub.openVerify[0].InferReceipt
	if submitted == nil {
		t.Fatal("OpenVerifyTx.InferReceipt must be populated")
	}
	if !bytes.Equal(submitted.GetOutputHash(), outputHash) {
		t.Fatalf("InferReceipt.output_hash mismatch: %x", submitted.GetOutputHash())
	}
	if hex.EncodeToString(submitted.GetTaskId()) != task ||
		submitted.GetSchemaVersion() != nodecontract.InferReceiptSchemaVersionV2 ||
		submitted.GetChainId() != testChainID || submitted.GetServiceAuthorizationNonce() == 0 ||
		submitted.GetExpiryHeight() == 0 || len(submitted.GetGenerationParamsDigest()) != 32 ||
		len(submitted.GetRequiredEvidenceCommitments()) != 1 {
		t.Fatalf("InferReceipt is not the frozen InferReceiptV2 shape: %+v", submitted)
	}

	// 6a) On-chain open-verify included → Verifying + open-verify notification (v1.5: no seed, with package hash).
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	assertState(t, c, session, task, types.Verifying)
	assertPhase(t, c, session, task, types.PhaseOpenVerify)
	if verifySelect.count() != 1 {
		t.Fatalf("expected 1 VerifySelectNotify, got %d", verifySelect.count())
	}
	vs := decodeTestPayload[busv1.VerifierAssignmentNotifyV1](t, verifySelect.last())
	if len(vs.GetVerifiers()) != 3 || !bytes.Equal(vs.GetOutputHash(), outputHash) || vs.GetOpenVerifyHeight() != 200 {
		t.Fatalf("VerifySelectNotify mismatch: %+v", vs)
	}
	// 6b) On-chain SampleReady: record only the seed and phase. Contract §5.1 has no
	// trueopen.sample-ready.*, and §5.9 states the notification carries no verification position
	// selection data, so this notification no longer goes on NATS.
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

	// 7) 2 consistent V_i → SettleTx directly. Normal verification no longer has a Worker reveal
	// step (04 Task Execution, Verification and Settlement §9); the Worker's commitment is already
	// locked by the accepted InferReceipt.
	// The two receipts' result_reveal_hash values differ (each salted); consistency looks only at the re-execution results.
	vi := [][]byte{[]byte("v0"), []byte("v1")}
	publishEnvelope(t, bus, keys, verifiers[0], msgbus.SubjectVerifyResultV1(task),
		wirebus.KindVerifyResult, testVerifyResult(task, verifiers[0], vi))
	if len(sub.settle) != 0 {
		t.Fatalf("SettleTx must wait for a second consistent result, got %d", len(sub.settle))
	}
	publishEnvelope(t, bus, keys, verifiers[1], msgbus.SubjectVerifyResultV1(task),
		wirebus.KindVerifyResult, testVerifyResult(task, verifiers[1], vi))
	if len(sub.verifyResults) != 2 {
		t.Fatalf("expected 2 relayed MsgSubmitVerifyResult, got %d", len(sub.verifyResults))
	}
	if sub.verifyResults[0].Submitter != testBuilderSelf ||
		!proto.Equal(sub.verifyResults[0].Receipt, testVerifyResult(task, verifiers[0], vi)) {
		t.Fatalf("relayed receipt was not forwarded verbatim: %+v", sub.verifyResults[0])
	}
	// §10.10a: settlement is only sent in the window after the reveal deadline, and the public
	// request carries only task_id + submitter_address; verdict/receipt references/evidence root
	// are Keeper-derived.
	if len(sub.settle) != 0 {
		t.Fatalf("SettleTx must wait for the settlement window, got %d", len(sub.settle))
	}
	c.onNewBlock(4)
	if len(sub.settle) != 1 {
		t.Fatalf("expected 1 SettleTx after two consistent results, got %d", len(sub.settle))
	}
	// 8) The Worker reveal event does not exist in the frozen contract; even if it arrives it is only recorded and triggers no second transaction.
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
	if string(held.InferReceiptHash) != "infer-receipt" || held.WorkerAddress == "" {
		t.Fatalf("custody must hold the signed InferReceipt: %+v", held)
	}
	// The contract's "target state baseline" removed sealed key delivery: tiers no longer change the returned content.
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
	bus := msgbus.NewStub(log, nil)
	rl := relay.NewMem(log)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_ = enableTestBusEnvelopes(c)
	c.submit = &fakeSubmitter{}

	const session, task = "sess-sw", "task-sw"
	ctx := context.Background()
	if err := c.OnOrder(ctx, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
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
	bus := msgbus.NewStub(log, nil)
	rl := relay.NewMem(log)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_ = enableTestBusEnvelopes(c)
	c.submit = &fakeSubmitter{}

	const session, task = "sess-sw-live", "task-sw-live"
	if err := c.OnOrder(context.Background(), testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
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
	bus := msgbus.NewStub(log, nil)
	rl := relay.NewMem(log)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID)
	_ = enableTestBusEnvelopes(c)
	c.submit = &fakeSubmitter{}

	const session, task, winner = "sess-out", "task-out", "worker-1"
	ctx := context.Background()
	if err := c.OnOrder(ctx, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: winner, Height: 101})

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

func TestWorkerHandraiseRequiresSignedMaterial(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	sub := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub

	const session = "sess-bad-worker"
	task := testTaskID("bad-worker")
	if err := c.OnOrder(context.Background(), testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	for _, cand := range []string{testOperator("worker-1"), testOperator("worker-2"), testOperator("worker-3")} {
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise,
			// Carries only task_id and member.operator_address: every other frozen required field is
			// missing, so validWorkerHandraise must drop it at the entrance.
			&taskv1.WorkerHandraiseV1{
				TaskId: mustHex32(task),
				Member: &taskv1.CandidateMemberRefV1{OperatorAddress: cand},
			})
	}
	if len(sub.assign) != 0 {
		t.Fatalf("malformed worker handraises must not submit AssignTx, got %d", len(sub.assign))
	}
}

func TestVerifierHandraiseMustMatchOutputMaterial(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	sub := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub

	const session, winner = "sess-bad-verifier", "worker-1"
	task := testTaskID("bad-verifier")
	ctx := context.Background()
	if err := c.OnOrder(ctx, testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: winner, Height: 101})
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, winner, []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	for _, cand := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		// The output commitment binds the wrong value: validVerifierHandraise must drop it at the entrance.
		hr := testVerifierHandraise(session, task, cand, []byte("wrong"), []byte("infer-receipt"))
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectVerifierHandraiseV1(task),
			wirebus.KindVerifierHandraise, hr)
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
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	_ = enableTestBusEnvelopes(c)
	c.submit = sub

	const session = "sess-bad-result"
	task := testTaskID("bad-result")
	if err := c.OnOrder(context.Background(), testPlaceholderOrder(session, task)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1", Height: 101})
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
	// Not a selected Verifier: drop and do not redeliver.
	if err := fsm.onVerifyResult(testVerifyResult(task, "stranger", vals)); err != nil {
		t.Fatalf("stranger verify result should be dropped without retry: %v", err)
	}
	// Missing metric fields: drop and do not redeliver.
	incomplete := testVerifyResult(task, "verifier-1", vals)
	incomplete.MetricRoot = nil
	if err := fsm.onVerifyResult(incomplete); err != nil {
		t.Fatalf("verify result without metric material should be dropped without retry: %v", err)
	}
	// Unsupported verify round: drop and do not redeliver.
	wrongRound := testVerifyResult(task, "verifier-1", vals)
	wrongRound.VerifyRound = 2
	if err := fsm.onVerifyResult(wrongRound); err != nil {
		t.Fatalf("verify result for an unsupported round should be dropped without retry: %v", err)
	}
	if len(fsm.verifyResults) != 0 {
		t.Fatalf("no invalid verify result may be recorded, got %d", len(fsm.verifyResults))
	}
	if len(sub.settle) != 0 {
		t.Fatalf("invalid verify results must not submit SettleTx, got %d", len(sub.settle))
	}
}

// TestSettleWaitsForConsistentResultsAndReveals: 2 consistent V_i + 1 Verifier self-rescuing via
// FullResultRevealTx + Worker reveal → submit SettleTx. The public request of §10.10a carries only
// task_id + submitter_address; receipt references and self-rescue references are derived by the
// Keeper from authoritative state.
// The only settlement precondition is "≥2 consistent re-execution results":
//   - result_reveal_hash differs per node (each salted) and must not enter the grouping key (nexus#71);
//   - the Worker reveal does not exist in the frozen contract and must not be a hard precondition (nexus#72).
func TestSettleWaitsForConsistentResultsOnly(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	sub := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub

	const session, task = "sess-fr", "4444444444444444444444444444444444444444444444444444444444444444"
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	// Advance to Verifying.
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1", Height: 101})
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
	// 1 receipt: no settlement.
	publishEnvelope(t, bus, keys, settleVerifiers[0], msgbus.SubjectVerifyResultV1(task),
		wirebus.KindVerifyResult, testVerifyResult(task, settleVerifiers[0], vi))
	if len(sub.settle) != 0 {
		t.Fatalf("one result must not settle, got %d", len(sub.settle))
	}
	// The 2nd has different re-execution results: still no settlement.
	publishEnvelope(t, bus, keys, settleVerifiers[1], msgbus.SubjectVerifyResultV1(task),
		wirebus.KindVerifyResult, testVerifyResult(task, settleVerifiers[1], other))
	if len(sub.settle) != 0 {
		t.Fatalf("two inconsistent results must not settle, got %d", len(sub.settle))
	}
	// The 3rd matches the 1st's results (reveal hashes still differ): settle, and no Worker reveal is needed.
	publishEnvelope(t, bus, keys, settleVerifiers[2], msgbus.SubjectVerifyResultV1(task),
		wirebus.KindVerifyResult, testVerifyResult(task, settleVerifiers[2], vi))
	if len(sub.verifyResults) != 3 {
		t.Fatalf("expected 3 relayed MsgSubmitVerifyResult, got %d", len(sub.verifyResults))
	}
	if r0, r2 := sub.verifyResults[0].Receipt, sub.verifyResults[2].Receipt; bytes.Equal(r0.GetVerifierEvidenceBundleHash(), r2.GetVerifierEvidenceBundleHash()) ||
		!bytes.Equal(r0.GetMetricRoot(), r2.GetMetricRoot()) {
		t.Fatalf("fixture must differ in verifier_evidence_bundle_hash and agree on metric_root")
	}
	if len(sub.settle) != 0 {
		t.Fatalf("SettleTx must wait for the settlement window, got %d", len(sub.settle))
	}
	c.onNewBlock(4)
	if len(sub.settle) != 1 {
		t.Fatalf("expected 1 SettleTx after two consistent results without any worker reveal, got %d", len(sub.settle))
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

func mustSub(t *testing.T, bus msgbus.Bus, subject string, cap *captured) {
	t.Helper()
	if _, err := bus.Subscribe(subject, func(_ string, data []byte) error {
		cap.add(data)
		return nil
	}); err != nil {
		t.Fatalf("subscribe %s: %v", subject, err)
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

// The relay semantics of onVerifyResult: transient failure Nak for redelivery, definitive
// rejection Ack and drop, redelivery of the same receipt passes idempotently without a second
// on-chain submission.
func TestVerifyResultRelaySemantics(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	task := testTaskID("vr-relay")
	verifier := testOperator("vr-relay-verifier")
	sub := &fakeSubmitter{}
	fsm := &taskFSM{
		log: log, chainID: testChainID, self: testBuilderSelf,
		sessionID: "session-1", taskID: task,
		state: types.Verifying, verifiers: []string{verifier},
		verifyResults: map[string]*taskv1.ResultReceiptV2{},
		submit:        sub,
	}
	receipt := testVerifyResult(task, verifier, [][]byte{[]byte("v0")})

	// Transient failure: not stored locally, error propagated (JetStream Naks for redelivery).
	sub.verifyResultErr = errors.New("broadcast timeout")
	if err := fsm.onVerifyResult(receipt); err == nil {
		t.Fatal("transient relay failure must surface for redelivery")
	}
	if len(fsm.verifyResults) != 0 {
		t.Fatal("receipt stored before chain accepted it")
	}

	// Redelivery after recovery: submitted on-chain once and stored locally.
	sub.verifyResultErr = nil
	if err := fsm.onVerifyResult(receipt); err != nil {
		t.Fatalf("relay after recovery: %v", err)
	}
	if len(sub.verifyResults) != 1 || len(fsm.verifyResults) != 1 {
		t.Fatalf("submitted=%d stored=%d, want 1/1", len(sub.verifyResults), len(fsm.verifyResults))
	}

	// The same receipt again (redelivery after a lost Ack): passes idempotently without a second on-chain submission.
	if err := fsm.onVerifyResult(receipt); err != nil {
		t.Fatalf("idempotent redelivery: %v", err)
	}
	if len(sub.verifyResults) != 1 {
		t.Fatalf("duplicate receipt was resubmitted, %d submissions", len(sub.verifyResults))
	}

	// Definitive rejection: Ack and drop, not stored locally.
	other := testOperator("vr-relay-verifier-2")
	fsm.verifiers = append(fsm.verifiers, other)
	sub.verifyResultErr = &SubmissionError{Definitive: true, Err: errors.New("signature digest mismatch")}
	if err := fsm.onVerifyResult(testVerifyResult(task, other, [][]byte{[]byte("v1")})); err != nil {
		t.Fatalf("definitive rejection must be acked, got %v", err)
	}
	if len(fsm.verifyResults) != 1 {
		t.Fatal("definitively rejected receipt was stored")
	}
}
