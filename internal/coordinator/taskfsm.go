package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

var errTaskFSMStopping = errors.New("coordinator: task FSM stopping")

// taskFSM is the per-order state machine instance (Detailed Design §3). One per order;
// events are routed by the coordinator into the matching instance, which serializes
// them with its own mutex, so orders never interfere with one another.
// v1.5 happy path: Pending(RANDOMNESS_PENDING)→Assigned(FINALIZED)→
// Verifying(OPEN_VERIFY→SAMPLE_READY→…)→Settled→Closed; sweep events can converge from any phase.
type taskFSM struct {
	mu sync.Mutex

	log *slog.Logger
	bus msgbus.Bus
	// publisher/receiver are the send/receive ports for TRUEOPEN_BUS_ENVELOPE_V2 envelopes
	// (shared by the coordinator, see buswiring.go). nil = service key not configured: when
	// a compliant frame cannot be signed, the only correct behaviour is not to send, and
	// inbound frames are treated as chain-lookup-unavailable.
	publisher *busadapter.Publisher
	receiver  *busadapter.Receiver
	prepares  *prepareCodec // issue/verify Builder↔Builder prepare announcements (prepare.go)
	submit    Submitter
	relay     relay.Custodian
	self      string // this node's builder address (envelope sender / AssignTx submitter)
	chainID   string // Task Chain ID (envelope field 2, prevents cross-chain replay)

	sessionID      string
	taskID         string
	modelID        string
	profileVersion uint32
	payloadCID     string
	user           string // ordering user's address (SDK envelope signer; SEALED_KEY retrieval authorization)
	deadline       int64
	priceHint      string
	builderSet     []types.BuilderRef // candidate Builder group coordinating this order (with endpoints)
	order          types.Order

	state types.TaskState
	phase types.TaskPhase // fine-grained phase (v1.5 §0.1), drives the external task_phase
	// terminal records that this FSM already crossed its irreversible local
	// cleanup boundary, including StageSettle sweeps whose coarse state is Settled.
	terminal bool

	events *journal // per-task event log (GetTaskEvents); owned by the coordinator, kept after close

	// Hand-raise / verification-result collection buffers (deduplicated by sender). They hold the
	// proto message bodies of the frozen wire: whatever bytes Cortex signed are the bytes
	// the Builder submits, with no second declaration (gen/bus/v1).
	workerHR   map[string]*taskv1.WorkerHandraiseV1
	verifierHR map[string]*taskv1.VerifierHandraiseV1
	// verifierHRProposed: hand-raisers already broadcast via MsgSubmitVerifierHandraises
	// (passed CheckTx). Later proposals carry only hand-raises not in here; persisted with
	// the snapshot, see taskSnapshot.VerifierHandraisesProposed.
	verifierHRProposed map[string]bool
	// verifierHRExcluded: hand-raisers the chain refused on their own when this Builder
	// simulated its proposal, keyed to the epoch of that refusal. They are not simulated again
	// until the epoch changes, when bond, support and scoring may have changed; a refusal is
	// not taken as final.
	verifierHRExcluded map[string]uint64
	verifyResults      map[string]*taskv1.ResultReceiptV2
	// verifyCommits: Verifier commits already relayed on-chain (by Verifier address), for idempotent dedup.
	verifyCommits map[string]*taskv1.VerifyCommitV1
	fullReveals   map[string]bool // Verifiers that already self-rescued on-chain via FullResultRevealTx
	// workerRevealed: on-chain Worker reveal. The frozen contract has no such Msg / Event,
	// so it is always false in Phase 0; kept only as "record if present", no longer a
	// settlement precondition.
	workerRevealed bool

	// acceptedTaskHash is the authoritative on-chain task_hash (only from query/event;
	// Nexus never creates it). Non-empty means the task has been accepted, and later Worker
	// proposals must take the ExistingTaskRefV1 branch instead of carrying signed_order
	// again (§4.2.1).
	acceptedTaskHash []byte
	// assignRetries counts filtered resubmissions after an invalid-assignment rejection.
	assignRetries int

	// Per-phase dedup: once a phase's Tx is submitted it is not reassembled (the chain has its own idempotency fallback).
	assignSubmitted     bool
	assignTxHash        []byte
	openVerifySubmitted bool
	// receiptOnChain: the chain has accepted this InferReceipt. OPEN_VERIFY may only be sent
	// after it is true (§5.8): a Verifier queries the chain as soon as it receives the
	// message and cannot hand-raise without an on-chain receipt, while OPEN_VERIFY is Core
	// tier and sent once. At least one block lies between accepting the receipt locally and
	// the transaction being included.
	receiptOnChain bool
	// acceptedOutputHash / acceptedReceiptHash come from the chain's accepted InferReceipt when
	// this Builder did not receive the signed receipt (see acceptedReceiptHashesLocked).
	acceptedOutputHash  []byte
	acceptedReceiptHash []byte
	openVerifyPublished bool // OPEN_VERIFY already sent by this process; reconcile reruns do not resend
	// resultReadiness answers local data-ready (04 §326); dataReady caches a positive answer.
	// Neither is persisted: the answer is derived from task data storage. The question is asked
	// off the FSM lock (checkDataReady), since storage can be held by a sweep for a long time;
	// dataReadyChecking marks one in flight and dataReadyRecheck asks it to run once more.
	resultReadiness   ResultReadiness
	dataReady         bool
	dataReadyChecking bool
	dataReadyRecheck  bool
	// settleSubmittedHeight is the chain height at which this node last sent a settlement
	// transaction (0 = not sent this round). A "submitted" boolean is not used: a tx that
	// passes CheckTx may still be rejected at execution (before the window, not this
	// phase's submitter), in which case no SettleAccepted event arrives and a boolean would
	// stop this node from ever retrying. Once the chain really settles,
	// onSettleAccepted sets state to Settled and trySettle's state check stops naturally.
	settleSubmittedHeight uint64
	// sweepSubmitted records the deadline kinds for which this node has already submitted
	// MsgSweepDeadline, so the same one is not resubmitted on every new block. Deliberately
	// not in taskSnapshot: after restart it is submitted at most once more, a NOOP on-chain.
	sweepSubmitted map[taskv1.DeadlineKindV1]bool

	// SETTLE rank timing (Detailed Design §4.2/§4.3; chain rule §10.10a).
	prepareSeen map[string]int64 // when other Builders in the group announced prepare (per phase; advisory de-duplication signal, not a blocking requirement)
	// settleGraceBlocks is the grace block count per rank (Hub parameter, read and persisted
	// together with the settlement ordering); observedHeight is the chain height of the
	// latest NewBlock. Rank ≥2 submits only after its own grace window has started.
	settleGraceBlocks uint64
	observedHeight    uint64
	// verifierProposalTimer batches hand-raises; when verifierProposalDelay is 0, submit synchronously (for tests).
	verifierProposalTimer *time.Timer
	verifierProposalDelay time.Duration
	settleSelection       chaincli.StageBuilderSelectionState

	// Backfilled once the chain finalizes.
	settlement  chaincli.TaskSettlementState
	verdict     types.TaskVerdict // chain-computed verdict (display only, never a substitute for on-chain facts)
	winner      string
	assignedSet []types.BuilderRef
	verifiers   []string
	assignSeed  []byte // from the chain's AssignmentFinalized (forwarded to the Worker for cross-checking)
	// The two height fields of the start-work notification. The event path fills them
	// directly from the event; the startup recovery path fills them from the on-chain task
	// snapshot (reconcile), after which resume re-sends the notification.
	assignFinalizedHeight uint64
	inferDeadlineHeight   uint64
	// pendingAssignmentNotify marks "this on-chain reconcile advanced the task to Assigned",
	// meaning it was finalized while offline and the Worker never got the notification;
	// resume re-sends it once.
	pendingAssignmentNotify bool
	sampleSeed              []byte // from the chain's SampleReady (sole authoritative source; nexus never derives it)
	deadlines               types.Deadlines
	outputHash              []byte
	inferReceipt            types.InferReceiptSubmission

	unsubs    []msgbus.Unsubscribe
	timer     *time.Timer
	onClose   func() // used by the coordinator to remove this instance from the task table
	onAbandon func() // pre-chain failure/expiry: remove without a terminal marker

	handlerMu sync.Mutex
	stopped   bool
	handlerWG sync.WaitGroup

	beginExternalHandler func() bool
	endExternalHandler   func()
	requestReconcile     func(string)

	// Snapshot persistence seam (crash recovery, Detailed Design §2.6); nil = no persistence
	// (some unit tests construct the fsm directly).
	persist   func(taskSnapshot) error // write KV after every state transition
	unpersist func()                   // clear KV once the task reaches a terminal state

	// currentEpoch returns the epoch of the last observed chain height, false when unknown.
	currentEpoch func() (uint64, bool)
}

// emit records one task event (state/phase taken from current values). Caller must hold the lock.
func (f *taskFSM) emit(code string, height int64) {
	if f.events == nil {
		return
	}
	f.events.append(types.TaskEvent{
		EventCode:   code,
		State:       f.state.String(),
		TaskPhase:   f.phase.String(),
		ChainHeight: height,
		TS:          nowMS(),
	})
}

// ---- Entry points (called via coordinator routing) ----

// onOrder is the first action after construction: broadcast the order to solicit hand-raises and subscribe to Worker hand-raises (Detailed Design §3, Pending row).
func (f *taskFSM) onOrder() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// ORDER_BROADCAST must carry the candidate task_hash: the whole
	// ORDER_BROADCAST → WORKER_HANDRAISE → MsgSubmitWorkerHandraises chain relies on it
	// to confirm everyone is hand-raising for the same order version. Without it there is
	// no candidate identity to bind to; broadcasting would only collect a batch of
	// hand-raises that each say something different, so fail closed here instead.
	if f.order.TaskHash == "" {
		return fmt.Errorf("order has no canonical task_hash: task %s cannot be broadcast", f.taskID)
	}
	// The broadcast carries only the complete user-signed order (OrderBroadcastV1):
	// task_id/task_hash are recomputed by the receiver from signed_order.order together with
	// the user signature check. A legacy JSON-envelope order has no frozen SignedOrderV2 and
	// cannot be broadcast legitimately, so fail closed (it would not pass the first
	// proposal's scope branch anyway).
	if len(f.order.SignedOrder) == 0 {
		return fmt.Errorf("order has no frozen SignedOrderV2: task %s cannot be broadcast", f.taskID)
	}
	var signedOrder taskv1.SignedOrderV2
	if err := proto.Unmarshal(f.order.SignedOrder, &signedOrder); err != nil {
		return fmt.Errorf("decode SignedOrderV2: %w", err)
	}
	if err := f.publish(msgbus.SubjectTaskOpen(f.modelID), bus.KindOrderBroadcast,
		&busv1.OrderBroadcastV1{SignedOrder: &signedOrder}, busadapter.TierCore); err != nil {
		return err
	}

	f.subscribeWorkerHandraise()
	f.subscribeBuilderPrepare()
	f.emit(EvOrderReceived, 0)
	if err := f.save(); err != nil {
		return err
	}
	f.log.Info("task pending: order broadcast, collecting worker handraise", "session_id", f.sessionID, "task_id", f.taskID)
	return nil
}

// onWorkerHandraise receives a Worker hand-raise: signature-check placeholder + dedup count; once the minimum is reached and it is our turn → submit AssignTx.
func (f *taskFSM) onWorkerHandraise(hr *taskv1.WorkerHandraiseV1) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// V2 envelopes carry no session_id/task_id: task binding is carried by the payload's
	// task_id, and the session segment is uniquely determined by the derivation
	// task_id = H(session_id, seq).
	if f.state != types.Pending || !bytes.Equal(hr.GetTaskId(), f.taskIDBytes()) {
		return
	}
	if !f.validWorkerHandraise(hr) {
		return
	}
	worker := hr.GetMember().GetOperatorAddress()
	f.workerHR[worker] = hr
	f.save()
	// Log accepted hand-raises at Info rather than Debug: after OPEN_TASK this is the only
	// signal proving "Cortex actually responded", and deployments running at Info can only
	// guess without it. Volume is bounded by the candidate pool cap, so it will not flood.
	f.log.Info("worker handraise accepted", "task_id", f.taskID, "candidate", worker,
		"count", len(f.workerHR), "need", proposalHandraiseMin)

	// The three gates are checked separately and each leaves a trace. Folded into one
	// condition with a silent return, "not enough collected", "not in the group" and
	// "already submitted" look identical in the logs -- nothing is printed -- and can only be
	// guessed one by one.
	if f.assignSubmitted {
		f.log.Debug("AssignTx already submitted for this task", "task_id", f.taskID)
		return
	}
	if !f.inProposalGroup(f.builderSet) {
		// Not an anomaly: this Builder is not in the Task's Builder group, so the proposal is
		// submitted by a group member. But it leaves the task "stuck collecting hand-raises
		// forever" on this node, so it must be visible.
		f.log.Info("not submitting AssignTx: this Builder is not in the task's proposal group",
			"task_id", f.taskID, "self", f.self, "builder_set", builderAddresses(f.builderSet),
			"handraises", len(f.workerHR))
		return
	}
	if len(f.workerHR) < proposalHandraiseMin {
		f.log.Info("waiting for more worker handraises before submitting AssignTx",
			"task_id", f.taskID, "count", len(f.workerHR), "need", proposalHandraiseMin)
		return
	}
	f.submitAssignLocked()
}

// submitAssignLocked builds the Worker handraise proposal from the handraises collected so
// far and submits it. Caller must hold the lock.
func (f *taskFSM) submitAssignLocked() {
	facts, err := workerAssignmentFactsFrom(f.workerHR)
	if err != nil {
		f.log.Warn("prepare AssignTx failed", "task_id", f.taskID, "err", err)
		return
	}
	// The fee/timeout cross-check of the legacy JSON envelope only holds on the legacy
	// path. Once an order carries the frozen SignedOrderV2, all of these facts are derived
	// by the Keeper from the signed order and the OrderEnvelope no longer contains any JSON
	// to compare; running this section would only lock legitimate orders out.
	if len(f.order.SignedOrder) == 0 {
		if err := validateOrderForAssign(f.order, facts); err != nil {
			f.log.Warn("prepare AssignTx failed", "task_id", f.taskID, "err", err)
			return
		}
	}
	// Frozen contract §4.2.1: what goes on-chain is only the scope oneof + the
	// WorkerHandraiseV1 list + submitter_address; everything else is a Keeper-derived fact.
	// Neither step may set assignSubmitted on failure, or later hand-raises would never
	// trigger a retry.
	signedOrder, existingTask, err := workerHandraiseScope(f.order, f.acceptedTaskHash)
	if err != nil {
		f.log.Warn("prepare AssignTx failed", "task_id", f.taskID, "err", err)
		return
	}
	handraisesV1, err := workerHandraisesV1(f.chainID, f.workerHR)
	if err != nil {
		f.log.Warn("prepare AssignTx failed", "task_id", f.taskID, "err", err)
		return
	}

	f.assignSubmitted = true
	tx := chaincli.AssignTx{
		SignedOrder: signedOrder, ExistingTask: existingTask, WorkerHandraises: handraisesV1,

		BuilderOperatorAddress: f.self, SessionID: f.sessionID, TaskID: f.taskID, UserAddress: f.order.User,
		OrderSequence: f.order.OrderSequence, OrderEnvelope: f.order.OrderEnvelope, TaskHash: f.order.TaskHash,
		SignatureScheme: f.order.SignatureScheme, UserSignature: f.order.UserSignature,
		MaxFee: f.order.MaxFee, TxFeeReserve: f.order.TxFeeReserve, AssignmentPriorityFee: 0,
		BuilderRank: f.order.Stage1BuilderRank, BuilderSelectionProof: f.order.Stage1SelectionProof,
		CandidateSnapshotID: facts.CandidateSnapshotID,
		MinWorkerHandraise:  proposalHandraiseMin,
		ReservedFee:         f.order.MaxFee,
		InferDeadlineHeight: f.order.InferTimeoutBlocks, Submitter: f.self,
	}
	result, err := f.submit.SubmitAssign(context.Background(), tx)
	if err != nil {
		f.log.Warn("submit AssignTx failed", "task_id", f.taskID, "err", err)
		f.assignSubmitted = false // let the next hand-raise retry
		return
	}
	f.assignTxHash = append(f.assignTxHash[:0], result.TxHash...)
	f.save()
	f.log.Info("AssignTx accepted by CheckTx", "task_id", f.taskID,
		"tx_hash", hex.EncodeToString(f.assignTxHash), "handraise", len(f.workerHR)-len(result.Excluded),
		"excluded", len(result.Excluded))
}

// assignRejectionRetries bounds how often a Worker handraise proposal the Keeper refused as an
// invalid assignment is filtered and submitted again.
const assignRejectionRetries = 2

// isInvalidAssignment reports the Keeper's ErrInvalidAssignment (x/task/types/errors.go): a
// proposal refused over its candidates, which a filtered resubmission can fix.
func isInvalidAssignment(result chaincli.TxResult) bool {
	return result.Codespace == "task" && result.Code == 1109
}

// rememberAcceptedTaskHash records the authoritative task_hash (lowercase hex) after
// on-chain acceptance. Only a canonical 32-byte value is accepted; invalid or empty values
// are ignored -- better to fall back to the first-proposal branch and fail there than to
// build ExistingTaskRefV1 from half a hash.
func (f *taskFSM) rememberAcceptedTaskHash(taskHash string) {
	if taskHash == "" {
		return
	}
	raw, err := nodecontract.Hash32Bytes("accepted task_hash", taskHash)
	if err != nil {
		f.log.Warn("ignore non-canonical accepted task_hash", "task_id", f.taskID, "err", err)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Equal(f.acceptedTaskHash, raw) {
		return
	}
	f.acceptedTaskHash = raw
	f.save()
}

func (f *taskFSM) onAssignRejected(result chaincli.TxResult) {
	f.mu.Lock()
	if f.state != types.Pending || !f.assignSubmitted {
		f.mu.Unlock()
		return
	}
	// The proposal was simulated before it was broadcast, but the Keeper judges candidates
	// against the state of the block that includes it; one that stopped qualifying in between
	// fails the whole proposal. Filter against the current state and submit again, a bounded
	// number of times; any other rejection ends the task as before.
	if isInvalidAssignment(result) && f.assignRetries < assignRejectionRetries {
		f.assignRetries++
		f.assignSubmitted = false
		f.assignTxHash = nil
		f.save()
		f.log.Warn("AssignTx rejected by DeliverTx over its candidates; filtering and submitting again",
			"task_id", f.taskID, "attempt", f.assignRetries, "height", result.Height, "raw_log", result.RawLog)
		f.submitAssignLocked()
		f.mu.Unlock()
		return
	}
	f.state = types.Failed
	f.terminal = true
	f.emit(EvAssignRejected, result.Height)
	f.save()
	f.teardown()
	f.relay.Release(f.sessionID, f.taskID)
	txHash := append([]byte(nil), f.assignTxHash...)
	f.mu.Unlock()

	f.log.Warn("AssignTx rejected by DeliverTx", "task_id", f.taskID,
		"tx_hash", hex.EncodeToString(txHash), "height", result.Height,
		"code", result.Code, "raw_log", result.RawLog)
	if f.onAbandon != nil {
		f.onAbandon()
	}
}

func (f *taskFSM) onAssignTimeout(height uint64) {
	f.mu.Lock()
	if f.state != types.Pending {
		f.mu.Unlock()
		return
	}
	f.state = types.Failed
	f.verdict = types.VerdictAssignTimeout
	f.terminal = true
	f.emit(EvAssignTimeout, int64(height))
	f.save()
	f.teardown()
	f.relay.Release(f.sessionID, f.taskID)
	deadline := f.order.DeadlineHeight
	handraiseCount := len(f.workerHR)
	f.mu.Unlock()

	f.log.Info("task assign timed out before on-chain acceptance", "task_id", f.taskID,
		"height", height, "deadline_height", deadline, "handraise", handraiseCount)
	if f.onAbandon != nil {
		f.onAbandon()
	}
}

// acceptInferReceipt records the first signed InferReceipt and makes exact
// retries idempotent (contract §6 I3: the material digest is unchanged under any legitimate retry).
// A retry still persists the snapshot so a prior persistence failure can recover.
func (f *taskFSM) acceptInferReceipt(receipt types.InferReceiptSubmission) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.validateInferReceiptLocked(receipt); err != nil {
		return false, err
	}
	if len(f.outputHash) > 0 {
		if !reflect.DeepEqual(f.inferReceipt, receipt) {
			return false, fmt.Errorf("%w: conflicting infer receipt", types.ErrInvalidArgument)
		}
		return true, f.save()
	}
	f.outputHash = receipt.OutputHash
	f.inferReceipt = receipt
	f.emit(EvInferReceiptReceived, 0)
	if err := f.save(); err != nil {
		return false, err
	}
	// OPEN_VERIFY waits for on-chain acceptance of the receipt (onInferReceiptAccepted);
	// when reconcile arrives before the local receipt, it is re-sent here.
	if f.receiptOnChain {
		f.publishOpenVerify()
	}
	// Submit the receipt on-chain as soon as it is accepted locally: only on-chain acceptance
	// opens the verification window and lets Verifier candidates read the authoritative
	// snapshot. This step does not wait for hand-raises.
	f.submitOpenVerifyLocked()
	f.log.Debug("infer receipt recorded", "task_id", f.taskID, "worker", receipt.WorkerAddress)
	return false, nil
}

// publishOpenVerify opens hand-raising to Verifier candidates (contract §5.6,
// subject=trueopen.verify.open.<task_id>, kind=OPEN_VERIFY). Caller must hold the lock.
//
// The publish point is "after the InferReceipt is accepted locally", not "after on-chain
// acceptance": on-chain acceptance goes through MsgSubmitInferReceipt, and that message
// itself must carry the VerifierHandraise list -- waiting for on-chain acceptance before
// opening verification would be a deadlock. The "Task whose InferReceipt has been accepted"
// of contract §5.6 can, on the Builder side, only mean the winner's signed InferReceipt
// has been received locally.
//
// The message carries no input/output/evidence bodies and does not mean any Verifier has
// been selected.
//
// It also waits for this Builder's local data-ready (04 §326): input, output and all required
// evidence stored and checked here, i.e. the Worker's FinalizeTaskResult succeeded on this
// Builder with the receipt this FSM holds. Opening verification without the data would make the
// Builder answer for data it cannot serve. The usual order is receipt accepted on chain, then
// Finalize, so onResultFinalized is the call that normally sends it.
func (f *taskFSM) publishOpenVerify() {
	if f.openVerifyPublished || f.state != types.Assigned || !f.receiptOnChain {
		return
	}
	payload := f.openVerifyPayload()
	if payload == nil {
		return
	}
	if !f.dataReadyLocked() {
		f.log.Debug("OPEN_VERIFY deferred: the Worker result is not finalized on this Builder", "task_id", f.taskID)
		return
	}
	if err := f.publish(msgbus.SubjectVerifyOpen(f.taskID), bus.KindOpenVerify, payload, busadapter.TierCore); err == nil {
		f.openVerifyPublished = true
	}
}

// onInferReceiptAccepted: the chain accepted the InferReceipt; this is the moment to send
// OPEN_VERIFY. It can only be sent if the receipt is also held locally (the payload needs
// output_hash and infer_receipt_hash); otherwise acceptInferReceipt re-sends it. Caller
// does not hold the lock.
func (f *taskFSM) onInferReceiptAccepted() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.receiptOnChain {
		f.receiptOnChain = true
		f.save()
	}
	// Every on-chain reconcile reaches here: OPEN_VERIFY is retried until this Builder is
	// data-ready (sent once per process), and buffered hand-raises whose last submission failed
	// are retried (still in batches).
	f.publishOpenVerify()
	f.scheduleVerifierProposalLocked()
}

// onResultFinalized: the Worker's FinalizeTaskResult succeeded on this Builder, normally the
// last condition of data-ready. Caller does not hold the lock.
func (f *taskFSM) onResultFinalized() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requestDataReadyCheckLocked()
}

// dataReadyLocked reports the cached local data-ready for the receipt this FSM holds. When not
// known ready it starts a check in the background; a positive answer then sends what was waiting
// (checkDataReady). Caller must hold the lock.
func (f *taskFSM) dataReadyLocked() bool {
	if !f.dataReady {
		f.requestDataReadyCheckLocked()
	}
	return f.dataReady
}

// requestDataReadyCheckLocked starts checkDataReady unless the answer is known or there is
// nothing to ask about; a request while one is in flight makes it run once more, so a Finalize
// that lands during a check is not missed. Caller must hold the lock.
func (f *taskFSM) requestDataReadyCheckLocked() {
	if f.dataReady || f.resultReadiness == nil || len(f.outputHash) == 0 {
		return
	}
	if f.dataReadyChecking {
		f.dataReadyRecheck = true
		return
	}
	if !f.beginHandler() {
		return
	}
	f.dataReadyChecking = true
	go func() {
		defer f.endHandler()
		f.checkDataReady()
	}()
}

// checkDataReady asks the task data plane without holding the FSM lock, then applies the answer:
// once ready, OPEN_VERIFY and the buffered Verifier proposal go out. The answer counts only if the
// FSM still holds the receipt that was asked about.
func (f *taskFSM) checkDataReady() {
	for {
		f.mu.Lock()
		f.dataReadyRecheck = false
		readiness := f.resultReadiness
		query := taskdata.ResultReadyQuery{
			TaskHash: f.inferReceipt.TaskHash, SessionID: f.sessionID, TaskID: f.taskID,
			OutputHash:       hex.EncodeToString(f.outputHash),
			InferReceiptHash: hex.EncodeToString(f.inferReceipt.InferReceiptHash),
		}
		f.mu.Unlock()

		ready, err := readiness.ResultReady(context.Background(), query)

		f.mu.Lock()
		if err != nil {
			f.log.Warn("data-ready check failed; will retry on the next trigger", "task_id", f.taskID, "err", err)
		} else if ready && query.InferReceiptHash == hex.EncodeToString(f.inferReceipt.InferReceiptHash) {
			f.dataReady = true
			f.publishOpenVerify()
			f.scheduleVerifierProposalLocked()
		}
		if f.dataReady || !f.dataReadyRecheck {
			f.dataReadyChecking = false
			f.dataReadyRecheck = false
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
	}
}

// openVerifyPayload builds this message's payload; nil means it must not be sent yet.
// Only a Builder that holds the Worker's signed receipt sends it: the receipt reaches this
// Builder together with the finalized output, and Verifiers fetch task data from the sender.
// Hashes taken from the chain do not make this Builder data-ready (04 §326).
func (f *taskFSM) openVerifyPayload() *busv1.OpenVerifyV1 {
	if len(f.outputHash) == 0 || f.winner == "" {
		return nil
	}
	taskID, taskHash := f.taskIDBytes(), f.orderTaskHashBytes()
	if taskID == nil || taskHash == nil {
		f.log.Warn("skip OPEN_VERIFY publish: task identity is not canonical", "task_id", f.taskID)
		return nil
	}
	return &busv1.OpenVerifyV1{
		TaskId:                taskID,
		TaskHash:              taskHash,
		ModelId:               f.modelID,
		ProfileVersion:        f.profileVersion,
		InferReceiptHash:      append([]byte(nil), f.inferReceipt.InferReceiptHash...),
		OutputHash:            append([]byte(nil), f.outputHash...),
		WorkerOperatorAddress: f.winner,
		VerifyRound:           uint32(nodecontract.SupportedVerifyRoundV1),
	}
}

func (f *taskFSM) validateInferReceipt(receipt types.InferReceiptSubmission) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validateInferReceiptLocked(receipt)
}

func (f *taskFSM) validateInferReceiptLocked(receipt types.InferReceiptSubmission) error {
	if receipt.SessionID != f.sessionID || receipt.TaskID != f.taskID {
		return types.ErrInvalidArgument
	}
	if f.state != types.Assigned && f.state != types.Verifying {
		return types.ErrUnauthorized
	}
	if f.winner == "" || receipt.WorkerAddress != f.winner {
		return types.ErrUnauthorized
	}
	if len(f.outputHash) > 0 && !reflect.DeepEqual(f.inferReceipt, receipt) {
		return fmt.Errorf("%w: conflicting infer receipt", types.ErrInvalidArgument)
	}
	if len(f.acceptedReceiptHash) > 0 && (!bytes.Equal(receipt.InferReceiptHash, f.acceptedReceiptHash) ||
		!bytes.Equal(receipt.OutputHash, f.acceptedOutputHash)) {
		return fmt.Errorf("%w: infer receipt differs from the one the chain accepted", types.ErrInvalidArgument)
	}
	return nil
}

// acceptedReceiptHashesLocked returns the output_hash and infer_receipt_hash of the accepted
// receipt: from the signed receipt this Builder received, or else from the chain once it has
// accepted one. The chain hashes only check Verifier handraises and fill the verifier assignment
// notice, which is a wake-up and not a data source; OPEN_VERIFY, handraise proposals, output
// delivery and data readiness keep requiring the local receipt. Caller must hold the lock.
func (f *taskFSM) acceptedReceiptHashesLocked() (outputHash, receiptHash []byte) {
	if len(f.outputHash) > 0 {
		return f.outputHash, f.inferReceipt.InferReceiptHash
	}
	return f.acceptedOutputHash, f.acceptedReceiptHash
}

// needsAcceptedReceipt reports whether this Builder has neither the signed receipt nor the
// chain's accepted hashes.
func (f *taskFSM) needsAcceptedReceipt() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.outputHash) == 0 && len(f.acceptedOutputHash) == 0
}

// setAcceptedReceipt records the chain's accepted receipt hashes.
func (f *taskFSM) setAcceptedReceipt(receipt chaincli.AcceptedInferReceipt) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.outputHash) > 0 || len(receipt.OutputHash) != 32 || len(receipt.InferReceiptHash) != 32 {
		return
	}
	f.acceptedOutputHash = bytes.Clone(receipt.OutputHash)
	f.acceptedReceiptHash = bytes.Clone(receipt.InferReceiptHash)
	f.save()
}

// onAssignAccepted: AssignTx included (first step of two): winner undecided, enter
// randomness pending. **No start-work notification** -- work starts after
// AssignmentFinalized (v1.5 §2.3/§4.3). Subscribe early to Verifier hand-raises + recompute
// returns (subscribing before messages is harmless; subscribing after loses core messages).
func (f *taskFSM) onAssignAccepted(ev chaincli.AssignAccepted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Pending || f.phase != types.PhaseUnspecified {
		return // idempotent: duplicate events are harmless
	}
	f.assignedSet = ev.AssignedSet
	f.phase = types.PhaseAssignRandomnessPending

	f.subscribeVerifierHandraise()
	f.subscribeVerifyResult()
	f.emit(EvAssignAccepted, ev.Height)
	f.save()
	f.log.Info("assign accepted: randomness pending, winner not final yet", "task_id", f.taskID, "height", ev.Height)
}

// onAssignmentFinalized: randomness settled, winner determined (second step of two):
// record the winner, move to Assigned, and only now notify the winner via trueopen.assign.
func (f *taskFSM) onAssignmentFinalized(ev chaincli.AssignmentFinalized) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Pending {
		return // idempotent
	}
	f.winner = ev.Winner
	f.assignSeed = ev.AssignSeed
	f.state = types.Assigned
	f.phase = types.PhaseAssignmentFinalized

	f.assignSeed = append([]byte(nil), ev.AssignSeed...)
	f.assignFinalizedHeight = uint64(max(ev.Height, 0))
	f.inferDeadlineHeight = ev.InferDeadlineHeight
	f.publishWorkerAssignmentNotify()
	f.emit(EvAssignmentFinalized, ev.Height)
	f.save()
	f.log.Info("assignment finalized: winner notified to start", "task_id", f.taskID, "winner", ev.Winner)
}

// publishWorkerAssignmentNotify sends one start-work notification. The event path
// (onAssignmentFinalized) and the startup recovery path (resume re-send) share the same
// assembly logic: two separate copies were exactly what caused the gap "tasks finalized
// while offline get no notification after restart". Caller must hold the lock.
//
// The notification creates no consensus fact: the authoritative winner and deadline are
// on-chain, and duplicates are deduplicated by the receiver against the on-chain
// assignment.
func (f *taskFSM) publishWorkerAssignmentNotify() {
	taskID, taskHash := f.taskIDBytes(), f.orderTaskHashBytes()
	if taskID == nil || taskHash == nil {
		f.log.Warn("skip WORKER_ASSIGNMENT_NOTIFY publish: task identity is not canonical", "task_id", f.taskID)
		return
	}
	if f.winner == "" {
		f.log.Warn("skip WORKER_ASSIGNMENT_NOTIFY publish: winner is unknown", "task_id", f.taskID)
		return
	}
	// input_hash comes from the user-signed order (TaskOrderV2 field 9); left empty when the
	// order lacks a frozen SignedOrderV2, in which case the receiver relies on the on-chain
	// accepted input.
	var inputHash []byte
	var signedOrder taskv1.SignedOrderV2
	if len(f.order.SignedOrder) > 0 && proto.Unmarshal(f.order.SignedOrder, &signedOrder) == nil {
		inputHash = signedOrder.GetOrder().GetInputHash()
	}
	f.publish(msgbus.SubjectWorkerAssignment(f.taskID), bus.KindWorkerAssignmentNotify,
		&busv1.WorkerAssignmentNotifyV1{
			TaskId:                taskID,
			TaskHash:              taskHash,
			WinnerOperatorAddress: f.winner,
			FinalizedHeight:       f.assignFinalizedHeight,
			AssignSeed:            append([]byte(nil), f.assignSeed...),
			InputHash:             inputHash,
			// The event path takes infer_deadline from WorkerAssignmentFinalized,
			// the recovery path from the task snapshot; the authoritative value is the on-chain Task state.
			InferDeadlineHeight: f.inferDeadlineHeight,
		}, busadapter.TierJetStream)
}

// onVerifierHandraise receives a Verifier hand-raise: dedup count; once the minimum is reached and a result commitment exists → submit OpenVerifyTx.
func (f *taskFSM) onVerifierHandraise(hr *taskv1.VerifierHandraiseV1) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Assigned || !bytes.Equal(hr.GetTaskId(), f.taskIDBytes()) {
		return
	}
	if !f.validVerifierHandraise(hr) {
		return
	}
	candidate := hr.GetMember().GetOperatorAddress()
	f.verifierHR[candidate] = hr
	f.save()
	f.log.Info("verifier handraise accepted", "task_id", f.taskID, "candidate", candidate,
		"count", len(f.verifierHR), "need", proposalHandraiseMin)

	f.submitOpenVerifyLocked()
	f.scheduleVerifierProposalLocked()
}

// scheduleVerifierProposalLocked batches hand-raises: once selectedVerifierCount
// not-yet-on-chain hand-raises are collected, submit immediately; otherwise start a
// verifierProposalDelay timer and submit whatever has been collected when it fires.
// Caller must hold the lock.
func (f *taskFSM) scheduleVerifierProposalLocked() {
	pending := len(f.pendingVerifierHandraises())
	if pending == 0 {
		return
	}
	if pending >= selectedVerifierCount || f.verifierProposalDelay <= 0 {
		f.stopVerifierProposalTimerLocked()
		f.submitVerifierProposalLocked()
		return
	}
	if f.verifierProposalTimer != nil {
		return // already batching
	}
	f.verifierProposalTimer = f.afterFunc(f.verifierProposalDelay, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.verifierProposalTimer = nil
		f.submitVerifierProposalLocked()
	})
}

func (f *taskFSM) stopVerifierProposalTimerLocked() {
	if f.verifierProposalTimer != nil {
		f.verifierProposalTimer.Stop()
		f.verifierProposalTimer = nil
	}
}

// submitVerifierProposalLocked submits the Verifier hand-raises not yet on-chain as one
// MsgSubmitVerifierHandraises proposal (Keeper Interface Contract §4.2.1/§10.4). Caller
// must hold the lock.
//
// There are two triggers: a new hand-raise, and on-chain reconcile
// (onInferReceiptAccepted). The latter carries the retry: one Beacon lies between receipt
// acceptance and the candidate window becoming READY, and the Keeper rejects before then
// ("verifier handraise window is unavailable"); hand-raises must not be lost because of it.
// Each proposal carries only new hand-raises: resubmitting ones already on-chain makes the
// Keeper reject the whole proposal as "no new members".
func (f *taskFSM) submitVerifierProposalLocked() {
	if f.state != types.Assigned || !f.receiptOnChain {
		return
	}
	// An accepted proposal declares this Builder data-ready for the selected Verifiers (02 §8).
	// Only a Builder that received the signed receipt and holds the finalized result may make
	// that claim; one that knows the accepted hashes from the chain keeps the handraises but does
	// not submit them.
	if len(f.outputHash) == 0 || !f.dataReadyLocked() {
		return
	}
	pending := f.pendingVerifierHandraises()
	if len(pending) == 0 {
		return
	}
	set := f.assignedSet
	if len(set) == 0 {
		set = f.builderSet
	}
	if !f.inProposalGroup(set) {
		f.log.Debug("not submitting MsgSubmitVerifierHandraises: this Builder is not in the task's proposal group",
			"task_id", f.taskID, "self", f.self, "handraises", len(pending))
		return
	}
	tx := chaincli.OpenVerifyTx{
		BuilderOperatorAddress: f.self, SessionID: f.sessionID, TaskID: f.taskID, WorkerOperatorAddress: f.winner,
		VerifierHandraises: pending, Submitter: f.self,
	}
	result, err := f.submit.SubmitVerifierHandraises(context.Background(), tx)
	f.excludeVerifierHandraisesLocked(result.Excluded)
	if err != nil {
		f.log.Warn("submit MsgSubmitVerifierHandraises failed; will retry on the next chain reconciliation",
			"task_id", f.taskID, "handraises", len(pending), "excluded", len(result.Excluded), "err", err)
		return
	}
	for _, hr := range pending {
		operator := hr.GetMember().GetOperatorAddress()
		if _, excluded := f.verifierHRExcluded[operator]; !excluded {
			f.verifierHRProposed[operator] = true
		}
	}
	f.save()
	f.log.Info("MsgSubmitVerifierHandraises submitted", "task_id", f.taskID,
		"handraises", len(pending)-len(result.Excluded), "excluded", len(result.Excluded),
		"proposed_total", len(f.verifierHRProposed))
}

// excludeVerifierHandraisesLocked records hand-raisers the chain refused on their own, with
// the current epoch. Caller must hold the lock.
func (f *taskFSM) excludeVerifierHandraisesLocked(excluded []ExcludedHandraise) {
	if len(excluded) == 0 {
		return
	}
	if f.verifierHRExcluded == nil {
		f.verifierHRExcluded = make(map[string]uint64)
	}
	epoch, _ := f.epochNow()
	for _, e := range excluded {
		f.verifierHRExcluded[e.Operator] = epoch
	}
}

func (f *taskFSM) epochNow() (uint64, bool) {
	if f.currentEpoch == nil {
		return 0, false
	}
	return f.currentEpoch()
}

// verifierHandraiseExcludedLocked reports whether a refused hand-raiser is still skipped: until
// a later epoch is known, it is. Caller must hold the lock.
func (f *taskFSM) verifierHandraiseExcludedLocked(operator string) bool {
	refusedIn, excluded := f.verifierHRExcluded[operator]
	if !excluded {
		return false
	}
	if now, ok := f.epochNow(); ok && now > refusedIn {
		delete(f.verifierHRExcluded, operator)
		return false
	}
	return true
}

// pendingVerifierHandraises returns hand-raises not yet on-chain, sorted by strictly increasing slot (Keeper requirement).
func (f *taskFSM) pendingVerifierHandraises() []*taskv1.VerifierHandraiseV1 {
	pending := make([]*taskv1.VerifierHandraiseV1, 0, len(f.verifierHR))
	for operator, hr := range f.verifierHR {
		if !f.verifierHRProposed[operator] && !f.verifierHandraiseExcludedLocked(operator) {
			pending = append(pending, hr)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].GetMember().GetSlot() < pending[j].GetMember().GetSlot()
	})
	return pending
}

// proposedVerifierOperators is the stable sequence of hand-raisers already on-chain (for persistence).
func (f *taskFSM) proposedVerifierOperators() []string {
	if len(f.verifierHRProposed) == 0 {
		return nil
	}
	operators := make([]string, 0, len(f.verifierHRProposed))
	for operator := range f.verifierHRProposed {
		operators = append(operators, operator)
	}
	sort.Strings(operators)
	return operators
}

// submitOpenVerifyLocked submits the accepted InferReceipt on-chain as MsgSubmitInferReceipt.
// Caller must hold the lock.
//
// The trigger is "InferReceipt accepted locally", not "Verifier hand-raise received". This
// transaction carries only the receipt and the submitter -- hand-raises go separately via
// MsgSubmitVerifierHandraises -- and on-chain acceptance of this receipt is exactly the
// step that freezes the VERIFIER eligibility bitmap and the whole verification clock, i.e.
// the precondition for Verifier candidates to read the authoritative snapshot. Waiting for
// hand-raises before submitting would deadlock: hand-raising requires reading the on-chain
// receipt first.
func (f *taskFSM) submitOpenVerifyLocked() {
	set := f.assignedSet
	if len(set) == 0 {
		set = f.builderSet
	}
	// The three gates are checked separately; otherwise, when open verify is stuck, there is
	// no way to tell "already submitted" from "not in the group" from "output not ready".
	if f.openVerifySubmitted {
		f.log.Debug("OpenVerifyTx already submitted for this task", "task_id", f.taskID)
		return
	}
	if !f.inProposalGroup(set) {
		f.log.Info("not submitting OpenVerifyTx: this Builder is not in the task's proposal group",
			"task_id", f.taskID, "self", f.self, "builder_set", builderAddresses(set),
			"handraises", len(f.verifierHR))
		return
	}
	if len(f.outputHash) == 0 {
		f.log.Info("waiting for the accepted output hash before submitting OpenVerifyTx",
			"task_id", f.taskID, "handraises", len(f.verifierHR))
		return
	}
	// v1.5: OpenVerifyTx carries no sample_seed -- the chain derives the seed after OpenVerify
	// from the aggregated future proposer-VRF beacon (SampleReady event).
	//
	// The old verifier_handraise_list / selected_verifiers / window_proof string copies are
	// no longer derived: SubmitOpenVerify puts only InferReceipt + Submitter on-chain, and
	// the selected Verifiers are drawn by the Keeper after the handraise window closes;
	// cross-hand-raise fact consistency has already been checked by validVerifierHandraise
	// against the local authoritative values, one by one.
	if err := validateReceiptForOpenVerify(f.inferReceipt, f.winner); err != nil {
		f.log.Warn("prepare OpenVerifyTx failed", "task_id", f.taskID, "err", err)
		return
	}
	// MsgSubmitInferReceipt carries the frozen-wire InferReceiptV2 body (§5.14 / §10.3), not
	// the old MsgOpenVerify string copies. If it cannot be filled, do not submit -- otherwise
	// the submitter fails with "receipt is required" while the Builder has already answered
	// the Worker with relay_accepted=true.
	receipt, err := nodecontract.InferReceiptV2FromSubmission(f.inferReceipt)
	if err != nil {
		f.log.Warn("prepare OpenVerifyTx failed", "task_id", f.taskID, "err", err)
		return
	}
	f.openVerifySubmitted = true
	tx := chaincli.OpenVerifyTx{
		InferReceipt:           receipt,
		BuilderOperatorAddress: f.self, SessionID: f.sessionID, TaskID: f.taskID, WorkerOperatorAddress: f.winner,
		Submitter: f.self,
	}
	if _, err := f.submit.SubmitOpenVerify(context.Background(), tx); err != nil {
		f.log.Warn("submit OpenVerifyTx failed", "task_id", f.taskID, "err", err)
		f.openVerifySubmitted = false
		return
	}
	f.save()
	f.log.Info("OpenVerifyTx submitted", "task_id", f.taskID, "verifier_handraise", len(f.verifierHR))
}

// onOpenVerifyAccepted: on-chain open-verify included: record the selected Verifiers and
// the four deadlines, and send the open-verify notification.
// v1.5: **the notification carries no seed** -- the seed is delivered separately via
// onSampleReady after the chain's SampleReady.
func (f *taskFSM) onOpenVerifyAccepted(ev chaincli.OpenVerifyAccepted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Assigned {
		return
	}
	// An empty verifier set means the chain only opened the verification window and has not
	// assigned yet: sending an assignment notification now would be wrong, as the receiver
	// would get 0 verifiers.
	if len(ev.Verifiers) == 0 {
		f.log.Debug("verifier set not decided yet; not dispatching assignment", "task_id", f.taskID)
		return
	}
	f.verifiers = ev.Verifiers
	f.deadlines = ev.Deadlines
	f.state = types.Verifying
	f.phase = types.PhaseOpenVerify

	taskID, taskHash := f.taskIDBytes(), f.orderTaskHashBytes()
	outputHash, _ := f.acceptedReceiptHashesLocked()
	if len(outputHash) == 0 {
		// The Worker hands its receipt to a single Builder; a notification sent by a Builder
		// that has neither the receipt nor the chain's accepted hashes has an empty output_hash, which the Verifier rejects and
		// redelivers repeatedly. The notification is only an early wake-up; the
		// obligation is defined by the on-chain snapshot, so simply do not send here. State
		// still follows the chain.
		f.log.Debug("skip VERIFIER_ASSIGNMENT_NOTIFY publish: no accepted output hash on this Builder",
			"task_id", f.taskID)
	} else if taskID != nil && taskHash != nil {
		// The selected verifiers' slot/slot_version are not in the event; only addresses are
		// backfilled. The authoritative set is the on-chain VerifierAssignmentState; this
		// message only speeds up coordination.
		verifiers := make([]*taskv1.SelectedVerifierV1, 0, len(ev.Verifiers))
		for _, verifier := range ev.Verifiers {
			verifiers = append(verifiers, &taskv1.SelectedVerifierV1{OperatorAddress: verifier})
		}
		f.publish(msgbus.SubjectVerifierAssignment(f.taskID), bus.KindVerifierAssignmentNotify,
			&busv1.VerifierAssignmentNotifyV1{
				TaskId:               taskID,
				TaskHash:             taskHash,
				VerifyRound:          uint32(nodecontract.SupportedVerifyRoundV1),
				Verifiers:            verifiers,
				OutputHash:           append([]byte(nil), outputHash...),
				OpenVerifyHeight:     uint64(max(ev.Height, 0)),
				CommitDeadlineHeight: uint64(max(ev.Deadlines.Commit, 0)),
				RevealDeadlineHeight: uint64(max(ev.Deadlines.Reveal, 0)),
				VerifyDeadlineHeight: uint64(max(ev.Deadlines.Verify, 0)),
			}, busadapter.TierJetStream)
	} else {
		f.log.Warn("skip VERIFIER_ASSIGNMENT_NOTIFY publish: task identity is not canonical", "task_id", f.taskID)
	}
	f.emit(EvOpenVerifyAccepted, ev.Height)
	f.save()
	f.log.Info("task verifying: verifier set + deadlines dispatched (seed pending beacon)",
		"task_id", f.taskID, "verifiers", len(ev.Verifiers))
}

// onSampleReady: the on-chain sample seed is ready (aggregated future proposer-VRF beacon):
// only record the seed and phase.
//
// The subject table in contract §5.1 has no trueopen.sample-ready.*, and §5.9 states that in
// V1 the selected Verifiers recompute all committed generated tokens and the notification
// "carries no additional verification position selection material". So this notification
// is no longer sent; the seed remains an authoritative on-chain fact and is
// kept locally for assembling SettleTx evidence.
func (f *taskFSM) onSampleReady(ev chaincli.SampleReady) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying || len(f.sampleSeed) > 0 {
		return // idempotent: the seed is recorded/sent only once
	}
	f.sampleSeed = ev.SampleSeed
	f.phase = types.PhaseSampleReady

	f.emit(EvSampleReady, ev.Height)
	f.save()
	f.log.Info("sample seed recorded from chain (not published: no v1 NATS subject)",
		"task_id", f.taskID, "ready_height", ev.ReadyHeight)
}

// onVerifyResult receives a Verifier verification result receipt: relay it on-chain verbatim first,
// and only after on-chain acceptance store it locally and Ack; then try to settle.
//
// The order is mandatory: MsgSettleTask submits only task_id, and the Keeper derives the
// settlement inputs from the on-chain accepted ResultReceiptState -- without the receipt
// on-chain there are no settlement inputs. A definitive on-chain rejection (invalid
// signature/fields) is Acked and dropped as a bad message; a transient failure returns an
// error so JetStream redelivers.
//
// Known boundaries (follow-ups, see the PR description): (1) "accepted" currently only
// means CheckTx passed; a receipt that passes CheckTx but is rejected at inclusion is
// stored locally yet absent on-chain and needs a reconcile fallback; (2) if the process
// crashes between successful submission and Ack, the redelivered second submission may be
// rejected by the Keeper as "already exists" and dropped as Definitive, leaving the receipt
// missing locally and settlement to the on-chain sweep fallback. The clean fix for both is
// to include verify results in on-chain reconcile (local yes/on-chain no → resubmit;
// on-chain yes/local no → backfill), to be implemented once chaincli offers a
// single-receipt query or an acceptance event.
func (f *taskFSM) onVerifyResult(vr *taskv1.ResultReceiptV2) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying || !bytes.Equal(vr.GetTaskId(), f.taskIDBytes()) {
		return nil
	}
	if !f.validVerifyResult(vr) {
		return nil
	}
	_, err := f.relayVerifyResultLocked(vr)
	if errors.Is(err, types.ErrInvalidArgument) {
		// Definitive on-chain rejection: the receipt itself is invalid and redelivery will not make it valid; Ack and drop as a bad message.
		return nil
	}
	return err
}

// relayVerifyResult is the Ingress unary path (contract §2.6): it carries the same
// ResultReceiptV2 as the JetStream path and goes through the same relay logic, except that
// validation failures are reported to the caller with types sentinels instead of being
// silently dropped as on the bus path.
func (f *taskFSM) relayVerifyResult(vr *taskv1.ResultReceiptV2) (types.VerifyRelayAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.verifyRelayPreconditionsLocked(vr.GetTaskId(), vr.GetVerifierOperatorAddress()); err != nil {
		return types.VerifyRelayAck{}, err
	}
	if !f.validVerifyResult(vr) {
		return types.VerifyRelayAck{}, fmt.Errorf("%w: result receipt fails the frozen field checks", types.ErrInvalidArgument)
	}
	return f.relayVerifyResultLocked(vr)
}

// relayVerifyCommit is the Ingress unary path (contract §2.5): in the initial relay implementation the Builder is
// trusted, and the Verifier-signed commit is relayed by this Builder via
// MsgBatchSubmitVerifyCommit. Recorded locally only after a successful broadcast; resending
// the same commit passes idempotently. The return only means broadcast, not on-chain
// accepted -- a Verifier that does not observe acceptance before the deadline still submits
// the same message itself per the contract.
func (f *taskFSM) relayVerifyCommit(commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	verifier := commit.GetVerifierOperatorAddress()
	if err := f.verifyRelayPreconditionsLocked(commit.GetTaskId(), verifier); err != nil {
		return types.VerifyRelayAck{}, err
	}
	if !f.validVerifyCommit(commit) {
		return types.VerifyRelayAck{}, fmt.Errorf("%w: verify commit fails the frozen field checks", types.ErrInvalidArgument)
	}
	if existing, ok := f.verifyCommits[verifier]; ok {
		if proto.Equal(existing, commit) {
			return types.VerifyRelayAck{Idempotent: true}, nil
		}
		// The chain accepts only the first commit per Verifier per round; a second one with
		// different content would surely be rejected, so report a conflict here rather than
		// waste a fee.
		return types.VerifyRelayAck{}, fmt.Errorf("%w: a different verify commit from this verifier was already relayed", types.ErrInvalidArgument)
	}
	if f.submit == nil {
		return types.VerifyRelayAck{}, fmt.Errorf("verify commit relay: submitter is not configured")
	}
	res, err := f.submit.SubmitVerifyCommit(context.Background(), chaincli.VerifyCommitTx{Commit: commit, Submitter: f.self})
	if err != nil {
		var submission *SubmissionError
		if errors.As(err, &submission) && submission.Definitive {
			f.log.Warn("verify commit rejected on chain", "task_id", f.taskID, "verifier", verifier, "err", err)
			return types.VerifyRelayAck{}, fmt.Errorf("%w: verify commit rejected on chain: %v", types.ErrInvalidArgument, err)
		}
		f.log.Warn("verify commit relay failed", "task_id", f.taskID, "verifier", verifier, "err", err)
		return types.VerifyRelayAck{}, err
	}
	f.verifyCommits[verifier] = commit
	if err := f.save(); err != nil {
		f.log.Warn("verify commit relayed but local snapshot save failed",
			"task_id", f.taskID, "verifier", verifier, "err", err)
	}
	f.log.Info("verify commit relayed", "task_id", f.taskID, "verifier", verifier,
		"tx_hash", hex.EncodeToString(res.TxHash))
	return types.VerifyRelayAck{TxHash: res.TxHash}, nil
}

// verifyRelayPreconditionsLocked are the relay preconditions: the task is in the
// verification phase, task_id is this task, and the Verifier is in the on-chain selected
// set. Caller must hold the lock.
func (f *taskFSM) verifyRelayPreconditionsLocked(taskID []byte, verifier string) error {
	if f.state != types.Verifying {
		return fmt.Errorf("%w: task is not in the verify stage (state %s)", types.ErrFailedPrecondition, f.state)
	}
	if !bytes.Equal(taskID, f.taskIDBytes()) {
		return fmt.Errorf("%w: task_id does not match this task", types.ErrInvalidArgument)
	}
	if verifier == "" || !containsString(f.verifiers, verifier) {
		return fmt.Errorf("%w: verifier is not selected for this task", types.ErrUnauthorized)
	}
	return nil
}

// relayVerifyResultLocked relays a receipt that passed validVerifyResult on-chain via
// MsgBatchSubmitVerifyResult: only after a successful broadcast is it stored locally and
// counted as received; then try to settle. Resending the same receipt passes
// idempotently. Caller must hold the lock.
//
// The order is mandatory: MsgSettleTask submits only task_id, and the Keeper derives the
// settlement inputs from the on-chain accepted ResultReceiptState -- without the receipt
// on-chain there are no settlement inputs. A definitive on-chain rejection (invalid
// signature/fields) returns types.ErrInvalidArgument; a transient failure is returned as is
// for the caller to retry.
//
// Known boundaries (follow-ups, see the PR description): (1) "accepted" currently only
// means CheckTx passed; a receipt that passes CheckTx but is rejected at inclusion is
// stored locally yet absent on-chain and needs a reconcile fallback; (2) if the process
// crashes between successful submission and Ack, the redelivered second submission may be
// rejected by the Keeper as "already exists" and dropped as Definitive, leaving the receipt
// missing locally and settlement to the on-chain sweep fallback. The clean fix for both is
// to include verify results in on-chain reconcile (local yes/on-chain no → resubmit;
// on-chain yes/local no → backfill), to be implemented once chaincli offers a
// single-receipt query or an acceptance event.
func (f *taskFSM) relayVerifyResultLocked(vr *taskv1.ResultReceiptV2) (types.VerifyRelayAck, error) {
	verifier := vr.GetVerifierOperatorAddress()
	if existing, ok := f.verifyResults[verifier]; ok && proto.Equal(existing, vr) {
		// Redelivery of the same receipt: the previous round already put it on-chain and stored it locally (e.g. the Ack was lost in flight); pass idempotently.
		return types.VerifyRelayAck{Idempotent: true}, nil
	}
	if f.submit == nil {
		return types.VerifyRelayAck{}, fmt.Errorf("verify result relay: submitter is not configured")
	}
	res, err := f.submit.SubmitVerifyResult(context.Background(), chaincli.VerifyResultTx{
		Receipt: vr, Submitter: f.self,
	})
	if err != nil {
		var submission *SubmissionError
		if errors.As(err, &submission) && submission.Definitive {
			f.log.Warn("verify result rejected on chain", "task_id", f.taskID,
				"verifier", verifier, "err", err)
			return types.VerifyRelayAck{}, fmt.Errorf("%w: verify result rejected on chain: %v", types.ErrInvalidArgument, err)
		}
		f.log.Warn("verify result relay failed; leaving message for redelivery",
			"task_id", f.taskID, "verifier", verifier, "err", err)
		return types.VerifyRelayAck{}, err
	}
	f.verifyResults[verifier] = vr
	if err := f.save(); err != nil {
		// The receipt is on-chain (the authoritative fact already holds); the local snapshot is
		// only a cache and can be completed from in-memory state on the next save. Rolling
		// back + Nak is not an option here: redelivery would submit on-chain a second time,
		// the Keeper's rejection of the duplicate would be classified as Definitive and dropped, and
		// the receipt would instead be permanently missing locally.
		f.log.Warn("verify result persisted on chain but local snapshot save failed",
			"task_id", f.taskID, "verifier", verifier, "err", err)
	}
	f.log.Debug("verify result relayed and stored", "task_id", f.taskID,
		"verifier", verifier, "count", len(f.verifyResults))
	f.trySettle()
	return types.VerifyRelayAck{TxHash: res.TxHash}, nil
}

// validVerifyCommit checks each field of the frozen VerifyCommitV1 field table (Keeper
// Interface Contract §5.14). Membership is decided by verifyRelayPreconditionsLocked; this
// only checks that the fields are complete.
func (f *taskFSM) validVerifyCommit(commit *taskv1.VerifyCommitV1) bool {
	verifier := commit.GetVerifierOperatorAddress()
	switch {
	case commit.GetSchemaVersion() != 1:
		f.log.Warn("drop verify commit with wrong schema_version", "task_id", f.taskID,
			"verifier", verifier, "schema_version", commit.GetSchemaVersion())
	case commit.GetChainId() != f.chainID:
		f.log.Warn("drop verify commit bound to a different chain", "task_id", f.taskID, "verifier", verifier)
	case uint64(commit.GetVerifyRound()) != nodecontract.SupportedVerifyRoundV1:
		f.log.Warn("drop verify commit for an unsupported verify round", "task_id", f.taskID,
			"verifier", verifier, "verify_round", commit.GetVerifyRound())
	case len(commit.GetCommitHash()) != 32:
		f.log.Warn("drop verify commit without a 32-byte commit_hash", "task_id", f.taskID, "verifier", verifier)
	case commit.GetServiceAuthorizationNonce() == 0 || commit.GetExpiryHeight() == 0 ||
		len(commit.GetServiceSignature()) != 64:
		f.log.Warn("drop verify commit without required frozen fields", "task_id", f.taskID, "verifier", verifier)
	default:
		return true
	}
	return false
}

// validWorkerHandraise checks each field of the frozen WorkerHandraiseV1 field table. It
// only does two things: "are the fields complete" and "is it bound to this broadcast".
// Membership is not decided here -- the Keeper looks up the member quadruple directly in
// the on-chain snapshot bitmap and slot binding, and Nexus holds no authoritative state to
// decide it from.
func (f *taskFSM) validWorkerHandraise(hr *taskv1.WorkerHandraiseV1) bool {
	worker := hr.GetMember().GetOperatorAddress()
	switch {
	case worker == "":
		f.log.Warn("drop worker handraise with empty member.operator_address", "task_id", f.taskID)
	case hr.GetSchemaVersion() != 1:
		f.log.Warn("drop worker handraise with wrong schema_version", "task_id", f.taskID,
			"candidate", worker, "schema_version", hr.GetSchemaVersion())
	// chain_id is the target chain declared by the sender. Anything other than the local chain is misdelivery or cross-chain replay; drop it.
	case hr.GetChainId() != f.chainID:
		f.log.Warn("drop worker handraise bound to a different chain", "task_id", f.taskID,
			"candidate", worker, "want", f.chainID, "got", hr.GetChainId())
	// A hand-raise must bind to the candidate task_hash of this broadcast.
	// Any other value from the hand-raiser -- a stale RBF version, a different order --
	// fails closed here and never enters f.workerHR to make up the count.
	case !bytes.Equal(hr.GetTaskHash(), f.orderTaskHashBytes()):
		f.log.Warn("drop worker handraise bound to a different task_hash", "task_id", f.taskID,
			"candidate", worker, "want", f.order.TaskHash, "got", hex.EncodeToString(hr.GetTaskHash()))
	case hr.GetDuty() != sharedv1.Duty_DUTY_WORKER:
		f.log.Warn("drop worker handraise whose duty is not DUTY_WORKER", "task_id", f.taskID,
			"candidate", worker, "duty", hr.GetDuty())
	// Frozen fields: missing any one of them makes a legitimate proposal impossible; rather
	// than submit with holes and be rejected by the chain, drop at the entrance and leave a
	// diagnosable log.
	case hr.GetModelId() == "" || hr.GetProfileVersion() == 0 ||
		hr.GetServiceAuthorizationNonce() == 0 || hr.GetExpiryHeight() == 0 ||
		len(hr.GetServiceSignature()) != 64:
		f.log.Warn("drop worker handraise without required frozen fields", "task_id", f.taskID, "candidate", worker)
	case len(hr.GetMember().GetCandidatePoolSnapshotId()) != 32 || hr.GetMember().GetSlotVersion() == 0:
		f.log.Warn("drop worker handraise with incomplete candidate member ref", "task_id", f.taskID,
			"candidate", worker, "slot", hr.GetMember().GetSlot())
	default:
		return true
	}
	return false
}

func (f *taskFSM) validVerifierHandraise(hr *taskv1.VerifierHandraiseV1) bool {
	candidate := hr.GetMember().GetOperatorAddress()
	outputHash, receiptHash := f.acceptedReceiptHashesLocked()
	switch {
	case candidate == "":
		f.log.Warn("drop verifier handraise with empty member.operator_address", "task_id", f.taskID)
	case hr.GetSchemaVersion() != 1:
		f.log.Warn("drop verifier handraise with wrong schema_version", "task_id", f.taskID,
			"candidate", candidate, "schema_version", hr.GetSchemaVersion())
	case hr.GetChainId() != f.chainID:
		f.log.Warn("drop verifier handraise bound to a different chain", "task_id", f.taskID,
			"candidate", candidate, "want", f.chainID, "got", hr.GetChainId())
	case hr.GetDuty() != sharedv1.Duty_DUTY_VERIFIER:
		f.log.Warn("drop verifier handraise whose duty is not DUTY_VERIFIER", "task_id", f.taskID,
			"candidate", candidate, "duty", hr.GetDuty())
	case uint64(hr.GetVerifyRound()) != nodecontract.SupportedVerifyRoundV1:
		f.log.Warn("drop verifier handraise for an unsupported verify round", "task_id", f.taskID,
			"candidate", candidate, "verify_round", hr.GetVerifyRound())
	// Contract §4.6: the Verifier handraise binds infer_receipt_hash / output_hash; there is
	// no longer a canonical_output_package_hash or a package pre-fetch declaration.
	case !bytes.Equal(hr.GetOutputHash(), outputHash):
		f.log.Warn("drop verifier handraise with mismatched output_hash", "task_id", f.taskID, "candidate", candidate)
	case !bytes.Equal(hr.GetInferReceiptHash(), receiptHash):
		f.log.Warn("drop verifier handraise with mismatched infer receipt", "task_id", f.taskID, "candidate", candidate)
	case hr.GetModelId() == "" || hr.GetProfileVersion() == 0 ||
		hr.GetServiceAuthorizationNonce() == 0 || hr.GetExpiryHeight() == 0 ||
		len(hr.GetServiceSignature()) != 64:
		f.log.Warn("drop verifier handraise without required frozen fields", "task_id", f.taskID, "candidate", candidate)
	case len(hr.GetMember().GetCandidatePoolSnapshotId()) != 32 || hr.GetMember().GetSlotVersion() == 0:
		f.log.Warn("drop verifier handraise with incomplete candidate member ref", "task_id", f.taskID,
			"candidate", candidate, "slot", hr.GetMember().GetSlot())
	default:
		return true
	}
	return false
}

func (f *taskFSM) validVerifyResult(vr *taskv1.ResultReceiptV2) bool {
	verifier := vr.GetVerifierOperatorAddress()
	switch {
	case verifier == "":
		f.log.Warn("drop verify result with empty verifier", "task_id", f.taskID)
	case !containsString(f.verifiers, verifier):
		f.log.Warn("drop verify result from non-selected verifier", "task_id", f.taskID, "verifier", verifier)
	case vr.GetSchemaVersion() != nodecontract.ResultReceiptSchemaVersionV2:
		f.log.Warn("drop verify result with wrong schema_version", "task_id", f.taskID,
			"verifier", verifier, "schema_version", vr.GetSchemaVersion())
	case vr.GetChainId() != f.chainID:
		f.log.Warn("drop verify result bound to a different chain", "task_id", f.taskID, "verifier", verifier)
	case uint64(vr.GetVerifyRound()) != nodecontract.SupportedVerifyRoundV1:
		f.log.Warn("drop verify result for an unsupported verify round", "task_id", f.taskID,
			"verifier", verifier, "verify_round", vr.GetVerifyRound())
	// metric_root / metric_summary / verifier_evidence_bundle_hash are the grouping inputs
	// for re-execution consistency (contract §5.11); generation_params_digest binds the re-execution
	// parameters. Missing any of them makes the consistency check impossible, so drop at the
	// entrance and leave a diagnosable log. From ResultReceiptV2 on, result_reveal_hash is
	// replaced by verifier_evidence_bundle_hash.
	case len(vr.GetMetricRoot()) != 32 || len(vr.GetVerifierEvidenceBundleHash()) != 32 ||
		len(vr.GetGenerationParamsDigest()) == 0 || vr.GetMetricSummary() == nil:
		f.log.Warn("drop verify result without frozen metric material", "task_id", f.taskID, "verifier", verifier)
	case vr.GetServiceAuthorizationNonce() == 0 || vr.GetExpiryHeight() == 0 ||
		len(vr.GetServiceSignature()) != 64:
		f.log.Warn("drop verify result without required frozen fields", "task_id", f.taskID, "verifier", verifier)
	default:
		return true
	}
	return false
}

// onWorkerRevealAccepted: the chain accepted the Worker reveal receipt: set the flag and try to settle.
func (f *taskFSM) onWorkerRevealAccepted(ev chaincli.WorkerRevealAccepted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying {
		return
	}
	f.workerRevealed = true
	f.phase = types.PhaseWorkerReveal
	f.emit(EvWorkerRevealAccepted, ev.Height)
	f.save()
	f.log.Debug("worker reveal accepted", "task_id", f.taskID)
	f.trySettle()
}

// onFullResultRevealAccepted: a Verifier's full-result reveal self-rescue was included: its
// V_i is written to FullResultRevealState, and SettleTx references it via
// registered_full_result_refs (values are not inlined).
func (f *taskFSM) onFullResultRevealAccepted(ev chaincli.FullResultRevealAccepted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying || ev.Verifier == "" {
		return
	}
	f.fullReveals[ev.Verifier] = true
	f.phase = types.PhaseFullResultReveal
	f.emit(EvFullResultRevealAccepted, ev.Height)
	f.save()
	f.log.Info("full result reveal accepted (verifier self-rescue on chain)",
		"task_id", f.taskID, "verifier", ev.Verifier)
	f.trySettle()
}

func (f *taskFSM) reconcileSettlementFacts(facts chaincli.SettlementBuildFacts, allowSettle bool) error {
	if facts.SnapshotHeight == 0 {
		return fmt.Errorf("settlement facts snapshot height is zero")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying || f.terminal {
		return nil
	}
	type acceptedReveal struct {
		height   uint64
		worker   bool
		verifier string
	}
	accepted := make([]acceptedReveal, 0, len(facts.FullResultReveals)+1)
	if facts.HasWorkerRevealReceipt {
		if facts.Worker == "" || (f.winner != "" && facts.Worker != f.winner) ||
			facts.WorkerRevealAcceptedHeight == 0 || facts.WorkerRevealAcceptedHeight > math.MaxInt64 {
			return fmt.Errorf("worker reveal fact is invalid")
		}
		if !f.workerRevealed {
			accepted = append(accepted, acceptedReveal{height: facts.WorkerRevealAcceptedHeight, worker: true})
		}
	}
	seen := make(map[string]struct{}, len(facts.FullResultReveals))
	for _, reveal := range facts.FullResultReveals {
		if reveal.Verifier == "" || (len(f.verifiers) > 0 && !containsString(f.verifiers, reveal.Verifier)) ||
			reveal.AcceptedHeight == 0 || reveal.AcceptedHeight > math.MaxInt64 {
			return fmt.Errorf("full result reveal fact is invalid")
		}
		if _, duplicate := seen[reveal.Verifier]; duplicate {
			return fmt.Errorf("duplicate full result reveal fact for verifier %q", reveal.Verifier)
		}
		seen[reveal.Verifier] = struct{}{}
		if f.fullReveals[reveal.Verifier] {
			continue
		}
		accepted = append(accepted, acceptedReveal{height: reveal.AcceptedHeight, verifier: reveal.Verifier})
	}
	sort.Slice(accepted, func(i, j int) bool {
		if accepted[i].height != accepted[j].height {
			return accepted[i].height < accepted[j].height
		}
		if accepted[i].worker != accepted[j].worker {
			return accepted[i].worker
		}
		return accepted[i].verifier < accepted[j].verifier
	})
	for _, reveal := range accepted {
		if reveal.worker {
			f.workerRevealed = true
			f.phase = types.PhaseWorkerReveal
			f.emit(EvWorkerRevealAccepted, int64(reveal.height))
			continue
		}
		f.fullReveals[reveal.verifier] = true
		f.phase = types.PhaseFullResultReveal
		f.emit(EvFullResultRevealAccepted, int64(reveal.height))
	}
	if err := f.save(); err != nil {
		return err
	}
	if allowSettle {
		f.trySettle()
	}
	return nil
}

func (f *taskFSM) onAuthoritativeFailure(snapshot chaincli.OnChainTask, height int64) {
	f.mu.Lock()
	if f.terminal {
		f.mu.Unlock()
		return
	}
	f.state = types.Failed
	f.terminal = true
	if snapshot.TaskVerdict != types.VerdictUnspecified {
		f.verdict = snapshot.TaskVerdict
	}
	if snapshot.Settlement.SettlementStatus != "" {
		f.settlement = snapshot.Settlement
	}
	f.emit(EvTaskFailed, height)
	_ = f.save()
	f.relay.Release(f.sessionID, f.taskID)
	f.teardown()
	f.mu.Unlock()

	if f.onClose != nil {
		f.onClose()
	}
	if f.unpersist != nil {
		f.unpersist()
	}
}

// DeadlineSweepPolicy decides whether this Builder actively acts as a public deadline runner.
//
// Keeper Interface Contract §9.6a defines MsgSweepDeadline as BOUNDED_RUNNER: any account
// may submit it, public runners pay their own gas, and EndBlock goes through the same
// internal executor. That is, "to sweep or not" is an operational choice rather than a
// protocol obligation, so it is off by default and the deployer enables it explicitly in
// chain.deadline_sweep -- otherwise every Builder would race at the same height to submit
// the same, most likely NOOP, transaction and burn gas for nothing.
type DeadlineSweepPolicy struct {
	// With Enabled=false, Nexus only observes DEADLINE_SWEPT events and never submits.
	Enabled bool
	// GraceBlocks is the number of blocks after a deadline expires during which others (including EndBlock) get to sweep first.
	GraceBlocks uint64
}

// sweepDueDeadlines, on observing a new block, checks whether this task has a deadline that
// has expired yet nobody has swept, and if so submits one MsgSweepDeadline to advance it.
//
// Only tasks this Builder is following are swept, and only the verify phases whose
// deadline_height the chain itself provided (commit / reveal / final) -- these three
// heights come from VerifierAssignmentFinalized and RevealPhaseStarted and are
// authoritative on-chain facts, not Nexus's own estimates. Nexus does not sweep
// indiscriminately for the whole network, nor guess deadlines the chain never gave.
//
// A successful submission only means "broadcast"; whether the task really converged is
// still decided by the DEADLINE_SWEPT event + Query reconcile (onSweepDeadlineAccepted).
func (f *taskFSM) sweepDueDeadlines(policy DeadlineSweepPolicy, height uint64) {
	if !policy.Enabled || height == 0 {
		return
	}
	f.mu.Lock()
	kind, deadline, ok := f.dueDeadlineKind(height, policy.GraceBlocks)
	if !ok {
		f.mu.Unlock()
		return
	}
	if f.sweepSubmitted == nil {
		f.sweepSubmitted = make(map[taskv1.DeadlineKindV1]bool)
	}
	f.sweepSubmitted[kind] = true
	tx := chaincli.SweepDeadlineTx{
		Submitter: f.self, SessionID: f.sessionID, TaskID: f.taskID, DeadlineKind: kind,
	}
	f.mu.Unlock()

	if _, err := f.submit.SubmitSweepDeadline(context.Background(), tx); err != nil {
		f.mu.Lock()
		delete(f.sweepSubmitted, kind)
		f.mu.Unlock()
		f.log.Warn("submit MsgSweepDeadline failed", "task_id", f.taskID,
			"deadline_kind", kind.String(), "err", err)
		return
	}
	f.log.Info("MsgSweepDeadline submitted", "task_id", f.taskID,
		"deadline_kind", kind.String(), "deadline_height", deadline, "height", height)
}

// dueDeadlineKind returns, in protocol advancement order, the first expired (grace
// included) verify-phase deadline. The deadlines of §5.9 are closed intervals:
// current_height >= deadline_height is executable. Caller must hold the lock.
func (f *taskFSM) dueDeadlineKind(height, grace uint64) (taskv1.DeadlineKindV1, uint64, bool) {
	if f.terminal || f.self == "" || f.submit == nil || f.state != types.Verifying {
		return taskv1.DeadlineKindV1_DEADLINE_KIND_V1_UNSPECIFIED, 0, false
	}
	for _, candidate := range []struct {
		kind     taskv1.DeadlineKindV1
		deadline int64
	}{
		{taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT, f.deadlines.Commit},
		{taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_REVEAL, f.deadlines.Reveal},
		{taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_FINAL, f.deadlines.Verify},
	} {
		if candidate.deadline <= 0 || f.sweepSubmitted[candidate.kind] {
			continue
		}
		if height >= uint64(candidate.deadline)+grace {
			return candidate.kind, uint64(candidate.deadline), true
		}
	}
	return taskv1.DeadlineKindV1_DEADLINE_KIND_V1_UNSPECIFIED, 0, false
}

// onSweepDeadlineAccepted: timeout sweep advanced (MsgSweepDeadline triggered by any party).
//
// A terminal state is reached only when the DeadlineTransitionCode explicitly says "this
// phase can go no further": a deadline sweep is never a successful settlement, and a swept
// SETTLE deadline means settlement timed out, so the terminal state is always Failed;
// "sweeping into Settled" does not exist.
//
// Conversely, COMMIT_CLOSED / REVEAL_CLOSED / SESSION_ACTIVE_TO_IDLE are only window
// advances (a commit window closing is usually exactly the reveal phase starting) and the
// task is still alive; these transitions only record the phase and leave state to Query
// reconcile, with no local decision -- otherwise in-flight tasks would be misclassified as
// failed.
func (f *taskFSM) onSweepDeadlineAccepted(ev chaincli.SweepDeadlineAccepted) {
	f.mu.Lock()
	if f.state == types.Closed || f.state == types.Failed {
		f.mu.Unlock()
		return
	}
	f.phase = types.PhaseSweepObserved
	if !ev.ConvergesTask() {
		f.emit(EvSweepObserved, ev.Height)
		f.save()
		f.mu.Unlock()
		f.log.Info("deadline sweep observed: window advanced, task still live", "task_id", f.taskID,
			"deadline_kind", ev.DeadlineKind.String(), "transition_code", ev.TransitionCode.String())
		return
	}
	f.state = types.Failed
	f.emit(EvSweepObserved, ev.Height)
	f.terminal = true
	f.save()
	f.relay.Release(f.sessionID, f.taskID)
	f.teardown()
	f.mu.Unlock()

	f.log.Info("deadline sweep observed: task converged", "task_id", f.taskID,
		"deadline_kind", ev.DeadlineKind.String(), "transition_code", ev.TransitionCode.String(),
		"final_state", types.Failed.String())
	if f.onClose != nil {
		f.onClose()
	}
	if f.unpersist != nil {
		f.unpersist()
	}
}

// trySettle is the settlement precondition: ≥2 V_i with consistent re-execution results.
//
// It does not wait for the Worker reveal: normal verification has no such step (Task
// Execution, Verification and Settlement §9 -- the Worker's commitment is already locked
// by the accepted InferReceipt), the frozen contract has no matching Msg / Event, and
// f.workerRevealed is always false in Phase 0, kept only as an observation.
//
// Timing is decided entirely by chain height (§10.10a, see settleSubmissionAllowed): do not
// send before the height at which this node may send; sending early or in someone else's
// slot is rejected by the chain and wastes the fee. At most one send per block; if the
// chain has not settled after a send (execution rejected or not included), the next block
// within the window sends again. Chain height comes from NewBlock (onHeight), not the local
// clock. Caller must hold the lock.
func (f *taskFSM) trySettle() {
	if f.state != types.Verifying || f.terminal || f.consistentVerifyGroup() == nil {
		return
	}
	rank, known, selected := f.settleRank()
	if !known {
		if f.requestReconcile != nil {
			f.requestReconcile("settle selection missing")
		}
		return
	}
	if !selected {
		return
	}
	if f.observedHeight == 0 || f.settleSubmittedHeight == f.observedHeight {
		return // no block seen yet, or already sent once in this block
	}
	allowed, permissionless := f.settleSubmissionAllowed(rank)
	if !allowed {
		f.log.Debug("settle conditions met; waiting for the height this Builder may submit at",
			"task_id", f.taskID, "rank", rank, "height", f.observedHeight,
			"reveal_deadline", f.deadlines.Reveal, "grace_blocks", f.settleGraceBlocks)
		return
	}
	f.log.Info("settle window open; submitting", "task_id", f.taskID, "rank", rank,
		"height", f.observedHeight, "execution_height", f.observedHeight+1, "permissionless", permissionless)
	f.submitSettle()
}

// settleSubmissionAllowed reports whether the chain would accept this node's MsgSettleTask (§10.10a):
//
//	reveal deadline < height ≤ verify deadline            public settlement window; no rank may go earlier
//	rank i exclusive (reveal+(i-1)·g, reveal+i·g]         g = settlement_builder_grace_blocks
//	height > reveal+k·g: anyone may submit                k = number of Builders in the frozen selection
//
// The decision uses the height at which the transaction **executes**, not the height this
// node just observed: the chain recomputes who may submit at the executing block, and the
// transaction can enter the next block at the earliest. Deciding by the observed height,
// a submission in the last block of this slot would execute in the next slot and be
// rejected as "submitter is not the Builder of the current slot".
//
// If any fact is missing (reveal/verify deadline, grace blocks, Builder count unknown),
// return false: never guess the window. Caller must hold the lock.
func (f *taskFSM) settleSubmissionAllowed(rank int) (allowed bool, permissionless bool) {
	builders := uint64(len(f.settleSelection.SelectedBuilders))
	if rank < 1 || builders == 0 || f.settleGraceBlocks == 0 ||
		f.deadlines.Reveal <= 0 || f.deadlines.Verify <= 0 {
		return false, false
	}
	reveal, verify, grace := uint64(f.deadlines.Reveal), uint64(f.deadlines.Verify), f.settleGraceBlocks
	height := f.observedHeight + 1 // the transaction executes in the next block at the earliest
	if height <= reveal || height > verify {
		return false, false
	}
	if height > reveal+builders*grace {
		return true, true
	}
	start := reveal + uint64(rank-1)*grace
	return height > start && height <= start+grace, false
}

// onHeight: a new block arrived: record the chain height, then check whether the settlement window has opened (including retries after a failed submission).
func (f *taskFSM) onHeight(height uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if height <= f.observedHeight {
		return
	}
	f.observedHeight = height
	f.trySettle()
}

// submitSettle assembles and submits SettleTx; before submitting it broadcasts a prepare
// announcement so other Builders can skip a duplicate submission (§4.3). Verifiers that already submitted directly on-chain via
// FullResultRevealTx are included by reference (values not inlined; the chain reads
// them from state). Caller must hold the lock.
func (f *taskFSM) submitSettle() {
	group := f.consistentVerifyGroup()
	if group == nil || len(f.verifiers) != 3 {
		return
	}
	// prepare de-duplication: tell higher ranks in the group that this node is about to submit, reducing races within the same slot.
	f.publishPrepare()

	// missing/outlier are logged only: the public request of MsgSettleTask is just task_id +
	// submitter_address (§10.10a); verdict, receipt references and evidence roots are all
	// derived by the Keeper from authoritative state, and Nexus no longer assembles local
	// copies.
	consistent := make(map[string]struct{}, len(group))
	for _, result := range group {
		consistent[result.GetVerifierOperatorAddress()] = struct{}{}
	}
	missing := make([]string, 0, len(f.verifiers))
	outliers := make([]string, 0, 1)
	for _, verifier := range f.verifiers {
		if _, ok := f.verifyResults[verifier]; !ok {
			missing = append(missing, verifier)
			continue
		}
		if _, ok := consistent[verifier]; !ok {
			outliers = append(outliers, verifier)
		}
	}
	f.settleSubmittedHeight = f.observedHeight
	tx := chaincli.SettleTx{
		Submitter: f.self, SessionID: f.sessionID, TaskID: f.taskID,
	}
	if _, err := f.submit.SubmitSettle(context.Background(), tx); err != nil {
		f.log.Warn("submit SettleTx failed", "task_id", f.taskID, "err", err)
		f.settleSubmittedHeight = 0
		// Retry on the next block (onHeight); if someone else settled on-chain, SettleAccepted arrives first and this becomes a no-op.
		return
	}
	f.save()
	f.log.Info("SettleTx submitted", "task_id", f.taskID,
		"consistent_results", len(group), "missing", strings.Join(missing, ","),
		"outlier", strings.Join(outliers, ","))
}

// publishPrepare broadcasts the SETTLE prepare announcement (nexus-internal signed
// message, prepare.go). If it cannot be signed, do not send: an unsigned announcement hands
// anyone a lever to suppress a fallback submission.
func (f *taskFSM) publishPrepare() {
	if f.prepares == nil || !f.prepares.ready() {
		f.log.Debug("skip prepare publish: service key is not configured", "task_id", f.taskID)
		return
	}
	data, err := f.prepares.encode(f.sessionID, f.taskID, uint64(nowMS()))
	if err != nil {
		f.log.Warn("encode prepare failed", "task_id", f.taskID, "err", err)
		return
	}
	subject := msgbus.SubjectBuilderPrepare(f.taskID)
	if err := f.bus.Publish(subject, data); err != nil {
		f.log.Warn("publish prepare failed", "task_id", f.taskID, "subject", subject, "err", err)
		return
	}
	f.log.Debug("prepare notice published", "task_id", f.taskID, "subject", subject)
}

// onSettleAccepted: on-chain settlement included: escrow remains held until on-chain finality allows release.
func (f *taskFSM) onSettleAccepted(ev chaincli.SettleAccepted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Verifying {
		return
	}
	f.state = types.Settled
	f.phase = types.PhaseSettle
	f.settlement = ev.Settlement
	f.verdict = ev.TaskVerdict
	f.emit(EvSettleAccepted, ev.Height)
	_ = f.save()
	f.log.Info("task settled; waiting for chain finality",
		"task_id", f.taskID,
		"verdict", ev.TaskVerdict,
		"settlement_height", ev.Settlement.SettlementHeight,
		"task_finality_height", ev.Settlement.TaskFinalityHeight)
}

// settlementAllowsCustodyRelease decides when a settled task can be closed and what it holds
// released. Settlement state is decided only by finality_status and task_finality_height
// (Challenge and Evidence spec §9): the chain reporting the task FINAL, with the chain height at
// or past task_finality_height, is the whole condition.
func settlementAllowsCustodyRelease(s chaincli.TaskSettlementState, height uint64) bool {
	return height != 0 && s.FinalityStatus == "FINAL" && s.TaskFinalityHeight != 0 && height >= s.TaskFinalityHeight
}

func (f *taskFSM) lifecycleBoundaryDue(height uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == types.Pending {
		return f.order.DeadlineHeight != 0 && height > f.order.DeadlineHeight
	}
	if f.state != types.Settled {
		return false
	}
	// challenge_close_height is not a boundary of its own: without a challenge round it equals
	// task_finality_height, and with one the task becomes final when the last round closes (06 §9).
	return height == f.settlement.TaskFinalityHeight
}

func (f *taskFSM) closeSettledAtHeight(height uint64) bool {
	f.mu.Lock()
	if f.state != types.Settled || !settlementAllowsCustodyRelease(f.settlement, height) {
		f.mu.Unlock()
		return false
	}
	return f.closeLocked(height)
}

// closeCompacted closes a task the chain has already compacted: QueryTask returns only the
// terminal summary, every round is closed and the task is final, so nothing is left to drive
// whatever local phase the task reached. A compacted FAILED task goes through
// onAuthoritativeFailure instead.
//
// The chain compacts a task only after it is FINAL, so a settled summary without FINAL or
// without task_finality_height is inconsistent: it is left open and logged rather than closed.
func (f *taskFSM) closeCompacted(snapshot chaincli.OnChainTask, height uint64) bool {
	if snapshot.Settlement.FinalityStatus != "FINAL" || snapshot.Settlement.TaskFinalityHeight == 0 {
		f.log.Warn("compacted task summary is not final; keeping the task open",
			"session_id", f.sessionID, "task_id", f.taskID,
			"finality_status", snapshot.Settlement.FinalityStatus,
			"task_finality_height", snapshot.Settlement.TaskFinalityHeight)
		return false
	}
	f.mu.Lock()
	if f.terminal {
		f.mu.Unlock()
		return false
	}
	if snapshot.TaskVerdict != types.VerdictUnspecified {
		f.verdict = snapshot.TaskVerdict
	}
	f.settlement.SettlementHeight = snapshot.Settlement.SettlementHeight
	f.settlement.SettlementStatus = snapshot.Settlement.SettlementStatus
	f.settlement.FinalityStatus = snapshot.Settlement.FinalityStatus
	f.settlement.TaskFinalityHeight = snapshot.Settlement.TaskFinalityHeight
	if height == 0 {
		height = snapshot.Settlement.TaskFinalityHeight
	}
	return f.closeLocked(height)
}

// closeGone closes a task the chain no longer returns (see reconcileTaskGone). A task still
// waiting for its assignment is not closed here: it may not have reached the chain yet.
func (f *taskFSM) closeGone(height uint64) bool {
	f.mu.Lock()
	if f.terminal || f.state == types.Pending {
		f.mu.Unlock()
		return false
	}
	return f.closeLocked(height)
}

// closeLocked moves the task to Closed and releases what it holds. The caller holds f.mu;
// closeLocked releases it.
func (f *taskFSM) closeLocked(height uint64) bool {
	previousState, previousTerminal := f.state, f.terminal
	f.state = types.Closed
	f.terminal = true
	if err := f.save(); err != nil {
		f.state, f.terminal = previousState, previousTerminal
		f.mu.Unlock()
		f.log.Warn("task close snapshot persist failed; retaining custody", "task_id", f.taskID, "err", err)
		return false
	}
	f.emit(EvTaskClosed, int64(height))
	if err := f.save(); err != nil {
		f.log.Warn("task close event persist failed", "task_id", f.taskID, "err", err)
	}
	f.relay.Release(f.sessionID, f.taskID)
	f.teardown()
	f.mu.Unlock()

	if f.onClose != nil {
		f.onClose()
	}
	if f.unpersist != nil {
		f.unpersist()
	}
	return true
}

// ---- Helpers ----

// onPrepare receives a prepare announcement from another Builder in the group: only the
// observation time is recorded (advisory de-duplication signal).
// §4.1: prepare must not be a blocking requirement for abandoning an ASSIGN/OPEN_VERIFY proposal;
// §4.3: SETTLE rank_k gives up this round and defers one step on seeing a fresh prepare
// (on-chain idempotency fallback).
func (f *taskFSM) onPrepare(p builderPrepare) {
	// self/sessionID/taskID never change after construction, so they can be pre-filtered
	// without the lock. Our own prepare must be filtered before taking the lock: the stub
	// bus loops back synchronously, so publishing under the lock delivers the message right
	// back into this handler, and filtering afterwards would self-deadlock.
	if p.SessionID != f.sessionID || p.TaskID != f.taskID || p.Submitter == f.self || p.Submitter == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.Stage == prepareStageSettle && !f.settlePrepareTrusted(p.Submitter) {
		f.log.Debug("prepare notice ignored (submitter not a lower-rank group member)",
			"task_id", f.taskID, "submitter", p.Submitter)
		return
	}
	if f.prepareSeen == nil {
		f.prepareSeen = make(map[string]int64)
	}
	f.prepareSeen[p.Stage] = nowMS()
	f.log.Debug("prepare notice observed", "task_id", f.taskID, "stage", p.Stage, "submitter", p.Submitter)
}

// settlePrepareTrusted: SETTLE prepare trusts only announcements "in the group and of lower
// rank than this node" -- prepares from nodes outside the group or of higher rank must not
// block a fallback submission (guards against griefing by a spoofed prepare). Trust is refused when the
// frozen selection is unknown or this node is not selected. Caller must hold the lock.
func (f *taskFSM) settlePrepareTrusted(submitter string) bool {
	selfRank, known, selected := f.settleRank()
	if !known || !selected {
		return false
	}
	for i, builder := range f.settleSelection.SelectedBuilders {
		if builder == submitter {
			return i+1 < selfRank
		}
	}
	return false
}

// builderAddresses takes only the addresses for logging: BuilderRef also carries the
// endpoint, and logging it whole is both verbose and prone to writing internal addresses
// into log files.
func builderAddresses(set []types.BuilderRef) []string {
	addresses := make([]string, 0, len(set))
	for _, member := range set {
		addresses = append(addresses, member.Address)
	}
	return addresses
}

// inProposalGroup is the submission gate for ASSIGN / OPEN_VERIFY (§4.1 proposal window):
// if this node belongs to the phase's Builder group it submits its own proposal, **without
// waiting for others or looking at prepare** -- the Keeper takes the legitimate union after
// the window ends. If the group or our own identity is unknown (legacy / devnet), allow
// leniently.
func (f *taskFSM) inProposalGroup(set []types.BuilderRef) bool {
	if f.self == "" || len(set) == 0 {
		return true
	}
	for _, m := range set {
		if m.Address == f.self {
			return true
		}
	}
	return false
}

// settleRank is this Builder's position (1-based) in the frozen Task Builder ordering.
// Caller must hold the lock.
func (f *taskFSM) settleRank() (rank int, known bool, selected bool) {
	if f.settleSelection.SessionID == "" {
		return 0, false, false
	}
	for i, builder := range f.settleSelection.SelectedBuilders {
		if builder == f.self {
			return i + 1, true, true
		}
	}
	return 0, true, false
}

func (f *taskFSM) needsSettleSelection() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state == types.Verifying && f.settleSelection.SessionID == "" &&
		f.consistentVerifyGroup() != nil
}

// authorizedForSealedKey is the SEALED_KEY retrieval authorization (v1.5 §3.2):
// the order's user, or a member of the selected Verifier set after verify-select.
// When the order's user is unknown (SDK envelope not enabled), only selected Verifiers are allowed.
func (f *taskFSM) authorizedForSealedKey(requester string) bool {
	if requester == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.user != "" && requester == f.user {
		return true
	}
	for _, v := range f.verifiers {
		if v == requester {
			return true
		}
	}
	return false
}

func (f *taskFSM) authorizedForPayload(requester, usage string) bool {
	if requester == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch usage {
	case "WORKER_INFERENCE":
		return f.winner != "" && requester == f.winner
	case "VERIFIER_RECOMPUTE":
		return containsString(f.verifiers, requester)
	case "CHALLENGE_EVIDENCE":
		return (f.user != "" && requester == f.user) || containsString(f.verifiers, requester)
	default:
		return false
	}
}

// consistentVerifyGroup returns a group of ResultReceiptV2 with consistent re-execution
// results and count ≥ threshold; nil if none. The consistency key = the combined digest
// of (metric_root, proto-serialized bytes of metric_summary) (contract §5.11: the verdict
// is recomputed by the Keeper from accepted typed summaries; this is only a local
// de-duplication decision). Caller must hold the lock.
func (f *taskFSM) consistentVerifyGroup() []*taskv1.ResultReceiptV2 {
	groups := make(map[string][]*taskv1.ResultReceiptV2)
	for _, vr := range f.verifyResults {
		key, err := verifyResultGroupKey(vr)
		if err != nil {
			f.log.Warn("skip verify result in consistency grouping", "task_id", f.taskID,
				"verifier", vr.GetVerifierOperatorAddress(), "err", err)
			continue
		}
		groups[key] = append(groups[key], vr)
	}
	for _, g := range groups {
		if len(g) >= minConsistentVerifyResults {
			return g
		}
	}
	return nil
}

// verifyResultGroupKey compresses the re-execution consistency inputs into a comparable
// key: metric_root + MetricSummaryV1 framed field by field (length-prefixed against
// concatenation ambiguity).
//
// verifier_evidence_bundle_hash is excluded: the evidence bundle carries each Verifier's own
// salt, so this hash is inherently different per Verifier; with it in the key every group
// has exactly 1 member and never reaches the threshold. ResultReceiptV2 lifted
// the salt into its own field, and the rationale is unchanged. On-chain settlement
// grouping likewise looks at the sample verdict and metric_summary_hash (keeper contract
// consensus_cluster_hash), not at it. The summary is framed field by field rather than
// proto.Marshal because protobuf serialization has no cross-implementation determinism
// guarantee.
func verifyResultGroupKey(vr *taskv1.ResultReceiptV2) (string, error) {
	summary := vr.GetMetricSummary()
	if summary == nil {
		return "", fmt.Errorf("metric summary is required")
	}
	h := sha256.New()
	var lenBuf [8]byte
	write := func(part []byte) {
		n := uint64(len(part))
		for i := 0; i < 8; i++ {
			lenBuf[i] = byte(n >> (8 * i))
		}
		h.Write(lenBuf[:])
		h.Write(part)
	}
	u32 := func(v uint32) []byte {
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	optional := func(v *uint32) []byte {
		if v == nil {
			return []byte{0}
		}
		return append([]byte{1}, u32(*v)...)
	}
	write(vr.GetMetricRoot())
	for _, part := range [][]byte{
		u32(summary.GetFiniteCount()), u32(summary.GetMissingComparedCount()),
		u32(summary.GetMeanAbsLogprobDiffFp_1E6()), u32(summary.GetAbsLogprobDiffP95Fp_1E6()),
		u32(summary.GetAbsLogprobDiffP99Fp_1E6()), u32(summary.GetRankDeltaNonzeroRateFp_1E6()),
		optional(summary.TopkJaccardMeanFp_1E6), optional(summary.UnionJsP99Fp_1E6),
		u32(summary.GetComparedTopkCount()), u32(summary.GetComparedRankCount()),
	} {
		write(part)
	}
	return string(h.Sum(nil)), nil
}

// subscribe subscribes to one core task-level subject and registers the unsubscribe function. Caller must hold the lock.
func (f *taskFSM) subscribe(subject string, h func(data []byte)) {
	unsub, err := f.bus.Subscribe(subject, func(_ string, data []byte) error {
		if !f.beginHandler() {
			return nil
		}
		defer f.endHandler()
		h(data)
		return nil
	})
	if err != nil {
		f.log.Warn("subscribe failed",
			"tier", "core", "session_id", f.sessionID, "task_id", f.taskID,
			"subject", subject, "err", err)
		return
	}
	f.unsubs = append(f.unsubs, unsub)
}

// jsSubscribe subscribes to one JetStream task-level subject (durable consumer) and
// registers the unsubscribe function. Caller must hold the lock.
func (f *taskFSM) jsSubscribe(subject, durable string, h func(data []byte) error) {
	unsub, err := f.bus.JSSubscribe(subject, durable, func(_ string, data []byte) error {
		if !f.beginHandler() {
			return errTaskFSMStopping
		}
		defer f.endHandler()
		return h(data)
	})
	if err != nil {
		f.log.Warn("JS subscribe failed",
			"tier", "jetstream", "session_id", f.sessionID, "task_id", f.taskID,
			"subject", subject, "durable", durable, "err", err)
		return
	}
	f.unsubs = append(f.unsubs, unsub)
}

// teardown unsubscribes from all task-level subjects and stops the timer. Caller must hold the lock.
func (f *taskFSM) teardown() {
	for _, u := range f.unsubs {
		u()
	}
	f.unsubs = nil
	if f.timer != nil {
		f.timer.Stop()
	}
	f.stopVerifierProposalTimerLocked()
}

func (f *taskFSM) afterFunc(delay time.Duration, callback func()) *time.Timer {
	return time.AfterFunc(delay, func() {
		if !f.beginHandler() {
			return
		}
		defer f.endHandler()
		callback()
	})
}

func (f *taskFSM) beginHandler() bool {
	f.handlerMu.Lock()
	defer f.handlerMu.Unlock()
	if f.stopped {
		return false
	}
	if f.beginExternalHandler != nil && !f.beginExternalHandler() {
		return false
	}
	f.handlerWG.Add(1)
	return true
}

func (f *taskFSM) endHandler() {
	f.handlerWG.Done()
	if f.endExternalHandler != nil {
		f.endExternalHandler()
	}
}

func (f *taskFSM) shutdown() {
	f.handlerMu.Lock()
	f.stopped = true
	f.handlerMu.Unlock()
	f.mu.Lock()
	f.teardown()
	f.mu.Unlock()
	f.handlerWG.Wait()
}

// ---- Task-level subscriptions (onOrder / onAssignAccepted / resume share the same definitions) ----
//
// The restart recovery path must reuse these functions: with subscription points scattered
// across taskfsm.go and snapshot.go, changing a subject in only one place would leave the
// post-restart subscription on the old subject, with no compile error whatsoever.

func (f *taskFSM) subscribeWorkerHandraise() {
	subject := msgbus.SubjectWorkerHandraiseV1(f.taskID)
	f.subscribe(subject, func(data []byte) {
		inbound, err := f.receive(subject, bus.KindWorkerHandraise,
			sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, data)
		if err != nil {
			f.log.Warn("drop bus envelope", "task_id", f.taskID, "subject", subject, "err", err)
			return
		}
		hr, ok := inbound.Payload.(*taskv1.WorkerHandraiseV1)
		if !ok {
			f.log.Warn("drop bus envelope with unexpected payload type",
				"task_id", f.taskID, "subject", subject)
			return
		}
		f.onWorkerHandraise(hr)
	})
}

func (f *taskFSM) subscribeVerifierHandraise() {
	subject := msgbus.SubjectVerifierHandraiseV1(f.taskID)
	f.subscribe(subject, func(data []byte) {
		inbound, err := f.receive(subject, bus.KindVerifierHandraise,
			sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, data)
		if err != nil {
			f.log.Warn("drop bus envelope", "task_id", f.taskID, "subject", subject, "err", err)
			return
		}
		hr, ok := inbound.Payload.(*taskv1.VerifierHandraiseV1)
		if !ok {
			f.log.Warn("drop bus envelope with unexpected payload type",
				"task_id", f.taskID, "subject", subject)
			return
		}
		f.onVerifierHandraise(hr)
	})
}

// subscribeBuilderPrepare: prepare de-duplication announcements (Detailed Design §8.1):
// the submission intent of Builders in the group, advisory only, never a
// blocking requirement. Uses the nexus.* internal subject and the internal signature format
// (prepare.go); Cortex is not involved.
func (f *taskFSM) subscribeBuilderPrepare() {
	subject := msgbus.SubjectBuilderPrepare(f.taskID)
	f.subscribe(subject, func(data []byte) {
		if f.prepares == nil {
			return
		}
		p, err := f.prepares.decode(context.Background(), data, uint64(nowMS()))
		if err != nil {
			f.log.Debug("drop prepare notice", "task_id", f.taskID, "err", err)
			return
		}
		f.onPrepare(p)
	})
}

func (f *taskFSM) subscribeVerifyResult() {
	subject := msgbus.SubjectVerifyResultV1(f.taskID)
	f.jsSubscribe(subject, msgbus.DurableConsumer(f.self, "vr-"+f.taskID), func(data []byte) error {
		inbound, err := f.receive(subject, bus.KindVerifyResult,
			sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, data)
		if err != nil {
			f.log.Warn("drop bus envelope", "task_id", f.taskID, "subject", subject, "err", err)
			// Infrastructure failures (chain unqueryable, replay-store read/write failure) are
			// Nak'ed for redelivery; "message invalid" is acked, or a bad frame would be
			// redelivered forever.
			if retryableBusError(err) {
				return err
			}
			return nil
		}
		vr, ok := inbound.Payload.(*taskv1.ResultReceiptV2)
		if !ok {
			f.log.Warn("drop bus envelope with unexpected payload type",
				"task_id", f.taskID, "subject", subject)
			return nil
		}
		return f.onVerifyResult(vr)
	})
}

// retryableBusError decides whether a failed inbound frame should be redelivered: only
// infrastructure failures (on-chain query unavailable, replay-store read/write failure)
// qualify; an invalid message does not -- a transient disk/KV failure of the replay store
// says nothing about the message, and acking would permanently drop a legitimate durable
// message.
func retryableBusError(err error) bool {
	return errors.Is(err, busadapter.ErrAuthorityUnavailable) ||
		errors.Is(err, bus.ErrStoreFailure)
}

// receive decodes and verifies one inbound frame in the 7-step frozen order of
// TRUEOPEN_BUS_ENVELOPE_V2 (wire bus.Verify), then checks the kind and the sender's
// participant type. If the returned error satisfies errors.Is(err,
// busadapter.ErrAuthorityUnavailable), it means "could not query" rather than "invalid":
// JetStream callers should Nak for redelivery, not ack and drop.
func (f *taskFSM) receive(
	subject string, wantKind int32, wantParticipant sharedv1.ParticipantType, data []byte,
) (*busadapter.Inbound, error) {
	if f.receiver == nil {
		return nil, fmt.Errorf("bus envelope: %w: envelope verification is not configured",
			busadapter.ErrAuthorityUnavailable)
	}
	inbound, err := f.receiver.Receive(context.Background(), subject, data)
	if err != nil {
		return nil, err
	}
	if int32(inbound.Envelope.GetKind()) != wantKind {
		return nil, fmt.Errorf("bus envelope: kind %s does not match subject expectation",
			inbound.Envelope.GetKind())
	}
	if inbound.Envelope.GetSenderParticipantType() != wantParticipant {
		return nil, fmt.Errorf("bus envelope: sender participant %s may not send %s",
			inbound.Envelope.GetSenderParticipantType(), inbound.Envelope.GetKind())
	}
	return inbound, nil
}

// publish assembles, signs and publishes one BusEnvelopeV1 (proto). The publisher also
// writes the complete envelope's raw bytes to the outbox, and after restart the
// coordinator's Republish resends them verbatim. If it cannot be signed, do not send: the
// envelope has no optional parts, and a dev fallback of "send one unsigned frame" would
// defeat envelope verification entirely.
func (f *taskFSM) publish(subject string, kind int32, payload proto.Message, tier busadapter.Tier) error {
	// Check the subject↔kind table before publishing (the publisher-side equivalent of step 2
	// of the old encode): a call site with a mistyped subject would sign a frame that
	// contradicts the vocabulary; better not to send.
	if spec, _, ok := msgbus.LookupSubjectV1(subject); !ok || spec.WireKind != kind {
		f.log.Warn("refuse to publish: subject does not carry this kind",
			"subject", subject, "kind", kind, "task_id", f.taskID)
		return fmt.Errorf("bus publish: subject %q does not carry kind %d", subject, kind)
	}
	kindName := busv1.BusMessageKind(kind).String()
	phase := "publish_" + strings.ToLower(strings.TrimPrefix(kindName, "BUS_MESSAGE_KIND_"))
	if f.publisher == nil {
		// When a compliant frame cannot be signed, the only correct behaviour is not to send
		// anything, but this is not a task-level failure: same semantics as the old
		// implementation, the local FSM advances as usual and on-chain facts are unaffected.
		f.log.Warn("encode envelope failed",
			"phase", phase,
			"session_id", f.sessionID, "task_id", f.taskID,
			"subject", subject, "kind", kindName,
			"err", "bus envelope signing is not configured")
		return nil
	}
	tierName := "core"
	if tier == busadapter.TierJetStream {
		tierName = "jetstream"
	}
	messageID, err := f.publisher.Publish(context.Background(), subject, kind, payload, tier)
	if err != nil {
		f.log.Error("bus publish failed",
			"phase", phase, "tier", tierName, "confirmed", false,
			"session_id", f.sessionID, "task_id", f.taskID,
			"subject", subject, "kind", kindName, "err", err)
		return fmt.Errorf("%s: %w", strings.ReplaceAll(phase, "_", " "), err)
	}
	f.log.Info("bus publish confirmed",
		"phase", phase, "tier", tierName, "confirmed", true,
		"session_id", f.sessionID, "task_id", f.taskID,
		"subject", subject, "kind", kindName, "message_id", messageID)
	return nil
}

// ---- Pure helper functions ----

func nowMS() int64 { return time.Now().UnixMilli() }

// taskIDBytes returns this task's task_id in 32-byte form; returns nil when the local value
// is not canonical (the caller fails closed).
func (f *taskFSM) taskIDBytes() []byte {
	raw, err := nodecontract.Hash32Bytes("task_id", f.taskID)
	if err != nil {
		return nil
	}
	return raw
}

// orderTaskHashBytes returns the candidate task_hash bound by this broadcast in 32-byte
// form; nil when missing or not canonical.
func (f *taskFSM) orderTaskHashBytes() []byte {
	if f.order.TaskHash == "" {
		return nil
	}
	raw, err := nodecontract.Hash32Bytes("task_hash", f.order.TaskHash)
	if err != nil {
		return nil
	}
	return raw
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

type workerAssignmentFacts struct {
	// TaskHash is the candidate order identity jointly bound by this batch of hand-raises
	// (lowercase 64-hex). Mixing different task_hash values within one proposal fails
	// outright.
	TaskHash string
	// CandidateSnapshotID comes from member.candidate_pool_snapshot_id of §5.5: hand-raises in
	// the same proposal must reference the same candidate pool snapshot, otherwise the
	// Keeper's slot lookups land on different snapshots and the union bitmap is meaningless.
	// candidate_set_hash used to be cross-checked too; §5.5 removed that field from the wire.
	CandidateSnapshotID string
}

// workerAssignmentFactsFrom extracts and cross-checks the proposal facts jointly bound by a
// set of hand-raises. The old canonical set (AssignTx's historical string fields) is no
// longer derived: SubmitAssign puts only scope / handraises / submitter_address on-chain and
// the string copies have no reader; only the cross-hand-raise fact consistency check it
// used to perform is kept here.
func workerAssignmentFactsFrom(input map[string]*taskv1.WorkerHandraiseV1) (workerAssignmentFacts, error) {
	if len(input) == 0 {
		return workerAssignmentFacts{}, fmt.Errorf("worker handraise set must not be empty")
	}
	addresses := make([]string, 0, len(input))
	for address := range input {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	var facts workerAssignmentFacts
	for i, address := range addresses {
		handraise := input[address]
		if address != handraise.GetMember().GetOperatorAddress() {
			return workerAssignmentFacts{}, fmt.Errorf("worker handraise map identity mismatch")
		}
		current := workerAssignmentFacts{
			TaskHash:            hex.EncodeToString(handraise.GetTaskHash()),
			CandidateSnapshotID: hex.EncodeToString(handraise.GetMember().GetCandidatePoolSnapshotId()),
		}
		if i == 0 {
			facts = current
		} else if current != facts {
			return workerAssignmentFacts{}, fmt.Errorf("worker handraises do not bind the same assignment facts")
		}
	}
	return facts, nil
}

// validateOrderForAssign cross-checks a legacy JSON-envelope order against the hand-raise facts.
//
// The `order.OrderDigest == hex(sha256(order.OrderEnvelope))` self-check was removed from
// here. It was the concrete symptom of "the same commitment has different semantics on the
// two ingress paths": the SignedOrder path stores OrderEnvelope as hex text and OrderDigest
// as sha256(raw), which never match; the legacy JSON path stores raw JSON, which happens to
// match. It is currently unreachable (the call site is kept on the legacy path by
// `len(f.order.SignedOrder) == 0`, see onWorkerHandraise), so not a production bug, but it
// would become a guaranteed failure as soon as someone removed that guard.
//
// There is no reason for that self-check to exist any more: the order identity is
// task_hash, derived from TaskOrderV2 and independent of the envelope byte encoding, and
// consistency is enforced by two gates: validWorkerHandraise (hand-raise vs broadcast) and
// submitter.validateScopeTaskHash (on-chain scope vs each hand-raise). Only what the legacy
// envelope can genuinely cross-check is kept here: fee and timeout.
func validateOrderForAssign(order types.Order, facts workerAssignmentFacts) error {
	if order.SessionID == "" || order.TaskID == "" || order.User == "" || order.OrderEnvelope == "" ||
		order.SignatureScheme != "secp256k1" || order.UserSignature == "" ||
		order.MaxFee == 0 || order.InferTimeoutBlocks == 0 {
		return fmt.Errorf("order is missing current Node assignment fields")
	}
	envelope, err := nodecontract.ParseAssignmentOrderEnvelope(order.OrderEnvelope)
	if err != nil {
		return err
	}
	if order.TaskHash != facts.TaskHash ||
		order.MaxFee != envelope.MaxFee || order.TxFeeReserve != envelope.TxFeeReserve ||
		order.InferTimeoutBlocks != envelope.InferTimeoutBlocks {
		return fmt.Errorf("order and worker handraise assignment facts do not match")
	}
	return nil
}

// validateReceiptForOpenVerify checks the frozen wire fields needed to assemble
// MsgSubmitInferReceipt (Keeper Interface Contract §5.14 / §10.3). The field set follows
// InferReceiptV2:
// batch_log_root / token_count / work_unit were removed from the wire and are no longer
// required. The kind set and count cap of evidence commitments are the Keeper's admission
// checks; locally only non-emptiness is required (the V1 text path of §9.7 always has
// WORKER_VALUE_OPENING).
func validateReceiptForOpenVerify(receipt types.InferReceiptSubmission, winner string) error {
	if receipt.SessionID == "" || receipt.TaskID == "" || receipt.TaskHash == "" ||
		receipt.WorkerAddress != winner || receipt.SchemaVersion == 0 || receipt.ChainID == "" ||
		receipt.ServiceAuthorizationNonce == 0 || len(receipt.GenerationParamsDigest) == 0 ||
		len(receipt.OutputHash) == 0 || receipt.OutputSizeBytes == 0 ||
		len(receipt.EvidenceCommitments) == 0 || receipt.ExpiryHeight == 0 ||
		len(receipt.WorkerServiceSignature) == 0 {
		return fmt.Errorf("infer receipt is missing frozen InferReceiptV2 fields")
	}
	return nil
}
