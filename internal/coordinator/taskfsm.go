package coordinator

import (
	"bytes"
	"context"
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

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

var errTaskFSMStopping = errors.New("coordinator: task FSM stopping")

// taskFSM is the per-task state machine instance. One per task;
// events are routed by the coordinator into the matching instance, which serializes
// them with its own mutex, so tasks never interfere with one another.
// Happy path: Pending→Assigned(winner recorded on chain)→
// Verifying(OPEN_VERIFY→SAMPLE_READY→…)→Settled→Closed; sweep events can converge from any phase.
type taskFSM struct {
	mu sync.Mutex

	log *slog.Logger
	// messages signs Builder messages and sends them to connected Cortex streams (cortexlink.go).
	// Without a service key nothing is signed, and the only correct behaviour is not to send.
	messages builderMessages
	submit   Submitter
	relay    relay.Custodian
	self     string // this node's builder address (Builder message signer / transaction submitter)
	chainID  string // Task Chain ID (binds every signed message and transaction to this chain)

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
	phase types.TaskPhase // fine-grained phase, drives the external task_phase
	// terminal records that this FSM already crossed its irreversible local
	// cleanup boundary, including StageSettle sweeps whose coarse state is Settled.
	terminal bool

	events *journal // per-task event log (GetTaskEvents); owned by the coordinator, kept after close

	// Hand-raise / verification-result collection buffers (deduplicated by sender). They hold the
	// proto message bodies of the frozen wire: whatever bytes Cortex signed are the bytes
	// the Builder submits, with no second declaration.
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
	verifyResults      map[string]*taskv1.ResultReceiptV3
	// verifyCommits: Verifier commits already relayed on-chain (by Verifier address), for idempotent dedup.
	verifyCommits map[string]*taskv1.VerifyCommitV1
	fullReveals   map[string]bool // Verifiers that already self-rescued on-chain via FullResultRevealTx
	// commitFlights / resultFlights: relays waiting for their block result outside the lock, by
	// Verifier address (txconfirm.go).
	commitFlights map[string]*relayFlight
	resultFlights map[string]*relayFlight
	// pendingResults: results whose relay failed temporarily, followed by reconciliation until
	// the chain holds them, by Verifier address (txconfirm.go).
	pendingResults map[string]*pendingResult
	// workerRevealed: on-chain Worker reveal. The chain has no such Msg / Event,
	// so it is always false in Phase 0; kept only as "record if present", no longer a
	// settlement precondition.
	workerRevealed bool

	// acceptedTaskHash is the authoritative on-chain task_hash (only from query/event;
	// Nexus never creates it). Non-empty means the task has been accepted.
	acceptedTaskHash []byte
	// acceptedInputHash is the accepted order's input_hash (lowercase hex), from the same chain
	// query; empty until it is known.
	acceptedInputHash string
	// versionMismatch is set once the chain accepted a version other than f.order: this Builder
	// then works with the accepted task_hash, holds no input for it, and is never data-ready.
	versionMismatch bool
	// mismatchNotReadyLogged keeps the "not data-ready" notice to one line per process.
	mismatchNotReadyLogged bool
	// Per-phase dedup: once a phase's Tx is submitted it is not reassembled (the chain has its own idempotency fallback).
	openVerifySubmitted bool
	// receiptOnChain: the chain has accepted this InferReceipt. OPEN_VERIFY may only be sent
	// after it is true: a Verifier queries the chain as soon as it receives the
	// message and cannot hand-raise without an on-chain receipt, while OPEN_VERIFY is Core
	// tier and sent once. At least one block lies between accepting the receipt locally and
	// the transaction being included.
	receiptOnChain bool
	// acceptedOutputHash / acceptedReceiptHash come from the chain's accepted InferReceipt when
	// this Builder did not receive the signed receipt (see acceptedReceiptHashesLocked).
	acceptedOutputHash  []byte
	acceptedReceiptHash []byte
	openVerifyPublished bool // OPEN_VERIFY already sent by this process; reconcile reruns do not resend
	// resultReadiness answers local data-ready; dataReady caches a positive answer.
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
	// With block results readable (confirm), settleTx paces the resubmissions instead of
	// one per block.
	settleSubmittedHeight uint64
	// receiptTx / settleTx follow this node's MsgSubmitInferReceipt and MsgSettleTask to their
	// block results; confirm reads them (nil: broadcast only, see txConfirm). requestTxCheck asks
	// reconciliation to read an outstanding result.
	receiptTx      submittedTx
	settleTx       submittedTx
	confirm        *txConfirm
	requestTxCheck func()
	// sweepSubmitted records the deadline kinds for which this node has already submitted
	// MsgSweepDeadline, so the same one is not resubmitted on every new block. Deliberately
	// not in taskSnapshot: after restart it is submitted at most once more, a NOOP on-chain.
	sweepSubmitted map[taskv1.DeadlineKindV1]bool

	// SETTLE rank timing.
	// settleGraceBlocks is the grace block count per rank (Hub parameter, read and persisted
	// together with the settlement ordering); observedHeight is the chain height of the
	// latest NewBlock. Rank ≥2 submits only after its own grace window has started.
	settleGraceBlocks uint64
	observedHeight    uint64
	// verifierProposalTimer batches hand-raises; when verifierProposalDelay is 0, submit synchronously (for tests).
	verifierProposalTimer *time.Timer
	verifierProposalDelay time.Duration
	// verifierWindow is the round 1 verifier window header, read by reconciliation. A selected
	// Task Builder may submit Verifier proposals up to BuilderProposalCloseHeight; after that only
	// the winner Worker may. verifierProposalClosed records that this Builder is past that height
	// and stops submitting. Neither is persisted: both are derived from the chain, and after a
	// restart the next reconciliation reads the window again.
	verifierWindow         chaincli.VerifierWindow
	verifierWindowKnown    bool
	verifierProposalClosed bool
	// verifierRandomnessTried records that the attempt due once the window randomness height has
	// passed was made, so each new block does not repeat it.
	verifierRandomnessTried bool
	settleSelection         chaincli.StageBuilderSelectionState
	// settleStage is the chain's word on whether the task can be settled now, read by
	// reconciliation (QueryTaskStage). Not persisted: after a restart the next reconciliation
	// reads it again, and until then this node only waits.
	settleStage settleStage
	// settleOpenHeight is the first chain height at which the chain accepted this task's
	// settlement in simulation, once anyone may submit; the stagger by rank counts from it
	// (trySettle). Every Builder reads the same chain, so they agree on it. 0 = not yet.
	settleOpenHeight uint64

	// Backfilled once the chain finalizes.
	settlement  chaincli.TaskSettlementState
	verdict     types.TaskVerdict // chain-computed verdict (display only, never a substitute for on-chain facts)
	winner      string
	assignedSet []types.BuilderRef
	verifiers   []string
	// recordHeight is the height the chain recorded the task's dispatch; 0 until known.
	recordHeight uint64
	// inferDeadlineHeight is the chain-height deadline for the winner's receipt, from the on-chain
	// task (reconcile).
	inferDeadlineHeight uint64
	sampleSeed          []byte // from the chain's SampleReady (sole authoritative source; nexus never derives it)
	deadlines           types.Deadlines
	outputHash          []byte
	inferReceipt        types.InferReceiptSubmission

	timer     *time.Timer
	onClose   func() // used by the coordinator to remove this instance from the task table
	onAbandon func() // pre-chain failure/expiry: remove without a terminal marker

	handlerMu sync.Mutex
	stopped   bool
	handlerWG sync.WaitGroup

	beginExternalHandler func() bool
	endExternalHandler   func()
	requestReconcile     func(string)

	// Snapshot persistence seam (crash recovery); nil = no persistence
	// (some unit tests construct the fsm directly).
	persist   func(taskSnapshot) error // write KV after every state transition
	unpersist func()                   // clear KV once the task reaches a terminal state
	// persistDeferred writes like persist without waiting for the disk (kv.WriteDeferred); nil
	// falls back to persist.
	persistDeferred func(taskSnapshot) error

	// currentEpoch returns the epoch of the last observed chain height, false when unknown.
	currentEpoch func() (uint64, bool)
}

// emit records one task event (state/phase taken from current values). Caller must hold the lock.
func (f *taskFSM) emit(code string, height int64) { f.emitDetail(code, height, nil) }

// emitDetail is emit with the event's routing and rejection facts.
func (f *taskFSM) emitDetail(code string, height int64, detail *types.TaskEventDetail) {
	if f.events == nil {
		return
	}
	f.events.append(types.TaskEvent{
		EventCode:   code,
		State:       f.state.String(),
		TaskPhase:   f.phase.String(),
		ChainHeight: height,
		TS:          nowMS(),
		Detail:      detail,
	})
}

// ---- Entry points (called via coordinator routing) ----

// rememberAcceptedVersion records the authoritative task_hash and input_hash (lowercase hex) after
// on-chain acceptance. Only canonical 32-byte values are accepted; invalid or empty values are
// ignored -- better to fall back to the first-proposal branch and fail there than to build
// ExistingTaskRefV1 from half a hash.
//
// It reports true the first time the accepted version is found to differ from this Builder's
// order. From then on the task is identified by the accepted task_hash and this Builder is never
// data-ready; the caller removes the local input.
func (f *taskFSM) rememberAcceptedVersion(taskHash, inputHash string) bool {
	if taskHash == "" {
		return false
	}
	raw, err := nodecontract.Hash32Bytes("accepted task_hash", taskHash)
	if err != nil {
		f.log.Warn("ignore non-canonical accepted task_hash", "task_id", f.taskID, "err", err)
		return false
	}
	if inputHash != "" {
		if _, err := nodecontract.Hash32Bytes("accepted input_hash", inputHash); err != nil {
			f.log.Warn("ignore non-canonical accepted input_hash", "task_id", f.taskID, "err", err)
			inputHash = ""
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := false
	if !bytes.Equal(f.acceptedTaskHash, raw) {
		f.acceptedTaskHash = raw
		changed = true
	}
	if inputHash != "" && f.acceptedInputHash != inputHash {
		f.acceptedInputHash = inputHash
		changed = true
	}
	detected := false
	if !f.versionMismatch && f.order.TaskHash != "" && (f.order.TaskHash != taskHash ||
		(f.acceptedInputHash != "" && f.order.PayloadHash != "" && f.order.PayloadHash != f.acceptedInputHash)) {
		f.versionMismatch = true
		f.log.Error("chain accepted another version of this task",
			"task_id", f.taskID, "local_task_hash", f.order.TaskHash, "accepted_task_hash", taskHash)
		f.log.Error("chain accepted another version of this task: input differs",
			"task_id", f.taskID, "local_input_hash", f.order.PayloadHash, "accepted_input_hash", f.acceptedInputHash)
		changed, detected = true, true
	}
	if changed {
		f.save()
	}
	return detected
}

// acceptedInputContentHashLocked returns the content hash of the accepted version's INPUT object,
// derived from the chain's accepted input_hash once known, else from this Builder's order's while
// the receipt's task_hash is the order's own. Empty means unknown, and then this Builder is not
// data-ready. Caller must hold the lock.
func (f *taskFSM) acceptedInputContentHashLocked() string {
	switch {
	case f.acceptedInputHash != "":
		return taskdata.InputContentHash(f.acceptedInputHash)
	case !f.versionMismatch && f.order.TaskHash != "" && f.order.TaskHash == f.inferReceipt.TaskHash:
		return taskdata.InputContentHash(f.order.PayloadHash)
	default:
		return ""
	}
}

func (f *taskFSM) onAssignTimeout(height uint64) {
	if !f.failPending(EvAssignTimeout, types.VerdictAssignTimeout, height) {
		return
	}
	f.log.Info("task assign timed out before on-chain acceptance", "task_id", f.taskID,
		"height", height, "deadline_height", f.order.DeadlineHeight)
	if f.onAbandon != nil {
		f.onAbandon()
	}
}

// failPending ends a task that never reached the chain with event code and verdict; it reports
// false when the task is no longer Pending. Removing the task is the caller's.
func (f *taskFSM) failPending(code string, verdict types.TaskVerdict, height uint64) bool {
	return f.failPendingDetail(code, verdict, height, nil)
}

// failPendingDetail is failPending with the event's routing and rejection facts.
func (f *taskFSM) failPendingDetail(code string, verdict types.TaskVerdict, height uint64, detail *types.TaskEventDetail) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Pending {
		return false
	}
	f.state = types.Failed
	f.verdict = verdict
	f.terminal = true
	f.emitDetail(code, int64(height), detail)
	f.save()
	f.teardown()
	f.relay.Release(f.sessionID, f.taskID)
	return true
}

// acceptInferReceipt records the first signed InferReceipt and makes exact
// retries idempotent (the material digest is unchanged under any legitimate retry).
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

// publishOpenVerify opens hand-raising to Verifier candidates: one Builder-signed OpenVerifyV1 to
// every connected Cortex stream. Caller must hold the lock.
//
// It waits for the chain to accept the receipt: a Verifier queries the chain as soon as it receives
// the message and cannot hand-raise without an on-chain receipt. The message carries no
// input/output/evidence bodies and does not mean any Verifier has been selected.
//
// It also waits for this Builder's local data-ready: input, output and all required
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
	ctx := context.Background()
	if err := f.messages.signOpenVerify(ctx, payload, f.recordHeight); err != nil {
		f.log.Warn("OPEN_VERIFY not sent: it cannot be signed", "task_id", f.taskID, "err", err)
		return
	}
	frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: payload}}
	if err := f.messages.broadcast(ctx, frame); err != nil {
		f.log.Warn("OPEN_VERIFY broadcast failed", "task_id", f.taskID, "err", err)
		return
	}
	f.openVerifyPublished = true
	f.log.Info("OPEN_VERIFY sent", "task_id", f.taskID)
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
			InputContentHash: f.acceptedInputContentHashLocked(),
		}
		if f.versionMismatch {
			// Not a fault to retry: the input this Builder holds is not the accepted one, so it
			// cannot serve Verifiers the whole data set. It never sends OPEN_VERIFY or a Verifier
			// proposal for this task.
			if !f.mismatchNotReadyLogged {
				f.mismatchNotReadyLogged = true
				f.log.Info("holds a different input version; not data-ready for verification", "task_id", f.taskID)
			}
			f.dataReadyChecking = false
			f.dataReadyRecheck = false
			f.mu.Unlock()
			return
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
// Hashes taken from the chain do not make this Builder data-ready.
func (f *taskFSM) openVerifyPayload() *nexusv1.OpenVerifyV1 {
	if len(f.outputHash) == 0 || f.winner == "" {
		return nil
	}
	taskID, taskHash := f.taskIDBytes(), f.taskHashBytes()
	modelID, err := hex.DecodeString(f.modelID)
	if taskID == nil || taskHash == nil || err != nil || len(modelID) != hash32Len {
		f.log.Warn("skip OPEN_VERIFY publish: task identity is not canonical", "task_id", f.taskID)
		return nil
	}
	return &nexusv1.OpenVerifyV1{
		TaskId:                taskID,
		TaskHash:              taskHash,
		ModelId:               modelID,
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

// onWinnerRecorded: the chain recorded the task's dispatch and its winning Worker: record the winner
// and move to Assigned. The Worker learned of its win from the dispatch itself; nothing is sent.
func (f *taskFSM) onWinnerRecorded(winner string, assignedSet []types.BuilderRef, height int64, inferDeadline uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Pending {
		return // idempotent
	}
	f.winner = winner
	if height > 0 {
		f.recordHeight = uint64(height)
	}
	if len(assignedSet) > 0 {
		f.assignedSet = assignedSet
	}
	if inferDeadline != 0 {
		f.inferDeadlineHeight = inferDeadline
	}
	f.state = types.Assigned
	f.phase = types.PhaseAssignmentFinalized
	f.emit(EvDispatchRecorded, height)
	f.save()
	f.log.Info("dispatch recorded on chain: winner known", "task_id", f.taskID, "winner", winner)
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
	logAccepted := f.log.Info
	if f.verifierProposalClosed {
		logAccepted = f.log.Debug // kept, but this Builder can no longer submit it
	}
	logAccepted("verifier handraise accepted", "task_id", f.taskID, "candidate", candidate,
		"count", len(f.verifierHR), "need", proposalHandraiseMin)

	f.submitOpenVerifyLocked()
	f.scheduleVerifierProposalLocked()
}

// scheduleVerifierProposalLocked batches hand-raises: once selectedVerifierCount
// not-yet-on-chain hand-raises are collected, submit immediately; otherwise start a
// verifierProposalDelay timer and submit whatever has been collected when it fires.
// Caller must hold the lock.
func (f *taskFSM) scheduleVerifierProposalLocked() {
	if f.verifierProposalClosed {
		return
	}
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
// MsgSubmitVerifierHandraises proposal. Caller
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
	// An accepted proposal declares this Builder data-ready for the selected Verifiers.
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
	if !f.verifierProposalOpenLocked(len(pending)) {
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
		// The chain gives the same "window is unavailable" before the window is READY and after it
		// closes, so whether to keep retrying is decided by height, never by the error text.
		if f.pastBuilderProposalCloseLocked() {
			f.closeVerifierProposalsLocked(len(pending))
		}
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

// verifierProposalOpenLocked reports whether this Builder may submit a Verifier proposal now.
// Without the window (not read yet, or the read failed) it keeps the default: submit, and retry on
// the next reconciliation if the chain refuses. A proposal executes at observedHeight+1 at the
// earliest, and the chain accepts a Builder's proposal while the height is at most
// BuilderProposalCloseHeight. Caller must hold the lock.
func (f *taskFSM) verifierProposalOpenLocked(pending int) bool {
	if !f.verifierWindowKnown || f.observedHeight == 0 {
		return true
	}
	if f.pastBuilderProposalCloseLocked() {
		f.closeVerifierProposalsLocked(pending)
		return false
	}
	next := f.observedHeight + 1
	if f.verifierWindow.Ready {
		// GeneratedHeight is at most the height at which READY was read, so this almost never holds
		// back a proposal; nothing re-triggers one when it does, and the next reconciliation retries.
		return next >= f.verifierWindow.GeneratedHeight
	}
	// Not READY when last read. Until the window randomness height the beacon cannot have arrived,
	// so a submission would surely be refused; after it the cached status may be stale, so try, and
	// a refusal is retried on the next reconciliation as before.
	return next > f.verifierWindow.WindowRandomnessHeight
}

// pastBuilderProposalCloseLocked reports whether a proposal sent now would execute after the last
// height at which the chain accepts one from a Task Builder. Caller must hold the lock.
func (f *taskFSM) pastBuilderProposalCloseLocked() bool {
	return f.verifierWindowKnown && f.observedHeight > 0 &&
		f.observedHeight+1 > f.verifierWindow.BuilderProposalCloseHeight
}

// closeVerifierProposalsLocked stops this Builder submitting Verifier proposals for the task. The
// hand-raises still pending are kept, but only the winner Worker can put them on chain now.
// Caller must hold the lock.
func (f *taskFSM) closeVerifierProposalsLocked(pending int) {
	if f.verifierProposalClosed {
		return
	}
	f.verifierProposalClosed = true
	f.stopVerifierProposalTimerLocked()
	f.log.Info("Builder Verifier proposal window closed; remaining hand-raises are left to the winner Worker",
		"task_id", f.taskID, "builder_proposal_close_height", f.verifierWindow.BuilderProposalCloseHeight,
		"height", f.observedHeight, "pending_handraises", pending)
}

// needsVerifierWindow reports whether reconciliation should read the round 1 verifier window:
// while this Builder may still submit proposals and the window is not known READY. Reconciliation
// asks only once the chain has accepted the receipt, which is when the window is written.
func (f *taskFSM) needsVerifierWindow() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state == types.Assigned && !f.verifierProposalClosed &&
		(!f.verifierWindowKnown || !f.verifierWindow.Ready)
}

// setVerifierWindow records the round 1 verifier window header read by reconciliation.
func (f *taskFSM) setVerifierWindow(window chaincli.VerifierWindow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifierWindow = window
	f.verifierWindowKnown = true
}

// onHeightVerifierProposalLocked acts on two points in the Builder proposal window that a new
// block can pass without any reconciliation or hand-raise to trigger a submission. Heights come
// from polling and can skip blocks, so both are ranges, not exact heights:
//   - once the next block is past the window randomness height, hand-raises held back by
//     verifierProposalOpenLocked are tried once;
//   - once the next block is within verifierProposalCloseLeadBlocks of BuilderProposalCloseHeight,
//     batched hand-raises are submitted instead of letting the batching delay carry them past it.
//
// Caller must hold the lock.
func (f *taskFSM) onHeightVerifierProposalLocked() {
	if !f.verifierWindowKnown || f.verifierProposalClosed {
		return
	}
	next := f.observedHeight + 1
	if !f.verifierWindow.Ready && !f.verifierRandomnessTried && next > f.verifierWindow.WindowRandomnessHeight {
		f.verifierRandomnessTried = true
		f.scheduleVerifierProposalLocked()
	}
	// Checked before stopping the timer, in the same order as submitVerifierProposalLocked: only a
	// Builder holding the signed receipt and data-ready can submit, and if the window holds the
	// proposal back the batch keeps its timer instead of waiting for the next reconciliation. A
	// Builder that could never submit therefore does not close the window or log it.
	if f.verifierProposalTimer != nil && next+verifierProposalCloseLeadBlocks >= f.verifierWindow.BuilderProposalCloseHeight &&
		len(f.outputHash) > 0 && f.dataReadyLocked() &&
		f.verifierProposalOpenLocked(len(f.pendingVerifierHandraises())) {
		f.stopVerifierProposalTimerLocked()
		f.submitVerifierProposalLocked()
	}
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
	// After a failed block result: given up, or waiting out the backoff (txconfirm.go).
	if f.resubmitHeldLocked(&f.receiptTx) {
		f.log.Debug("OpenVerifyTx resubmission held", "task_id", f.taskID, "stopped", f.receiptTx.stopped,
			"retry_at_height", f.receiptTx.retryAt, "height", f.observedHeight)
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
	// OpenVerifyTx carries no sample_seed -- the chain derives the seed after OpenVerify
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
	// MsgSubmitInferReceipt carries the frozen-wire InferReceiptV2 body, not
	// the old MsgOpenVerify string copies. If it cannot be filled, do not submit -- otherwise
	// the submitter fails with "receipt is required" while the Builder has already answered
	// the Worker with relay_accepted=true.
	receipt, err := nodecontract.InferReceiptV3FromSubmission(f.inferReceipt)
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
	res, err := f.submit.SubmitOpenVerify(context.Background(), tx)
	if err != nil {
		f.log.Warn("submit OpenVerifyTx failed", "task_id", f.taskID, "err", err)
		f.openVerifySubmitted = false
		return
	}
	// CheckTx passing is not acceptance: reconciliation reads the block result by this hash.
	f.sentLocked(&f.receiptTx, res.TxHash)
	f.save()
	f.log.Info("OpenVerifyTx submitted", "task_id", f.taskID, "verifier_handraise", len(f.verifierHR),
		"tx_hash", hex.EncodeToString(res.TxHash))
}

// onOpenVerifyAccepted: on-chain open-verify included: record the selected Verifiers and
// the four deadlines, and send the open-verify notification.
// **The notification carries no seed** -- the seed is delivered separately via
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

	taskID, taskHash := f.taskIDBytes(), f.taskHashBytes()
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
		// The authoritative set is the on-chain VerifierAssignmentState; this message only speeds
		// up coordination.
		verifiers := notifyVerifiers(ev)
		f.publishVerifierAssignment(&nexusv1.VerifierAssignmentNotifyV1{
			TaskId:               taskID,
			TaskHash:             taskHash,
			VerifyRound:          uint32(nodecontract.SupportedVerifyRoundV1),
			Verifiers:            verifiers,
			OutputHash:           append([]byte(nil), outputHash...),
			OpenVerifyHeight:     uint64(max(ev.Height, 0)),
			CommitDeadlineHeight: uint64(max(ev.Deadlines.Commit, 0)),
			RevealDeadlineHeight: uint64(max(ev.Deadlines.Reveal, 0)),
			VerifyDeadlineHeight: uint64(max(ev.Deadlines.Verify, 0)),
		})
	} else {
		f.log.Warn("skip VERIFIER_ASSIGNMENT_NOTIFY publish: task identity is not canonical", "task_id", f.taskID)
	}
	f.emit(EvOpenVerifyAccepted, ev.Height)
	f.save()
	f.log.Info("task verifying: verifier set + deadlines dispatched (seed pending beacon)",
		"task_id", f.taskID, "verifiers", len(ev.Verifiers))
}

// notifyVerifiers is the verifiers[] of a VerifierAssignmentNotifyV1: each formal Verifier with
// its candidate slot and slot version when the source read them (QueryTask), the address alone
// when it did not (the chain event).
func notifyVerifiers(ev chaincli.OpenVerifyAccepted) []*taskv1.SelectedVerifierV1 {
	verifiers := make([]*taskv1.SelectedVerifierV1, 0, len(ev.Verifiers))
	slotted := len(ev.Selected) == len(ev.Verifiers)
	for i, verifier := range ev.Verifiers {
		v := &taskv1.SelectedVerifierV1{OperatorAddress: verifier}
		if slotted && ev.Selected[i].Operator == verifier {
			v.Slot, v.SlotVersion = ev.Selected[i].Slot, ev.Selected[i].SlotVersion
		}
		verifiers = append(verifiers, v)
	}
	return verifiers
}

// publishVerifierAssignment sends one Builder-signed VerifierAssignmentNotifyV1 to every connected
// Cortex stream. It is a wake-up; the authoritative set is the on-chain VerifierAssignmentState.
// Caller must hold the lock.
func (f *taskFSM) publishVerifierAssignment(msg *nexusv1.VerifierAssignmentNotifyV1) {
	ctx := context.Background()
	if err := f.messages.signVerifierAssignment(ctx, msg, f.recordHeight); err != nil {
		f.log.Warn("VERIFIER_ASSIGNMENT_NOTIFY not sent: it cannot be signed", "task_id", f.taskID, "err", err)
		return
	}
	frame := &nexusv1.DispatchStreamFrameV1{
		Message: &nexusv1.DispatchStreamFrameV1_VerifierAssignment{VerifierAssignment: msg},
	}
	if err := f.messages.broadcast(ctx, frame); err != nil {
		f.log.Warn("VERIFIER_ASSIGNMENT_NOTIFY broadcast failed", "task_id", f.taskID, "err", err)
	}
}

// onSampleReady: the on-chain sample seed is ready (aggregated future proposer-VRF beacon):
// only record the seed and phase.
//
// There is no trueopen.sample-ready.* subject, and in V1 the selected Verifiers recompute all
// committed generated tokens, so the notification carries no additional verification position
// selection material. So this notification
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
	f.log.Info("sample seed recorded from chain (not published)",
		"task_id", f.taskID, "ready_height", ev.ReadyHeight)
}

// relayVerifyResult is the Ingress unary path: validation failures are reported to the caller with
// types sentinels.
func (f *taskFSM) relayVerifyResult(vr *taskv1.ResultReceiptV3) (types.VerifyRelayAck, error) {
	f.mu.Lock()
	if err := f.verifyRelayPreconditionsLocked(vr.GetTaskId(), vr.GetVerifierOperatorAddress()); err != nil {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, err
	}
	if !f.validVerifyResult(vr) {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, fmt.Errorf("%w: result receipt fails the frozen field checks", types.ErrInvalidArgument)
	}
	return f.relayVerifyResultLocked(vr)
}

// relayVerifyCommit is the Ingress unary path: in the initial relay implementation the Builder is
// trusted, and the Verifier-signed commit is relayed by this Builder via
// MsgBatchSubmitVerifyCommit. It answers once the chain holds the commit (recorded locally
// then; resending the same commit passes idempotently), or with an error when the chain
// refused it (types.ErrInvalidArgument for the content, otherwise temporary) or showed no
// block result within the wait (temporary). A Verifier that does not observe acceptance
// before the deadline still submits the same message itself.
//
// The lock is held to validate and broadcast, released while the block result is awaited, and
// taken again to record; meanwhile other operations on this task proceed.
func (f *taskFSM) relayVerifyCommit(commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error) {
	f.mu.Lock()
	verifier := commit.GetVerifierOperatorAddress()
	if err := f.verifyRelayPreconditionsLocked(commit.GetTaskId(), verifier); err != nil {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, err
	}
	if !f.validVerifyCommit(commit) {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, fmt.Errorf("%w: verify commit fails the frozen field checks", types.ErrInvalidArgument)
	}
	if existing, ok := f.verifyCommits[verifier]; ok {
		f.mu.Unlock()
		if proto.Equal(existing, commit) {
			return types.VerifyRelayAck{Idempotent: true}, nil
		}
		// The chain accepts only the first commit per Verifier per round; a second one with
		// different content would surely be rejected, so report a conflict here rather than
		// waste a fee.
		return types.VerifyRelayAck{}, fmt.Errorf("%w: a different verify commit from this verifier was already relayed", types.ErrInvalidArgument)
	}
	if flight, ok := f.commitFlights[verifier]; ok {
		f.mu.Unlock()
		return flight.join(commit, "verify commit")
	}
	if f.submit == nil {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, fmt.Errorf("verify commit relay: submitter is not configured")
	}
	res, err := f.submit.SubmitVerifyCommit(context.Background(), chaincli.VerifyCommitTx{Commit: commit, Submitter: f.self})
	flight := startRelayFlightLocked(&f.commitFlights, verifier, commit)
	f.mu.Unlock()

	ack, onChain, relayErr := f.relayOutcome(f.commitRelayItem(commit), res, err)

	f.mu.Lock()
	defer f.mu.Unlock()
	if onChain && !f.terminal {
		f.verifyCommits[verifier] = commit
		if err := f.save(); err != nil {
			f.log.Warn("verify commit relayed but local snapshot save failed",
				"task_id", f.taskID, "verifier", verifier, "err", err)
		}
		f.log.Info("verify commit relayed", "task_id", f.taskID, "verifier", verifier,
			"tx_hash", hex.EncodeToString(ack.TxHash), "idempotent", ack.Idempotent)
	}
	flight.finishLocked(f.commitFlights, verifier, ack, relayErr)
	return ack, relayErr
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
// MsgBatchSubmitVerifyResult: only once the chain holds it is it stored locally and counted
// as received; then try to settle. Resending the same receipt passes idempotently, and a
// resend while the first is still awaiting its block result shares that result. Caller must
// hold the lock; it is released on return, and also while the block result is awaited.
//
// The order is mandatory: MsgSettleTask submits only task_id, and the Keeper derives the
// settlement inputs from the on-chain accepted ResultReceiptState -- without the receipt
// on-chain there are no settlement inputs. A rejection of the receipt's content returns
// types.ErrInvalidArgument; a temporary failure, or no block result within the wait, returns
// another error for the caller to retry. Whether the chain already holds this receipt is read
// from the chain's record (relayOutcome), which also settles a redelivery after a crash
// between broadcast and Ack.
func (f *taskFSM) relayVerifyResultLocked(vr *taskv1.ResultReceiptV3) (types.VerifyRelayAck, error) {
	verifier := vr.GetVerifierOperatorAddress()
	if existing, ok := f.verifyResults[verifier]; ok && proto.Equal(existing, vr) {
		f.mu.Unlock()
		// Redelivery of the same receipt: the previous round already put it on-chain and stored it locally (e.g. the Ack was lost in flight); pass idempotently.
		return types.VerifyRelayAck{Idempotent: true}, nil
	}
	if flight, ok := f.resultFlights[verifier]; ok {
		f.mu.Unlock()
		return flight.join(vr, "verify result")
	}
	if pending, ok := f.pendingResults[verifier]; ok {
		f.mu.Unlock()
		// Followed by reconciliation until the chain holds it. Ask the caller to come back.
		if !proto.Equal(pending.receipt, vr) {
			return types.VerifyRelayAck{}, fmt.Errorf("%w: a different verify result from this verifier is being relayed", types.ErrInvalidArgument)
		}
		return types.VerifyRelayAck{}, fmt.Errorf("%w: verify result is being confirmed", errRelayUnconfirmed)
	}
	if f.submit == nil {
		f.mu.Unlock()
		return types.VerifyRelayAck{}, fmt.Errorf("verify result relay: submitter is not configured")
	}
	res, err := f.submit.SubmitVerifyResult(context.Background(), chaincli.VerifyResultTx{
		Receipt: vr, Submitter: f.self,
	})
	flight := startRelayFlightLocked(&f.resultFlights, verifier, vr)
	f.mu.Unlock()

	ack, onChain, relayErr := f.relayOutcome(f.resultRelayItem(vr), res, err)

	f.mu.Lock()
	defer f.mu.Unlock()
	if onChain && !f.terminal {
		f.recordVerifyResultLocked(vr, ack.Idempotent)
	} else if relayErr != nil && !errors.Is(relayErr, types.ErrInvalidArgument) {
		f.followFailedRelayLocked(vr, res, err, relayErr)
	}
	flight.finishLocked(f.resultFlights, verifier, ack, relayErr)
	return ack, relayErr
}

// recordVerifyResultLocked stores a result the chain holds and tries to settle. Caller must hold
// the lock.
func (f *taskFSM) recordVerifyResultLocked(vr *taskv1.ResultReceiptV3, idempotent bool) {
	verifier := vr.GetVerifierOperatorAddress()
	f.verifyResults[verifier] = vr
	if err := f.save(); err != nil {
		// The receipt is on-chain (the authoritative fact already holds); the local snapshot is
		// only a cache and can be completed from in-memory state on the next save.
		f.log.Warn("verify result persisted on chain but local snapshot save failed",
			"task_id", f.taskID, "verifier", verifier, "err", err)
	}
	f.log.Debug("verify result relayed and stored", "task_id", f.taskID,
		"verifier", verifier, "count", len(f.verifyResults), "idempotent", idempotent)
	f.trySettle()
}

// validVerifyCommit checks each field of the frozen VerifyCommitV1 field table.
// Membership is decided by verifyRelayPreconditionsLocked; this
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
	// The Verifier handraise binds infer_receipt_hash / output_hash; there is
	// no longer a canonical_output_package_hash or a package pre-fetch declaration.
	case !bytes.Equal(hr.GetOutputHash(), outputHash):
		f.log.Warn("drop verifier handraise with mismatched output_hash", "task_id", f.taskID, "candidate", candidate)
	case !bytes.Equal(hr.GetInferReceiptHash(), receiptHash):
		f.log.Warn("drop verifier handraise with mismatched infer receipt", "task_id", f.taskID, "candidate", candidate)
	case len(hr.GetModelId()) != hash32Len || hr.GetProfileVersion() == 0 ||
		hr.GetServiceAuthorizationNonce() == 0 || hr.GetExpiryHeight() == 0 ||
		len(hr.GetServiceSignature()) != 64:
		f.log.Warn("drop verifier handraise without required frozen fields", "task_id", f.taskID, "candidate", candidate)
	case len(hr.GetRecipientPubkey()) != 0:
		f.log.Warn("drop verifier handraise with a recipient_pubkey while encryption is inactive", "task_id", f.taskID, "candidate", candidate)
	case len(hr.GetMember().GetCandidatePoolSnapshotId()) != 32 || hr.GetMember().GetSlotVersion() == 0:
		f.log.Warn("drop verifier handraise with incomplete candidate member ref", "task_id", f.taskID,
			"candidate", candidate, "slot", hr.GetMember().GetSlot())
	default:
		return true
	}
	return false
}

func (f *taskFSM) validVerifyResult(vr *taskv1.ResultReceiptV3) bool {
	verifier := vr.GetVerifierOperatorAddress()
	switch {
	case verifier == "":
		f.log.Warn("drop verify result with empty verifier", "task_id", f.taskID)
	case !containsString(f.verifiers, verifier):
		f.log.Warn("drop verify result from non-selected verifier", "task_id", f.taskID, "verifier", verifier)
	case vr.GetSchemaVersion() != nodecontract.ResultReceiptSchemaVersionV3:
		f.log.Warn("drop verify result with wrong schema_version", "task_id", f.taskID,
			"verifier", verifier, "schema_version", vr.GetSchemaVersion())
	case vr.GetChainId() != f.chainID:
		f.log.Warn("drop verify result bound to a different chain", "task_id", f.taskID, "verifier", verifier)
	case uint64(vr.GetVerifyRound()) != nodecontract.SupportedVerifyRoundV1:
		f.log.Warn("drop verify result for an unsupported verify round", "task_id", f.taskID,
			"verifier", verifier, "verify_round", vr.GetVerifyRound())
	// metric_root / metric_summary / verifier_evidence_bundle_hash are the grouping inputs
	// for re-execution consistency; generation_params_digest binds the re-execution
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
// MsgSweepDeadline is a BOUNDED_RUNNER: any account
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
// included) verify-phase deadline. Task deadlines are closed intervals:
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

// settleStage is what the chain reports about settling a task. ready is true while the task is
// SETTLING, not settled and not final: every verification round has closed. The chain may mark a
// task SETTLING a few blocks before its challenge window closes and refuses a settlement until
// then; the simulation before each submission holds it over those blocks. deadline is the
// settlement deadline, at which the chain settles the task by itself; 0 = unknown.
type settleStage struct {
	ready    bool
	deadline uint64
}

// settleStageFrom reads the settlement facts out of a chain TaskStage.
func settleStageFrom(stage chaincli.TaskStage) settleStage {
	// ADR-0040 v4: while the chain holds settlement for the anchor audit verdict it reports
	// ANCHOR_VERDICT as the next deadline; a settlement sent before then is refused, so do
	// not simulate one every block. The periodic reconciliation re-reads the stage.
	out := settleStage{ready: stage.TaskPhase == "SETTLING" && stage.SettlementStatus == "NONE" &&
		stage.FinalityStatus == "PENDING" && stage.NextDeadlineKind != "ANCHOR_VERDICT"}
	if out.ready && stage.NextDeadlineKind == "TASK_SETTLEMENT" {
		out.deadline = stage.NextDeadlineHeight
	}
	return out
}

// setSettleStageLocked records the chain's settlement facts. Once the settlement order is known
// it tries to settle; before that, reconcileSettleSelection reads the order and tries. Caller must
// hold the lock.
func (f *taskFSM) setSettleStageLocked(stage settleStage) {
	if stage.ready && !f.settleStage.ready {
		f.log.Info("chain reports the task ready to settle", "task_id", f.taskID,
			"settlement_deadline", stage.deadline)
	}
	f.settleStage = stage
	if !stage.ready {
		f.settleOpenHeight = 0
	}
	if f.settleSelection.SessionID != "" {
		f.trySettle()
	}
}

// trySettle submits MsgSettleTask once the chain reports the task ready to settle
// (settleStage) and this Builder may submit at the next height.
//
// Whether the task can be settled is the chain's decision, never a local count of Verifier
// results: the chain groups results by each Verifier's own verdict and token count and closes
// the rounds itself, and local result copies may be missing or differ in fields the chain does
// not compare. A Builder's settlement only brings the settlement forward: the chain settles the
// task by itself at its settlement deadline.
//
// Timing is decided entirely by chain height (see settleSubmissionAllowed): do not send before
// the height at which this node may send; sending in someone else's slot is rejected by the
// chain and wastes the fee. At most one send per block, and each send is simulated first. When
// block results can be read, the next send waits for the last one's result and, after a failure,
// for its backoff (txconfirm.go). Chain height comes from NewBlock (onHeight), not the local
// clock. Caller must hold the lock.
func (f *taskFSM) trySettle() {
	if f.state != types.Verifying || f.terminal || !f.settleStage.ready {
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
	if f.resubmitHeldLocked(&f.settleTx) {
		return // awaiting the block result of the last one, waiting out a backoff, or given up
	}
	allowed, permissionless := f.settleSubmissionAllowed(rank)
	if !allowed {
		f.log.Debug("task ready to settle; waiting for the height this Builder may submit at",
			"task_id", f.taskID, "rank", rank, "height", f.observedHeight,
			"reveal_deadline", f.deadlines.Reveal, "grace_blocks", f.settleGraceBlocks)
		return
	}
	if permissionless {
		if !f.settlePermissionlessTurnLocked(rank) {
			return
		}
	} else if !f.settleSlotChangesAtExecution() && !f.settlePassesSimulationLocked() {
		// In the first block of this Builder's slot a simulation still sees the previous
		// submitter's slot and would refuse; broadcast without it there.
		return
	}
	f.log.Info("settle window open; submitting", "task_id", f.taskID, "rank", rank,
		"height", f.observedHeight, "execution_height", f.observedHeight+1, "permissionless", permissionless)
	f.submitSettle()
}

// settleSubmissionAllowed reports whether the chain would accept this node's MsgSettleTask from
// the submitter schedule, with g = settlement_builder_grace_blocks and k = number of Builders in
// the frozen selection:
//
//	height <= reveal + g                   rank 1
//	reveal + (i-1)·g < height <= reveal + i·g   rank i
//	height > reveal + k·g                  anyone
//
// The schedule has no upper bound: settling is open until the task is settled. Whether the task
// can be settled at all is settleStage's part.
//
// The schedule counts from the reveal deadline while settling opens only after the challenge
// window, so under current parameters every settlement falls in the phase where anyone may
// submit; trySettle staggers the Builders there (settlePermissionlessTurnLocked).
//
// The decision uses the height at which the transaction **executes**, not the height this
// node just observed: the chain recomputes who may submit at the executing block, and the
// transaction can enter the next block at the earliest. Deciding by the observed height,
// a submission in the last block of this slot would execute in the next slot and be
// rejected as "submitter is not the Builder of the current slot".
//
// If any fact is missing (reveal deadline, grace blocks, Builder count unknown), return false:
// never guess the window. Caller must hold the lock.
func (f *taskFSM) settleSubmissionAllowed(rank int) (allowed bool, permissionless bool) {
	builders := uint64(len(f.settleSelection.SelectedBuilders))
	if rank < 1 || uint64(rank) > builders {
		return false, false
	}
	slot, permissionless, ok := f.settleSlotAt(f.observedHeight + 1) // the transaction executes in the next block at the earliest
	if !ok {
		return false, false
	}
	return permissionless || slot == uint64(rank-1), permissionless
}

// settlePermissionlessTurnLocked decides whether it is this Builder's turn once anyone may submit.
// Left alone every Builder would submit in the same block; the chain applies one and replays the
// others as no-ops, each still paying its fee. So rank i waits (i-1)·g blocks from settleOpenHeight,
// the first height at which the chain accepts the settlement in simulation, and stops once the
// chain settles the task; rank 1 does not wait. Counting from the task turning ready instead would
// let the challenge window hold rank 1 until the others' waits ran out as well. Every submission
// is simulated first. Caller must hold the lock.
func (f *taskFSM) settlePermissionlessTurnLocked(rank int) bool {
	simulated := false
	if f.settleOpenHeight == 0 {
		if !f.settleSlotChangesAtExecution() && !f.settlePassesSimulationLocked() {
			return false
		}
		f.settleOpenHeight, simulated = f.observedHeight, true
	}
	if due := f.settleOpenHeight + uint64(rank-1)*f.settleGraceBlocks; f.observedHeight < due {
		f.log.Debug("settlement open; waiting for this Builder's turn", "task_id", f.taskID,
			"rank", rank, "height", f.observedHeight, "open_height", f.settleOpenHeight, "due_height", due)
		return false
	}
	return simulated || f.settlePassesSimulationLocked()
}

// settleSlotAt is the chain's settlement submitter schedule at a height: the 0-based rank whose
// slot it is, or permissionless once every slot has passed. ok is false while the reveal
// deadline, grace blocks or Builder count is unknown. Caller must hold the lock.
func (f *taskFSM) settleSlotAt(height uint64) (slot uint64, permissionless bool, ok bool) {
	builders := uint64(len(f.settleSelection.SelectedBuilders))
	if builders == 0 || f.settleGraceBlocks == 0 || f.deadlines.Reveal <= 0 {
		return 0, false, false
	}
	reveal, grace := uint64(f.deadlines.Reveal), f.settleGraceBlocks
	if height > reveal+builders*grace {
		return 0, true, true
	}
	if height > reveal {
		slot = (height - reveal - 1) / grace
	}
	return slot, false, true
}

// settleSlotChangesAtExecution reports whether the submitter slot of the block the settlement
// executes in differs from that of the latest block. A simulation runs against the latest block,
// so in the first block of a new slot it would judge by the previous submitter and refuse.
// Caller must hold the lock.
func (f *taskFSM) settleSlotChangesAtExecution() bool {
	now, nowOpen, ok1 := f.settleSlotAt(f.observedHeight)
	next, nextOpen, ok2 := f.settleSlotAt(f.observedHeight + 1)
	return ok1 && ok2 && (now != next || nowOpen != nextOpen)
}

// onHeight: a new block arrived: record the chain height, then check whether the settlement window has opened (including retries after a failed submission).
func (f *taskFSM) onHeight(height uint64) {
	f.mu.Lock()
	if height <= f.observedHeight {
		f.mu.Unlock()
		return
	}
	f.observedHeight = height
	f.onHeightVerifierProposalLocked()
	f.trySettle()
	check := f.followSubmittedTxsLocked()
	f.mu.Unlock()
	// Enqueued off the lock: the reconcile worker takes this lock too.
	if check && f.requestTxCheck != nil {
		f.requestTxCheck()
	}
}

// submitSettle submits MsgSettleTask. The request is just task_id + submitter: the verdict, receipt
// references and evidence roots are derived by the chain from its own state. Caller must hold the
// lock.
func (f *taskFSM) submitSettle() {
	// Local result copies are logged only; they play no part in the settlement.
	missing := make([]string, 0, len(f.verifiers))
	for _, verifier := range f.verifiers {
		if _, ok := f.verifyResults[verifier]; !ok {
			missing = append(missing, verifier)
		}
	}
	f.settleSubmittedHeight = f.observedHeight
	tx := chaincli.SettleTx{
		Submitter: f.self, SessionID: f.sessionID, TaskID: f.taskID,
	}
	res, err := f.submit.SubmitSettle(context.Background(), tx)
	if err != nil {
		f.log.Warn("submit SettleTx failed", "task_id", f.taskID, "err", err)
		f.settleSubmittedHeight = 0
		// Retry on the next block (onHeight); if someone else settled on-chain, SettleAccepted arrives first and this becomes a no-op.
		return
	}
	f.sentLocked(&f.settleTx, res.TxHash)
	f.save()
	f.log.Info("SettleTx submitted", "task_id", f.taskID, "tx_hash", hex.EncodeToString(res.TxHash),
		"local_results", len(f.verifyResults), "local_results_missing", strings.Join(missing, ","))
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
// released. Settlement state is decided only by finality_status and task_finality_height:
// the chain reporting the task FINAL, with the chain height at
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
	// task_finality_height, and with one the task becomes final when the last round closes.
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

// inProposalGroup is the submission gate for the receipt and Verifier proposals:
// if this node belongs to the task's Builder group it submits its own proposal without
// waiting for others -- the Keeper takes the legitimate union after the window ends. If the group or our own identity is unknown (legacy / devnet), allow
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
	return f.state == types.Verifying && f.settleSelection.SessionID == "" && f.settleStage.ready
}

// teardown stops the task's timers. Caller must hold the lock.
func (f *taskFSM) teardown() {
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

// taskHashBytes returns the task_hash that identifies the task: the chain's accepted task_hash once
// it is known, else this Builder's order's candidate task_hash. After acceptance the task is the
// chain's version, even when this Builder's order was another one.
func (f *taskFSM) taskHashBytes() []byte {
	if len(f.acceptedTaskHash) == hash32Len {
		return append([]byte(nil), f.acceptedTaskHash...)
	}
	return f.orderTaskHashBytes()
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

// validateReceiptForOpenVerify checks the frozen wire fields needed to assemble
// MsgSubmitInferReceipt. The field set follows
// InferReceiptV2:
// batch_log_root / token_count / work_unit were removed from the wire and are no longer
// required. The kind set and count cap of evidence commitments are the Keeper's admission
// checks; locally only non-emptiness is required (the V1 text path always has
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
