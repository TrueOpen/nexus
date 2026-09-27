package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
)

// Block result checks for this node's own transactions. CheckTx passing only puts a transaction
// in the mempool; the chain can still refuse it when the block executes it. The Verifier commit
// and result relays wait for that result before answering (the caller retries on a temporary
// failure); the receipt and settlement transactions are followed by chain reconciliation and
// resubmitted at a paced rate.

// TxConfirmPolicy bounds the block result wait of a Verifier commit or result relay.
type TxConfirmPolicy struct {
	// BlockInterval spaces the result queries, about one block apart.
	BlockInterval time.Duration
	// WaitBlocks is how many block intervals a relay waits before answering "no result yet".
	WaitBlocks uint64
}

// relayLookupTimeout bounds the read of a Verifier's commit or receipt already on chain. The
// whole wait is capped at config.MaxTxConfirmWait, which with a broadcast and this lookup stays
// under the 30 s JetStream AckWait and the 60 s Cortex relay call timeout.
const relayLookupTimeout = 3 * time.Second

// WithTxConfirmPolicy sets the block result wait of the Verifier relays. Zero fields keep the
// defaults (3 intervals of 5 s); the whole wait is capped at config.MaxTxConfirmWait.
func WithTxConfirmPolicy(policy TxConfirmPolicy) Option {
	return func(c *Coordinator) { c.txConfirmPolicy = policy }
}

// VerifyStateQuerier reads the Verifier commit and result receipt the chain accepted, so a relay
// can tell "already on chain" from the chain's own record rather than from error text.
type VerifyStateQuerier interface {
	QueryVerifyCommit(ctx context.Context, taskID string, verifyRound uint32, verifier string) (chaincli.AcceptedVerifyCommit, error)
	QueryResultReceipt(ctx context.Context, taskID string, verifyRound uint32, verifier string) (chaincli.AcceptedResultReceipt, error)
}

// txConfirm is what a task FSM needs to read its transactions' block results. A nil *txConfirm
// (no Tx Query configured, as in stub mode) keeps the broadcast-only behaviour: CheckTx
// acceptance is taken as the outcome.
type txConfirm struct {
	txs      chaincli.TxQuerier
	state    VerifyStateQuerier // nil: nothing on chain can be looked up
	interval time.Duration
	wait     time.Duration
}

func (c *Coordinator) newTxConfirm() *txConfirm {
	if c.txQuery == nil {
		return nil
	}
	interval, blocks := c.txConfirmPolicy.BlockInterval, c.txConfirmPolicy.WaitBlocks
	if interval <= 0 {
		interval = config.DefaultTxConfirmBlockInterval
	}
	if blocks == 0 {
		blocks = config.DefaultTxConfirmWaitBlocks
	}
	return &txConfirm{
		txs: c.txQuery, state: c.verifyState, interval: interval,
		wait: min(interval*time.Duration(blocks), config.MaxTxConfirmWait),
	}
}

// temporaryTxFailure reports a refusal another try may pass. Only three cosmos-sdk refusals
// clear by themselves: a sequence mismatch (32), a full mempool (20) and the tx already in the
// mempool cache (19). Every other refusal -- a chain module's verdict, insufficient fee (13), out
// of gas (11), a recovered panic (codespace "undefined") -- fails the same way on every try, and
// retrying it only burns fees.
func temporaryTxFailure(result chaincli.TxResult) bool {
	return result.Codespace == "sdk" && (result.Code == 19 || result.Code == 20 || result.Code == 32)
}

// temporaryBroadcastError reports a broadcast that failed for a reason another try may clear:
// the node could not be reached, or CheckTx refused it temporarily.
func temporaryBroadcastError(err error) bool {
	var submission *SubmissionError
	if !errors.As(err, &submission) || !submission.Definitive {
		return true
	}
	return submission.Phase == SubmissionBroadcast && temporaryTxFailure(submission.Result)
}

var (
	// errRelayUnconfirmed: the relayed transaction has no block result within the wait. It may
	// still be included; the caller retries and a retry settles it from the chain's record.
	errRelayUnconfirmed = errors.New("relayed transaction has no block result yet")
	// errRelayTemporary: the chain refused the relayed transaction for a reason outside the
	// relayed content; a retry may pass.
	errRelayTemporary = errors.New("relayed transaction failed temporarily on chain")
)

// ---- Verifier commit and result relays ----

// relayFlight is one commit or result relay waiting for its block result outside the FSM lock.
// A resubmission of the same content from the same Verifier waits for it and shares its outcome
// instead of broadcasting again; different content is refused as a conflict.
type relayFlight struct {
	msg  proto.Message
	done chan struct{}
	ack  types.VerifyRelayAck
	err  error
}

// startRelayFlightLocked registers a relay about to wait. Caller must hold the lock.
func startRelayFlightLocked(flights *map[string]*relayFlight, verifier string, msg proto.Message) *relayFlight {
	if *flights == nil {
		*flights = make(map[string]*relayFlight)
	}
	flight := &relayFlight{msg: msg, done: make(chan struct{})}
	(*flights)[verifier] = flight
	return flight
}

// finishLocked publishes the outcome to joined callers. Caller must hold the lock.
func (fl *relayFlight) finishLocked(flights map[string]*relayFlight, verifier string, ack types.VerifyRelayAck, err error) {
	if flights[verifier] == fl {
		delete(flights, verifier)
	}
	fl.ack, fl.err = ack, err
	close(fl.done)
}

// join waits for an in-flight relay of the same content. Caller must not hold the lock.
func (fl *relayFlight) join(msg proto.Message, kind string) (types.VerifyRelayAck, error) {
	if !proto.Equal(fl.msg, msg) {
		return types.VerifyRelayAck{}, fmt.Errorf("%w: a different %s from this verifier is being relayed", types.ErrInvalidArgument, kind)
	}
	<-fl.done
	return fl.ack, fl.err
}

// relayItem is what the commit and result relays differ in.
type relayItem struct {
	kind     string // "verify commit" / "verify result"
	msgKind  string // the chain message, for the block failure log
	verifier string
	// onChain reads this Verifier's item for this round from the chain and reports whether it
	// equals the relayed one; found is false when the chain has none.
	onChain func(ctx context.Context, state VerifyStateQuerier) (found, same bool, err error)
}

func (f *taskFSM) commitRelayItem(commit *taskv1.VerifyCommitV1) relayItem {
	taskID, round, verifier := f.taskID, commit.GetVerifyRound(), commit.GetVerifierOperatorAddress()
	return relayItem{
		kind: "verify commit", msgKind: "MsgBatchSubmitVerifyCommit", verifier: verifier,
		// The chain keeps the first commit per Verifier and round; the commitment itself is
		// commit_hash. A copy re-signed with a fresh nonce or expiry commits to the same thing.
		onChain: func(ctx context.Context, state VerifyStateQuerier) (bool, bool, error) {
			accepted, err := state.QueryVerifyCommit(ctx, taskID, round, verifier)
			if err != nil {
				return false, false, err
			}
			return true, bytes.Equal(accepted.CommitHash, commit.GetCommitHash()), nil
		},
	}
}

func (f *taskFSM) resultRelayItem(vr *taskv1.ResultReceiptV3) relayItem {
	taskID, round, verifier := f.taskID, vr.GetVerifyRound(), vr.GetVerifierOperatorAddress()
	return relayItem{
		kind: "verify result", msgKind: "MsgBatchSubmitVerifyResult", verifier: verifier,
		// The chain keeps the first receipt per Verifier and round, with its
		// result_receipt_signing_digest: the digest of every receipt field but the signature,
		// the strongest content equality the stored row allows.
		// A receipt whose digest cannot be computed cannot be the one the chain accepted.
		onChain: func(ctx context.Context, state VerifyStateQuerier) (bool, bool, error) {
			accepted, err := state.QueryResultReceipt(ctx, taskID, round, verifier)
			if err != nil {
				return false, false, err
			}
			digest, err := nodecontract.ResultReceiptSigningDigest(vr)
			return true, err == nil && bytes.Equal(accepted.SigningDigest, digest[:]), nil
		},
	}
}

// lookupRelayed reads the Verifier's item from the chain; ErrNotFound becomes found=false.
func (f *taskFSM) lookupRelayed(item relayItem) (found, same bool, err error) {
	if f.confirm == nil || f.confirm.state == nil {
		return false, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayLookupTimeout)
	defer cancel()
	found, same, err = item.onChain(ctx, f.confirm.state)
	if errors.Is(err, chaincli.ErrNotFound) {
		return false, false, nil
	}
	return found, same, err
}

// relayOutcome turns a relay broadcast into the answer for the Verifier, and says whether the
// item is now on chain and may be recorded locally (onChain). It waits for the block result and reads
// the chain, so the caller must not hold the lock.
//
//   - executed in a block: recorded, acknowledged;
//   - refused by the chain: the Verifier's item may be refused because it is already there (a
//     redelivery, a crash between broadcast and acknowledgement, the Verifier's own submission).
//     Only the chain's stored item decides that: the same content is a success, different
//     content is invalid. Otherwise a temporary refusal (temporaryTxFailure) is temporary and
//     any other is invalid (types.ErrInvalidArgument);
//   - no block result within the wait: the chain's stored item decides as above if there is
//     one, otherwise it is temporary and nothing is recorded.
func (f *taskFSM) relayOutcome(item relayItem, res chaincli.TxResult, submitErr error) (ack types.VerifyRelayAck, onChain bool, err error) {
	var refused chaincli.TxResult
	checkTx := false
	switch {
	case submitErr != nil:
		var submission *SubmissionError
		if !errors.As(submitErr, &submission) || !submission.Definitive {
			f.log.Warn(item.kind+" relay failed; the verifier may retry", "task_id", f.taskID,
				"verifier", item.verifier, "err", submitErr)
			return types.VerifyRelayAck{}, false, submitErr
		}
		if submission.Phase != SubmissionBroadcast || f.confirm == nil {
			f.log.Warn(item.kind+" rejected on chain", "task_id", f.taskID, "verifier", item.verifier, "err", submitErr)
			return types.VerifyRelayAck{}, false, fmt.Errorf("%w: %s rejected on chain: %v", types.ErrInvalidArgument, item.kind, submitErr)
		}
		refused, checkTx = submission.Result, true
	case f.confirm == nil:
		return types.VerifyRelayAck{TxHash: res.TxHash}, true, nil
	default:
		result, err := chaincli.WaitTx(context.Background(), f.log, f.confirm.txs, res.TxHash, chaincli.TxWait{
			Kind: item.msgKind, TaskID: f.taskID, Interval: f.confirm.interval, Timeout: f.confirm.wait,
		})
		if err == nil && result.Code == 0 {
			return types.VerifyRelayAck{TxHash: res.TxHash}, true, nil
		}
		if err != nil {
			found, same, lookupErr := f.lookupRelayed(item)
			if ack, decided, relayErr := f.relayOnChainOutcome(item, found, same, lookupErr); decided {
				return ack, relayErr == nil, relayErr
			}
			f.log.Warn(item.kind+" has no block result within the wait; the verifier may retry",
				"task_id", f.taskID, "verifier", item.verifier, "tx_hash", hex.EncodeToString(res.TxHash),
				"wait", f.confirm.wait, "err", err)
			return types.VerifyRelayAck{}, false, fmt.Errorf("%w: %s: %v", errRelayUnconfirmed, item.kind, err)
		}
		refused = result
	}

	found, same, lookupErr := f.lookupRelayed(item)
	if ack, decided, relayErr := f.relayOnChainOutcome(item, found, same, lookupErr); decided {
		return ack, relayErr == nil, relayErr
	}
	stage := "block execution"
	if checkTx {
		stage = "CheckTx"
	}
	refusal := fmt.Sprintf("%s refused in %s (code %d, codespace %q): %s", item.kind, stage,
		refused.Code, refused.Codespace, chaincli.TruncateRawLog(refused.RawLog))
	if lookupErr != nil {
		f.log.Warn(item.kind+" refused and the chain record could not be read; the verifier may retry",
			"task_id", f.taskID, "verifier", item.verifier, "code", refused.Code,
			"codespace", refused.Codespace, "err", lookupErr)
		return types.VerifyRelayAck{}, false, fmt.Errorf("%w: %s; chain record unreadable: %v", errRelayTemporary, refusal, lookupErr)
	}
	if !temporaryTxFailure(refused) {
		f.log.Warn(item.kind+" rejected on chain as invalid", "task_id", f.taskID, "verifier", item.verifier,
			"stage", stage, "code", refused.Code, "codespace", refused.Codespace,
			"raw_log", chaincli.TruncateRawLog(refused.RawLog))
		return types.VerifyRelayAck{}, false, fmt.Errorf("%w: %s", types.ErrInvalidArgument, refusal)
	}
	f.log.Warn(item.kind+" failed on chain temporarily; the verifier may retry", "task_id", f.taskID,
		"verifier", item.verifier, "stage", stage, "code", refused.Code, "codespace", refused.Codespace)
	return types.VerifyRelayAck{}, false, fmt.Errorf("%w: %s", errRelayTemporary, refusal)
}

// relayOnChainOutcome decides a relay from the Verifier's item already on chain, if there is one.
func (f *taskFSM) relayOnChainOutcome(item relayItem, found, same bool, lookupErr error) (ack types.VerifyRelayAck, decided bool, err error) {
	switch {
	case lookupErr != nil || !found:
		return types.VerifyRelayAck{}, false, nil
	case same:
		f.log.Info(item.kind+" already on chain with the same content", "task_id", f.taskID, "verifier", item.verifier)
		return types.VerifyRelayAck{Idempotent: true}, true, nil
	default:
		f.log.Warn(item.kind+" differs from the one already on chain", "task_id", f.taskID, "verifier", item.verifier)
		return types.VerifyRelayAck{}, true, fmt.Errorf("%w: a different %s from this verifier is already on chain", types.ErrInvalidArgument, item.kind)
	}
}

// ---- Receipt and settlement transactions ----

// asyncTx names the two transactions the FSM submits on its own and follows through
// reconciliation.
type asyncTx int

const (
	asyncReceipt asyncTx = iota // MsgSubmitInferReceipt
	asyncSettle                 // MsgSettleTask
)

func (k asyncTx) msgKind() string {
	if k == asyncSettle {
		return "MsgSettleTask"
	}
	return "MsgSubmitInferReceipt"
}

const (
	// receiptRefusalRetries is how many resubmissions a receipt refused for good gets.
	receiptRefusalRetries = 1
	// txVerdictBlocks is how long a broadcast transaction may go without a block result -- not
	// found, or its result unreadable -- before it counts as lost (a temporary failure).
	txVerdictBlocks = 5
	// maxBackoffBlocks caps the doubling wait between resubmissions.
	maxBackoffBlocks = 16
)

// backoffBlocks is the wait before the n-th retry (n ≥ 1): 1, 2, 4, ... blocks, capped.
func backoffBlocks(n int) uint64 {
	return min(uint64(1)<<min(max(n, 1)-1, 30), maxBackoffBlocks)
}

// submittedTx follows one asynchronous transaction from broadcast to its block result and paces
// resubmission after a failure.
type submittedTx struct {
	hash   []byte // broadcast and awaiting its block result; nil when none is outstanding
	height uint64 // chain height seen at broadcast (0: none seen yet)
	// retryAt is the first chain height a resubmission may go out at; retry marks one as due.
	retryAt uint64
	retry   bool
	// refusals / temporaryFailures count the failed block results so far.
	refusals          int
	temporaryFailures int
	stopped           bool // given up and logged at ERROR; nothing more is submitted
}

// sentLocked records a broadcast that passed CheckTx. Caller must hold the lock.
func (f *taskFSM) sentLocked(tx *submittedTx, txHash []byte) {
	if f.confirm == nil || len(txHash) == 0 {
		return
	}
	tx.hash = bytes.Clone(txHash)
	tx.height = f.observedHeight
	tx.retry = false
}

// resubmitHeldLocked reports whether a resubmission must wait: the transaction awaits its block
// result, its backoff has not passed yet, or it was given up. Caller must hold the lock.
func (f *taskFSM) resubmitHeldLocked(tx *submittedTx) bool {
	return tx.stopped || len(tx.hash) > 0 || (tx.retry && f.observedHeight < tx.retryAt)
}

// awaitingVerdict reports whether a transaction without a block result may still get one: it has
// been out of every readable block for fewer than txVerdictBlocks. Caller must hold the lock.
func awaitingVerdict(tx *submittedTx, height uint64) bool {
	if tx.height == 0 {
		tx.height = height // broadcast before any block was seen: count from now
	}
	return height < tx.height+txVerdictBlocks
}

func (f *taskFSM) submittedTxLocked(kind asyncTx) *submittedTx {
	if kind == asyncSettle {
		return &f.settleTx
	}
	return &f.receiptTx
}

// asyncTxDoneLocked reports whether the chain no longer needs the transaction: a receipt is
// accepted (the local Verifying state too is entered only once the chain selected Verifiers,
// which follows an accepted receipt), or the task has left the verify stage (settled by anyone,
// or ended). Caller must hold the lock.
func (f *taskFSM) asyncTxDoneLocked(kind asyncTx) bool {
	if f.terminal {
		return true
	}
	if kind == asyncSettle {
		return f.state != types.Verifying
	}
	return f.receiptOnChain || f.state != types.Assigned
}

// asyncTxDeadlineLocked is the last chain height at which the transaction still helps: the
// receipt's infer deadline (or the receipt's own expiry, whichever is earlier), and for the
// settlement the verify deadline that closes the settlement window. 0 = unknown. Caller must
// hold the lock.
func (f *taskFSM) asyncTxDeadlineLocked(kind asyncTx) uint64 {
	if kind == asyncSettle {
		return uint64(max(f.deadlines.Verify, 0))
	}
	deadline := f.inferDeadlineHeight
	if expiry := f.inferReceipt.ExpiryHeight; expiry != 0 && (deadline == 0 || expiry < deadline) {
		deadline = expiry
	}
	return deadline
}

// outstandingTx returns the hash awaiting a block result, dropping it once the chain no longer
// needs it.
func (f *taskFSM) outstandingTx(kind asyncTx) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	tx := f.submittedTxLocked(kind)
	if len(tx.hash) == 0 {
		return nil
	}
	if f.asyncTxDoneLocked(kind) {
		tx.hash = nil
		return nil
	}
	return bytes.Clone(tx.hash)
}

// onSubmittedTxResult applies the block result of an asynchronous transaction read by
// reconciliation (queryErr is the QueryTx error, if any).
func (f *taskFSM) onSubmittedTxResult(kind asyncTx, txHash []byte, result chaincli.TxResult, queryErr error, height uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tx := f.submittedTxLocked(kind)
	if !bytes.Equal(tx.hash, txHash) {
		return // superseded by a later broadcast
	}
	if f.asyncTxDoneLocked(kind) {
		tx.hash = nil
		return
	}
	height = max(height, f.observedHeight)
	switch {
	case queryErr != nil:
		// Not found, or not readable (tx indexing off, result pruned, query failing): either way no
		// verdict. Past txVerdictBlocks the transaction is taken as lost and sent again.
		if !errors.Is(queryErr, chaincli.ErrNotFound) {
			f.log.Warn(kind.msgKind()+" block result query failed", "task_id", f.taskID,
				"tx_hash", hex.EncodeToString(txHash), "err", queryErr)
		}
		if awaitingVerdict(tx, height) {
			return
		}
		f.asyncTxFailedLocked(kind, tx, chaincli.TxResult{TxHash: txHash, RawLog: "no block result"}, height)
	case result.Code == 0:
		tx.hash = nil
		f.log.Info(kind.msgKind()+" executed in a block", "task_id", f.taskID,
			"tx_hash", hex.EncodeToString(txHash), "height", result.Height)
	default:
		if len(result.TxHash) == 0 {
			result.TxHash = txHash
		}
		chaincli.LogTxFailure(f.log, kind.msgKind(), f.taskID, result)
		f.asyncTxFailedLocked(kind, tx, result, height)
	}
}

// asyncTxFailedLocked handles a failed or missing block result (a missing one has Code 0 and
// counts as temporary). Temporary failures are resubmitted with a doubling wait until the
// transaction's deadline. A receipt refused for good is resubmitted once and then given up. A
// refused settlement is not given up: the chain judges it at the height it executes, so a
// settlement sent in the last block of this Builder's slot and executed in the next is refused
// only for its timing; it waits out a doubling backoff and goes again at the next height this
// Builder may settle at (trySettle), until the chain settles or the deadline passes. Caller must
// hold the lock.
func (f *taskFSM) asyncTxFailedLocked(kind asyncTx, tx *submittedTx, result chaincli.TxResult, height uint64) {
	tx.hash = nil
	refused := result.Code != 0 && !temporaryTxFailure(result)
	var backoff uint64
	if refused {
		tx.refusals++
		backoff = backoffBlocks(tx.refusals)
	} else {
		tx.temporaryFailures++
		backoff = backoffBlocks(tx.temporaryFailures)
	}
	deadline := f.asyncTxDeadlineLocked(kind)
	retryAt := height + backoff
	switch {
	case kind == asyncReceipt && refused && tx.refusals > receiptRefusalRetries:
		f.stopAsyncTxLocked(kind, tx, result, "the chain refused it again", deadline)
		return
	case deadline != 0 && retryAt > deadline:
		f.stopAsyncTxLocked(kind, tx, result, "its deadline has passed", deadline)
		return
	}
	tx.retry, tx.retryAt = true, retryAt
	switch kind {
	case asyncReceipt:
		f.openVerifySubmitted = false
	case asyncSettle:
		f.settleSubmittedHeight = 0
	}
	f.log.Warn(kind.msgKind()+" failed on chain; will resubmit", "task_id", f.taskID,
		"tx_hash", hex.EncodeToString(result.TxHash), "code", result.Code, "codespace", result.Codespace,
		"refused", refused, "retry_at_height", retryAt, "deadline_height", deadline)
}

// settlePassesSimulationLocked dry-runs a settlement resend before it is broadcast: a failed
// settlement is resent until the deadline, and each broadcast the chain refuses costs a fee. When
// the chain refuses it in simulation nothing is broadcast; the next height this Builder may settle
// at simulates again (at most once per block). A node that cannot simulate leaves the resend to
// its backoff alone. Caller must hold the lock.
func (f *taskFSM) settlePassesSimulationLocked() bool {
	simulator, ok := f.submit.(SettleSimulator)
	if !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	result, err := simulator.SimulateSettle(ctx, chaincli.SettleTx{Submitter: f.self, SessionID: f.sessionID, TaskID: f.taskID})
	cancel()
	if err != nil {
		f.log.Warn("settle resend not simulated: the node cannot simulate; broadcasting on backoff",
			"task_id", f.taskID, "err", err)
		return true
	}
	if result.OK {
		return true
	}
	f.settleSubmittedHeight = f.observedHeight
	f.log.Info("settle resend held: the chain refuses it in simulation", "task_id", f.taskID,
		"height", f.observedHeight, "error", chaincli.TruncateRawLog(result.Error))
	return false
}

func (f *taskFSM) stopAsyncTxLocked(kind asyncTx, tx *submittedTx, result chaincli.TxResult, why string, deadline uint64) {
	tx.stopped, tx.retry = true, false
	attrs := []any{"task_id", f.taskID, "reason", why,
		"tx_hash", hex.EncodeToString(result.TxHash), "code", result.Code, "codespace", result.Codespace,
		"raw_log", chaincli.TruncateRawLog(result.RawLog),
		"refusals", tx.refusals, "temporary_failures", tx.temporaryFailures,
		"deadline_height", deadline}
	if kind == asyncSettle {
		f.log.Error("MsgSettleTask failed on chain; this Builder stopped resubmitting. "+
			"Another Builder or the chain's own fallback may still settle the task", attrs...)
		return
	}
	f.log.Error("MsgSubmitInferReceipt failed on chain; stopped resubmitting", attrs...)
}

// followSubmittedTxsLocked runs on each new block: it resubmits a receipt or a bus result whose
// backoff has passed, and reports whether something awaits its block result or a chain lookup
// (the caller then asks reconciliation to read it, off the lock). Caller must hold the lock.
func (f *taskFSM) followSubmittedTxsLocked() bool {
	if f.confirm == nil || f.terminal {
		return false
	}
	if f.receiptTx.retry && !f.openVerifySubmitted && !f.asyncTxDoneLocked(asyncReceipt) &&
		f.observedHeight >= f.receiptTx.retryAt {
		f.submitOpenVerifyLocked()
	}
	check := f.resendPendingResultsLocked()
	return check || (len(f.receiptTx.hash) > 0 && f.observedHeight > f.receiptTx.height) ||
		(len(f.settleTx.hash) > 0 && f.observedHeight > f.settleTx.height)
}

// confirmSubmittedTxs reads the block results of the task's outstanding receipt, settlement and
// bus-relayed result transactions. Runs in reconciliation after the chain snapshot was applied,
// so a receipt the chain accepted or a task it settled is already visible and nothing is
// resubmitted for it.
func (c *Coordinator) confirmSubmittedTxs(fsm *taskFSM) {
	if c.txQuery == nil {
		return
	}
	for _, kind := range []asyncTx{asyncReceipt, asyncSettle} {
		txHash := fsm.outstandingTx(kind)
		if txHash == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
		result, err := c.txQuery.QueryTx(ctx, txHash)
		cancel()
		height, _ := c.currentChainHeight()
		fsm.onSubmittedTxResult(kind, txHash, result, err, height)
	}
	c.confirmPendingResults(fsm)
}

// ---- Verifier results taken off the bus ----

// pendingResult is a Verifier result that arrived on the bus and was broadcast. The bus message
// is acknowledged at once -- waiting for the block in the handler would hold every later result
// of the same consumer behind it -- and reconciliation confirms it: only then is it recorded and
// counted towards settlement. Persisted with the snapshot, since the bus will not deliver it
// again.
type pendingResult struct {
	receipt *taskv1.ResultReceiptV3
	tx      submittedTx
	// lookup: there is no transaction to query (CheckTx refused it, or its result was lost), so
	// the chain's record is read next. refused is that CheckTx refusal, if any.
	lookup  bool
	refused chaincli.TxResult
}

// busRetryLocked asks the bus to redeliver a result after a temporary failure, after a doubling
// number of block intervals per Verifier. Caller must hold the lock.
func (f *taskFSM) busRetryLocked(verifier string, err error) error {
	if f.busRetries == nil {
		f.busRetries = make(map[string]int)
	}
	f.busRetries[verifier]++
	delay := f.blockInterval() * time.Duration(backoffBlocks(f.busRetries[verifier]))
	f.log.Warn("verify result relay failed; the bus redelivers it later", "task_id", f.taskID,
		"verifier", verifier, "delay", delay, "err", err)
	return msgbus.RetryAfter(err, delay)
}

func (f *taskFSM) blockInterval() time.Duration {
	if f.confirm != nil {
		return f.confirm.interval
	}
	return config.DefaultTxConfirmBlockInterval
}

// relayBusResultLocked broadcasts a result that arrived on the bus and registers it for
// reconciliation to confirm, returning at once. The returned error asks the bus for a delayed
// redelivery (a temporary failure before the transaction reached the mempool); nil acknowledges
// the message. Caller must hold the lock.
func (f *taskFSM) relayBusResultLocked(vr *taskv1.ResultReceiptV3) error {
	verifier := vr.GetVerifierOperatorAddress()
	if existing, ok := f.verifyResults[verifier]; ok && proto.Equal(existing, vr) {
		return nil
	}
	var inFlight proto.Message
	if flight := f.resultFlights[verifier]; flight != nil {
		inFlight = flight.msg // a unary relay is waiting for it and records it
	} else if pending := f.pendingResults[verifier]; pending != nil {
		inFlight = pending.receipt
	}
	if inFlight != nil {
		if !proto.Equal(inFlight, vr) {
			f.log.Warn("drop verify result: a different one from this verifier is being relayed",
				"task_id", f.taskID, "verifier", verifier)
		}
		return nil
	}
	if f.submit == nil {
		return f.busRetryLocked(verifier, fmt.Errorf("verify result relay: submitter is not configured"))
	}
	pending := &pendingResult{receipt: vr}
	if keep, temporary := f.broadcastPendingResultLocked(pending); !keep {
		if temporary != nil {
			return f.busRetryLocked(verifier, temporary)
		}
		return nil
	}
	if f.pendingResults == nil {
		f.pendingResults = make(map[string]*pendingResult)
	}
	f.pendingResults[verifier] = pending
	if err := f.save(); err != nil {
		delete(f.pendingResults, verifier)
		return f.busRetryLocked(verifier, fmt.Errorf("persist pending verify result: %w", err))
	}
	delete(f.busRetries, verifier)
	f.log.Info("verify result broadcast; reconciliation confirms it", "task_id", f.taskID,
		"verifier", verifier, "tx_hash", hex.EncodeToString(pending.tx.hash), "chain_lookup", pending.lookup)
	return nil
}

// broadcastPendingResultLocked broadcasts a pending result. keep is false when it is not in the
// mempool: temporary then carries a failure another try may clear, and is nil for a result
// refused before it could reach the chain (dropped). A CheckTx refusal keeps it for a chain
// lookup, since the chain may refuse it because it already holds it. Caller must hold the lock.
func (f *taskFSM) broadcastPendingResultLocked(pending *pendingResult) (keep bool, temporary error) {
	verifier := pending.receipt.GetVerifierOperatorAddress()
	res, submitErr := f.submit.SubmitVerifyResult(context.Background(), chaincli.VerifyResultTx{
		Receipt: pending.receipt, Submitter: f.self,
	})
	var submission *SubmissionError
	switch {
	case submitErr == nil:
		f.sentLocked(&pending.tx, res.TxHash)
		pending.lookup = len(pending.tx.hash) == 0
	case temporaryBroadcastError(submitErr):
		return false, submitErr
	case errors.As(submitErr, &submission) && submission.Phase == SubmissionBroadcast:
		pending.lookup, pending.refused = true, submission.Result
	default:
		f.log.Warn("drop verify result: rejected before broadcast", "task_id", f.taskID,
			"verifier", verifier, "err", submitErr)
		return false, nil
	}
	// No longer due for a rebroadcast: reconciliation now reads the block result or, without a
	// transaction to query, the chain's record. Left marked, it would be rebroadcast on every
	// block and never checked.
	pending.tx.retry = false
	return true, nil
}

// followFailedRelayLocked hands a result whose unary relay failed temporarily to reconciliation,
// which follows it like a result taken off the bus: a bus redelivery of it may already have been
// acknowledged on the strength of that relay. The caller still gets its temporary error. Caller
// must hold the lock.
func (f *taskFSM) followFailedRelayLocked(vr *taskv1.ResultReceiptV3, res chaincli.TxResult, submitErr, relayErr error) {
	verifier := vr.GetVerifierOperatorAddress()
	if f.confirm == nil || f.terminal || f.state != types.Verifying || f.pendingResults[verifier] != nil {
		return
	}
	pending := &pendingResult{receipt: vr}
	if submitErr == nil && errors.Is(relayErr, errRelayUnconfirmed) && len(res.TxHash) > 0 {
		f.sentLocked(&pending.tx, res.TxHash) // still may land: keep reading its block result
	} else {
		pending.lookup = true // read the chain's record, then rebroadcast if it is not there
	}
	if f.pendingResults == nil {
		f.pendingResults = make(map[string]*pendingResult)
	}
	f.pendingResults[verifier] = pending
	if err := f.save(); err != nil {
		f.log.Warn("persist pending verify result failed", "task_id", f.taskID, "verifier", verifier, "err", err)
	}
	f.log.Info("verify result relay failed temporarily; reconciliation follows it", "task_id", f.taskID,
		"verifier", verifier, "tx_hash", hex.EncodeToString(pending.tx.hash))
}

// resendPendingResultsLocked rebroadcasts pending results whose backoff has passed, and reports
// whether any awaits a block result or a chain lookup. Caller must hold the lock.
func (f *taskFSM) resendPendingResultsLocked() bool {
	check := false
	for verifier, pending := range f.pendingResults {
		if pending.tx.retry && f.observedHeight >= pending.tx.retryAt && f.submit != nil {
			keep, temporary := f.broadcastPendingResultLocked(pending)
			switch {
			case keep:
				f.save()
			case temporary != nil:
				f.scheduleResultRetryLocked(verifier, pending, chaincli.TxResult{RawLog: temporary.Error()})
				continue
			default:
				f.dropPendingResultLocked(verifier, chaincli.TxResult{}, "rejected before broadcast")
				continue
			}
		}
		if pending.lookup || (len(pending.tx.hash) > 0 && f.observedHeight > pending.tx.height) {
			check = true
		}
	}
	return check
}

// resultDeadlineLocked is the last height a result can still be accepted at: the reveal deadline
// (the verify deadline when that is unknown). Caller must hold the lock.
func (f *taskFSM) resultDeadlineLocked() uint64 {
	if f.deadlines.Reveal > 0 {
		return uint64(f.deadlines.Reveal)
	}
	return uint64(max(f.deadlines.Verify, 0))
}

// scheduleResultRetryLocked schedules a rebroadcast of a pending result after a temporary
// failure, or drops it with an ERROR once the backoff passes the deadline. Caller must hold the lock.
func (f *taskFSM) scheduleResultRetryLocked(verifier string, pending *pendingResult, result chaincli.TxResult) {
	pending.tx.hash, pending.lookup = nil, false
	pending.tx.temporaryFailures++
	retryAt := max(f.observedHeight, pending.tx.height) + backoffBlocks(pending.tx.temporaryFailures)
	if deadline := f.resultDeadlineLocked(); deadline != 0 && retryAt > deadline {
		f.dropPendingResultLocked(verifier, result, "its deadline has passed")
		return
	}
	pending.tx.retry, pending.tx.retryAt = true, retryAt
	f.log.Warn("verify result failed on chain; will rebroadcast", "task_id", f.taskID, "verifier", verifier,
		"code", result.Code, "codespace", result.Codespace, "retry_at_height", retryAt)
}

func (f *taskFSM) dropPendingResultLocked(verifier string, result chaincli.TxResult, why string) {
	delete(f.pendingResults, verifier)
	f.save()
	f.log.Error("verify result is not on chain; stopped relaying it", "task_id", f.taskID,
		"verifier", verifier, "reason", why, "tx_hash", hex.EncodeToString(result.TxHash),
		"code", result.Code, "codespace", result.Codespace, "raw_log", chaincli.TruncateRawLog(result.RawLog))
}

// pendingResultCheck is what reconciliation reads for one pending result.
type pendingResultCheck struct {
	verifier string
	hash     []byte
	item     relayItem
}

func (f *taskFSM) pendingResultChecks() []pendingResultCheck {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.terminal || f.state != types.Verifying {
		if len(f.pendingResults) > 0 {
			f.pendingResults = nil
			f.save()
		}
		return nil
	}
	checks := make([]pendingResultCheck, 0, len(f.pendingResults))
	for verifier, pending := range f.pendingResults {
		if pending.tx.retry {
			continue // waiting to be rebroadcast
		}
		checks = append(checks, pendingResultCheck{verifier: verifier, hash: bytes.Clone(pending.tx.hash),
			item: f.resultRelayItem(pending.receipt)})
	}
	return checks
}

// confirmPendingResults reads, for each pending bus result, its block result and -- unless the
// block executed it -- the chain's record for the Verifier.
func (c *Coordinator) confirmPendingResults(fsm *taskFSM) {
	for _, check := range fsm.pendingResultChecks() {
		var result chaincli.TxResult
		var queryErr error
		if len(check.hash) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
			result, queryErr = c.txQuery.QueryTx(ctx, check.hash)
			cancel()
		}
		var found, same bool
		var lookupErr error
		if len(check.hash) == 0 || queryErr != nil || result.Code != 0 {
			found, same, lookupErr = fsm.lookupRelayed(check.item)
		}
		height, _ := c.currentChainHeight()
		fsm.onPendingResultChecked(check, result, queryErr, found, same, lookupErr, height)
	}
}

// onPendingResultChecked applies what reconciliation read for one pending result. It is recorded
// once the block executed it or the chain holds the same content; the chain holding different
// content, or a refusal that fails every time, drops it with an ERROR; a temporary failure or a
// transaction lost for txVerdictBlocks schedules a rebroadcast.
func (f *taskFSM) onPendingResultChecked(check pendingResultCheck, result chaincli.TxResult, queryErr error,
	found, same bool, lookupErr error, height uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pending := f.pendingResults[check.verifier]
	if pending == nil || pending.tx.retry || !bytes.Equal(pending.tx.hash, check.hash) {
		return // confirmed, dropped or rebroadcast meanwhile
	}
	if f.terminal || f.state != types.Verifying {
		return
	}
	height = max(height, f.observedHeight)
	if len(result.TxHash) == 0 {
		result.TxHash = check.hash
	}
	switch {
	case len(check.hash) > 0 && queryErr == nil && result.Code == 0:
		f.confirmPendingResultLocked(check.verifier, pending, "executed in a block")
		return
	case lookupErr == nil && found && same:
		f.confirmPendingResultLocked(check.verifier, pending, "already on chain with the same content")
		return
	case lookupErr == nil && found:
		f.dropPendingResultLocked(check.verifier, result, "a different result from this verifier is on chain")
		return
	}
	switch {
	case len(check.hash) > 0 && queryErr == nil:
		chaincli.LogTxFailure(f.log, "MsgBatchSubmitVerifyResult", f.taskID, result)
		f.pendingResultRefusedLocked(check.verifier, pending, result, lookupErr)
	case len(check.hash) > 0:
		if !errors.Is(queryErr, chaincli.ErrNotFound) {
			f.log.Warn("MsgBatchSubmitVerifyResult block result query failed", "task_id", f.taskID,
				"verifier", check.verifier, "tx_hash", hex.EncodeToString(check.hash), "err", queryErr)
		}
		if awaitingVerdict(&pending.tx, height) {
			return
		}
		// Lost: read the chain's record next, then rebroadcast if it is not there.
		pending.tx.hash, pending.lookup, pending.refused = nil, true, chaincli.TxResult{}
	case lookupErr != nil:
		f.log.Warn("verify result chain record unreadable; will read it again", "task_id", f.taskID,
			"verifier", check.verifier, "err", lookupErr)
	case pending.refused.Code != 0 && !temporaryTxFailure(pending.refused):
		f.dropPendingResultLocked(check.verifier, pending.refused, "the chain refused it")
	default:
		f.scheduleResultRetryLocked(check.verifier, pending, pending.refused)
	}
}

// pendingResultRefusedLocked handles a result the block refused and the chain does not hold.
// Caller must hold the lock.
func (f *taskFSM) pendingResultRefusedLocked(verifier string, pending *pendingResult, result chaincli.TxResult, lookupErr error) {
	switch {
	case lookupErr != nil:
		// Whether the chain already holds it is unknown: read its record again first.
		pending.tx.hash, pending.lookup, pending.refused = nil, true, result
	case temporaryTxFailure(result):
		f.scheduleResultRetryLocked(verifier, pending, result)
	default:
		f.dropPendingResultLocked(verifier, result, "the chain refused it")
	}
}

// confirmPendingResultLocked records a pending result the chain holds. Caller must hold the lock.
func (f *taskFSM) confirmPendingResultLocked(verifier string, pending *pendingResult, how string) {
	delete(f.pendingResults, verifier)
	f.log.Info("verify result confirmed on chain", "task_id", f.taskID, "verifier", verifier, "how", how)
	f.recordVerifyResultLocked(pending.receipt, false)
}
