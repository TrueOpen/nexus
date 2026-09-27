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

// chainModuleRefusal reports a failure raised by one of the chain's own modules: a verdict on
// the transaction's content that resubmitting cannot change. Every other codespace (sdk and the
// rest) concerns the transaction around the content -- sequence, fee, mempool, a recovered
// panic -- and may pass on another try.
func chainModuleRefusal(result chaincli.TxResult) bool {
	return result.Code != 0 && (result.Codespace == "task" || result.Codespace == "hub")
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
//     content is invalid. Otherwise a refusal by a chain module is invalid
//     (types.ErrInvalidArgument), any other is temporary;
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
	// A CheckTx refusal without a codespace keeps its old reading as a verdict on the content.
	if chainModuleRefusal(refused) || (checkTx && refused.Codespace == "") {
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
	// asyncTxChainModuleRetries is how many resubmissions a refusal by a chain module gets.
	asyncTxChainModuleRetries = 1
	// asyncTxInclusionBlocks is how long a broadcast transaction may stay out of every block
	// before it counts as dropped (a temporary failure).
	asyncTxInclusionBlocks = 5
	// asyncTxMaxBackoffBlocks caps the doubling wait between resubmissions after temporary failures.
	asyncTxMaxBackoffBlocks = 16
)

// submittedTx follows one asynchronous transaction from broadcast to its block result and paces
// resubmission after a failure. Not persisted: after a restart the transaction is submitted anew
// and the chain's own idempotency catches a duplicate.
type submittedTx struct {
	hash   []byte // broadcast and awaiting its block result; nil when none is outstanding
	height uint64 // chain height seen at broadcast (0: none seen yet)
	// retryAt is the first chain height a resubmission may go out at; retry marks one as due.
	retryAt uint64
	retry   bool
	// moduleRefusals / temporaryFailures count the failed block results so far.
	moduleRefusals    int
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

// resubmitHeldLocked reports whether a resubmission must wait: the transaction was given up, or
// its backoff has not passed yet. Caller must hold the lock.
func (f *taskFSM) resubmitHeldLocked(tx *submittedTx) bool {
	return tx.stopped || len(tx.hash) > 0 || (tx.retry && f.observedHeight < tx.retryAt)
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
	case errors.Is(queryErr, chaincli.ErrNotFound):
		if tx.height == 0 {
			tx.height = height // broadcast before any block was seen: count from now
		}
		if height < tx.height+asyncTxInclusionBlocks {
			f.log.Debug(kind.msgKind()+" awaiting its block", "task_id", f.taskID, "tx_hash", hex.EncodeToString(txHash))
			return
		}
		f.asyncTxFailedLocked(kind, tx, chaincli.TxResult{TxHash: txHash, RawLog: "not included in a block"}, height)
	case queryErr != nil:
		f.log.Warn(kind.msgKind()+" block result query failed; will query again", "task_id", f.taskID,
			"tx_hash", hex.EncodeToString(txHash), "err", queryErr)
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

// asyncTxFailedLocked handles a failed or missing block result. A refusal by a chain module is
// retried once; any other failure is retried with a doubling wait until the transaction's
// deadline. Past either limit the transaction is given up with an ERROR. Caller must hold the lock.
func (f *taskFSM) asyncTxFailedLocked(kind asyncTx, tx *submittedTx, result chaincli.TxResult, height uint64) {
	tx.hash = nil
	module := chainModuleRefusal(result)
	var backoff uint64 = 1
	if module {
		tx.moduleRefusals++
	} else {
		tx.temporaryFailures++
		backoff = min(uint64(1)<<min(tx.temporaryFailures-1, 30), asyncTxMaxBackoffBlocks)
	}
	deadline := f.asyncTxDeadlineLocked(kind)
	retryAt := height + backoff
	switch {
	case module && tx.moduleRefusals > asyncTxChainModuleRetries:
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
		"chain_module", module, "retry_at_height", retryAt, "deadline_height", deadline)
}

func (f *taskFSM) stopAsyncTxLocked(kind asyncTx, tx *submittedTx, result chaincli.TxResult, why string, deadline uint64) {
	tx.stopped, tx.retry = true, false
	attrs := []any{"task_id", f.taskID, "reason", why,
		"tx_hash", hex.EncodeToString(result.TxHash), "code", result.Code, "codespace", result.Codespace,
		"raw_log", chaincli.TruncateRawLog(result.RawLog),
		"chain_module_refusals", tx.moduleRefusals, "temporary_failures", tx.temporaryFailures,
		"deadline_height", deadline}
	if kind == asyncSettle {
		f.log.Error("MsgSettleTask failed on chain; this Builder stopped resubmitting. "+
			"Another Builder or the chain's own fallback may still settle the task", attrs...)
		return
	}
	f.log.Error("MsgSubmitInferReceipt failed on chain; stopped resubmitting", attrs...)
}

// followSubmittedTxsLocked runs on each new block: it resubmits a receipt whose backoff has
// passed, and reports whether a transaction awaits its block result (the caller then asks
// reconciliation to read it, off the lock). Caller must hold the lock.
func (f *taskFSM) followSubmittedTxsLocked() bool {
	if f.confirm == nil || f.terminal {
		return false
	}
	if f.receiptTx.retry && !f.openVerifySubmitted && !f.asyncTxDoneLocked(asyncReceipt) &&
		f.observedHeight >= f.receiptTx.retryAt {
		f.submitOpenVerifyLocked()
	}
	return (len(f.receiptTx.hash) > 0 && f.observedHeight > f.receiptTx.height) ||
		(len(f.settleTx.hash) > 0 && f.observedHeight > f.settleTx.height)
}

// confirmSubmittedTxs reads the block results of the task's outstanding receipt and settlement
// transactions. Runs in reconciliation after the chain snapshot was applied, so a receipt the
// chain accepted or a task it settled is already visible and nothing is resubmitted for it.
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
}
