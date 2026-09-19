// Task state machine snapshot persistence + restart recovery reconciliation (Detailed Design §2.6 / §6.2).
// The local snapshot is only a non-authoritative cache: on any doubt the on-chain query wins, and a lost snapshot can be rebuilt from the chain.
package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// snapshotVersionProtoPayloadV4 is the current snapshot version. v4 change: hand-raise/verification-result data is stored
// as proto-serialized bytes of the frozen wire (new JSON keys *_pb, []byte auto-base64 via encoding/json); the
// old msgbus JSON payload structs were removed with the bus format migration (TRUEOPEN_BUS_ENVELOPE_V2).
//
// A format migration must be expressed explicitly through the version number. Old keys of pre-v4 snapshots are ignored
// on decode and the new keys are empty -- hand-raises are re-sent on re-broadcast; already-Acked V_i are not redelivered
// by JetStream, so a task still in Verifying across the version boundary cannot reach 2/3 locally and falls back to
// on-chain sweep settlement. Under the four-component lockstep upgrade, in-flight tasks migrate format together anyway; correctness beats a dubious cache.
const snapshotVersionProtoPayloadV4 = 4

// taskSnapshot is the persisted encoding of the state machine (NSTask, key = session_id|task_id).
// Stores only the minimal set needed to resume: transient data such as hand-raises/verification results is not persisted
// (the message layer can redeliver; at worst we wait for the SDK to resend or the on-chain sweep -- correctness is unaffected).
type taskSnapshot struct {
	Version         int                                 `json:"version,omitempty"`
	Settlement      chaincli.TaskSettlementState        `json:"settlement,omitempty"`
	SettleSelection chaincli.StageBuilderSelectionState `json:"settle_selection,omitempty"`
	// SettleGraceBlocks reads the Hub parameter settlement_builder_grace_blocks used for settlement ordering.
	SettleGraceBlocks uint64 `json:"settle_grace_blocks,omitempty"`
	// LegacyChallengeUntil only consumes old snapshots; it is never promoted to live settlement facts.
	LegacyChallengeUntil int64                        `json:"challenge_until,omitempty"`
	Order                types.Order                  `json:"order"`
	InferReceipt         types.InferReceiptSubmission `json:"infer_receipt"`
	SessionID            string                       `json:"session_id"`
	TaskID               string                       `json:"task_id"`
	ModelID              string                       `json:"model_id"`
	ProfileVersion       uint32                       `json:"profile_version,omitempty"`
	PayloadCID           string                       `json:"payload_cid"`
	User                 string                       `json:"user,omitempty"`
	Deadline             int64                        `json:"deadline,omitempty"`
	PriceHint            string                       `json:"price_hint,omitempty"`
	BuilderSet           []types.BuilderRef           `json:"builder_set,omitempty"`

	State types.TaskState `json:"state"`
	Phase types.TaskPhase `json:"phase"`
	// Terminal is authoritative over State during recovery. StageSettle sweep
	// cleanup retains the coarse Settled state while still ending the local FSM.
	Terminal bool `json:"terminal,omitempty"`

	Winner      string             `json:"winner,omitempty"`
	AssignedSet []types.BuilderRef `json:"assigned_set,omitempty"`
	Verifiers   []string           `json:"verifiers,omitempty"`
	AssignSeed  []byte             `json:"assign_seed,omitempty"`
	SampleSeed  []byte             `json:"sample_seed,omitempty"`
	Deadlines   types.Deadlines    `json:"deadlines"`

	OutputHash []byte `json:"output_hash,omitempty"`
	// ReceiptOnChain: the chain has accepted the InferReceipt. Must survive recovery, otherwise a restart would wait
	// again for an event that will never come while the verify window is already open on-chain.
	ReceiptOnChain bool `json:"receipt_on_chain,omitempty"`

	Verdict types.TaskVerdict `json:"verdict,omitempty"`

	// AssignTxHash persists an in-flight CheckTx acceptance so recovery can query
	// the authoritative DeliverTx result without rebroadcasting the same order.
	AssignTxHash []byte `json:"assign_tx_hash,omitempty"`
	// AcceptedTaskHash is the authoritative task_hash after on-chain acceptance. Must survive recovery, otherwise
	// later proposals are mistaken for the "first" one, carry signed_order again and get rejected by §4.2.1.
	AcceptedTaskHash []byte `json:"accepted_task_hash,omitempty"`
	// The openVerify/settle "submitted" flags are not persisted; they only mean broadcast, not on-chain fact.
	WorkerRevealed bool     `json:"worker_revealed,omitempty"`
	FullReveals    []string `json:"full_reveals,omitempty"`

	// Hand-raise/verification-result data is stored as proto-serialized bytes of the frozen wire (acked V_i travel over
	// JetStream and are not redelivered, so they must be persisted). Entries failing proto.Unmarshal on recovery are dropped whole.
	VerifyResults      [][]byte `json:"verify_results_pb,omitempty"`
	VerifyCommits      [][]byte `json:"verify_commits_pb,omitempty"`
	WorkerHandraises   [][]byte `json:"worker_handraises_pb,omitempty"`
	VerifierHandraises [][]byte `json:"verifier_handraises_pb,omitempty"`
	// VerifierHandraisesProposed records which hand-raisers were already broadcast with MsgSubmitVerifierHandraises.
	// Including them again after restart makes the Keeper reject as "no new members" and drags the new hand-raises down with them.
	VerifierHandraisesProposed []string `json:"verifier_handraises_proposed,omitempty"`

	Events []types.TaskEvent `json:"events,omitempty"` // journal history (keeps cursor semantics across restarts)
}

// save writes the current state to the KV. Caller must hold the lock. No-op when persist is not wired (tests build the fsm directly).
func (f *taskFSM) save() error {
	if f.persist == nil {
		return nil
	}
	sn := taskSnapshot{
		Version:           snapshotVersionProtoPayloadV4,
		Settlement:        f.settlement,
		SettleSelection:   f.settleSelection,
		SettleGraceBlocks: f.settleGraceBlocks,
		Order:             f.order,
		InferReceipt:      f.inferReceipt,
		SessionID:         f.sessionID,
		TaskID:            f.taskID,
		ModelID:           f.modelID,
		ProfileVersion:    f.profileVersion,
		PayloadCID:        f.payloadCID,
		User:              f.user,
		Deadline:          f.deadline,
		PriceHint:         f.priceHint,
		BuilderSet:        f.builderSet,

		State:    f.state,
		Phase:    f.phase,
		Terminal: f.terminal,

		Winner:      f.winner,
		AssignedSet: f.assignedSet,
		Verifiers:   f.verifiers,
		AssignSeed:  f.assignSeed,
		SampleSeed:  f.sampleSeed,
		Deadlines:   f.deadlines,

		OutputHash:     f.outputHash,
		ReceiptOnChain: f.receiptOnChain,

		VerifierHandraisesProposed: f.proposedVerifierOperators(),

		Verdict: f.verdict,

		AssignTxHash:     append([]byte(nil), f.assignTxHash...),
		AcceptedTaskHash: append([]byte(nil), f.acceptedTaskHash...),
		WorkerRevealed:   f.workerRevealed,
	}
	for v := range f.fullReveals {
		sn.FullReveals = append(sn.FullReveals, v)
	}
	appendSorted := func(dst *[][]byte, keys []string, marshal func(string) ([]byte, error)) error {
		sort.Strings(keys)
		for _, key := range keys {
			raw, err := marshal(key)
			if err != nil {
				return err
			}
			*dst = append(*dst, raw)
		}
		return nil
	}
	verifyKeys := make([]string, 0, len(f.verifyResults))
	for key := range f.verifyResults {
		verifyKeys = append(verifyKeys, key)
	}
	if err := appendSorted(&sn.VerifyResults, verifyKeys, func(key string) ([]byte, error) {
		return proto.Marshal(f.verifyResults[key])
	}); err != nil {
		return fmt.Errorf("snapshot verify results: %w", err)
	}
	commitKeys := make([]string, 0, len(f.verifyCommits))
	for key := range f.verifyCommits {
		commitKeys = append(commitKeys, key)
	}
	if err := appendSorted(&sn.VerifyCommits, commitKeys, func(key string) ([]byte, error) {
		return proto.Marshal(f.verifyCommits[key])
	}); err != nil {
		return fmt.Errorf("snapshot verify commits: %w", err)
	}
	workerKeys := make([]string, 0, len(f.workerHR))
	for key := range f.workerHR {
		workerKeys = append(workerKeys, key)
	}
	if err := appendSorted(&sn.WorkerHandraises, workerKeys, func(key string) ([]byte, error) {
		return proto.Marshal(f.workerHR[key])
	}); err != nil {
		return fmt.Errorf("snapshot worker handraises: %w", err)
	}
	verifierKeys := make([]string, 0, len(f.verifierHR))
	for key := range f.verifierHR {
		verifierKeys = append(verifierKeys, key)
	}
	if err := appendSorted(&sn.VerifierHandraises, verifierKeys, func(key string) ([]byte, error) {
		return proto.Marshal(f.verifierHR[key])
	}); err != nil {
		return fmt.Errorf("snapshot verifier handraises: %w", err)
	}
	if f.events != nil {
		sn.Events = f.events.snapshot()
	}
	return f.persist(sn)
}

// restoreFrom refills state machine fields from a snapshot (called after construction, before subscribing; no concurrency).
func (f *taskFSM) restoreFrom(sn taskSnapshot) {
	if sn.Order.SessionID != "" {
		f.order = sn.Order
	}
	if sn.InferReceipt.SessionID != "" {
		f.inferReceipt = sn.InferReceipt
	}
	f.user = sn.User
	f.profileVersion = sn.ProfileVersion
	f.deadline = sn.Deadline
	f.priceHint = sn.PriceHint
	if len(sn.BuilderSet) > 0 {
		f.builderSet = sn.BuilderSet
	}
	f.state = sn.State
	f.phase = sn.Phase
	f.terminal = sn.Terminal
	f.winner = sn.Winner
	f.assignedSet = sn.AssignedSet
	f.verifiers = sn.Verifiers
	f.assignSeed = sn.AssignSeed
	f.sampleSeed = sn.SampleSeed
	f.deadlines = sn.Deadlines
	f.outputHash = sn.OutputHash
	f.receiptOnChain = sn.ReceiptOnChain
	for _, operator := range sn.VerifierHandraisesProposed {
		f.verifierHRProposed[operator] = true
	}
	f.settlement = sn.Settlement
	f.settleSelection = sn.SettleSelection
	f.settleGraceBlocks = sn.SettleGraceBlocks
	f.verdict = sn.Verdict
	f.assignTxHash = append([]byte(nil), sn.AssignTxHash...)
	f.acceptedTaskHash = append([]byte(nil), sn.AcceptedTaskHash...)
	f.assignSubmitted = len(f.assignTxHash) > 0
	f.workerRevealed = sn.WorkerRevealed
	for _, v := range sn.FullReveals {
		f.fullReveals[v] = true
	}
	// From v4 hand-raise/verification-result data is proto bytes of the frozen wire. Old JSON keys of pre-v4 snapshots are
	// ignored on decode (new keys empty); here the version gate additionally drops the anomaly "old version yet carrying
	// new keys" as a whole: the data can be re-received, correctness beats the cache.
	if sn.Version < snapshotVersionProtoPayloadV4 &&
		(len(sn.VerifyResults) > 0 || len(sn.WorkerHandraises) > 0 || len(sn.VerifierHandraises) > 0) {
		f.log.Warn("dropping pre-v4 snapshot payloads: they predate the proto bus migration",
			"task_id", f.taskID, "snapshot_version", sn.Version)
		sn.VerifyResults, sn.WorkerHandraises, sn.VerifierHandraises = nil, nil, nil
	}
	for _, raw := range sn.VerifyResults {
		var vr taskv1.ResultReceiptV2
		if err := proto.Unmarshal(raw, &vr); err != nil || vr.GetVerifierOperatorAddress() == "" {
			f.log.Warn("drop undecodable snapshotted verify result", "task_id", f.taskID)
			continue
		}
		f.verifyResults[vr.GetVerifierOperatorAddress()] = &vr
	}
	for _, raw := range sn.VerifyCommits {
		var commit taskv1.VerifyCommitV1
		if err := proto.Unmarshal(raw, &commit); err != nil || commit.GetVerifierOperatorAddress() == "" {
			f.log.Warn("drop undecodable snapshotted verify commit", "task_id", f.taskID)
			continue
		}
		f.verifyCommits[commit.GetVerifierOperatorAddress()] = &commit
	}
	for _, raw := range sn.WorkerHandraises {
		var hr taskv1.WorkerHandraiseV1
		if err := proto.Unmarshal(raw, &hr); err != nil || hr.GetMember().GetOperatorAddress() == "" {
			f.log.Warn("drop undecodable snapshotted worker handraise", "task_id", f.taskID)
			continue
		}
		f.workerHR[hr.GetMember().GetOperatorAddress()] = &hr
	}
	for _, raw := range sn.VerifierHandraises {
		var hr taskv1.VerifierHandraiseV1
		if err := proto.Unmarshal(raw, &hr); err != nil || hr.GetMember().GetOperatorAddress() == "" {
			f.log.Warn("drop undecodable snapshotted verifier handraise", "task_id", f.taskID)
			continue
		}
		f.verifierHR[hr.GetMember().GetOperatorAddress()] = &hr
	}
}

// reconcile against the chain}

// reconcile reconciles with the chain (§6.2 step 3): chain advanced, local behind -> jump straight to the on-chain state.
// Only forward, never back; on-chain fields overwrite local ones only when non-empty. Caller must hold the lock.
func (f *taskFSM) reconcile(t chaincli.OnChainTask) {
	// On-chain RECEIPT_COMMITTED also maps to Verifying, but that only means the verify window is open, verifiers undecided.
	// Local Verifying means "verifiers decided": hand-raises are only accepted in Assigned, so fast-forwarding here
	// would drop every verifier hand-raise that arrives afterwards. Stay in Assigned while the set is undecided.
	chainState := t.State
	if chainState == types.Verifying && len(t.Verifiers) == 0 {
		chainState = types.Assigned
	}
	if chainState < f.state {
		return // chain behind / no info: keep local state and fields untouched (guards against stub/empty overwrite)
	}
	if chainState > f.state {
		f.log.Info("recovery reconcile: chain ahead, fast-forwarding local state",
			"task_id", f.taskID, "local", f.state.String(), "chain", chainState.String())
		f.state = chainState
		// On a coarse-state jump the fine-grained phase takes that coarse state's entry phase (conservative mapping; chain events refine it later).
		switch chainState {
		case types.Assigned:
			f.phase = types.PhaseAssignmentFinalized
			// Assignment finalized while offline: the Worker never received the winner notification.
			// Record it so resume re-sends it once (the event path is handled by applyAuthoritativeTask;
			// the startup recovery path had no equivalent before).
			f.pendingAssignmentNotify = true
		case types.Verifying:
			f.phase = types.PhaseOpenVerify
		case types.Settled:
			f.phase = types.PhaseSettle
		}
	}
	// Merge non-empty on-chain fields even within the same coarse state: events missed during recovery may have
	// left new facts on-chain such as seed/deadline/settlement (§6.2 "on any doubt the on-chain query wins").
	if t.Winner != "" {
		f.winner = t.Winner
	}
	if t.Assignment.InferDeadlineHeight != 0 {
		f.inferDeadlineHeight = t.Assignment.InferDeadlineHeight
	}
	if t.Assignment.WinnerConfirmHeight != 0 {
		f.assignFinalizedHeight = t.Assignment.WinnerConfirmHeight
	}
	if len(t.AssignedSet) > 0 {
		f.assignedSet = t.AssignedSet
	}
	if len(t.Verifiers) > 0 {
		f.verifiers = t.Verifiers
	}
	if len(t.SampleSeed) > 0 {
		f.sampleSeed = t.SampleSeed
	}
	var zero types.Deadlines
	if t.Deadlines != zero {
		f.deadlines = t.Deadlines
	}
	if t.Settlement.SettlementHeight != 0 && t.Settlement.SettlementStatus != "" {
		f.settlement = t.Settlement
	}
	if t.TaskVerdict != types.VerdictUnspecified {
		f.verdict = t.TaskVerdict
	}
}

// resume restores subscriptions/timers and continues driving (called after restoreFrom + reconcile).
// Terminal states (Closed/Failed) return false = should not stay in the task table; the caller releases and cleans up.
func (f *taskFSM) resume() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.terminal {
		return false
	}

	switch f.state {
	case types.Closed, types.Failed:
		return false
	case types.Settled:
		// Settled tasks stay passive until a fresh chain query proves finality.
	default:
		// Pending/Assigned/Verifying: rebuild task-level subscriptions (subscribing before messages is harmless).
		// Subscription definitions share the same subscribeXxx functions as onOrder/onAssignAccepted -- a subject
		// missed on the recovery path is the easiest thing to miss in a format migration; sharing prevents it.
		f.subscribeWorkerHandraise()
		f.subscribeBuilderPrepare()
		f.subscribeVerifierHandraise()
		// Durable consumer restored under the same name -> JetStream resumes from the last ack position and catches up V_i missed while disconnected.
		f.subscribeVerifyResult()
		// Assignment missed while offline: re-send the start-of-work notification once, otherwise the winner never
		// learns its winner identity and infer deadline and the task never starts on the Worker side.
		// The notification creates no consensus fact; duplicates are deduplicated by the receiver against the on-chain assignment.
		if f.pendingAssignmentNotify {
			f.pendingAssignmentNotify = false
			f.publishWorkerAssignmentNotify()
		}
		// Settlement inputs may already have been complete before the crash (SettleTx broadcast but not seen included): re-evaluate immediately.
		// The submitted flag is not persisted, so we resubmit by rank timing -- the chain is idempotent as fallback; at worst one extra gas fee.
		if f.state == types.Verifying {
			f.trySettle()
		}
	}
	f.emit(EvTaskRecovered, 0)
	f.save()
	f.log.Info("task recovered", "task_id", f.taskID, "state", f.state.String(), "phase", f.phase.String())
	return true
}

// recoverTasks is the restart recovery at startup (§6.2): load snapshots -> reconcile each task on-chain -> resume subscriptions.
// A failed reconciliation query does not block recovery (local state continues; the event stream catches up naturally).
func (c *Coordinator) recoverTasks(ctx context.Context) error {
	if err := c.retryPayloadCleanup(ctx); err != nil {
		return err
	}
	var markerErr error
	if err := c.kv.Scan(kv.NSTerminalTask, func(key string, value []byte) bool {
		var record terminalTaskRecord
		if key == "" || json.Unmarshal(value, &record) != nil || record.Version != terminalTaskVersion {
			markerErr = fmt.Errorf("invalid terminal task marker %q", key)
			return false
		}
		c.terminalTasks[key] = record.Recipient
		return true
	}); err != nil {
		return fmt.Errorf("scan terminal task markers: %w", err)
	}
	if markerErr != nil {
		return markerErr
	}

	var snaps []taskSnapshot
	var snapshotErr error
	if err := c.kv.Scan(kv.NSTask, func(key string, val []byte) bool {
		var sn taskSnapshot
		if err := json.Unmarshal(val, &sn); err != nil {
			if _, terminal := c.terminalTasks[key]; terminal {
				snapshotErr = fmt.Errorf("decode terminal task snapshot %q: %w", key, err)
				return false
			}
			c.log.Warn("task snapshot corrupt, dropping", "key", key, "err", err)
			_ = c.kv.Delete(kv.NSTask, key)
			return true
		}
		if expected := taskKey(sn.SessionID, sn.TaskID); key != expected {
			snapshotErr = fmt.Errorf("task snapshot key mismatch %q (record key %q)", key, expected)
			return false
		}
		snaps = append(snaps, sn)
		return true
	}); err != nil {
		return fmt.Errorf("scan task snapshots: %w", err)
	}
	if snapshotErr != nil {
		return snapshotErr
	}
	if len(snaps) == 0 {
		return nil
	}
	c.log.Info("recovering in-flight tasks from snapshots", "count", len(snaps))

	for _, sn := range snaps {
		key := taskKey(sn.SessionID, sn.TaskID)
		_, terminalMarked := c.terminalTasks[key]
		c.journalFor(key).restoreEntries(sn.Events)
		order := sn.Order
		if order.SessionID == "" {
			order = types.Order{SessionID: sn.SessionID, TaskID: sn.TaskID, ModelID: sn.ModelID, PayloadCID: sn.PayloadCID, User: sn.User}
		}
		fsm := c.newFSM(order)
		fsm.restoreFrom(sn)
		freshTaskFacts := false

		if !terminalMarked {
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var t chaincli.OnChainTask
			var err error
			if c.query == nil {
				err = errors.New("Task Query is not configured")
			} else {
				t, err = c.query.QueryTask(qctx, chaincli.TaskKey{SessionID: sn.SessionID, TaskID: sn.TaskID})
			}
			cancel()
			if err != nil {
				c.log.Warn("recovery: chain query failed, keeping local snapshot state",
					"task_id", sn.TaskID, "err", err)
			} else {
				fsm.mu.Lock()
				fsm.reconcile(t)
				fsm.mu.Unlock()
				freshTaskFacts = true
				if t.State == types.Verifying && t.Status != "RECEIPT_ONLY_ACCEPTED" {
					if c.settlementFacts == nil {
						c.log.Warn("recovery: SettlementBuildFacts Query is not configured", "task_id", sn.TaskID)
						freshTaskFacts = false
					} else {
						factsCtx, factsCancel := context.WithTimeout(ctx, reconcileQueryTimeout)
						facts, factsErr := c.settlementFacts.QuerySettlementBuildFacts(factsCtx, chaincli.TaskKey{
							SessionID: sn.SessionID, TaskID: sn.TaskID,
						})
						factsCancel()
						if factsErr != nil {
							c.log.Warn("recovery: settlement facts query failed, keeping local reveal state",
								"task_id", sn.TaskID, "err", factsErr)
							freshTaskFacts = false
						} else if err := fsm.reconcileSettlementFacts(facts, false); err != nil {
							c.log.Warn("recovery: settlement facts invalid, keeping local reveal state",
								"task_id", sn.TaskID, "err", err)
							freshTaskFacts = false
						}
					}
				}
			}
		}

		// Publish before any terminal callback so onClose can remove this exact FSM.
		c.mu.Lock()
		c.tasks[key] = fsm
		c.mu.Unlock()
		fsm.mu.Lock()
		trackEvents := !terminalMarked && !fsm.terminal && fsm.state != types.Closed && fsm.state != types.Failed
		fsm.mu.Unlock()
		if trackEvents {
			if err := c.trackTaskEvents(key, fsm); err != nil {
				return fmt.Errorf("recovery: track task events %s: %w", key, err)
			}
		}
		if terminalMarked || !fsm.resume() {
			// Keep the terminal snapshot until outputdelivery has durably
			// reconciled a possible PREPARED plaintext record.
			recipient := c.removeTask(key)
			c.deletePayload(sn.SessionID, sn.TaskID)
			c.relay.Release(sn.SessionID, sn.TaskID)
			if c.outputs != nil {
				if err := c.outputs.Terminate(sn.SessionID, sn.TaskID, recipient); err != nil {
					return fmt.Errorf("recover terminal output %s: %w", key, err)
				}
			}
			c.deleteTaskSnapshot(key)
			c.log.Info("recovery: task already terminal, cleaned up",
				"task_id", sn.TaskID, "state", fsm.state.String())
			continue
		}
		if freshTaskFacts {
			c.reconcileSettleSelection(fsm)
			if height, authoritative := c.currentChainHeight(); authoritative {
				fsm.closeSettledAtHeight(height)
			}
		}
	}
	return nil
}
