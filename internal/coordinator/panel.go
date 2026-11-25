package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sort"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/types"
)

// Verifier panel rounds of an anchor audit.
//
// A task verified by the anchor audit alone owns verify round 1 with no Verifier. When the chain
// audits such a task by a Verifier panel (anchor_audit_mode 2), every panel is one more verify
// round: the first panel is round 2, an automatic retry round 3, a re-audit the next free number.
// The chain opens the round's Verifier window when the Worker's proof is recorded and draws the
// panel from the hand-raises Builders relay, exactly as it draws logprob Verifiers. So for a
// panel round this Builder does what it does for round 1 of an ordinary task: send OPEN_VERIFY,
// collect VerifierHandraiseV1, and propose them, with verify_round = the panel round.
//
// Differences from round 1:
//   - the trigger is the audit row (a round that is open and not drawn yet), not the receipt;
//   - nothing is fetched from this Builder by a panel member (the audit material comes from the
//     Worker's store), so OPEN_VERIFY does not wait for this Builder's data-ready;
//   - the Worker of the task and the members of earlier panels of the task are never proposed;
//   - who may serve is the chain's rule (the audit capability); a Cortex without it does not
//     hand-raise, and the chain refuses one that does.
//
// The state is kept in memory only: after a restart the next reconciliation finds the open round
// again and OPEN_VERIFY is sent again, which makes the Cortex nodes hand-raise again.

// AnchorPanelQuerier is the chain read a Coordinator needs for panel rounds.
type AnchorPanelQuerier interface {
	QueryAnchorPanel(ctx context.Context, taskID string) (chaincli.AnchorPanel, error)
}

// panelRoundState is this Builder's hand-raise collection for one panel round.
type panelRoundState struct {
	round       uint32
	kind        uint32
	window      chaincli.VerifierWindow
	windowKnown bool
	published   bool
	closed      bool
	handraises  map[string]*taskv1.VerifierHandraiseV1
	proposed    map[string]bool
	excluded    map[string]struct{}
	// barred are operators this Builder does not propose: the Worker and earlier panel members.
	barred map[string]bool
}

// needsPanelRound reports whether reconciliation should read the task's panel state: only for a
// task the chain verifies by the anchor audit alone, while it is not terminal.
func (f *taskFSM) needsPanelRound() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.terminal && f.state == types.Verifying && f.anchorOnlyRound
}

// setPanelRound applies the chain's panel state. It returns the verify round whose messages are to
// be retired from the Cortex link (a round that is no longer collecting), or zero.
func (f *taskFSM) setPanelRound(p chaincli.AnchorPanel) (retire uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	collecting := p.AuditMode == chaincli.AnchorAuditModePanel && p.Round >= 2 && p.Collecting
	if f.panel != nil && (!collecting || p.Round != f.panel.round) {
		// Rounds only go up: the round this Builder collected for is drawn, closed or replaced.
		retire = f.panel.round
		f.panelRetired = f.panel.round
		f.log.Info("panel round left the hand-raise stage", "task_id", f.taskID, "panel_round", f.panel.round,
			"handraises", len(f.panel.handraises), "proposed", len(f.panel.proposed))
		f.panel = nil
	}
	if !collecting || f.panel != nil || p.Round <= f.panelRetired {
		return retire
	}
	barred := map[string]bool{}
	if f.winner != "" {
		barred[f.winner] = true
	}
	for _, member := range p.PriorMembers {
		barred[member] = true
	}
	f.panel = &panelRoundState{
		round: p.Round, kind: p.Kind, barred: barred,
		handraises: map[string]*taskv1.VerifierHandraiseV1{}, proposed: map[string]bool{}, excluded: map[string]struct{}{},
	}
	f.log.Info("panel round open: collecting Verifier hand-raises", "task_id", f.taskID,
		"panel_round", p.Round, "kind", p.Kind, "open_height", p.OpenHeight)
	return retire
}

// panelWindowRound is the round whose Verifier window reconciliation should read, or zero.
func (f *taskFSM) panelWindowRound() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panel == nil || f.panel.closed || (f.panel.windowKnown && f.panel.window.Ready) {
		return 0
	}
	return f.panel.round
}

func (f *taskFSM) setPanelWindow(round uint32, window chaincli.VerifierWindow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panel == nil || f.panel.round != round {
		return
	}
	f.panel.window, f.panel.windowKnown = window, true
}

// advancePanelRound sends OPEN_VERIFY for the open panel round (once) and proposes the hand-raises
// collected so far. Every reconciliation of the task reaches here, which is the retry.
func (f *taskFSM) advancePanelRound() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishPanelOpenVerifyLocked()
	f.submitPanelProposalLocked()
}

// panelOpenVerifyPayloadLocked is the round's OPEN_VERIFY; nil while the accepted receipt hashes
// are not known. Caller must hold the lock.
func (f *taskFSM) panelOpenVerifyPayloadLocked() *nexusv1.OpenVerifyV1 {
	outputHash, receiptHash := f.acceptedReceiptHashesLocked()
	taskID, taskHash := f.taskIDBytes(), f.taskHashBytes()
	modelID, err := hex.DecodeString(f.modelID)
	if len(outputHash) == 0 || len(receiptHash) == 0 || f.winner == "" ||
		taskID == nil || taskHash == nil || err != nil || len(modelID) != hash32Len {
		return nil
	}
	return &nexusv1.OpenVerifyV1{
		TaskId:                taskID,
		TaskHash:              taskHash,
		ModelId:               modelID,
		ProfileVersion:        f.profileVersion,
		InferReceiptHash:      append([]byte(nil), receiptHash...),
		OutputHash:            append([]byte(nil), outputHash...),
		WorkerOperatorAddress: f.winner,
		VerifyRound:           f.panel.round,
	}
}

func (f *taskFSM) publishPanelOpenVerifyLocked() {
	if f.panel == nil || f.panel.published || f.panel.closed || f.terminal {
		return
	}
	payload := f.panelOpenVerifyPayloadLocked()
	if payload == nil {
		f.log.Debug("panel OPEN_VERIFY deferred: the accepted receipt is not known yet", "task_id", f.taskID,
			"panel_round", f.panel.round)
		return
	}
	ctx := context.Background()
	if err := f.messages.signOpenVerify(ctx, payload, f.recordHeight); err != nil {
		f.log.Warn("panel OPEN_VERIFY not sent: it cannot be signed", "task_id", f.taskID, "panel_round", f.panel.round, "err", err)
		return
	}
	frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: payload}}
	if err := f.messages.broadcast(ctx, frame); err != nil {
		f.log.Warn("panel OPEN_VERIFY broadcast failed", "task_id", f.taskID, "panel_round", f.panel.round, "err", err)
		return
	}
	f.panel.published = true
	f.log.Info("panel OPEN_VERIFY sent", "task_id", f.taskID, "panel_round", f.panel.round)
}

// onPanelHandraiseLocked takes a hand-raise for the open panel round. Caller must hold the lock
// and has matched the task id and the round.
func (f *taskFSM) onPanelHandraiseLocked(hr *taskv1.VerifierHandraiseV1) {
	candidate := hr.GetMember().GetOperatorAddress()
	switch {
	case f.terminal || f.state != types.Verifying || f.panel.closed:
		return
	case f.panel.barred[candidate]:
		f.log.Warn("drop panel handraise from the task's Worker or a member of an earlier panel of the task",
			"task_id", f.taskID, "panel_round", f.panel.round, "candidate", candidate)
		return
	case !f.validVerifierHandraiseRound(hr, uint64(f.panel.round)):
		return
	}
	f.panel.handraises[candidate] = hr
	f.log.Info("panel handraise accepted", "task_id", f.taskID, "panel_round", f.panel.round,
		"candidate", candidate, "count", len(f.panel.handraises))
	if len(f.pendingPanelHandraisesLocked()) >= selectedVerifierCount {
		f.submitPanelProposalLocked()
	}
}

func (f *taskFSM) pendingPanelHandraisesLocked() []*taskv1.VerifierHandraiseV1 {
	pending := make([]*taskv1.VerifierHandraiseV1, 0, len(f.panel.handraises))
	for operator, hr := range f.panel.handraises {
		if _, excluded := f.panel.excluded[operator]; !excluded && !f.panel.proposed[operator] {
			pending = append(pending, hr)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].GetMember().GetSlot() < pending[j].GetMember().GetSlot()
	})
	return pending
}

// submitPanelProposalLocked proposes the hand-raises not yet on chain. Each proposal carries only
// new ones, as for round 1. Caller must hold the lock.
func (f *taskFSM) submitPanelProposalLocked() {
	if f.panel == nil || f.panel.closed || f.terminal || f.submit == nil {
		return
	}
	pending := f.pendingPanelHandraisesLocked()
	if len(pending) == 0 {
		return
	}
	set := f.assignedSet
	if len(set) == 0 {
		set = f.builderSet
	}
	if !f.inProposalGroup(set) {
		return
	}
	if p := f.panel; p.windowKnown && f.observedHeight > 0 {
		next := f.observedHeight + 1
		switch {
		case next > p.window.BuilderProposalCloseHeight:
			p.closed = true
			f.log.Info("panel proposal window closed for this Builder", "task_id", f.taskID, "panel_round", p.round,
				"builder_proposal_close_height", p.window.BuilderProposalCloseHeight, "pending_handraises", len(pending))
			return
		case p.window.Ready && next < p.window.GeneratedHeight:
			return
		case !p.window.Ready && next <= p.window.WindowRandomnessHeight:
			return // the beacon cannot have arrived: the chain would refuse
		}
	}
	tx := chaincli.OpenVerifyTx{
		BuilderOperatorAddress: f.self, SessionID: f.sessionID, TaskID: f.taskID, WorkerOperatorAddress: f.winner,
		VerifierHandraises: pending, Submitter: f.self,
	}
	result, err := f.submit.SubmitVerifierHandraises(context.Background(), tx)
	for _, ex := range result.Excluded {
		f.panel.excluded[ex.Operator] = struct{}{}
	}
	if err != nil {
		f.log.Warn("submit panel MsgSubmitVerifierHandraises failed; will retry on the next chain reconciliation",
			"task_id", f.taskID, "panel_round", f.panel.round, "handraises", len(pending), "err", err)
		return
	}
	for _, hr := range pending {
		operator := hr.GetMember().GetOperatorAddress()
		if _, excluded := f.panel.excluded[operator]; !excluded {
			f.panel.proposed[operator] = true
		}
	}
	f.log.Info("panel MsgSubmitVerifierHandraises submitted", "task_id", f.taskID, "panel_round", f.panel.round,
		"handraises", len(pending)-len(result.Excluded), "excluded", len(result.Excluded), "proposed_total", len(f.panel.proposed))
}

// fillPanelRound reads the panel state of a task verified by the anchor audit alone and drives the
// hand-raise collection of its open round. On a chain without panels it does nothing.
func (c *Coordinator) fillPanelRound(fsm *taskFSM) {
	if c.panels == nil || c.panelsUnsupported.Load() || !fsm.needsPanelRound() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	panel, err := c.panels.QueryAnchorPanel(ctx, fsm.taskID)
	cancel()
	switch {
	case errors.Is(err, chaincli.ErrAnchorPanelUnsupported):
		c.panelsUnsupported.Store(true)
		return
	case errors.Is(err, chaincli.ErrNotFound):
		return // not sampled: no audit row, no panel
	case err != nil:
		c.log.Debug("anchor panel query failed", "task_id", fsm.taskID, "err", err)
		return
	}
	if retire := fsm.setPanelRound(panel); retire != 0 {
		c.retirePanelMessages(fsm.taskID, retire)
	}
	if round := fsm.panelWindowRound(); round != 0 && c.verifierWindows != nil {
		ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
		window, err := c.verifierWindows.QueryVerifierCandidateWindow(ctx, fsm.taskID, round)
		cancel()
		if err == nil {
			fsm.setPanelWindow(round, window)
		}
	}
	fsm.advancePanelRound()
}

func (c *Coordinator) retirePanelMessages(taskID string, round uint32) {
	raw, err := hex.DecodeString(taskID)
	if c.cortex == nil || err != nil || len(raw) != hash32Len {
		return
	}
	c.cortex.Retire(raw, round)
}

// panelHandraiseLocked routes a hand-raise to the open panel round when it names that round. It
// reports whether the hand-raise was a panel one (taken or dropped). Caller must hold the lock.
func (f *taskFSM) panelHandraiseLocked(hr *taskv1.VerifierHandraiseV1) bool {
	if f.panel == nil || hr.GetVerifyRound() != f.panel.round || !bytes.Equal(hr.GetTaskId(), f.taskIDBytes()) {
		return false
	}
	f.onPanelHandraiseLocked(hr)
	return true
}
