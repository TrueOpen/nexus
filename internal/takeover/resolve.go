package takeover

import (
	"context"
	"encoding/hex"
	"errors"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/types"
)

// Event codes the held order's task ends or moves with.
const (
	codeVoided     = coordinator.EvTakeoverVoided
	codeExpired    = coordinator.EvOrderExpired
	codeRejected   = coordinator.EvRecordRejected
	codeTaskFailed = coordinator.EvTaskFailed
)

// cause is what a job on a takeover handles.
type cause uint8

const (
	// causeCheck: an event, a block or a restart asks for the session state; a submitted entry
	// waits for its result.
	causeCheck cause = iota + 1
	// causeRegistered: the entry's result says the chain registered it.
	causeRegistered
	// causeRefused: the chain refused the entry with job.code.
	causeRefused
	// causeLapsed: the entry got no result before the order expired.
	causeLapsed
	// causeVoided: the chain voided this Builder's registration.
	causeVoided
	// causeSettle: a submitted entry is judged again by Admit's rules and sent again under the
	// session's current bound_change_height (after a restart, or a result that could not be
	// attributed to it).
	causeSettle
)

// job is one thing to handle on a takeover. The jobs of a takeover run one at a time, in order,
// in the background, so a job may read the chain without holding any lock of the Manager.
type job struct {
	why  cause
	code taskv1.DispatchRejectCodeV1
}

// TakeoverRegistered implements recorder.Takeovers: the chain registered the takeover (or
// answered its replay); the session state gives the activation height.
func (m *Manager) TakeoverRegistered(sessionID string, sequence, _ uint64) {
	m.schedule(sessionID, sequence, job{why: causeRegistered})
}

// TakeoverRefused implements recorder.Takeovers. Refused because the sequence is consumed (the
// bound Builder recorded it, or it was cancelled) or because another takeover is registered, the
// takeover is voided: the order and its input are dropped and the task records where the session
// went. Any other refusal ends the task as RECORD_REJECTED.
func (m *Manager) TakeoverRefused(sessionID string, sequence uint64, code taskv1.DispatchRejectCodeV1) {
	m.schedule(sessionID, sequence, job{why: causeRefused, code: code})
}

// TakeoverLapsed implements recorder.Takeovers: the entry got no result before the order
// expired; the session state tells whether it registered.
func (m *Manager) TakeoverLapsed(sessionID string, sequence uint64) {
	m.schedule(sessionID, sequence, job{why: causeLapsed})
}

// TakeoverUnsettled implements recorder.Takeovers: the entry's result could not be attributed
// and the entry was dropped; it is judged again with the chain and sent again if it still may.
func (m *Manager) TakeoverUnsettled(sessionID string, sequence uint64) {
	m.schedule(sessionID, sequence, job{why: causeSettle})
}

// HandleChainEvent follows the head and the takeover events of the held sessions. The caller
// feeds it every task chain event.
func (m *Manager) HandleChainEvent(ev chaincli.ChainEvent) {
	if ev.Height > 0 {
		for {
			head := m.head.Load()
			if uint64(ev.Height) <= head || m.head.CompareAndSwap(head, uint64(ev.Height)) {
				break
			}
		}
	}
	if ev.Type == chaincli.EventNewBlock {
		m.onBlock()
		return
	}
	switch t := ev.Typed.(type) {
	case chaincli.SessionTakeoverRegistered:
		if t.CandidateBuilder == m.cfg.Builder {
			m.registered(t.SessionID, t.OrderSequence, t.ActivationHeight)
		}
	case chaincli.SessionBuilderBound:
		// Bound here, the takeover took effect; bound to another Builder, it never will.
		if r := m.lookup(t.SessionID); r != nil {
			m.schedule(t.SessionID, r.Sequence, job{why: causeCheck})
		}
	case chaincli.SessionTakeoverVoided:
		if t.CandidateBuilder == m.cfg.Builder {
			m.log.Info("takeover voided", "session_id", t.SessionID, "order_sequence", t.OrderSequence, "reason", t.Reason)
			m.schedule(t.SessionID, t.OrderSequence, job{why: causeVoided})
		}
	}
}

// onBlock runs again the jobs a chain read left without a verdict, and checks the registered
// takeovers whose activation height the head reached (their binding event may have been missed).
func (m *Manager) onBlock() {
	head := m.head.Load()
	type due struct {
		session string
		seq     uint64
		job     job
	}
	var dues []due
	m.mu.Lock()
	for _, r := range m.records {
		switch {
		case r.Phase == phaseReserved:
		case r.retry != nil:
			dues = append(dues, due{r.SessionID, r.Sequence, *r.retry})
			r.retry = nil
		case r.Phase == phaseRegistered && r.ActivationHeight != 0 && r.ActivationHeight <= head:
			dues = append(dues, due{r.SessionID, r.Sequence, job{why: causeCheck}})
		}
	}
	m.mu.Unlock()
	for _, d := range dues {
		m.schedule(d.session, d.seq, d.job)
	}
}

// schedule queues j on the session's takeover of seq and starts its jobs unless they run. A check
// already queued is not queued twice.
func (m *Manager) schedule(sessionID string, seq uint64, j job) {
	m.mu.Lock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq {
		m.mu.Unlock()
		return
	}
	for _, queued := range r.jobs {
		if j.why == causeCheck && queued.why == causeCheck {
			m.mu.Unlock()
			return
		}
	}
	r.jobs = append(r.jobs, j)
	start := !r.running
	r.running = true
	m.mu.Unlock()
	if start {
		m.later(func(ctx context.Context) { m.run(ctx, r) })
	}
}

// run handles r's jobs one at a time until none is left or r is dropped.
func (m *Manager) run(ctx context.Context, r *record) {
	for {
		m.mu.Lock()
		if m.records[r.SessionID] != r || len(r.jobs) == 0 {
			r.running, r.jobs = false, nil
			m.mu.Unlock()
			return
		}
		j := r.jobs[0]
		r.jobs = r.jobs[1:]
		m.mu.Unlock()
		m.handle(ctx, r, j)
	}
}

func (m *Manager) handle(ctx context.Context, r *record, j job) {
	switch j.why {
	case causeRefused:
		m.log.Info("takeover entry refused", "session_id", r.SessionID, "order_sequence", r.Sequence, "reject_code", j.code)
		switch j.code {
		case taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_SEQUENCE_CONSUMED,
			taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING:
			m.end(ctx, r, codeVoided, true, m.elsewhere(ctx, r, nil))
		default:
			m.end(ctx, r, codeRejected, false, nil)
		}
	case causeVoided:
		m.end(ctx, r, codeVoided, true, m.elsewhere(ctx, r, nil))
	case causeSettle:
		m.settle(ctx, r, j)
	default:
		m.resolve(ctx, r, j)
	}
}

// resolve reads the session and acts on it. Closed (the chain no longer has it), the takeover is
// voided. Bound here, the takeover took effect and the order is dispatched. A takeover of this
// Builder for the sequence registered, it waits for the activation height. Neither: a submitted
// entry waits for its result, or, lapsed, never registered before the order expired
// (ORDER_EXPIRED: the session stays with its Builder, and a re-signed resend registers a takeover
// again); a registered takeover was voided, once a second read confirms it (a node read may trail
// the registration). A read without a verdict is tried again at the next block.
func (m *Manager) resolve(ctx context.Context, r *record, j job) {
	if j.why == causeRegistered && m.phase(r) == phaseSubmitted {
		m.setPhase(r, phaseRegistered)
	}
	state, err := m.cfg.Chain.QuerySession(ctx, r.SessionID)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		m.log.Info("held session is closed; takeover voided", "session_id", r.SessionID)
		m.end(ctx, r, codeVoided, true, nil)
		return
	case err != nil:
		m.log.Warn("held session not read; tried again at the next block", "session_id", r.SessionID, "err", err)
		m.retryNextBlock(r, j)
		return
	}
	switch t := state.PendingTakeover; {
	case state.BoundBuilder == m.cfg.Builder:
		m.activate(ctx, r, state.BoundChangeHeight)
	case t != nil && t.CandidateBuilder == m.cfg.Builder && t.OrderSequence == r.Sequence:
		m.registered(r.SessionID, r.Sequence, t.ActivationHeight)
	case m.phase(r) == phaseSubmitted && j.why == causeLapsed:
		m.end(ctx, r, codeExpired, false, nil)
	case m.phase(r) == phaseSubmitted:
		// Not registered yet: the entry's result decides.
	case m.miss(r) < 2:
		m.retryNextBlock(r, job{why: causeCheck})
	default:
		m.log.Info("takeover will not take effect", "session_id", r.SessionID, "order_sequence", r.Sequence, "bound_builder", state.BoundBuilder)
		m.end(ctx, r, codeVoided, true, m.elsewhere(ctx, r, &state))
	}
}

// settle judges a submitted entry again by Admit's rules with the current chain state and, when
// the takeover still may register, hands the recorder its entry under the session's current
// bound_change_height (dropping the one sent under an older one). A pending key rotation or a
// compensation account below its minimum ends it as TASK_FAILED: no takeover then.
func (m *Manager) settle(ctx context.Context, r *record, j job) {
	if err := m.cfg.Keys.CheckBuilderKey(ctx); err != nil {
		if errors.Is(err, handraise.ErrBuilderRotationPending) || errors.Is(err, dispatcher.ErrCompensationBelowMin) {
			m.log.Warn("takeover dropped: no takeover while this Builder cannot record", "session_id", r.SessionID, "err", err)
			m.end(ctx, r, codeTaskFailed, false, nil)
			return
		}
		m.retryNextBlock(r, j)
		return
	}
	state, err := m.cfg.Chain.QuerySession(ctx, r.SessionID)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		m.end(ctx, r, codeVoided, true, nil)
		return
	case err != nil:
		m.retryNextBlock(r, j)
		return
	}
	switch t := state.PendingTakeover; {
	case state.BoundBuilder == m.cfg.Builder:
		m.activate(ctx, r, state.BoundChangeHeight)
		return
	case t != nil && t.CandidateBuilder == m.cfg.Builder && t.OrderSequence == r.Sequence:
		m.cfg.Recorder.WithdrawTakeover(ctx, r.SessionID, r.Sequence)
		m.registered(r.SessionID, r.Sequence, t.ActivationHeight)
		return
	case t != nil:
		m.end(ctx, r, codeVoided, true, &types.SessionElsewhere{Builder: t.CandidateBuilder, ActivationHeight: t.ActivationHeight})
		return
	}
	rec, err := m.cfg.Chain.QueryDispatchRecordByOrder(ctx, r.SessionID, r.Sequence)
	switch {
	case err == nil:
		m.end(ctx, r, codeVoided, true, &types.SessionElsewhere{Builder: rec.GetBuilderAddress(), TaskID: hex.EncodeToString(rec.GetTaskId())})
		return
	case !errors.Is(err, chaincli.ErrNotFound):
		m.retryNextBlock(r, j)
		return
	}
	if r.Sequence != state.NextExpectedSequence {
		m.end(ctx, r, codeVoided, true, &types.SessionElsewhere{Builder: state.BoundBuilder})
		return
	}
	if err := inflight.CheckTakeoverFunds(inflight.Session{SessionState: state, Found: true}, r.Precheck.MaxFee); err != nil {
		m.log.Info("takeover dropped", "session_id", r.SessionID, "err", err)
		m.end(ctx, r, codeTaskFailed, false, nil)
		return
	}
	if state.BoundChangeHeight != m.boundChange(r) {
		m.cfg.Recorder.WithdrawTakeover(ctx, r.SessionID, r.Sequence)
		m.setBoundChange(r, state.BoundChangeHeight)
	}
	if err := m.submitEntry(ctx, r); err != nil {
		m.log.Error("takeover entry not handed to the recorder", "session_id", r.SessionID, "err", err)
		m.end(ctx, r, codeTaskFailed, false, nil)
	}
}

// elsewhere finds where the session went when r ends: the Builder that recorded the order with
// its task, else the candidate of another registered takeover, else the Builder it is bound to.
// state is the session state when already read. Nil when the chain cannot tell.
func (m *Manager) elsewhere(ctx context.Context, r *record, state *chaincli.SessionState) *types.SessionElsewhere {
	if rec, err := m.cfg.Chain.QueryDispatchRecordByOrder(ctx, r.SessionID, r.Sequence); err == nil {
		return &types.SessionElsewhere{Builder: rec.GetBuilderAddress(), TaskID: hex.EncodeToString(rec.GetTaskId())}
	}
	if state == nil {
		s, err := m.cfg.Chain.QuerySession(ctx, r.SessionID)
		if err != nil {
			return nil
		}
		state = &s
	}
	if t := state.PendingTakeover; t != nil && t.CandidateBuilder != m.cfg.Builder {
		return &types.SessionElsewhere{Builder: t.CandidateBuilder, ActivationHeight: t.ActivationHeight}
	}
	if state.BoundBuilder != "" && state.BoundBuilder != m.cfg.Builder {
		return &types.SessionElsewhere{Builder: state.BoundBuilder}
	}
	return nil
}

// registered records the activation height of this Builder's registered takeover of the
// session's sequence.
func (m *Manager) registered(sessionID string, seq, activation uint64) {
	m.mu.Lock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq {
		m.mu.Unlock()
		return
	}
	r.misses = 0
	if r.Phase == phaseRegistered && r.ActivationHeight == activation {
		m.mu.Unlock()
		return
	}
	r.Phase, r.ActivationHeight = phaseRegistered, activation
	if err := m.saveLocked(r); err != nil {
		m.log.Error("takeover registration not written", "session_id", sessionID, "err", err)
	}
	taskID := r.TaskID
	m.mu.Unlock()
	m.log.Info("takeover registered", "session_id", sessionID, "order_sequence", seq, "activation_height", activation)
	m.cfg.Tasks.TakeoverRegistered(sessionID, taskID, activation)
}

// activate dispatches the held order once the session is bound here (at boundChange): it is
// prechecked again without freshness, which reserves it in the in-flight ledger, and handed to
// the dispatcher on its task. An order that can no longer be recorded before it expires ends as
// ORDER_EXPIRED (the session is here now: the SDK resends it re-signed); one the precheck refuses
// otherwise as TASK_FAILED. A precheck without a verdict (state unreadable, or the cached state
// not bound here yet) is tried again at the next block.
func (m *Manager) activate(ctx context.Context, r *record, boundChange uint64) {
	m.cfg.Recorder.WithdrawTakeover(ctx, r.SessionID, r.Sequence)
	pre := r.Precheck
	pre.Takeover = true
	res, err := m.cfg.Precheck.Reserve(ctx, pre)
	switch {
	case errors.Is(err, inflight.ErrUnavailable), errors.Is(err, inflight.ErrOrderUploading),
		err == nil && res.Binding != inflight.BoundHere:
		m.log.Info("taken over order not prechecked yet; tried again at the next block", "session_id", r.SessionID, "err", err)
		m.retryNextBlock(r, job{why: causeCheck})
		return
	case err != nil:
		m.cfg.Tasks.TakeoverActivated(r.SessionID, r.TaskID, boundChange)
		code := codeTaskFailed
		if errors.Is(err, inflight.ErrOrderExpired) {
			code = codeExpired
		}
		m.log.Info("taken over order not dispatched", "session_id", r.SessionID, "order_sequence", r.Sequence, "err", err)
		m.end(ctx, r, code, false, nil)
		return
	}
	if res.Existing == nil {
		m.cfg.Tasks.TakeoverActivated(r.SessionID, r.TaskID, boundChange)
		if err := m.cfg.Tasks.OnOrder(ctx, r.Order); err != nil {
			if res.Reservation != nil {
				if relErr := m.cfg.Precheck.Release(res.Reservation); relErr != nil {
					m.log.Error("release in-flight reservation", "session_id", r.SessionID, "err", relErr)
				}
			}
			m.log.Error("taken over order not dispatched", "session_id", r.SessionID, "order_sequence", r.Sequence, "err", err)
			m.end(ctx, r, codeTaskFailed, false, nil)
			return
		}
	}
	m.log.Info("takeover took effect; order dispatched", "session_id", r.SessionID, "order_sequence", r.Sequence, "bound_change_height", boundChange)
	m.forget(r)
}

// end drops r and its outbox entry, telling its task code and where the session went.
func (m *Manager) end(ctx context.Context, r *record, code string, dropInput bool, where *types.SessionElsewhere) {
	m.forget(r)
	m.cfg.Recorder.WithdrawTakeover(ctx, r.SessionID, r.Sequence)
	m.cfg.Tasks.TakeoverEnded(r.SessionID, r.TaskID, code, m.head.Load(), dropInput, where)
}

func (m *Manager) lookup(sessionID string) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[sessionID]; r != nil && r.Phase != phaseReserved {
		return r
	}
	return nil
}

// retryNextBlock runs j again at the next block.
func (m *Manager) retryNextBlock(r *record, j job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.retry = &j
}

// miss counts a read that shows a registered takeover neither pending nor taken effect.
func (m *Manager) miss(r *record) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.misses++
	return r.misses
}

func (m *Manager) phase(r *record) phase {
	m.mu.Lock()
	defer m.mu.Unlock()
	return r.Phase
}

func (m *Manager) boundChange(r *record) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return r.BoundChangeHeight
}

func (m *Manager) setPhase(r *record, p phase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Phase = p
	if err := m.saveLocked(r); err != nil {
		m.log.Error("takeover phase not written", "session_id", r.SessionID, "err", err)
	}
}

func (m *Manager) setBoundChange(r *record, height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.BoundChangeHeight = height
	if err := m.saveLocked(r); err != nil {
		m.log.Error("takeover binding generation not written", "session_id", r.SessionID, "err", err)
	}
}
