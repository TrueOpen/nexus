package takeover

import (
	"context"
	"errors"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// Event codes the held order's task ends or moves with.
const (
	codeVoided     = coordinator.EvTakeoverVoided
	codeExpired    = coordinator.EvOrderExpired
	codeRejected   = coordinator.EvRecordRejected
	codeTaskFailed = coordinator.EvTaskFailed
)

// TakeoverRegistered implements recorder.Takeovers: the chain registered the takeover (or
// answered its replay); the session state gives the activation height.
func (m *Manager) TakeoverRegistered(sessionID string, sequence, _ uint64) {
	m.later(func(ctx context.Context) { m.resolve(ctx, sessionID, sequence, false) })
}

// TakeoverRefused implements recorder.Takeovers. Refused because the sequence is consumed (the
// bound Builder recorded it, or it was cancelled) or because another takeover is registered, the
// takeover is voided: the order and its input are dropped and the SDK goes where the chain says.
// Any other refusal ends the task as RECORD_REJECTED.
func (m *Manager) TakeoverRefused(sessionID string, sequence uint64, code taskv1.DispatchRejectCodeV1) {
	r := m.take(sessionID, sequence)
	if r == nil {
		return
	}
	m.log.Info("takeover entry refused", "session_id", sessionID, "order_sequence", sequence, "reject_code", code)
	switch code {
	case taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_SEQUENCE_CONSUMED,
		taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_TAKEOVER_PENDING:
		m.end(r, codeVoided, true)
	default:
		m.end(r, codeRejected, false)
	}
}

// TakeoverLapsed implements recorder.Takeovers: the entry got no result before the order
// expired; the session state tells whether it registered.
func (m *Manager) TakeoverLapsed(sessionID string, sequence uint64) {
	m.later(func(ctx context.Context) { m.resolve(ctx, sessionID, sequence, true) })
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
			seq := r.Sequence
			m.later(func(ctx context.Context) { m.resolve(ctx, t.SessionID, seq, false) })
		}
	case chaincli.SessionTakeoverVoided:
		if t.CandidateBuilder != m.cfg.Builder {
			return
		}
		if r := m.take(t.SessionID, t.OrderSequence); r != nil {
			m.log.Info("takeover voided", "session_id", t.SessionID, "order_sequence", t.OrderSequence, "reason", t.Reason)
			m.end(r, codeVoided, true)
		}
	}
}

// onBlock resolves again the takeovers due: registered ones whose activation height the head
// reached (their binding event may have been missed) and those a chain read left unresolved.
func (m *Manager) onBlock() {
	head := m.head.Load()
	type due struct {
		session string
		seq     uint64
	}
	var dues []due
	m.mu.Lock()
	for _, r := range m.records {
		if !r.busy && (r.retry || r.Phase == phaseRegistered && r.ActivationHeight != 0 && r.ActivationHeight <= head) {
			dues = append(dues, due{r.SessionID, r.Sequence})
		}
	}
	m.mu.Unlock()
	for _, d := range dues {
		m.later(func(ctx context.Context) { m.resolve(ctx, d.session, d.seq, false) })
	}
}

// resolve reads the session and acts on it: bound here, the takeover took effect and the order
// is dispatched; a takeover of this Builder for the sequence registered, it waits for the
// activation height; neither, the registration was voided (or, lapsed, the order expired before
// it registered). An unreadable chain is tried again at the next block.
func (m *Manager) resolve(ctx context.Context, sessionID string, seq uint64, lapsed bool) {
	r := m.take(sessionID, seq)
	if r == nil {
		return
	}
	state, err := m.cfg.Chain.QuerySession(ctx, sessionID)
	if err != nil {
		m.log.Warn("held session not read; tried again at the next block", "session_id", sessionID, "err", err)
		m.untake(r, true)
		return
	}
	switch t := state.PendingTakeover; {
	case state.BoundBuilder == m.cfg.Builder:
		m.activate(ctx, r, state.BoundChangeHeight)
	case t != nil && t.CandidateBuilder == m.cfg.Builder && t.OrderSequence == r.Sequence:
		m.untake(r, false)
		m.registered(sessionID, seq, t.ActivationHeight)
	case lapsed && r.Phase == phaseSubmitted:
		m.end(r, codeExpired, false)
	default:
		m.log.Info("takeover will not take effect", "session_id", sessionID, "order_sequence", seq, "bound_builder", state.BoundBuilder)
		m.end(r, codeVoided, true)
	}
}

// registered records the activation height of this Builder's registered takeover of the
// session's sequence.
func (m *Manager) registered(sessionID string, seq, activation uint64) {
	m.mu.Lock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq || r.Phase == phaseRegistered && r.ActivationHeight == activation {
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
// ORDER_EXPIRED; one the precheck refuses otherwise as TASK_FAILED. A precheck without a verdict
// (state unreadable, or the cached state not bound here yet) is tried again at the next block.
// The caller took r.
func (m *Manager) activate(ctx context.Context, r *record, boundChange uint64) {
	pre := r.Precheck
	pre.Takeover = true
	res, err := m.cfg.Precheck.Reserve(ctx, pre)
	switch {
	case errors.Is(err, inflight.ErrUnavailable), errors.Is(err, inflight.ErrOrderUploading),
		err == nil && res.Binding != inflight.BoundHere:
		m.log.Info("taken over order not prechecked yet; tried again at the next block", "session_id", r.SessionID, "err", err)
		m.untake(r, true)
		return
	case err != nil:
		m.cfg.Tasks.TakeoverActivated(r.SessionID, r.TaskID, boundChange)
		code := codeTaskFailed
		if errors.Is(err, inflight.ErrOrderExpired) {
			code = codeExpired
		}
		m.log.Info("taken over order not dispatched", "session_id", r.SessionID, "order_sequence", r.Sequence, "err", err)
		m.end(r, code, false)
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
			m.end(r, codeTaskFailed, false)
			return
		}
	}
	m.log.Info("takeover took effect; order dispatched", "session_id", r.SessionID, "order_sequence", r.Sequence, "bound_change_height", boundChange)
	m.forget(r)
}

// end drops r, telling its task code.
func (m *Manager) end(r *record, code string, dropInput bool) {
	m.forget(r)
	m.cfg.Tasks.TakeoverEnded(r.SessionID, r.TaskID, code, m.head.Load(), dropInput)
}

// take marks the session's takeover of seq busy and returns it; nil when there is none past its
// upload, or it is busy.
func (m *Manager) take(sessionID string, seq uint64) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq || r.busy {
		return nil
	}
	r.busy, r.retry = true, false
	return r
}

// untake ends what take started; retry asks for another try at the next block.
func (m *Manager) untake(r *record, retry bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.busy, r.retry = false, retry
}

func (m *Manager) lookup(sessionID string) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[sessionID]; r != nil && r.Phase != phaseReserved {
		return r
	}
	return nil
}
