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

// cause is why a takeover is resolved with the chain.
type cause uint8

const (
	// resolveCheck: an event, a block or a restart; a submitted entry waits for its result.
	resolveCheck cause = iota + 1
	// resolveRegistered: the entry's result says the chain registered it.
	resolveRegistered
	// resolveLapsed: the entry got no result before the order expired.
	resolveLapsed
)

// TakeoverRegistered implements recorder.Takeovers: the chain registered the takeover (or
// answered its replay); the session state gives the activation height.
func (m *Manager) TakeoverRegistered(sessionID string, sequence, _ uint64) {
	m.schedule(sessionID, sequence, resolveRegistered)
}

// TakeoverRefused implements recorder.Takeovers. Refused because the sequence is consumed (the
// bound Builder recorded it, or it was cancelled) or because another takeover is registered, the
// takeover is voided: the order and its input are dropped and the SDK goes where the chain says.
// Any other refusal ends the task as RECORD_REJECTED.
func (m *Manager) TakeoverRefused(sessionID string, sequence uint64, code taskv1.DispatchRejectCodeV1) {
	m.work.Lock()
	defer m.work.Unlock()
	r := m.current(sessionID, sequence)
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
	m.schedule(sessionID, sequence, resolveLapsed)
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
			m.schedule(t.SessionID, r.Sequence, resolveCheck)
		}
	case chaincli.SessionTakeoverVoided:
		if t.CandidateBuilder != m.cfg.Builder {
			return
		}
		m.work.Lock()
		defer m.work.Unlock()
		if r := m.current(t.SessionID, t.OrderSequence); r != nil {
			m.log.Info("takeover voided", "session_id", t.SessionID, "order_sequence", t.OrderSequence, "reason", t.Reason)
			m.end(r, codeVoided, true)
		}
	}
}

// onBlock resolves again the takeovers due: registered ones whose activation height the head
// reached (their binding event may have been missed) and those a chain read left unresolved.
func (m *Manager) onBlock() {
	head := m.head.Load()
	m.mu.Lock()
	var due []*record
	for _, r := range m.records {
		if r.Phase != phaseReserved && (r.retry || r.Phase == phaseRegistered && r.ActivationHeight != 0 && r.ActivationHeight <= head) {
			due = append(due, r)
		}
	}
	m.mu.Unlock()
	for _, r := range due {
		m.schedule(r.SessionID, r.Sequence, resolveCheck)
	}
}

// schedule resolves the session's takeover of seq in the background, unless a check of it is
// queued already. A result or a lapse is always scheduled: it decides a submitted entry.
func (m *Manager) schedule(sessionID string, seq uint64, why cause) {
	m.mu.Lock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq || why == resolveCheck && r.queued {
		m.mu.Unlock()
		return
	}
	if why == resolveCheck {
		r.queued = true
	}
	m.mu.Unlock()
	m.later(func(ctx context.Context) { m.resolve(ctx, sessionID, seq, why) })
}

// resolve reads the session and acts on it: bound here, the takeover took effect and the order
// is dispatched; a takeover of this Builder for the sequence registered, it waits for the
// activation height. Neither: a registered takeover was voided; an entry that lapsed never
// registered before the order expired; a submitted entry waits for its result. An unreadable
// chain is tried again at the next block.
func (m *Manager) resolve(ctx context.Context, sessionID string, seq uint64, why cause) {
	m.work.Lock()
	defer m.work.Unlock()
	r := m.current(sessionID, seq)
	if r == nil {
		return
	}
	m.mu.Lock()
	if why == resolveCheck {
		r.queued = false
	}
	r.retry = false
	m.mu.Unlock()
	if why == resolveRegistered && r.Phase == phaseSubmitted {
		m.setPhase(r, phaseRegistered)
	}
	state, err := m.cfg.Chain.QuerySession(ctx, sessionID)
	if err != nil {
		m.log.Warn("held session not read; tried again at the next block", "session_id", sessionID, "err", err)
		m.setRetry(r)
		return
	}
	switch t := state.PendingTakeover; {
	case state.BoundBuilder == m.cfg.Builder:
		m.activate(ctx, r, state.BoundChangeHeight)
	case t != nil && t.CandidateBuilder == m.cfg.Builder && t.OrderSequence == r.Sequence:
		m.registered(sessionID, seq, t.ActivationHeight)
	case r.Phase == phaseSubmitted && why == resolveLapsed:
		m.end(r, codeExpired, false)
	case r.Phase == phaseSubmitted:
		// Not registered yet: the entry's result decides.
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
// The caller holds m.work.
func (m *Manager) activate(ctx context.Context, r *record, boundChange uint64) {
	pre := r.Precheck
	pre.Takeover = true
	res, err := m.cfg.Precheck.Reserve(ctx, pre)
	switch {
	case errors.Is(err, inflight.ErrUnavailable), errors.Is(err, inflight.ErrOrderUploading),
		err == nil && res.Binding != inflight.BoundHere:
		m.log.Info("taken over order not prechecked yet; tried again at the next block", "session_id", r.SessionID, "err", err)
		m.setRetry(r)
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
	m.cfg.Tasks.TakeoverEnded(r.SessionID, r.TaskID, code, m.head.Load(), dropInput, nil)
}

// current returns the session's stored takeover of seq; nil when there is none past its upload.
func (m *Manager) current(sessionID string, seq uint64) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != seq {
		return nil
	}
	return r
}

func (m *Manager) lookup(sessionID string) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[sessionID]; r != nil && r.Phase != phaseReserved {
		return r
	}
	return nil
}

func (m *Manager) setRetry(r *record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.retry = true
}

func (m *Manager) setPhase(r *record, p phase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Phase = p
	if err := m.saveLocked(r); err != nil {
		m.log.Error("takeover phase not written", "session_id", r.SessionID, "err", err)
	}
}

// TakeoverUnsettled implements recorder.Takeovers: the entry's result could not be attributed
// and the entry was dropped; the session state settles the takeover.
func (m *Manager) TakeoverUnsettled(sessionID string, sequence uint64) {
	m.schedule(sessionID, sequence, resolveLapsed)
}
