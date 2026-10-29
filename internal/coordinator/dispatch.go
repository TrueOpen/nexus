package coordinator

import (
	"context"
	"errors"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/types"
)

// ErrDispatchUnavailable refuses new orders on a Builder without direct dispatch configured (no
// service key or no VRF key): it accepts none rather than one it cannot run. It is the
// dispatcher's sentinel, so a refusal from either maps alike.
var ErrDispatchUnavailable = dispatcher.ErrDispatchUnavailable

// Dispatcher dispatches the orders the in-flight precheck reserved (package dispatcher). Which
// version of an order may be dispatched, retried or is locked is the precheck's decision.
type Dispatcher interface {
	// Probe refuses, before the input is stored, an order no Worker can take now.
	Probe(ctx context.Context, o types.Order) error
	// Dispatch takes over a reserved order and walks it in the background.
	Dispatch(ctx context.Context, o types.Order) error
	// RecordDeadline returns the last height the order of (session, sequence) can be recorded at.
	RecordDeadline(sessionID string, sequence uint64) (uint64, bool)
}

// SetDispatcher wires direct dispatch in; call it before Start. Without it every new order is
// refused with ErrDispatchUnavailable.
func (c *Coordinator) SetDispatcher(d Dispatcher) { c.dispatcher = d }

// SetAttempts wires the book of winning dispatch attempts in; call it before Start.
func (c *Coordinator) SetAttempts(b *attempt.Book) { c.attempts = b }

// defaultAttemptRetentionBlocks is how long the attempt of a terminal or dropped task is kept
// when no retention is set.
const defaultAttemptRetentionBlocks = 120960

// SetAttemptRetention sets how many blocks the attempt of a terminal or dropped task is kept
// (its header served to late subscribers) before the book forgets it; 0 keeps the default.
func (c *Coordinator) SetAttemptRetention(blocks uint64) { c.attemptRetention = blocks }

// expireAttempt has the book forget the task's attempt after the retention.
func (c *Coordinator) expireAttempt(taskID string) {
	retention := c.attemptRetention
	if retention == 0 {
		retention = defaultAttemptRetentionBlocks
	}
	height, _ := c.currentChainHeight()
	c.attempts.ExpireAt(taskID, height+retention)
}

// endAttemptOfTerminalTask closes the uploads of a terminal task's attempt and has it expire.
func (c *Coordinator) endAttemptOfTerminalTask(sessionID, taskID string) {
	if c.attempts == nil {
		return
	}
	if a, ok := c.attempts.Current(taskID); !ok || a.SessionID != sessionID {
		return
	}
	c.attempts.CloseUploads(taskID)
	c.expireAttempt(taskID)
}

// retireAbandonedAttempt drops the output stream of a dropped task's attempt that was never
// recorded and has the attempt expire; its REJECTED header is served until then.
func (c *Coordinator) retireAbandonedAttempt(sessionID, taskID string) {
	if c.attempts == nil {
		return
	}
	a, ok := c.attempts.Current(taskID)
	if !ok || a.SessionID != sessionID || a.Status == attempt.Recorded {
		return
	}
	if c.payloads != nil {
		if err := c.payloads.RetireOutput(context.Background(), sessionID, taskID, a.TicketHash[:]); err != nil {
			c.log.Warn("abandoned attempt output not retired", "task_id", taskID, "err", err)
		}
	}
	c.expireAttempt(taskID)
}

// limitAttemptUploads bounds the recorded attempt's uploads by the task's infer deadline.
func (c *Coordinator) limitAttemptUploads(sessionID, taskID string, inferDeadline uint64) {
	if c.attempts == nil || inferDeadline == 0 {
		return
	}
	if a, ok := c.attempts.Current(taskID); ok && a.SessionID == sessionID && a.Status == attempt.Recorded {
		c.attempts.LimitUploads(taskID, a.TicketHash, inferDeadline)
	}
}

// OnOrder implements the ingress order entry (called by IngressAPI after the precheck reserved the
// order and its input is stored): the task's state machine starts (ORDER_RECEIVED) and the order
// goes to the dispatcher. A retry of an order whose earlier attempt failed reuses the task's
// event journal.
func (c *Coordinator) OnOrder(ctx context.Context, o types.Order) error {
	if c.dispatcher == nil {
		return ErrDispatchUnavailable
	}
	key := taskKey(o.SessionID, o.TaskID)
	o.Payload = nil
	c.mu.Lock()
	fsm, exists := c.tasks[key]
	if exists && fsm.order.TaskHash != o.TaskHash {
		// The precheck admitted another version: the tracked one failed (after a restart the
		// dispatcher no longer reports it), and this is its retry.
		c.mu.Unlock()
		c.abandonTask(key, fsm)
		c.mu.Lock()
		fsm, exists = c.tasks[key]
	}
	if !exists {
		fsm = c.newFSM(o)
		c.tasks[key] = fsm
	}
	c.mu.Unlock()
	if !exists {
		if err := c.trackTaskEvents(key, fsm); err != nil {
			c.abandonTask(key, fsm)
			return err
		}
		fsm.mu.Lock()
		fsm.emit(EvOrderReceived, 0)
		err := fsm.save()
		fsm.mu.Unlock()
		if err != nil {
			c.abandonTask(key, fsm)
			return err
		}
	}
	if err := c.dispatcher.Dispatch(ctx, o); err != nil {
		if !exists {
			c.abandonTask(key, fsm)
		}
		return err
	}
	return nil
}

// CheckOrder refuses, without changing any state, an order OnOrder would refuse before its input is
// stored: no dispatcher, or no Worker can take it now.
func (c *Coordinator) CheckOrder(ctx context.Context, o types.Order) error {
	if c.dispatcher == nil {
		return ErrDispatchUnavailable
	}
	if err := c.dispatcher.Probe(ctx, o); err != nil {
		c.log.Info("order refused before input upload", "session_id", o.SessionID, "task_id", o.TaskID, "err", err)
		return err
	}
	return nil
}

// DispatchResult returns the signed dispatch result header of the task's winning attempt at its
// current record status.
func (c *Coordinator) DispatchResult(_ context.Context, sessionID, taskID string) (*nexusv1.DispatchResultHeaderV1, bool) {
	if c.attempts == nil {
		return nil, false
	}
	a, ok := c.attempts.Current(taskID)
	if !ok || a.SessionID != sessionID {
		return nil, false
	}
	header, err := a.ResultHeader()
	if err != nil {
		c.log.Error("stored dispatch result header unreadable", "task_id", taskID, "err", err)
		return nil, false
	}
	return header, true
}

// DispatchAccepted implements dispatcher.Observer: a Worker accepted the order (DISPATCH_ACCEPTED).
// The task stays Pending until the chain records the dispatch.
func (c *Coordinator) DispatchAccepted(sessionID, taskID string, _ [32]byte, worker string) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	fsm.mu.Lock()
	fsm.emit(EvDispatchAccepted, 0)
	fsm.save()
	fsm.mu.Unlock()
	c.log.Info("dispatch accepted", "session_id", sessionID, "task_id", taskID, "worker", worker)
}

// DispatchFailed implements dispatcher.Observer: the order's attempt ended without a winner
// (NO_CAPACITY; RECORD_REJECTED when it or an earlier order of the session cannot be recorded by
// its deadline; TASK_FAILED for any other reason). The task is dropped; its journal stays so the user sees why, and a retry
// of the sequence starts a new task on it. Its input stays for that retry.
func (c *Coordinator) DispatchFailed(sessionID, taskID string, reason error) {
	key := taskKey(sessionID, taskID)
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	if c.attempts != nil {
		if a, ok := c.attempts.Current(taskID); ok && a.SessionID == sessionID && a.Status == attempt.Recorded {
			// The chain recorded the task (a voided winner whose record landed after all): it is
			// assigned, not failed. The chain's state decides it.
			c.log.Warn("dispatch failure of a recorded task ignored; reconciling", "session_id", sessionID, "task_id", taskID, "reason", reason)
			c.requestTaskReconcile(sessionID, taskID, 0, "dispatch failed after the record")
			return
		}
	}
	code := EvTaskFailed
	switch {
	case errors.Is(reason, dispatchdraw.ErrNoCapacity):
		code = EvNoCapacity
	case errors.Is(reason, dispatcher.ErrRecordRejected), errors.Is(reason, dispatcher.ErrRecordDeadline):
		code = EvRecordRejected
	}
	fsm.mu.Lock()
	fsm.emit(code, 0)
	fsm.mu.Unlock()
	c.abandonTask(key, fsm)
	c.log.Info("dispatch failed", "session_id", sessionID, "task_id", taskID, "reason", reason)
}

// DispatchRecorded is the Recorder's report that the chain admitted the task's dispatch entry at
// height: the task is reconciled with the chain, which moves it to Assigned (DISPATCH_RECORDED).
func (c *Coordinator) DispatchRecorded(sessionID, taskID string, height uint64) {
	c.requestTaskReconcile(sessionID, taskID, int64(height), "dispatch recorded")
}

// RecordRejected is the Recorder's report that the chain refused the task's dispatch entry with
// code, or did not record it by its deadline (RECORD_REJECTED). The task is dropped like a failed
// dispatch: its journal and input stay for a resend of the sequence.
func (c *Coordinator) RecordRejected(sessionID, taskID string, code taskv1.DispatchRejectCodeV1) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	height, _ := c.currentChainHeight()
	c.failRecord(fsm, height)
	c.log.Info("dispatch record rejected", "session_id", sessionID, "task_id", taskID, "reject_code", code)
}

// failRecord ends a Pending task whose dispatch entry will not be recorded.
func (c *Coordinator) failRecord(fsm *taskFSM, height uint64) {
	if fsm.failPending(EvRecordRejected, types.VerdictUnspecified, height) {
		c.abandonTask(taskKey(fsm.sessionID, fsm.taskID), fsm)
	}
}
