package coordinator

import (
	"context"
	"errors"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
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
	// DispatchResult returns the signed result header of an accepted, unrecorded order.
	DispatchResult(sessionID, taskID string) (*nexusv1.DispatchResultHeaderV1, bool)
	// RecordDeadline returns the last height the order of (session, sequence) can be recorded at.
	RecordDeadline(sessionID string, sequence uint64) (uint64, bool)
}

// SetDispatcher wires direct dispatch in; call it before Start. Without it every new order is
// refused with ErrDispatchUnavailable.
func (c *Coordinator) SetDispatcher(d Dispatcher) { c.dispatcher = d }

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

// DispatchResult returns the signed dispatch result header of an accepted, unrecorded order.
func (c *Coordinator) DispatchResult(_ context.Context, sessionID, taskID string) (*nexusv1.DispatchResultHeaderV1, bool) {
	if c.dispatcher == nil {
		return nil, false
	}
	return c.dispatcher.DispatchResult(sessionID, taskID)
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
// (NO_CAPACITY; RECORD_REJECTED when an earlier order of the session was not recorded; TASK_FAILED
// for any other reason). The task is dropped; its journal stays so the user sees why, and a retry
// of the sequence starts a new task on it. Its input stays for that retry.
func (c *Coordinator) DispatchFailed(sessionID, taskID string, reason error) {
	key := taskKey(sessionID, taskID)
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	code := EvTaskFailed
	switch {
	case errors.Is(reason, dispatchdraw.ErrNoCapacity):
		code = EvNoCapacity
	case errors.Is(reason, dispatcher.ErrRecordRejected):
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
	if fsm.failPending(EvRecordRejected, height) {
		c.abandonTask(taskKey(fsm.sessionID, fsm.taskID), fsm)
	}
}
