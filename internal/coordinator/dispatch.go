package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/taskgroup"
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
	if !ok || a.SessionID != sessionID {
		return
	}
	if a.Status == attempt.Recorded {
		// The chain holds this attempt: its output is not dropped, the attempt only expires.
		c.expireAttempt(taskID)
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
		// ORDER_RECEIVED does not wait for the disk: the dispatcher commits the order with a
		// synced write before any ticket goes out, which makes the snapshot durable first. A crash
		// before that commit loses both, and the order with them.
		fsm.mu.Lock()
		fsm.emit(EvOrderReceived, 0)
		err := fsm.saveDeferred()
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
// stored: no dispatcher; no current BuilderSet snapshot known (ErrDispatchUnavailable); an order
// whose builder_set_id/hash is not the current snapshot even after this Builder read it again
// (taskgroup.ErrBuilderSetStale: the user re-signs the same sequence against the current one, no
// takeover); or no Worker can take it now.
func (c *Coordinator) CheckOrder(ctx context.Context, o types.Order) error {
	if c.dispatcher == nil {
		return ErrDispatchUnavailable
	}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(o.SignedOrder, &signed); err != nil {
		return fmt.Errorf("check order: signed order does not decode: %w", err)
	}
	err := c.checkBuilderSet(ctx, signed.GetOrder())
	if err == nil {
		err = c.dispatcher.Probe(ctx, o)
	}
	if err != nil {
		c.log.Info("order refused before input upload", "session_id", o.SessionID, "task_id", o.TaskID,
			"model_id", hex.EncodeToString(signed.GetOrder().GetModelId()), "profile_version", signed.GetOrder().GetProfileVersion(), "err", err)
	}
	return err
}

const (
	// builderSetRefreshInterval is how long after a BuilderSet read, failed or not, a stale order
	// causes no other one.
	builderSetRefreshInterval = time.Second
	// builderSetRefreshTimeout bounds the BuilderSet read a stale order waits for.
	builderSetRefreshTimeout = 2 * time.Second
)

// errBuilderSetRefreshBusy refuses, as retryable, a stale order that cannot cause a BuilderSet read
// now: one runs, or the last was attempted less than builderSetRefreshInterval ago.
var errBuilderSetRefreshBusy = errors.New("the current BuilderSet was read too recently or is being read")

// checkBuilderSet checks the order names the current BuilderSet snapshot (taskgroup.CheckOrder).
// An order naming another one may mean this Builder's view is the one behind, so before the order
// is called stale the BuilderSet is read from the chain again (refreshBuilderSet) and the order
// checked once more: only an order whose snapshot is still not the current one after that read is
// taskgroup.ErrBuilderSetStale. No snapshot known, or no read that could be made or that succeeded,
// is ErrDispatchUnavailable (retryable): an order is never called stale from a view older than the
// request.
func (c *Coordinator) checkBuilderSet(ctx context.Context, order *taskv1.TaskOrderV3) error {
	_, err := taskgroup.CheckOrder(c, order)
	if errors.Is(err, taskgroup.ErrBuilderSetStale) {
		if refreshErr := c.refreshBuilderSet(ctx); refreshErr != nil {
			return fmt.Errorf("%w: the order names another BuilderSet and the current one could not be read again: %v", ErrDispatchUnavailable, refreshErr)
		}
		_, err = taskgroup.CheckOrder(c, order)
	}
	if errors.Is(err, taskgroup.ErrNoSnapshot) {
		return fmt.Errorf("%w: %w", ErrDispatchUnavailable, err)
	}
	return err
}

// refreshBuilderSet reads the current BuilderSet from the chain within builderSetRefreshTimeout.
// It never waits for another caller: while a read runs, or less than builderSetRefreshInterval
// after the last attempt, failed or not, it returns errBuilderSetRefreshBusy at once.
func (c *Coordinator) refreshBuilderSet(ctx context.Context) error {
	if !c.builderSetRefresh.TryLock() {
		return errBuilderSetRefreshBusy
	}
	defer c.builderSetRefresh.Unlock()
	if !c.builderSetRefreshedAt.IsZero() && time.Since(c.builderSetRefreshedAt) < builderSetRefreshInterval {
		return errBuilderSetRefreshBusy
	}
	c.builderSetRefreshedAt = time.Now()
	ctx, cancel := context.WithTimeout(ctx, builderSetRefreshTimeout)
	defer cancel()
	return c.seedBuilderSet(ctx)
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
func (c *Coordinator) DispatchAccepted(sessionID, taskID string, ticket [32]byte, worker string) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	fsm.mu.Lock()
	fsm.emitDetail(EvDispatchAccepted, 0, &types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket[:]), WorkerOperatorAddress: worker})
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
	var detail *types.TaskEventDetail
	switch {
	case errors.Is(reason, dispatchdraw.ErrNoCapacity):
		code = EvNoCapacity
	case errors.Is(reason, dispatcher.ErrRecordRejected):
		// An earlier order of the session cannot be recorded, so neither can this one. Its
		// sequence was not consumed and is resent as it is: CONFLICT, the category the Recorder
		// gives the later entries of a refused one, never SEQUENCE_CONSUMED.
		code, detail = EvRecordRejected, c.recordRejection(sessionID, taskID, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_CONFLICT)
	case errors.Is(reason, dispatcher.ErrRecordDeadline):
		code, detail = EvRecordRejected, c.recordRejection(sessionID, taskID, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE)
	}
	fsm.mu.Lock()
	fsm.emitDetail(code, 0, detail)
	fsm.mu.Unlock()
	c.abandonTask(key, fsm)
	c.log.Info("dispatch failed", "session_id", sessionID, "task_id", taskID, "reason", reason)
}

// DispatchRecorded is the Recorder's report that the chain admitted the task's dispatch entry at
// height: the task is reconciled with the chain, which moves it to Assigned (DISPATCH_RECORDED).
func (c *Coordinator) DispatchRecorded(sessionID, taskID string, height uint64) {
	c.requestTaskReconcile(sessionID, taskID, int64(height), "dispatch recorded")
}

// RecordRejected is the Recorder's report that the chain refused the dispatch entry of the task's
// ticket with code, or did not record it by its deadline (RECORD_REJECTED). The task is dropped
// like a failed dispatch: its journal and input stay for a resend of the sequence.
func (c *Coordinator) RecordRejected(sessionID, taskID string, ticket [32]byte, code taskv1.DispatchRejectCodeV1) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	height, _ := c.currentChainHeight()
	c.failRecord(fsm, height, &types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket[:]), RejectCode: RejectCategory(code)})
	c.log.Info("dispatch record rejected", "session_id", sessionID, "task_id", taskID, "reject_code", code)
}

// failRecord ends a Pending task whose dispatch entry will not be recorded.
func (c *Coordinator) failRecord(fsm *taskFSM, height uint64, detail *types.TaskEventDetail) {
	if fsm.failPendingDetail(EvRecordRejected, types.VerdictUnspecified, height, detail) {
		c.abandonTask(taskKey(fsm.sessionID, fsm.taskID), fsm)
	}
}

// RejectCategory is the RECORD_REJECTED rejection category of a refusal with code. The event always
// names a nonzero category: a refusal that came without a code is CONFLICT.
func RejectCategory(code taskv1.DispatchRejectCodeV1) int32 {
	if code == taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_UNSPECIFIED {
		return int32(taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_CONFLICT)
	}
	return int32(code)
}

// recordRejection is the RECORD_REJECTED detail of a task with code: with the ticket of its
// attempt when it has one.
func (c *Coordinator) recordRejection(sessionID, taskID string, code taskv1.DispatchRejectCodeV1) *types.TaskEventDetail {
	detail := &types.TaskEventDetail{RejectCode: RejectCategory(code)}
	if c.attempts != nil {
		if a, ok := c.attempts.Current(taskID); ok && a.SessionID == sessionID {
			detail.DispatchTicketHash = hex.EncodeToString(a.TicketHash[:])
		}
	}
	return detail
}
