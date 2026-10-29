package coordinator

import (
	"context"
	"strings"

	"github.com/TrueOpen/nexus/internal/types"
)

// OnTakeover starts the task of an order this Builder holds while a takeover of its session is
// registered (ORDER_RECEIVED). The order is not dispatched: once the takeover took effect,
// OnOrder hands it to the dispatcher on the same task. The same order again changes nothing.
func (c *Coordinator) OnTakeover(_ context.Context, o types.Order) error {
	key := taskKey(o.SessionID, o.TaskID)
	o.Payload = nil
	c.mu.Lock()
	fsm, exists := c.tasks[key]
	if exists && fsm.order.TaskHash != o.TaskHash {
		// Another version failed before; this order replaces it.
		c.mu.Unlock()
		c.abandonTask(key, fsm)
		c.mu.Lock()
		fsm, exists = c.tasks[key]
	}
	if exists {
		c.mu.Unlock()
		return nil
	}
	fsm = c.newFSM(o)
	c.tasks[key] = fsm
	c.mu.Unlock()
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
	return nil
}

// TakeoverRegistered reports that the chain registered the takeover the task's order was held
// for; it takes effect at activation (TAKEOVER_PENDING with chain_height = activation).
func (c *Coordinator) TakeoverRegistered(sessionID, taskID string, activation uint64) {
	c.takeoverEvent(sessionID, taskID, EvTakeoverPending, activation)
}

// TakeoverActivated reports that the takeover took effect at height (TAKEOVER_RECORDED); OnOrder
// follows with the order.
func (c *Coordinator) TakeoverActivated(sessionID, taskID string, height uint64) {
	c.takeoverEvent(sessionID, taskID, EvTakeoverRecorded, height)
}

func (c *Coordinator) takeoverEvent(sessionID, taskID, code string, height uint64) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	fsm.mu.Lock()
	fsm.emit(code, int64(height))
	if err := fsm.save(); err != nil {
		c.log.Warn("takeover event not saved", "session_id", sessionID, "task_id", taskID, "code", code, "err", err)
	}
	fsm.mu.Unlock()
}

// TakeoverEnded drops the task of a held order whose takeover will not dispatch it, with code
// (TAKEOVER_VOIDED, ORDER_EXPIRED, or the refusal) and where, when known, where the session went;
// its journal stays. dropInput removes the order's input as well: a voided takeover leaves
// nothing for a resend here.
func (c *Coordinator) TakeoverEnded(sessionID, taskID, code string, height uint64, dropInput bool, where *types.SessionElsewhere) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return
	}
	if !fsm.failPendingElsewhere(code, types.VerdictUnspecified, height, where) {
		return
	}
	c.abandonTask(taskKey(sessionID, taskID), fsm)
	if dropInput {
		c.deletePayload(orderInput(fsm.order))
	}
	c.log.Info("takeover ended", "session_id", sessionID, "task_id", taskID, "code", code)
}

// takeoverStage is the latest takeover event of a pending task, the stage GetTaskStatus reports;
// empty for an ordinary order.
func (c *Coordinator) takeoverStage(sessionID, taskID string) string {
	c.jmu.Lock()
	j, ok := c.journals[taskKey(sessionID, taskID)]
	c.jmu.Unlock()
	if !ok {
		return ""
	}
	events := j.snapshot()
	for i := len(events) - 1; i >= 0; i-- {
		if strings.HasPrefix(events[i].EventCode, "TAKEOVER_") {
			return events[i].EventCode
		}
	}
	return ""
}
