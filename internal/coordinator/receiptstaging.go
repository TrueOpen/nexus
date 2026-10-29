package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// Receipt staging: a winner may finish and sign its InferReceipt before this Builder's dispatch
// entry is recorded. The chain has no task for it then, so the receipt is kept in
// kv.NSReceiptStaging and relayed through the normal path once the chain shows the task recorded;
// a refused record drops it with the task. The Worker sees relay_accepted either way.

// checkReceiptAttempt requires the receipt to name the task's live winning attempt: its
// dispatch_ticket_hash, worker and task_hash.
func (c *Coordinator) checkReceiptAttempt(receipt types.InferReceiptSubmission) error {
	a, ok := c.attempts.Current(receipt.TaskID)
	switch {
	case !ok || a.SessionID != receipt.SessionID:
		return fmt.Errorf("%w: no dispatch attempt of this task is held", types.ErrInvalidArgument)
	case !a.Live():
		return fmt.Errorf("%w: the dispatch record of ticket %x was refused", types.ErrInvalidArgument, a.TicketHash)
	case !bytes.Equal(receipt.DispatchTicketHash, a.TicketHash[:]):
		return fmt.Errorf("%w: dispatch_ticket_hash is not the winner ticket", types.ErrInvalidArgument)
	case receipt.WorkerAddress != a.Worker || receipt.TaskHash != a.TaskHash:
		return fmt.Errorf("%w: receipt worker or task_hash is not the winning attempt's", types.ErrInvalidArgument)
	}
	return nil
}

// stageInferReceipt keeps the receipt while the task waits for its dispatch record and reports
// whether it did. The same receipt again is idempotent; another receipt of the same ticket is a
// conflict. The decision is taken under the task lock, so a receipt is either staged before the
// task becomes Assigned (and released after) or goes the normal way.
func (f *taskFSM) stageInferReceipt(store kv.Store, receipt types.InferReceiptSubmission) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != types.Pending {
		return false, nil
	}
	key := taskKey(f.sessionID, f.taskID)
	if raw, found := store.Get(kv.NSReceiptStaging, key); found {
		var staged types.InferReceiptSubmission
		if err := json.Unmarshal(raw, &staged); err == nil && bytes.Equal(staged.DispatchTicketHash, receipt.DispatchTicketHash) {
			if reflect.DeepEqual(staged, receipt) {
				return true, nil
			}
			return false, fmt.Errorf("%w: conflicting infer receipt", types.ErrInvalidArgument)
		}
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return false, fmt.Errorf("encode staged infer receipt: %w", err)
	}
	if err := store.Set(kv.NSReceiptStaging, key, raw); err != nil {
		return false, fmt.Errorf("stage infer receipt: %w", err)
	}
	f.log.Info("infer receipt staged until the dispatch is recorded", "task_id", f.taskID, "worker", receipt.WorkerAddress)
	return true, nil
}

// releaseStagedReceipt relays the receipt staged for a task the chain now shows recorded. A receipt
// the normal path refuses as invalid is dropped; one it cannot take now stays for the next
// reconcile.
func (c *Coordinator) releaseStagedReceipt(fsm *taskFSM) {
	key := taskKey(fsm.sessionID, fsm.taskID)
	raw, found := c.kv.Get(kv.NSReceiptStaging, key)
	if !found {
		return
	}
	var receipt types.InferReceiptSubmission
	if err := json.Unmarshal(raw, &receipt); err != nil {
		c.log.Error("staged infer receipt unreadable; dropped", "task_id", fsm.taskID, "err", err)
		c.dropStagedReceipt(key)
		return
	}
	err := c.OnInferReceipt(context.Background(), receipt)
	switch {
	case err == nil:
		c.log.Info("staged infer receipt relayed after the dispatch record", "task_id", fsm.taskID)
	case errors.Is(err, types.ErrInvalidArgument) || errors.Is(err, types.ErrUnauthorized):
		c.log.Warn("staged infer receipt refused after the dispatch record; dropped", "task_id", fsm.taskID, "err", err)
	default:
		c.log.Warn("staged infer receipt not relayed yet", "task_id", fsm.taskID, "err", err)
		return
	}
	c.dropStagedReceipt(key)
}

func (c *Coordinator) dropStagedReceipt(key string) {
	if err := c.kv.Delete(kv.NSReceiptStaging, key); err != nil {
		c.log.Warn("staged infer receipt not deleted", "key", key, "err", err)
	}
}
