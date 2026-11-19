package coordinator

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

// An order this Builder acknowledged can end before it reaches the chain: no Worker took it
// (NO_CAPACITY), the chain will not record its dispatch (RECORD_REJECTED), it expired
// (ASSIGN_TIMEOUT) or the takeover it was held for ended. The task is then dropped, and the
// terminal event is the only answer the user gets after the OpenTask ack. An abandoned task record
// keeps the owner, phase and journal of such a task for a while, so a signed GetTaskEvents or
// GetTaskStatus still reads that answer, also after a restart. It is a local record for the user
// and no chain decision reads it.

const abandonedTaskVersion = 1

// DefaultAbandonedTaskRetention is how long an abandoned task record is kept unless
// SetAbandonedTaskRetention sets another value.
const DefaultAbandonedTaskRetention = 24 * time.Hour

// abandonedTaskSweepInterval is how often expired abandoned task records are removed.
const abandonedTaskSweepInterval = 10 * time.Minute

// abandonedTaskRecord is the NSAbandonedTask value, keyed by session_id|task_id.
type abandonedTaskRecord struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"`
	// Phase is the task phase when the task was dropped, the task_phase GetTaskStatus reports.
	Phase   string            `json:"phase"`
	Journal []types.TaskEvent `json:"journal"`
	// AbandonedAt is the wall time the task was dropped, in Unix seconds.
	AbandonedAt int64 `json:"abandoned_at"`
}

// SetAbandonedTaskRetention sets how long an abandoned task record is kept; call it before Start.
// A value that is not positive keeps the default.
func (c *Coordinator) SetAbandonedTaskRetention(retention time.Duration) {
	if retention > 0 {
		c.abandonedRetention = retention
	}
}

// abandonFailedTask drops a task that ended before it reached the chain with a terminal event the
// user must still be able to read, and keeps its abandoned task record.
func (c *Coordinator) abandonFailedTask(key string, expected *taskFSM) {
	c.dropTask(key, expected, true)
}

// abandonedRecordOp returns the write that stores the abandoned task record of fsm, and the
// record's time; ok is false when the record cannot be encoded.
func (c *Coordinator) abandonedRecordOp(key string, fsm *taskFSM) (kv.WriteOp, int64, bool) {
	fsm.mu.Lock()
	recipient := fsm.user
	phase := fsm.phase.String()
	fsm.mu.Unlock()
	at := c.now().Unix()
	raw, err := json.Marshal(abandonedTaskRecord{
		Version:     abandonedTaskVersion,
		Recipient:   recipient,
		Phase:       phase,
		Journal:     fsm.events.snapshot(),
		AbandonedAt: at,
	})
	if err != nil {
		c.log.Warn("abandoned task record encode failed; its events are not kept", "key", key, "err", err)
		return kv.WriteOp{}, 0, false
	}
	return kv.WriteOp{NS: kv.NSAbandonedTask, Key: key, Val: raw}, at, true
}

// hasAbandonedRecord reports whether key has an abandoned task record.
func (c *Coordinator) hasAbandonedRecord(key string) bool {
	c.amu.Lock()
	_, ok := c.abandoned[key]
	c.amu.Unlock()
	return ok
}

// abandonedRecord reads the abandoned task record of key.
func (c *Coordinator) abandonedRecord(key string) (abandonedTaskRecord, bool, error) {
	if !c.hasAbandonedRecord(key) {
		return abandonedTaskRecord{}, false, nil
	}
	raw, found, err := c.kv.GetWithError(kv.NSAbandonedTask, key)
	if err != nil || !found {
		return abandonedTaskRecord{}, false, err
	}
	var record abandonedTaskRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != abandonedTaskVersion {
		return abandonedTaskRecord{}, false, fmt.Errorf("invalid abandoned task record %q", key)
	}
	return record, true, nil
}

// abandonedJournal returns the journal of key for a reader when it has an abandoned task record,
// restoring it into the shared map from the record when it is not there. Unlike journalFor it
// creates nothing for a key without a record, so a record the sweep removed meanwhile does not
// leave an empty journal behind.
func (c *Coordinator) abandonedJournal(key string) (*journal, bool) {
	c.jmu.Lock()
	defer c.jmu.Unlock()
	if j, ok := c.journals[key]; ok {
		return j, true
	}
	record, found, err := c.abandonedRecord(key)
	if err != nil {
		c.log.Warn("abandoned task record unreadable", "key", key, "err", err)
		return nil, false
	}
	if !found {
		return nil, false
	}
	j := newJournal()
	j.restoreEntries(record.Journal)
	c.journals[key] = j
	return j, true
}

// abandonedTaskStatus is the GetTaskStatus answer for a task that has no state machine: FAILED
// with the phase it was dropped in when it has an abandoned task record, ErrTaskNotFound
// otherwise. Stage follows the takeover events of its journal, as for a pending task.
func (c *Coordinator) abandonedTaskStatus(sessionID, taskID string) (types.TaskStatus, error) {
	record, found, err := c.abandonedRecord(taskKey(sessionID, taskID))
	if err != nil {
		return types.TaskStatus{}, err
	}
	if !found {
		return types.TaskStatus{}, ErrTaskNotFound
	}
	return types.TaskStatus{
		State:     types.Failed.String(),
		TaskPhase: record.Phase,
		Stage:     takeoverStageOf(record.Journal),
	}, nil
}

// clearAbandonedRecord removes the abandoned task record of key, if any: a new task on the same
// key (a retry of the sequence) is what the user reads from then on, and it continues the
// journal the record held.
func (c *Coordinator) clearAbandonedRecord(key string) {
	c.amu.Lock()
	_, ok := c.abandoned[key]
	delete(c.abandoned, key)
	c.amu.Unlock()
	if !ok {
		return
	}
	if err := c.kv.Delete(kv.NSAbandonedTask, key); err != nil {
		c.log.Warn("abandoned task record delete failed; the expiry sweep removes it", "key", key, "err", err)
	}
}

// loadAbandonedTasks indexes the stored abandoned task records at startup, after task recovery.
// A record whose key has a recovered task is stale and removed; expired records go with the
// first sweep.
func (c *Coordinator) loadAbandonedTasks() error {
	loaded := make(map[string]int64)
	var stale []string
	if err := c.kv.Scan(kv.NSAbandonedTask, func(key string, val []byte) bool {
		var record abandonedTaskRecord
		if err := json.Unmarshal(val, &record); err != nil || record.Version != abandonedTaskVersion {
			c.log.Warn("invalid abandoned task record removed", "key", key, "err", err)
			stale = append(stale, key)
			return true
		}
		loaded[key] = record.AbandonedAt
		return true
	}); err != nil {
		return fmt.Errorf("load abandoned task records: %w", err)
	}
	c.mu.RLock()
	for key := range loaded {
		if _, active := c.tasks[key]; active {
			delete(loaded, key)
			stale = append(stale, key)
		}
	}
	c.mu.RUnlock()
	c.amu.Lock()
	for key, at := range loaded {
		c.abandoned[key] = at
	}
	c.amu.Unlock()
	for _, key := range stale {
		if err := c.kv.Delete(kv.NSAbandonedTask, key); err != nil {
			c.log.Warn("stale abandoned task record delete failed", "key", key, "err", err)
		}
	}
	return nil
}

// sweepAbandonedTasks removes the abandoned task records older than the retention, with the
// journals they kept in memory. A key that has a task again keeps its journal.
func (c *Coordinator) sweepAbandonedTasks() {
	cutoff := c.now().Add(-c.abandonedRetention).Unix()
	var expired []string
	c.amu.Lock()
	for key, at := range c.abandoned {
		if at <= cutoff {
			expired = append(expired, key)
		}
	}
	c.amu.Unlock()
	for _, key := range expired {
		c.mu.Lock()
		if _, active := c.tasks[key]; active {
			c.mu.Unlock()
			continue
		}
		c.amu.Lock()
		at, ok := c.abandoned[key]
		if ok && at <= cutoff {
			delete(c.abandoned, key)
		}
		c.amu.Unlock()
		if ok && at <= cutoff {
			c.jmu.Lock()
			delete(c.journals, key)
			c.jmu.Unlock()
		}
		c.mu.Unlock()
		if !ok || at > cutoff {
			continue
		}
		if err := c.kv.Delete(kv.NSAbandonedTask, key); err != nil {
			c.log.Warn("expired abandoned task record delete failed", "key", key, "err", err)
		}
	}
}

// runAbandonedTaskSweep removes expired abandoned task records until Stop.
func (c *Coordinator) runAbandonedTaskSweep() {
	c.sweepAbandonedTasks()
	ticker := time.NewTicker(abandonedTaskSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.sweepAbandonedTasks()
		}
	}
}
