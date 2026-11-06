package ingress

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// TaskBuilders reads the frozen Task Builders of a task from the chain
// (chaincli.Client.QueryTaskBuilders): chaincli.ErrNotFound until the chain recorded the task's
// dispatch.
type TaskBuilders interface {
	QueryTaskBuilders(ctx context.Context, key chaincli.TaskKey) (chaincli.TaskBuilderSelectionState, error)
}

const (
	// taskRecordMissTTL is how long "not recorded" stands before the chain is read again.
	taskRecordMissTTL = time.Second
	// maxTaskRecords bounds each kind of cached answer: a full set of recorded tasks is dropped
	// (they are read again), and no further miss is kept until the expired ones are dropped.
	maxTaskRecords = 4096
)

// taskRecords answers whether the chain recorded a task's dispatch with builder (this Builder) in
// its Task Builders group. A recorded group never changes, so that answer is kept; "not recorded"
// is kept for taskRecordMissTTL.
type taskRecords struct {
	chain   TaskBuilders
	builder string
	now     func() time.Time

	mu       sync.Mutex
	recorded map[string]bool      // task -> this Builder is in its group
	misses   map[string]time.Time // task -> until when "not recorded" stands
}

func newTaskRecords(chain TaskBuilders, builder string) *taskRecords {
	return &taskRecords{chain: chain, builder: builder, now: time.Now, recorded: map[string]bool{}, misses: map[string]time.Time{}}
}

// member reports whether the chain recorded the task (session and task ids in hex) and, if so,
// whether this Builder is in its Task Builders group.
func (r *taskRecords) member(ctx context.Context, sessionID, taskID string) (recorded, member bool, err error) {
	r.mu.Lock()
	member, recorded = r.recorded[taskID]
	until, missed := r.misses[taskID]
	r.mu.Unlock()
	if recorded {
		return true, member, nil
	}
	if missed && r.now().Before(until) {
		return false, false, nil
	}
	state, err := r.chain.QueryTaskBuilders(ctx, chaincli.TaskKey{SessionID: sessionID, TaskID: taskID})
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		if len(r.misses) >= maxTaskRecords {
			for task, until := range r.misses {
				if !r.now().Before(until) {
					delete(r.misses, task)
				}
			}
		}
		if len(r.misses) < maxTaskRecords {
			r.misses[taskID] = r.now().Add(taskRecordMissTTL)
		}
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	member = slices.Contains(state.SelectedBuilders, r.builder)
	if len(r.recorded) >= maxTaskRecords {
		clear(r.recorded)
	}
	r.recorded[taskID] = member
	delete(r.misses, taskID)
	return true, member, nil
}
