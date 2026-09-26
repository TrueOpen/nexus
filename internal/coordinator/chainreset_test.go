package coordinator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/types"
)

type fakeChainResetWatch struct {
	mu       sync.Mutex
	reasons  []string
	same     bool
	sameErr  error
	sameRuns int
}

func (w *fakeChainResetWatch) Suspect(reason string) {
	w.mu.Lock()
	w.reasons = append(w.reasons, reason)
	w.mu.Unlock()
}

func (w *fakeChainResetWatch) SameChain(context.Context) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sameRuns++
	return w.same, w.sameErr
}

func (w *fakeChainResetWatch) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.reasons)
}

// A small step back of the latest height is a lagging RPC; a fall of more than the tolerance is
// reported as a possible chain reset.
func TestRefreshChainHeightReportsLargeRegression(t *testing.T) {
	facts := &chainFactsFake{height: 100000}
	suspects := &fakeChainResetWatch{}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithChainResetWatch(suspects))
	for _, step := range []struct {
		height uint64
		want   int
	}{{100000, 0}, {99950, 0}, {2000, 1}} {
		facts.mu.Lock()
		facts.height = step.height
		facts.mu.Unlock()
		if _, err := c.refreshChainHeight(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := suspects.count(); got != step.want {
			t.Fatalf("after height %d: suspects = %d, want %d", step.height, got, step.want)
		}
	}
}

func assignedTaskMissingFromChain(t *testing.T, opts ...Option) (*Coordinator, *taskFSM, *bytes.Buffer) {
	t.Helper()
	facts := &chainFactsFake{height: 100}
	c, _ := newTestCoordinator(t, append([]Option{WithHeightQuerier(facts), WithTaskQuerier(facts)}, opts...)...)
	var logs bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM("session-1", "task-1")
	if !ok {
		t.Fatal("task not tracked")
	}
	fsm.mu.Lock()
	fsm.state = types.Assigned
	fsm.mu.Unlock()
	return c, fsm, &logs
}

// The chain removes finished tasks itself: on the same chain, a task it no longer returns is
// closed locally and not reconciled again.
func TestReconcileClosesTaskGoneFromSameChain(t *testing.T) {
	watch := &fakeChainResetWatch{same: true}
	c, fsm, logs := assignedTaskMissingFromChain(t, WithChainResetWatch(watch))
	if !c.reconcileTask("session-1", "task-1", 0, "periodic", nil) {
		t.Fatal("closed task not reported as reconciled")
	}
	fsm.mu.Lock()
	state, terminal := fsm.state, fsm.terminal
	fsm.mu.Unlock()
	if state != types.Closed || !terminal {
		t.Fatalf("state = %v, terminal = %v", state, terminal)
	}
	if _, active := c.getFSM("session-1", "task-1"); active {
		t.Fatal("closed task still active")
	}
	if watch.count() != 0 || strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("suspects = %d, logs:\n%s", watch.count(), logs.String())
	}
}

// Without a confirmed same chain the task stays open, is retried, and its WARN is not repeated on
// every reconcile; a missing task is never taken as a sign of a reset.
func TestReconcileKeepsTaskGoneWithoutSameChain(t *testing.T) {
	tests := map[string]*fakeChainResetWatch{
		"identity changed":   {same: false},
		"identity unknown":   {sameErr: errors.New("down")},
		"identity check off": nil,
	}
	for name, watch := range tests {
		t.Run(name, func(t *testing.T) {
			var opts []Option
			if watch != nil {
				opts = append(opts, WithChainResetWatch(watch))
			}
			c, fsm, logs := assignedTaskMissingFromChain(t, opts...)
			for i := 0; i < 3; i++ {
				if c.reconcileTask("session-1", "task-1", 0, "periodic", nil) {
					t.Fatal("a task missing from the chain was reported as reconciled")
				}
			}
			fsm.mu.Lock()
			terminal := fsm.terminal
			fsm.mu.Unlock()
			if terminal {
				t.Fatal("task closed without a confirmed same chain")
			}
			if got := strings.Count(logs.String(), "task not found on chain"); got != 1 {
				t.Fatalf("WARN lines = %d, want 1:\n%s", got, logs.String())
			}
			if watch != nil && watch.count() != 0 {
				t.Fatalf("missing task reported as reset suspicion %d times", watch.count())
			}
		})
	}
}
