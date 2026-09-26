package coordinator

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/types"
)

type suspectRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (r *suspectRecorder) suspect(reason string) {
	r.mu.Lock()
	r.reasons = append(r.reasons, reason)
	r.mu.Unlock()
}

func (r *suspectRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reasons)
}

// A small step back of the latest height is a lagging RPC; a fall of more than the tolerance is
// reported as a possible chain reset.
func TestRefreshChainHeightReportsLargeRegression(t *testing.T) {
	facts := &chainFactsFake{height: 100000}
	suspects := &suspectRecorder{}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithChainResetSuspect(suspects.suspect))
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

// A task this Builder saw on chain and the chain no longer knows is reported as a possible reset,
// and its WARN is not repeated on every reconcile.
func TestReconcileOfTaskGoneFromChain(t *testing.T) {
	facts := &chainFactsFake{height: 100}
	suspects := &suspectRecorder{}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts), WithChainResetSuspect(suspects.suspect))
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

	for i := 0; i < 3; i++ {
		if c.reconcileTask("session-1", "task-1", 0, "periodic", nil) {
			t.Fatal("a task missing from the chain was reported as reconciled")
		}
	}
	if got := suspects.count(); got != 3 {
		t.Fatalf("suspects = %d, want 3", got)
	}
	if got := strings.Count(logs.String(), "task not found on chain"); got != 1 {
		t.Fatalf("WARN lines = %d, want 1:\n%s", got, logs.String())
	}
}
