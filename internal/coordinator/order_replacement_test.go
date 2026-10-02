package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func TestOnOrderRefusesReplacementVersion(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	ctx := context.Background()
	first := testPlaceholderOrder("session-1", "task-1")
	replacement := first
	replacement.TaskHash = strings.Repeat("b", 64)

	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckOrder(ctx, replacement); !errors.Is(err, ErrOrderReplacementUnsupported) {
		t.Fatalf("CheckOrder(replacement) = %v, want ErrOrderReplacementUnsupported", err)
	}
	if err := c.OnOrder(ctx, replacement); !errors.Is(err, ErrOrderReplacementUnsupported) {
		t.Fatalf("OnOrder(replacement) = %v, want ErrOrderReplacementUnsupported", err)
	}
	fsm, ok := c.getFSM(first.SessionID, first.TaskID)
	if !ok {
		t.Fatal("tracked task disappeared")
	}
	if fsm.order.TaskHash != first.TaskHash {
		t.Fatalf("tracked task_hash = %s, want %s", fsm.order.TaskHash, first.TaskHash)
	}
	// An exact retry of the tracked version is still accepted.
	if err := c.CheckOrder(ctx, first); err != nil {
		t.Fatalf("CheckOrder(retry) = %v", err)
	}
	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatalf("OnOrder(retry) = %v", err)
	}
	// An unknown task is not refused.
	if err := c.CheckOrder(ctx, testPlaceholderOrder("session-1", "task-2")); err != nil {
		t.Fatalf("CheckOrder(new task) = %v", err)
	}
}

func TestOnOrderTerminalTaskRefusesOtherVersion(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	ctx := context.Background()
	first := testPlaceholderOrder("session-1", "task-1")
	replacement := first
	replacement.TaskHash = strings.Repeat("b", 64)
	key := taskKey(first.SessionID, first.TaskID)

	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	c.removeTask(key)
	raw, found, err := store.GetWithError(kv.NSTerminalTask, key)
	if err != nil || !found {
		t.Fatalf("terminal marker: found=%v err=%v", found, err)
	}
	var record terminalTaskRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.TaskHash != first.TaskHash {
		t.Fatalf("terminal marker task_hash = %q, want %q", record.TaskHash, first.TaskHash)
	}

	check := func(stage string) {
		t.Helper()
		if err := c.CheckOrder(ctx, replacement); !errors.Is(err, ErrTaskTerminal) {
			t.Fatalf("%s: CheckOrder(other version) = %v, want ErrTaskTerminal", stage, err)
		}
		if err := c.OnOrder(ctx, replacement); !errors.Is(err, ErrTaskTerminal) {
			t.Fatalf("%s: OnOrder(other version) = %v, want ErrTaskTerminal", stage, err)
		}
		if err := c.CheckOrder(ctx, first); err != nil {
			t.Fatalf("%s: CheckOrder(retry) = %v", stage, err)
		}
		if err := c.OnOrder(ctx, first); err != nil {
			t.Fatalf("%s: OnOrder(retry) = %v", stage, err)
		}
		if _, ok := c.getFSM(first.SessionID, first.TaskID); ok {
			t.Fatalf("%s: terminal task was tracked again", stage)
		}
	}
	check("cached marker")
	c.releaseTerminalTask(first.SessionID, first.TaskID)
	check("durable marker only")
}

func TestTerminalMarkerWithoutTaskHashTreatsOrderAsRetry(t *testing.T) {
	store := kv.NewMemStore()
	c, _ := newTaskTrackingCoordinator(t, store)
	ctx := context.Background()
	order := testPlaceholderOrder("session-1", "task-1")
	// A marker written before the task_hash field existed.
	legacy, err := json.Marshal(map[string]any{"version": terminalTaskVersion, "recipient": testUserAddress})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSTerminalTask, taskKey(order.SessionID, order.TaskID), legacy); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckOrder(ctx, order); err != nil {
		t.Fatalf("CheckOrder = %v", err)
	}
	if err := c.OnOrder(ctx, order); err != nil {
		t.Fatalf("OnOrder = %v", err)
	}
	if _, ok := c.getFSM(order.SessionID, order.TaskID); ok {
		t.Fatal("terminal task was tracked again")
	}
}
