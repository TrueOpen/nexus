package coordinator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskgroup"
	"github.com/TrueOpen/nexus/internal/types"
)

// seedTestBuilderSet makes the BuilderSet the test orders name (testBuilderSetRef) current.
func seedTestBuilderSet(c *Coordinator) {
	c.active.Update(1, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, testBuilderSetRef)
}

// The OpenTask precheck refuses an order whose builder_set_id/hash is not the current BuilderSet
// snapshot as NEXUS_INGRESS_BUILDER_SET_STALE before the dispatcher is asked: the user re-signs the
// same sequence against the current snapshot. Without a current snapshot no order is taken.
func TestCheckOrderRefusesAStaleBuilderSet(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.SetDispatcher(&fakeDispatcher{probeErr: dispatchdraw.ErrNoCapacity})
	o := testPlaceholderOrder("session-1", "task-1")

	err := c.CheckOrder(context.Background(), o)
	if !errors.Is(err, ErrDispatchUnavailable) || !errors.Is(err, taskgroup.ErrNoSnapshot) {
		t.Fatalf("without a current snapshot: %v", err)
	}

	c.active.Update(2, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{
		ID: "term-2", Hash: testBuilderSetRef.Hash,
	})
	err = c.CheckOrder(context.Background(), o)
	if !errors.Is(err, taskgroup.ErrBuilderSetStale) || errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("an order of a replaced snapshot: %v", err)
	}

	seedTestBuilderSet(c)
	if err := c.CheckOrder(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("an order of the current snapshot reaches the dispatcher: %v", err)
	}
}

// Each refusal before input upload is logged with the model and profile the order asked for, so a
// NO_CAPACITY can be told apart from a model mismatch without the client's request.
func TestCheckOrderLogsTheOrdersProfile(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	var buf bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&buf, nil))
	c.SetDispatcher(&fakeDispatcher{probeErr: dispatchdraw.ErrNoCapacity})
	o := testPlaceholderOrder("session-1", "task-1")
	want := "model_id=" + testModelIDHex + " profile_version=2"

	c.active.Update(2, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{
		ID: "term-2", Hash: testBuilderSetRef.Hash,
	})
	if err := c.CheckOrder(context.Background(), o); !errors.Is(err, taskgroup.ErrBuilderSetStale) {
		t.Fatalf("an order of a replaced snapshot: %v", err)
	}
	if line := buf.String(); !strings.Contains(line, "order refused before input upload") || !strings.Contains(line, want) {
		t.Fatalf("stale refusal log = %q, want %q", line, want)
	}

	buf.Reset()
	seedTestBuilderSet(c)
	if err := c.CheckOrder(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe refusal: %v", err)
	}
	if line := buf.String(); !strings.Contains(line, "order refused before input upload") || !strings.Contains(line, want) {
		t.Fatalf("probe refusal log = %q, want %q", line, want)
	}
}

// builderSetRegistry answers set as the chain's current BuilderSet, with this Builder in it.
func builderSetRegistry(id string) *fakeBuilderRegistry {
	return &fakeBuilderRegistry{
		builder: chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "ACTIVE"},
		height:  100,
		set: chaincli.BuilderSet{Epoch: 2, BuilderSetID: id, Members: []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}},
			SetHash: strings.Repeat("44", 32)},
	}
}

// An order naming another snapshot may mean this Builder is the one behind: the BuilderSet is read
// from the chain again before the order is judged. When the chain's current snapshot is the
// order's, the order goes on; when it is still another, the order is stale. The read never makes a
// request wait for another one: while a read runs, or within builderSetRefreshInterval of the last
// attempt (failed or not), the answer is the retryable DISPATCH_UNAVAILABLE rather than STALE from
// a view older than the request.
func TestCheckOrderReadsTheBuilderSetAgainBeforeCallingAnOrderStale(t *testing.T) {
	order := testPlaceholderOrder("session-1", "task-1")
	newCoordinator := func(t *testing.T, chainSet, localSet string) (*Coordinator, *fakeBuilderRegistry) {
		registry := builderSetRegistry(chainSet)
		c, _ := newTestCoordinator(t, WithBuilderRegistry(registry))
		c.SetDispatcher(&fakeDispatcher{})
		c.active.Update(1, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{ID: localSet, Hash: testBuilderSetRef.Hash})
		return c, registry
	}
	reads := func(r *fakeBuilderRegistry) int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.setCalls
	}
	unavailable := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrDispatchUnavailable) || errors.Is(err, taskgroup.ErrBuilderSetStale) {
			t.Fatalf("err = %v, want DISPATCH_UNAVAILABLE", err)
		}
	}
	t.Run("this Builder behind", func(t *testing.T) {
		c, _ := newCoordinator(t, testBuilderSetRef.ID, "term-0")
		if err := c.CheckOrder(context.Background(), order); err != nil {
			t.Fatalf("order of the chain's current snapshot: %v", err)
		}
	})
	t.Run("client behind", func(t *testing.T) {
		c, registry := newCoordinator(t, "term-2", "term-2")
		if err := c.CheckOrder(context.Background(), order); !errors.Is(err, taskgroup.ErrBuilderSetStale) {
			t.Fatalf("order of a replaced snapshot: %v", err)
		}
		unavailable(t, c.CheckOrder(context.Background(), order))
		if n := reads(registry); n != 1 {
			t.Fatalf("BuilderSet reads = %d, want one within the interval", n)
		}
		c.builderSetRefreshedAt = c.builderSetRefreshedAt.Add(-builderSetRefreshInterval)
		if err := c.CheckOrder(context.Background(), order); !errors.Is(err, taskgroup.ErrBuilderSetStale) || reads(registry) != 2 {
			t.Fatalf("after the interval: %v, %d reads", err, reads(registry))
		}
	})
	t.Run("read failed", func(t *testing.T) {
		c, registry := newCoordinator(t, testBuilderSetRef.ID, "term-0")
		registry.setErr = errors.New("hub unreachable")
		unavailable(t, c.CheckOrder(context.Background(), order))
		unavailable(t, c.CheckOrder(context.Background(), order))
		if n := reads(registry); n != 1 {
			t.Fatalf("BuilderSet reads = %d, want a failed read to count against the interval", n)
		}
	})
	t.Run("read running", func(t *testing.T) {
		c, registry := newCoordinator(t, testBuilderSetRef.ID, "term-0")
		c.builderSetRefresh.Lock()
		unavailable(t, c.CheckOrder(context.Background(), order))
		c.builderSetRefresh.Unlock()
		if n := reads(registry); n != 0 {
			t.Fatalf("BuilderSet reads = %d while another read runs", n)
		}
	})
}
