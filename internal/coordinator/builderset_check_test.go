package coordinator

import (
	"context"
	"errors"
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
// order's, the order goes on; when it is still another, the order is stale. A read this recent is
// not repeated for the next stale order; a read that fails leaves the answer retryable.
func TestCheckOrderReadsTheBuilderSetAgainBeforeCallingAnOrderStale(t *testing.T) {
	t.Run("this Builder behind", func(t *testing.T) {
		registry := builderSetRegistry(testBuilderSetRef.ID)
		c, _ := newTestCoordinator(t, WithBuilderRegistry(registry))
		c.SetDispatcher(&fakeDispatcher{})
		c.active.Update(1, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{ID: "term-0", Hash: testBuilderSetRef.Hash})
		if err := c.CheckOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
			t.Fatalf("order of the chain's current snapshot: %v", err)
		}
	})
	t.Run("client behind", func(t *testing.T) {
		registry := builderSetRegistry("term-2")
		c, _ := newTestCoordinator(t, WithBuilderRegistry(registry))
		c.SetDispatcher(&fakeDispatcher{})
		c.active.Update(2, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{ID: "term-2", Hash: testBuilderSetRef.Hash})
		for range 3 {
			if err := c.CheckOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); !errors.Is(err, taskgroup.ErrBuilderSetStale) {
				t.Fatalf("order of a replaced snapshot: %v", err)
			}
		}
		registry.mu.Lock()
		calls := registry.setCalls
		registry.mu.Unlock()
		if calls != 1 {
			t.Fatalf("BuilderSet reads = %d, want one while the last read is fresh", calls)
		}
	})
	t.Run("read failed", func(t *testing.T) {
		registry := builderSetRegistry(testBuilderSetRef.ID)
		registry.setErr = errors.New("hub unreachable")
		c, _ := newTestCoordinator(t, WithBuilderRegistry(registry))
		c.SetDispatcher(&fakeDispatcher{})
		c.active.Update(1, []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}, builderSetRef{ID: "term-0", Hash: testBuilderSetRef.Hash})
		err := c.CheckOrder(context.Background(), testPlaceholderOrder("session-1", "task-1"))
		if !errors.Is(err, ErrDispatchUnavailable) || errors.Is(err, taskgroup.ErrBuilderSetStale) {
			t.Fatalf("BuilderSet unreadable: %v", err)
		}
	})
}
