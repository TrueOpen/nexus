package coordinator

import (
	"context"
	"errors"
	"testing"

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
