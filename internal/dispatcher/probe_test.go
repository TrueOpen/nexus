package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
)

// A NO_CAPACITY answer from the root walk says which model and profile the order asked for and
// how far the latest root's leaves got: admitted, serving the profile, with a free slot, unexpired.
func TestProbeNoCapacitySaysWhichConditionFailed(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.handraises.setRoot(0xd2, 2, op1, op3, op7)
	e.handraises.mu.Lock()
	root := e.handraises.root
	for range 2 {
		root.Leaves = append(root.Leaves, proto.Clone(root.Leaves[0]).(*taskv1.HandraiseRootLeafV1))
	}
	leaves := root.Leaves
	otherModel := fill32(0x78)
	leaves[0].Admitted = false
	leaves[1].Handraise.Profiles = []*taskv1.DispatchProfileV1{{ModelId: otherModel[:], ProfileVersion: 1}}
	leaves[2].Handraise.FreeSlotCount = 0
	leaves[3].Handraise.ExpiryHeight = testESH - 1
	leaves[4].Handraise.Profiles[0].ProfileVersion = 2
	e.handraises.mu.Unlock()

	err := e.d.Probe(context.Background(), o)
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe = %v", err)
	}
	want := fmt.Sprintf("%v: no admitted handraise for model %x profile 1: root 210 has 5 leaves, "+
		"4 admitted, 2 serving the profile, 1 of those with a free slot, 0 of those unexpired at head %d",
		dispatchdraw.ErrNoCapacity, testModel[:], testESH)
	if err.Error() != want {
		t.Fatalf("probe = %q\nwant    %q", err, want)
	}
}

// With the order's pool at hand (built for an earlier order of its epoch), Probe refuses an order
// no admitted, serving, free and unexpired handraise of a pool member can take, with the roster's
// NO_CAPACITY answer: the root alone would accept it. Without it Probe does not read the pool.
func TestProbeRefusesAnOrderNoPoolMemberHandraisedFor(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.handraises.setRoot(0xd2, 2, op1, op3)
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe without the pool = %v", err)
	}
	e.drawer.mu.Lock()
	e.drawer.cached = dispatchdraw.NewPool(e.drawer.epoch, testProfile, []dispatch.RosterMember{member(op7)})
	e.drawer.mu.Unlock()
	err := e.d.Probe(context.Background(), o)
	want := fmt.Sprintf("%v: empty dispatch roster: root 210 has 2 leaves, 2 admitted, 2 serving the profile, "+
		"2 of those with a free slot and unexpired at height %d, 0 of those in the pool; pool of model %x profile 1 at epoch %d: 1 members",
		dispatchdraw.ErrNoCapacity, testESH, testModel[:], e.drawer.epoch.Number)
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) || err.Error() != want {
		t.Fatalf("probe = %q\nwant    %q", err, want)
	}
	e.handraises.setRoot(0xd3, 2, op1, op7)
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe with a pool member's handraise = %v", err)
	}
}
