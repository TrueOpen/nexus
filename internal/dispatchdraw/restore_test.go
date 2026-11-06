package dispatchdraw

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// A roster restored from its stored full text and root digest is the roster that was built.
func TestRestoreRosterFromItsText(t *testing.T) {
	pool := vectorPool(t)
	built := rosterOf(t, pool, vectorOp7, vectorOp3)
	restored, err := RestoreRoster(vectorChainID, built.RootDigest, built.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Hash != built.Hash || restored.RootDigest != built.RootDigest ||
		!reflect.DeepEqual(restored.Members(), built.Members()) {
		t.Fatalf("restored roster = %+v, want %+v", restored, built)
	}
	for _, m := range pool.Members {
		if restored.Contains(m) != built.Contains(m) {
			t.Fatalf("Contains(%v) differs", m)
		}
	}

	bad := map[string]func(*taskv1.DispatchRosterV1){
		"empty":          func(m *taskv1.DispatchRosterV1) { m.Members = nil },
		"slot order":     func(m *taskv1.DispatchRosterV1) { m.Members[0], m.Members[1] = m.Members[1], m.Members[0] },
		"task_id":        func(m *taskv1.DispatchRosterV1) { m.TaskId = m.TaskId[:31] },
		"snapshot":       func(m *taskv1.DispatchRosterV1) { m.CandidatePoolSnapshotId = nil },
		"duplicate slot": func(m *taskv1.DispatchRosterV1) { m.Members[1].Slot = m.Members[0].Slot },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			msg := cloneRoster(built.Msg)
			mutate(msg)
			if _, err := RestoreRoster(vectorChainID, built.RootDigest, msg); err == nil {
				t.Fatal("malformed roster text was restored")
			}
		})
	}
}

// An order restored from its members and sticky decision walks like the order NewOrder built.
func TestRestoreOrderKeepsTheStickyDecision(t *testing.T) {
	pool := vectorPool(t)
	built, err := NewOrder(drawnVector(t, pool), vectorRoster(t, pool), stickySnapshot(), stickyParams, stickyESH, stickySequence)
	if err != nil {
		t.Fatal(err)
	}
	anchor, run := built.Sticky(0)
	restored, err := RestoreOrder(built.Members, built.StickyApplied, stickySequence, anchor, run)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Members, built.Members) || restored.StickyApplied != built.StickyApplied {
		t.Fatalf("restored order = %+v, want %+v", restored, built)
	}
	for rank := uint32(0); rank < uint32(len(built.Members)); rank++ {
		a1, r1 := built.Sticky(rank)
		a2, r2 := restored.Sticky(rank)
		if a1 != a2 || r1 != r2 {
			t.Fatalf("rank %d sticky = (%d, %d), want (%d, %d)", rank, a2, r2, a1, r1)
		}
	}
	if _, err := RestoreOrder(nil, false, stickySequence, stickySequence, 1); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("empty order: %v", err)
	}
}

func TestNewPoolIndexesMembers(t *testing.T) {
	built := vectorPool(t)
	pool := NewPool(built.Epoch, built.Profile, built.Members)
	for _, m := range built.Members {
		got, ok := pool.Member(m.OperatorAddress)
		if !ok || got != m {
			t.Fatalf("Member(%s) = %v %v", m.OperatorAddress, got, ok)
		}
	}
	if _, ok := pool.Member("trueopen1notinpool"); ok {
		t.Fatal("unknown operator found")
	}
}

func cloneRoster(m *taskv1.DispatchRosterV1) *taskv1.DispatchRosterV1 {
	return proto.Clone(m).(*taskv1.DispatchRosterV1)
}
