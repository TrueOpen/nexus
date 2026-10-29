// Package taskgroup is the Task Builders group of an order.
//
// The group is every member of the BuilderSet snapshot the order signs in (builder_set_id,
// builder_set_hash). Its frozen order puts the dispatching Builder first (position 0) and the other
// members after it in snapshot order, wrapping around; that position is the Builder's rank for
// settlement, Open Verify proposals and answering roster challenges. The chain locks the group when
// it admits the dispatch entry, and only for an order whose snapshot is the current BuilderSet
// snapshot: an order signed against a replaced snapshot must be re-signed by the user.
package taskgroup

import (
	"bytes"
	"errors"
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

var (
	// ErrNoSnapshot means this Builder knows no current BuilderSet snapshot: it must not take new
	// orders (workload readiness is false).
	ErrNoSnapshot = errors.New("no current BuilderSet snapshot")
	// ErrBuilderSetStale refuses an order whose builder_set_id/hash is not the current snapshot;
	// the user re-signs it against the current one. Its text is the ingress status code.
	ErrBuilderSetStale = errors.New("NEXUS_INGRESS_BUILDER_SET_STALE")
)

// Snapshot is one BuilderSet snapshot: its id, its hash and its members in snapshot order.
type Snapshot struct {
	ID      string
	Hash    [32]byte
	Members []string
}

// Source answers the current BuilderSet snapshot.
type Source interface {
	// CurrentBuilderSet returns the current snapshot; false when none is known.
	CurrentBuilderSet() (Snapshot, bool)
}

// Group is the frozen Task Builders group of one order. It is a value; Members must not be
// modified.
type Group struct {
	BuilderSetID   string
	BuilderSetHash [32]byte
	// Members is the frozen order: Members[0] is the dispatching Builder.
	Members []string
}

// New builds the group of an order dispatched by dispatcher from the order's snapshot: the
// dispatcher first, then the members after it in snapshot order, wrapping around. The dispatcher
// must be a member.
func New(snapshot Snapshot, dispatcher string) (Group, error) {
	start := -1
	seen := make(map[string]bool, len(snapshot.Members))
	for i, member := range snapshot.Members {
		if member == "" || seen[member] {
			return Group{}, fmt.Errorf("BuilderSet %s has an empty or repeated member", snapshot.ID)
		}
		seen[member] = true
		if member == dispatcher {
			start = i
		}
	}
	if start < 0 {
		return Group{}, fmt.Errorf("dispatching Builder %s is not a member of BuilderSet %s", dispatcher, snapshot.ID)
	}
	n := len(snapshot.Members)
	members := make([]string, n)
	for i := range members {
		members[i] = snapshot.Members[(start+i)%n]
	}
	return Group{BuilderSetID: snapshot.ID, BuilderSetHash: snapshot.Hash, Members: members}, nil
}

// Frozen rebuilds a group from an order the chain already froze (the Task's selected Task
// Builders), keeping that order as is.
func Frozen(setID string, setHash [32]byte, ordered []string) (Group, error) {
	if len(ordered) == 0 {
		return Group{}, fmt.Errorf("frozen Task Builders of BuilderSet %s are empty", setID)
	}
	return Group{BuilderSetID: setID, BuilderSetHash: setHash, Members: append([]string(nil), ordered...)}, nil
}

// Dispatcher is the dispatching Builder, position 0.
func (g Group) Dispatcher() string { return g.Members[0] }

// Position returns builder's position in the frozen order; false when it is not in the group.
func (g Group) Position(builder string) (int, bool) {
	for i, member := range g.Members {
		if member == builder {
			return i, true
		}
	}
	return 0, false
}

// Others returns the members other than builder, in frozen order: the peers builder keeps in
// step with.
func (g Group) Others(builder string) []string {
	out := make([]string, 0, len(g.Members))
	for _, member := range g.Members {
		if member != builder {
			out = append(out, member)
		}
	}
	return out
}

// CheckOrder returns the current snapshot when the order's builder_set_id/hash name it:
// ErrNoSnapshot when none is known, ErrBuilderSetStale when the order names another.
func CheckOrder(src Source, order *taskv1.TaskOrderV3) (Snapshot, error) {
	current, ok := src.CurrentBuilderSet()
	if !ok {
		return Snapshot{}, ErrNoSnapshot
	}
	if order.GetBuilderSetId() != current.ID || !bytes.Equal(order.GetBuilderSetHash(), current.Hash[:]) {
		return Snapshot{}, fmt.Errorf("%w: order names BuilderSet %q, current is %q", ErrBuilderSetStale, order.GetBuilderSetId(), current.ID)
	}
	return current, nil
}

// ForOrder checks the order against the current snapshot and returns its group with dispatcher
// at position 0.
func ForOrder(src Source, order *taskv1.TaskOrderV3, dispatcher string) (Group, error) {
	snapshot, err := CheckOrder(src, order)
	if err != nil {
		return Group{}, err
	}
	return New(snapshot, dispatcher)
}

// Ready reports whether new orders can be taken: a current snapshot is known.
func Ready(src Source) error {
	if _, ok := src.CurrentBuilderSet(); !ok {
		return ErrNoSnapshot
	}
	return nil
}
