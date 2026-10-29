package dispatchdraw

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/handraise"
)

// ErrRosterTooLarge means the roster's full text exceeds max_dispatch_roster_bytes.
var ErrRosterTooLarge = errors.New("dispatch roster exceeds max_dispatch_roster_bytes")

// Roster is the availability filter of one dispatch round: the pool members holding an admitted,
// unexpired standing handraise for the order's profile with a free slot in the round's handraise
// root. It never reorders the draw.
type Roster struct {
	// RootDigest is the handraise_root_digest every ticket of the round binds.
	RootDigest [32]byte
	// Msg is the full roster text, members in slot order.
	Msg *taskv1.DispatchRosterV1
	// Hash is roster_hash.
	Hash [32]byte

	members []dispatch.RosterMember
	bySlot  map[uint32]dispatch.RosterMember
}

// Members returns the roster members in slot order. The slice is shared and must not be modified.
func (r *Roster) Members() []dispatch.RosterMember { return r.members }

// Contains reports whether m (slot, slot version, operator, weight) is in the roster.
func (r *Roster) Contains(m dispatch.RosterMember) bool {
	got, ok := r.bySlot[m.Slot]
	return ok && got == m
}

// BuildRoster builds the roster of one round of taskID from root, the latest root signed before
// the round's first ticket. A member is taken from each admitted leaf whose handraise lists the
// pool's profile, has a free slot, has an expiry height not below height (this Builder's chain
// height) and whose operator is in the pool; it carries the pool's slot, slot version and weight.
// No root or no member is ErrNoCapacity; a roster whose protobuf text exceeds maxBytes is
// ErrRosterTooLarge.
func BuildRoster(chainID string, taskID [32]byte, root *handraise.IssuedRoot, pool *Pool, height, maxBytes uint64) (*Roster, error) {
	if maxBytes == 0 {
		return nil, fmt.Errorf("max_dispatch_roster_bytes must be positive")
	}
	if root == nil {
		return nil, ErrNoCapacity
	}
	r := &Roster{RootDigest: root.Digest, bySlot: map[uint32]dispatch.RosterMember{}}
	for _, leaf := range root.Leaves {
		h := leaf.GetHandraise()
		if !leaf.GetAdmitted() || h.GetFreeSlotCount() == 0 || h.GetExpiryHeight() < height || !servesProfile(h, pool.Profile) {
			continue
		}
		m, ok := pool.Member(h.GetMember().GetOperatorAddress())
		if !ok {
			continue
		}
		if _, dup := r.bySlot[m.Slot]; dup {
			continue
		}
		r.bySlot[m.Slot] = m
		r.members = append(r.members, m)
	}
	if len(r.members) == 0 {
		return nil, ErrNoCapacity
	}
	sort.Slice(r.members, func(i, j int) bool { return r.members[i].Slot < r.members[j].Slot })

	ep := pool.Epoch
	r.Msg = &taskv1.DispatchRosterV1{
		TaskId:                  append([]byte(nil), taskID[:]...),
		ReferenceHeight:         ep.ReferenceHeight,
		CandidatePoolSnapshotId: append([]byte(nil), ep.SnapshotID[:]...),
		Members:                 make([]*taskv1.DispatchRosterMemberV1, len(r.members)),
	}
	for i, m := range r.members {
		r.Msg.Members[i] = &taskv1.DispatchRosterMemberV1{Slot: m.Slot, SlotVersion: m.SlotVersion, OperatorAddress: m.OperatorAddress, CandidateWeight: m.CandidateWeight}
	}
	if size := uint64(proto.Size(r.Msg)); size > maxBytes {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrRosterTooLarge, size, maxBytes)
	}
	var err error
	r.Hash, err = dispatch.RosterDigest(chainID, taskID, ep.ReferenceHeight, ep.SnapshotID, r.members)
	if err != nil {
		return nil, fmt.Errorf("dispatch roster hash: %w", err)
	}
	return r, nil
}

func servesProfile(h *taskv1.StandingHandraiseV1, p Profile) bool {
	for _, got := range h.GetProfiles() {
		if got.GetProfileVersion() == p.Version && bytes.Equal(got.GetModelId(), p.ModelID[:]) {
			return true
		}
	}
	return false
}
