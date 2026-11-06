package dispatchdraw

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// NewPool is the dispatch pool of profile at ep with members in slot order, as BuildPool reads it
// from the chain.
func NewPool(ep Epoch, profile Profile, members []dispatch.RosterMember) *Pool {
	pool := &Pool{Epoch: ep, Profile: profile, Members: members, byOperator: make(map[string]int, len(members))}
	for i, m := range members {
		pool.byOperator[m.OperatorAddress] = i
	}
	return pool
}

// RestoreRoster rebuilds a round's roster from its stored full text and handraise root digest, so a
// restarted dispatcher filters with exactly the roster the round's tickets bind. The text must be
// what BuildRoster produced: members in strictly ascending slot order and 32-byte identifiers.
func RestoreRoster(chainID string, rootDigest [32]byte, msg *taskv1.DispatchRosterV1) (*Roster, error) {
	if len(msg.GetTaskId()) != 32 || len(msg.GetCandidatePoolSnapshotId()) != 32 || len(msg.GetMembers()) == 0 {
		return nil, fmt.Errorf("stored dispatch roster is malformed")
	}
	r := &Roster{RootDigest: rootDigest, Msg: msg, bySlot: make(map[uint32]dispatch.RosterMember, len(msg.GetMembers()))}
	for i, m := range msg.GetMembers() {
		if i > 0 && msg.GetMembers()[i-1].GetSlot() >= m.GetSlot() {
			return nil, fmt.Errorf("stored dispatch roster members are not in ascending slot order")
		}
		member := dispatch.RosterMember{Slot: m.GetSlot(), SlotVersion: m.GetSlotVersion(), OperatorAddress: m.GetOperatorAddress(), CandidateWeight: m.GetCandidateWeight()}
		r.bySlot[member.Slot] = member
		r.members = append(r.members, member)
	}
	var err error
	r.Hash, err = dispatch.RosterDigest(chainID, [32]byte(msg.GetTaskId()), msg.GetReferenceHeight(), [32]byte(msg.GetCandidatePoolSnapshotId()), r.members)
	if err != nil {
		return nil, fmt.Errorf("dispatch roster hash: %w", err)
	}
	return r, nil
}

// RestoreOrder rebuilds an order NewOrder decided: its members in rank order, whether stickiness
// applied, the order's sequence and, when it applied, the sticky target's commitments
// (Order.Sticky(0)). The decision is never taken again.
func RestoreOrder(members []dispatch.RosterMember, stickyApplied bool, orderSequence, anchorSequence uint64, runCount uint32) (*Order, error) {
	if len(members) == 0 {
		return nil, ErrNoCapacity
	}
	o := &Order{Members: append([]dispatch.RosterMember(nil), members...), StickyApplied: stickyApplied, sequence: orderSequence}
	if stickyApplied {
		o.anchorSequence, o.runCount = anchorSequence, runCount
	}
	return o, nil
}
