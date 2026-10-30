package dispatcher

import (
	"math"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// unknownAnchorHeight stands for the anchor height A of a run an earlier, not yet recorded order of
// the session starts: A becomes that order's record height, which is not known yet. A is at least
// the head (a record at or below it would already be seen), and the precheck admits an order only
// with earliest_submit_height at most head + 1 (the head only grows since), so the real distance
// earliest_submit_height - A is at most 1, and an earliest_submit_height below A counts as
// distance 0. With sticky_window_blocks >= 1 the order is inside the window either way, and the
// unknown height, above every earliest_submit_height, gives exactly that. With sticky_window_blocks
// 0 a distance of 1 is outside, so the order waits while the head is at or below its
// earliest_submit_height; once the head is past it, A is above earliest_submit_height and the
// distance is 0 (stickySnapshot).
const unknownAnchorHeight = math.MaxUint64

// stickySnapshot is the session's sticky state as it will be when this order is recorded: the
// chain's StreamState after every earlier order of the session this Builder still has in flight
// is recorded with its accepted winner ticket. It reports wait while an earlier order has no
// winner yet (it is still dispatching, or failed and not resent) or is recorded but the session
// state read does not include it yet, and, with sticky_window_blocks 0, while a run an earlier
// order starts has an unknown anchor height that may still continue and the head is at or below
// this order's earliest_submit_height. Caller holds o.mu; the earlier orders' locks are taken
// inside it.
func (d *Dispatcher) stickySnapshot(o *order, session inflight.Session) (*taskv1.DispatchStickySnapshotV1, bool) {
	snap := &taskv1.DispatchStickySnapshotV1{
		AnchorSequence: session.StickyAnchorSequence,
		AnchorHeight:   session.StickyAnchorHeight,
		RunCount:       session.StickyRunCount,
	}
	if session.LastRecordWinner != "" {
		snap.LastRecordWinner = proto.String(session.LastRecordWinner)
	}
	for seq := session.NextExpectedSequence; seq < o.st.Sequence; seq++ {
		pred := d.get(stateKey(o.st.SessionID, seq))
		if pred == nil {
			return nil, true
		}
		pred.mu.Lock()
		w := pred.st.winner()
		var ticket taskv1.DispatchTicketV1
		ok := pred.st.Phase == phaseAccepted && w != nil && proto.Unmarshal(w.Ticket, &ticket) == nil
		pred.mu.Unlock()
		if !ok {
			return nil, true
		}
		snap.LastRecordWinner = proto.String(ticket.GetTarget().GetOperatorAddress())
		if ticket.GetStickyAnchorSequence() == seq {
			snap.AnchorSequence, snap.AnchorHeight, snap.RunCount = seq, unknownAnchorHeight, 1
		} else {
			snap.RunCount = ticket.GetStickyRunCount()
		}
	}
	sticky := d.params.Load().Sticky
	if snap.AnchorHeight == unknownAnchorHeight && sticky.WindowBlocks == 0 && snap.RunCount < sticky.MaxOrders &&
		o.signed.GetOrder().GetEarliestSubmitHeight() >= d.cfg.Sessions.Head() {
		return nil, true
	}
	return snap, false
}
