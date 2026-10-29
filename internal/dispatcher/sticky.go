package dispatcher

import (
	"math"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// unknownAnchorHeight stands for the anchor height of a run an earlier, not yet recorded order of
// the session starts: it becomes that order's record height, which is not known yet. No later
// order is promoted against it.
const unknownAnchorHeight = math.MaxUint64

// stickySnapshot is the session's sticky state as it will be when this order is recorded: the
// chain's StreamState after every earlier order of the session this Builder still has in flight
// is recorded with its accepted winner ticket. It reports wait while an earlier order has no
// winner yet (it is still dispatching, or failed and not resent) or is recorded but the session
// state read does not include it yet. Caller holds o.mu; the earlier orders' locks are taken
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
	return snap, false
}
