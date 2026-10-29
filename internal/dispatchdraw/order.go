package dispatchdraw

import (
	"fmt"
	"iter"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// StickyParams are the chain's session stickiness limits (sticky_max_orders,
// sticky_window_blocks).
type StickyParams struct {
	MaxOrders    uint32
	WindowBlocks uint64
}

// Order is the complete dispatch order of one order: the full-pool draw, with the previous
// recorded winner moved to the front when stickiness applies. It is fixed for every round of the
// order in its epoch; rosters only filter it. The index of a member is its ticket rank.
type Order struct {
	Members []dispatch.RosterMember
	// StickyApplied is the record's and every ticket's sticky_applied.
	StickyApplied bool

	sequence       uint64
	anchorSequence uint64
	runCount       uint32
}

// NewOrder decides stickiness once, from the first round's roster and the chain's sticky state
// (StreamState's last_record_winner, sticky_anchor_sequence, sticky_anchor_height and
// sticky_run_count as of this order's admission; while earlier orders of the session are still
// unrecorded, the state they will leave once all are admitted). The previous winner moves to the front exactly
// when it is in the first roster (so it has a free slot), its run count is below MaxOrders, and
// earliestSubmitHeight is at most WindowBlocks past the run's anchor height; otherwise the drawn
// order stands.
func NewOrder(drawn []dispatch.RosterMember, firstRoster *Roster, sticky *taskv1.DispatchStickySnapshotV1, params StickyParams, earliestSubmitHeight, orderSequence uint64) (*Order, error) {
	if len(drawn) == 0 {
		return nil, ErrNoCapacity
	}
	if firstRoster == nil {
		return nil, fmt.Errorf("dispatch order needs the first round's roster")
	}
	o := &Order{Members: append([]dispatch.RosterMember(nil), drawn...), sequence: orderSequence}
	target := -1
	if winner := sticky.GetLastRecordWinner(); winner != "" && withinStickyLimits(sticky, params, earliestSubmitHeight) {
		for i, m := range o.Members {
			if m.OperatorAddress == winner && firstRoster.Contains(m) {
				target = i
				break
			}
		}
	}
	if target >= 0 {
		m := o.Members[target]
		copy(o.Members[1:target+1], o.Members[:target])
		o.Members[0] = m
		o.StickyApplied = true
		o.anchorSequence = sticky.GetAnchorSequence()
		o.runCount = sticky.GetRunCount() + 1
	}
	return o, nil
}

func withinStickyLimits(s *taskv1.DispatchStickySnapshotV1, params StickyParams, esh uint64) bool {
	if s.GetRunCount() >= params.MaxOrders {
		return false
	}
	// An order may carry an earliest_submit_height below the anchor's record height (it was
	// signed before the anchor order was recorded); that is inside the window.
	return esh <= s.GetAnchorHeight() || esh-s.GetAnchorHeight() <= params.WindowBlocks
}

// Sticky returns the ticket sticky commitments (sticky_anchor_sequence, sticky_run_count) of rank:
// the promoted previous winner's ticket continues its run; every other ticket starts a new run at
// this order.
func (o *Order) Sticky(rank uint32) (anchorSequence uint64, runCount uint32) {
	if o.StickyApplied && rank == 0 {
		return o.anchorSequence, o.runCount
	}
	return o.sequence, 1
}

// Candidate is one dispatch attempt target: a member of the order that is in the round's roster.
type Candidate struct {
	Rank                 uint32
	Member               dispatch.RosterMember
	StickyAnchorSequence uint64
	StickyRunCount       uint32
}

// Next returns the first member at rank from or later that is in roster. Members not in roster
// are skipped: they are not attempts and do not count as skips.
func (o *Order) Next(roster *Roster, from uint32) (Candidate, bool) {
	for c := range o.Candidates(roster, from) {
		return c, true
	}
	return Candidate{}, false
}

// Candidates yields, in rank order from rank from, the members of the order that are in roster.
func (o *Order) Candidates(roster *Roster, from uint32) iter.Seq[Candidate] {
	return func(yield func(Candidate) bool) {
		for i := uint64(from); i < uint64(len(o.Members)); i++ {
			m := o.Members[i]
			if !roster.Contains(m) {
				continue
			}
			rank := uint32(i)
			seq, run := o.Sticky(rank)
			if !yield(Candidate{Rank: rank, Member: m, StickyAnchorSequence: seq, StickyRunCount: run}) {
				return
			}
		}
	}
}
