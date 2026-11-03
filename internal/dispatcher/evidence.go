package dispatcher

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
)

// Evidence keeps the evidence of the orders this Builder dispatched after they leave the
// dispatcher (dispatchevidence.Store): the claims and challenges on them are answered from it.
type Evidence interface {
	// Put stores the evidence with extra written in the same batch.
	Put(o *dispatchevidence.Order, extra ...kv.WriteOp) error
}

// saveWithEvidence stores the order's state together with its evidence: an accepted order with
// its record, a failed one with a record without a winner. Evidence that cannot be built is
// logged and the state is stored alone. Caller holds the order's lock.
func (d *Dispatcher) saveWithEvidence(st *orderState) error {
	op, err := saveStateOp(st)
	if err != nil {
		return err
	}
	return d.putEvidence(st, 0, op, func() error { return saveState(d.cfg.Store, st) })
}

// putEvidence writes the order's evidence (recorded at recordedHeight when non-zero) with op; it
// falls back to alone when there is no evidence to write. Caller holds the order's lock.
func (d *Dispatcher) putEvidence(st *orderState, recordedHeight uint64, op kv.WriteOp, alone func() error) error {
	if d.cfg.Evidence == nil {
		return alone()
	}
	ev, err := d.evidenceOf(st, recordedHeight)
	if err != nil {
		d.log.Error("dispatch evidence not built; claims on the order cannot be rebutted", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
		return alone()
	}
	if ev == nil {
		return alone()
	}
	if err := d.cfg.Evidence.Put(ev, op); err != nil {
		return fmt.Errorf("write dispatch state with its evidence: %w", err)
	}
	if d.cfg.Sync != nil {
		d.cfg.Sync.OrderChanged(ev)
	}
	return nil
}

// OrderSync hands the evidence of the orders this Builder dispatches to the other members of each
// order's Task Builders group (buildersync.Sender).
type OrderSync interface {
	// OrderChanged is called with the order's evidence after every stored change of it, with the
	// order's lock held: it must not block.
	OrderChanged(o *dispatchevidence.Order)
}

// save stores the order's state and hands the change to the group sync. Caller holds the order's
// lock.
func (d *Dispatcher) save(st *orderState) error {
	if err := saveState(d.cfg.Store, st); err != nil {
		return err
	}
	d.syncOrder(st)
	return nil
}

// syncOrder hands the order as it stands to the group sync; its record, when it has none yet, is
// left out rather than signed. Caller holds the order's lock, or the order is not live yet.
func (d *Dispatcher) syncOrder(st *orderState) {
	if d.cfg.Sync == nil {
		return
	}
	ev, err := d.evidenceView(st, 0)
	if err != nil {
		d.log.Warn("dispatch state not synced to the group", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
		return
	}
	if ev != nil {
		d.cfg.Sync.OrderChanged(ev)
	}
}

// evidenceOf is the evidence of the order as it stands; nil when no ticket was issued. An order
// without a stored record gets one with no winner, signed now. Caller holds the order's lock.
func (d *Dispatcher) evidenceOf(st *orderState, recordedHeight uint64) (*dispatchevidence.Order, error) {
	ev, err := d.evidenceView(st, recordedHeight)
	if err != nil || ev == nil {
		return ev, err
	}
	var last []byte
	for _, r := range ev.Rounds {
		if n := len(r.Attempts); n > 0 {
			last = r.Attempts[n-1].Ticket
		}
	}
	if len(ev.Record) == 0 && last != nil {
		var ticket taskv1.DispatchTicketV1
		if err := proto.Unmarshal(last, &ticket); err != nil {
			return nil, fmt.Errorf("stored ticket: %w", err)
		}
		if ev.Record, err = d.recordWithoutWinner(st, &ticket); err != nil {
			return nil, err
		}
	}
	return ev, nil
}

// evidenceView is the evidence of the order as it stands, with the stored record only; nil when no
// ticket was issued. Caller holds the order's lock.
func (d *Dispatcher) evidenceView(st *orderState, recordedHeight uint64) (*dispatchevidence.Order, error) {
	if len(st.Rounds) == 0 || st.Epoch == nil {
		return nil, nil
	}
	signed, err := st.signedOrder()
	if err != nil {
		return nil, err
	}
	esh := signed.GetOrder().GetEarliestSubmitHeight()
	ev := &dispatchevidence.Order{
		SessionID: st.SessionID, Sequence: st.Sequence, TaskID: st.TaskID, TaskHash: st.TaskHash, Epoch: st.Epoch.Number,
		SignedOrder: st.SignedOrder, DeadlineBase: esh, Accept: st.Accept, Record: st.Record,
		Recorded: recordedHeight > 0 && len(st.Record) > 0, RecordedHeight: recordedHeight, Windows: st.Windows,
	}
	if !ev.Recorded {
		ev.RecordedHeight = 0
	}
	for _, r := range st.Rounds {
		round := dispatchevidence.Round{Number: r.Number, RootDigest: r.RootDigest, Roster: r.Roster}
		for _, a := range r.Attempts {
			var ticket taskv1.DispatchTicketV1
			if err := proto.Unmarshal(a.Ticket, &ticket); err != nil {
				return nil, fmt.Errorf("stored ticket of rank %d: %w", a.Rank, err)
			}
			if round.RosterHash == nil {
				round.RosterHash = ticket.GetRosterHash()
			}
			ev.BoundChangeHeight = ticket.GetBoundChangeHeight()
			ev.DeadlineBase = max(ev.DeadlineBase, ticket.GetBoundChangeHeight())
			round.Attempts = append(round.Attempts, dispatchevidence.Attempt{
				Ticket: a.Ticket, Hash: a.Hash, Rank: a.Rank, Operator: a.Operator, Sent: a.Sent, Outcome: a.Outcome,
				Reject: a.Reject, LateAccept: a.LateAccept,
			})
		}
		ev.Rounds = append(ev.Rounds, round)
	}
	return ev, nil
}

// recordWithoutWinner signs the record of an order that has no winner. It is refused while an
// attempt is still out or ACCEPTED: this Builder never signs a record that shows an attempt it
// has not decided, or a second winner.
func (d *Dispatcher) recordWithoutWinner(st *orderState, last *taskv1.DispatchTicketV1) ([]byte, error) {
	for _, r := range st.Rounds {
		for _, a := range r.Attempts {
			if a.Outcome == outcomeAccepted || a.Outcome == taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED {
				return nil, fmt.Errorf("attempt of rank %d is %s; no record without a winner is signed", a.Rank, a.Outcome)
			}
		}
	}
	record, err := buildRecord(d.cfg.ChainID, d.cfg.Builder, st, last, make([]byte, 32))
	if err != nil {
		return nil, err
	}
	raw, _, err := signRecord(d.cfg.Signer.Key(), record)
	return raw, err
}

// BoundRoots returns the handraise roots the rounds of the orders still held bind. Such a root may
// not be in any evidence yet and must not be pruned.
func (d *Dispatcher) BoundRoots() map[[32]byte]bool {
	d.mu.Lock()
	orders := make([]*order, 0, len(d.orders))
	for _, o := range d.orders {
		orders = append(orders, o)
	}
	d.mu.Unlock()
	out := map[[32]byte]bool{}
	for _, o := range orders {
		o.mu.Lock()
		for _, r := range o.st.Rounds {
			if len(r.RootDigest) == 32 {
				out[[32]byte(r.RootDigest)] = true
			}
		}
		o.mu.Unlock()
	}
	return out
}
