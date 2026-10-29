package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// errLost fails a committed order whose dispatch state did not survive a restart.
var errLost = errors.New("dispatch state lost across a restart")

// recover resumes what a previous run left, matching the stored dispatch states with the ledger:
//
//   - a state whose ledger entry is committed and DISPATCHING or ACCEPTED (the same task_hash)
//     resumes: a ticket still out waits for the rest of its deadline (the stream hub replays the
//     offer as stored), an expired one times out, an accepted order goes to the Recorder again;
//   - a FAILED state is kept while its ledger entry is FAILED, for a retry to continue it;
//   - any other state is dropped: its order was never committed, so no ticket of it went out, or
//     it is recorded;
//   - a committed DISPATCHING or ACCEPTED ledger entry without a state is marked failed: nothing
//     remembers its tickets.
func (d *Dispatcher) recover(ctx context.Context) error {
	states, err := loadStates(d.cfg.Store)
	if err != nil {
		return err
	}
	var resume []*order
	var accepted []*Bundle
	for _, st := range states {
		entry, ok := d.cfg.Ledger.Get(st.SessionID, st.Sequence)
		live := ok && entry.Committed && entry.TaskHash == st.TaskHash &&
			(entry.State == inflight.StateDispatching || entry.State == inflight.StateAccepted)
		keepFailed := ok && st.Phase == phaseFailed && entry.State == inflight.StateFailed
		if !live && !keepFailed {
			if err := d.dropStale(st, entry, ok); err != nil {
				return fmt.Errorf("drop stale dispatch state: %w", err)
			}
			continue
		}
		o, err := restoreOrder(st)
		if err != nil {
			return fmt.Errorf("dispatch state %s/%d: %w", st.SessionID, st.Sequence, err)
		}
		d.register(o)
		switch {
		case !live:
		case st.Phase == phaseFailed:
			if err := d.cfg.Ledger.MarkFailed(st.SessionID, st.Sequence); err != nil {
				return fmt.Errorf("fail in-flight order: %w", err)
			}
		case st.Phase == phaseAccepted:
			if err := d.cfg.Ledger.MarkAccepted(st.SessionID, st.Sequence); err != nil {
				return fmt.Errorf("accept in-flight order: %w", err)
			}
			b, err := d.bundle(st, d.recordDeadline(o, entry.Deadline))
			if err != nil {
				return fmt.Errorf("dispatch state %s/%d: %w", st.SessionID, st.Sequence, err)
			}
			accepted = append(accepted, b)
		default:
			if entry.State == inflight.StateAccepted {
				// The accept was voided just before the restart.
				if err := d.cfg.Ledger.MarkDispatching(st.SessionID, st.Sequence); err != nil {
					return fmt.Errorf("resume in-flight order: %w", err)
				}
			}
			resume = append(resume, o)
		}
	}
	for _, e := range d.cfg.Ledger.Unfinished() {
		if d.get(stateKey(e.SessionID, e.Sequence)) != nil {
			continue
		}
		if err := d.cfg.Ledger.MarkFailed(e.SessionID, e.Sequence); err != nil {
			return fmt.Errorf("fail in-flight order: %w", err)
		}
		d.log.Warn("in-flight order without dispatch state marked failed", "session_id", e.SessionID, "order_sequence", e.Sequence)
		d.cfg.Observer.DispatchFailed(e.SessionID, e.TaskID, errLost)
	}
	for _, b := range accepted {
		d.accepted(b)
		if err := d.cfg.Recorder.Record(ctx, b); err != nil {
			d.log.Error("dispatch entry not handed to the recorder", "session_id", b.SessionID, "order_sequence", b.Sequence, "err", err)
		}
	}
	for _, o := range resume {
		o.mu.Lock()
		a := o.st.pending()
		if a == nil {
			o.mu.Unlock()
			d.kick(o.key())
			continue
		}
		now := uint64(d.clock.Now().UnixMilli())
		remaining := time.Duration(0)
		if a.DeadlineMs > now {
			remaining = time.Duration(a.DeadlineMs-now) * time.Millisecond
		}
		d.armTimer(o, [32]byte(a.Hash), remaining)
		o.mu.Unlock()
	}
	return nil
}

// dropStale deletes a state that is no longer live. An accepted order the ledger shows recorded,
// or no longer holds, was recorded after its last write (the evidence write of Recorded failed,
// or the process stopped in between): its evidence is marked recorded in the same write, at the
// order's record deadline, which is not below the recorded height.
func (d *Dispatcher) dropStale(st *orderState, entry inflight.Entry, inLedger bool) error {
	recorded := st.Phase == phaseAccepted && (!inLedger || entry.State == inflight.StateRecorded)
	if !recorded {
		return deleteState(d.cfg.Store, st.SessionID, st.Sequence)
	}
	height := entry.Deadline
	if !inLedger {
		height = d.cfg.Sessions.Head()
	}
	return d.putEvidence(st, max(height, 1), deleteStateOp(st.SessionID, st.Sequence), func() error {
		return deleteState(d.cfg.Store, st.SessionID, st.Sequence)
	})
}

// restoreOrder rebuilds an order's in-memory parts from its stored state. The round's roster is
// restored when the next ticket needs it.
func restoreOrder(st *orderState) (*order, error) {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(st.SignedOrder, &signed); err != nil {
		return nil, fmt.Errorf("stored signed order: %w", err)
	}
	o := &order{st: st, signed: &signed}
	if len(st.Members) > 0 {
		ord, err := dispatchdraw.RestoreOrder(st.Members, st.StickyApplied, st.Sequence, st.StickyAnchor, st.StickyRun)
		if err != nil {
			return nil, err
		}
		o.draw = ord
	}
	return o, nil
}
