package dispatcher

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
)

const (
	outcomeAccepted = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_ACCEPTED
	outcomeRejected = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED
	outcomeTimeout  = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_TIMEOUT
	outcomeVoided   = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_VOIDED
)

// recordLeadBlocks is how far ahead of its record deadline an order must be accepted: an entry
// accepted while the head is h goes out with the record transaction of block h+1 and lands in
// block h+2 at the earliest.
const recordLeadBlocks = 2

// TooLateToRecord reports whether an entry accepted with the chain head at head can no longer be
// recorded by deadline. No ticket is issued and no accept taken then: a late record is charged to
// the Builder.
func TooLateToRecord(head, deadline uint64) bool { return head+recordLeadBlocks > deadline }

// recordDeadline is the last height the order can be recorded at: its deadline in the ledger
// and, while another Builder's takeover of its session is registered, the takeover's activation
// height (records of that block are admitted before EndBlock moves the binding; a later record
// is refused and its Worker claims compensation).
// A session state that cannot be read leaves the ledger deadline.
func (d *Dispatcher) recordDeadline(ctx context.Context, st *orderState) (uint64, bool) {
	entry, ok := d.cfg.Ledger.Get(st.SessionID, st.Sequence)
	if !ok {
		return 0, false
	}
	deadline := entry.Deadline
	if s, _, err := d.cfg.Sessions.Lookup(ctx, st.SessionID); err == nil && s.Found {
		if t := s.PendingTakeover; t != nil && t.CandidateBuilder != d.cfg.Builder && t.ActivationHeight > 0 {
			deadline = min(deadline, t.ActivationHeight)
		}
	}
	return deadline, true
}

// done is what a step leaves for after the order's lock is released.
type done struct {
	// accepted and failed name an order that left DISPATCHING; the observer and the Recorder are
	// told and the parked orders of the session go on.
	accepted *Bundle
	worker   string
	ticket   [32]byte
	failed   error
	session  string
	sequence uint64
	taskID   string
}

// advance runs one step of an order and acts on its outcome.
func (d *Dispatcher) advance(ctx context.Context, key string) {
	o := d.get(key)
	if o == nil {
		return
	}
	o.mu.Lock()
	out := d.step(ctx, o)
	o.mu.Unlock()
	d.finish(ctx, out)
}

// finish tells the observer and the Recorder about an order that left DISPATCHING. It runs with
// no order locked.
func (d *Dispatcher) finish(ctx context.Context, out done) {
	switch {
	case out.accepted != nil:
		d.cfg.Observer.DispatchAccepted(out.session, out.taskID, out.ticket, out.worker)
		if err := d.cfg.Recorder.Record(ctx, out.accepted); err != nil {
			d.log.Error("dispatch entry not handed to the recorder", "session_id", out.session, "order_sequence", out.sequence, "err", err)
		}
	case out.failed != nil:
		d.cfg.Observer.DispatchFailed(out.session, out.taskID, out.failed)
	default:
		return
	}
	d.kickParked(out.session)
}

// kickParked lets the parked orders of a session try again: an earlier order of it was decided.
func (d *Dispatcher) kickParked(sessionID string) {
	for _, o := range d.sessionOrders(sessionID) {
		o.mu.Lock()
		parked := o.parked
		o.mu.Unlock()
		if parked {
			d.kick(o.key())
		}
	}
}

// onBlock lets every parked order try again at a new head.
func (d *Dispatcher) onBlock() {
	d.mu.Lock()
	orders := make([]*order, 0, len(d.orders))
	for _, o := range d.orders {
		orders = append(orders, o)
	}
	d.mu.Unlock()
	for _, o := range orders {
		o.mu.Lock()
		parked := o.parked
		o.mu.Unlock()
		if parked {
			d.kick(o.key())
		}
	}
}

// HandleChainEvent follows the head and the bindings of the sessions this Builder dispatches for.
// The caller feeds it every chain event.
func (d *Dispatcher) HandleChainEvent(ev chaincli.ChainEvent) {
	if ev.Type == chaincli.EventNewBlock {
		d.onBlock()
		return
	}
	if t, ok := ev.Typed.(chaincli.SessionBuilderBound); ok {
		d.onBound(context.Background(), t.SessionID, t.NewBuilder, t.BoundChangeHeight)
	}
}

// step issues the order's next ticket, if it may: no ticket is out, the order still dispatches,
// its record deadline is ahead and this Builder's key may issue tickets. It walks past members
// that cannot be reached until one is offered or the order fails. Caller holds o.mu.
func (d *Dispatcher) step(ctx context.Context, o *order) done {
	st := o.st
	o.parked = false
	for {
		if st.Phase != phaseDispatching || st.pending() != nil {
			return done{}
		}
		if deadline, ok := d.recordDeadline(ctx, st); ok && TooLateToRecord(d.cfg.Sessions.Head(), deadline) {
			return d.fail(o, fmt.Errorf("%w: deadline %d", ErrRecordDeadline, deadline))
		}
		if err := d.cfg.Keys.CheckBuilderKey(ctx); err != nil {
			switch {
			case errors.Is(err, handraise.ErrBuilderRotationPending):
				d.log.Info("no ticket issued: this Builder's service key rotation is pending", "session_id", st.SessionID, "order_sequence", st.Sequence)
			case errors.Is(err, ErrCompensationUnread):
				d.log.Warn("no ticket issued: this Builder's compensation account is not read yet", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			case errors.Is(err, ErrCompensationBelowMin):
				d.log.Warn("no ticket issued: this Builder's compensation account is below its minimum", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			default:
				d.log.Warn("no ticket issued: Builder service key not confirmed", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
			o.parked = true
			return done{}
		}
		if o.draw == nil || st.NewRound || o.roster == nil || !roundStored(o) {
			ready, out := d.openRound(ctx, o)
			if !ready {
				return out
			}
		}
		params := d.params.Load()
		if st.Skips > params.MaxSkips {
			return d.fail(o, fmt.Errorf("%w: %d skips", dispatchdraw.ErrNoCapacity, st.Skips))
		}
		cand, ok := o.draw.Next(o.roster, st.Cursor)
		if !ok {
			return d.fail(o, fmt.Errorf("%w: no member of round %d left after rank %d", dispatchdraw.ErrNoCapacity, o.rosterRound, st.Cursor))
		}
		offered, err := d.issue(ctx, o, cand)
		if err != nil {
			d.log.Error("ticket not issued", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			o.parked = true
			return done{}
		}
		if offered {
			return done{}
		}
	}
}

// roundStored reports whether the round in use already holds a ticket. Until it does, its roster
// is not bound yet: the next attempt opens it again from the then latest root (and, for round 0,
// decides stickiness again). Caller holds o.mu.
func roundStored(o *order) bool {
	rounds := o.st.Rounds
	return len(rounds) > 0 && rounds[len(rounds)-1].Number == o.rosterRound
}

// openRound prepares the round the next ticket belongs to. After a restart it is the stored last
// round. Otherwise the order is drawn when it has no draw yet (round 0, which also decides
// stickiness) and a new round binds the latest signed root. It returns false when the order must
// wait (it is then parked) or failed. Caller holds o.mu.
func (d *Dispatcher) openRound(ctx context.Context, o *order) (bool, done) {
	st := o.st
	if o.draw != nil && !st.NewRound && len(st.Rounds) > 0 && o.roster == nil {
		last := st.Rounds[len(st.Rounds)-1]
		var msg taskv1.DispatchRosterV1
		if err := proto.Unmarshal(last.Roster, &msg); err != nil {
			return false, d.fail(o, fmt.Errorf("stored roster of round %d: %w", last.Number, err))
		}
		roster, err := dispatchdraw.RestoreRoster(d.cfg.ChainID, [32]byte(last.RootDigest), &msg)
		if err != nil {
			return false, d.fail(o, err)
		}
		o.roster, o.rosterRound = roster, last.Number
		return true, done{}
	}
	signedOrder := o.signed.GetOrder()
	esh := signedOrder.GetEarliestSubmitHeight()
	head := d.cfg.Sessions.Head()
	if head < esh {
		o.parked = true
		return false, done{}
	}
	session, _, err := d.cfg.Sessions.Lookup(ctx, st.SessionID)
	if err != nil || !session.Found {
		d.log.Warn("order waits: session state unreadable", "session_id", st.SessionID, "err", err)
		o.parked = true
		return false, done{}
	}
	if session.BoundBuilder != d.cfg.Builder {
		return false, d.fail(o, fmt.Errorf("%w: bound to %s", ErrBoundElsewhere, session.BoundBuilder))
	}
	params := d.params.Load()
	profile := dispatchdraw.Profile{ModelID: [32]byte(signedOrder.GetModelId()), Version: signedOrder.GetProfileVersion()}
	draw, err := d.cfg.Drawer.Draw(ctx, [32]byte(signedOrder.GetSessionId()), st.Sequence, esh, profile, params.MaxDrawAttempts)
	if errors.Is(err, dispatchdraw.ErrNoCapacity) {
		return false, d.fail(o, err)
	}
	if err != nil {
		d.log.Warn("order waits: draw failed", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
		o.parked = true
		return false, done{}
	}
	// Stickiness is decided against the roster round 0 binds. Until round 0 holds a ticket (a first
	// ticket not issued, or a restart with the draw stored but no round) it is decided again.
	fresh := o.draw == nil || st.Epoch == nil || st.Epoch.Number != draw.Epoch.Number || len(st.Rounds) == 0
	var sticky *taskv1.DispatchStickySnapshotV1
	if fresh {
		var wait bool
		sticky, wait = d.stickySnapshot(o, session)
		if wait {
			o.parked = true
			return false, done{}
		}
	}
	root, _ := d.cfg.Handraises.LatestRoot()
	roster, err := dispatchdraw.BuildRoster(d.cfg.ChainID, [32]byte(mustHex(st.TaskID)), root, draw.Pool, head, params.MaxRosterBytes)
	if err != nil {
		return false, d.fail(o, err)
	}
	if fresh {
		ord, err := dispatchdraw.NewOrder(draw.Drawn, roster, sticky, params.Sticky, esh, st.Sequence)
		if err != nil {
			return false, d.fail(o, err)
		}
		anchor, run := ord.Sticky(0)
		st.Epoch = &epochState{
			Number: draw.Epoch.Number, ReferenceHeight: draw.Epoch.ReferenceHeight, SnapshotID: append([]byte(nil), draw.Epoch.SnapshotID[:]...),
			VRFOutput: append([]byte(nil), draw.VRF.Output[:]...), VRFProof: append([]byte(nil), draw.VRF.Proof...),
		}
		st.Members, st.StickyApplied, st.StickyAnchor, st.StickyRun = ord.Members, ord.StickyApplied, anchor, run
		st.Cursor, st.Skips, st.Rounds = 0, 0, nil
		o.draw = ord
	}
	o.roster, o.rosterRound = roster, nextRound(st)
	// bound_change_height only grows; a binding event may have been seen before the session read.
	st.BoundChangeHeight, st.NewRound = max(st.BoundChangeHeight, session.BoundChangeHeight), false
	return true, done{}
}

func nextRound(st *orderState) uint32 {
	if len(st.Rounds) == 0 {
		return 0
	}
	return st.Rounds[len(st.Rounds)-1].Number + 1
}

// cortexPending reports whether operator's key rotation is pending; an unreadable key counts as
// pending, so no ticket goes to a Worker the chain may refuse.
func (d *Dispatcher) cortexPending(ctx context.Context, operator string) bool {
	pending, err := d.cfg.Keys.CortexRotationPending(ctx, operator)
	if err != nil {
		d.log.Warn("Cortex key unreadable; its ticket times out unsent", "operator", operator, "err", err)
		return true
	}
	return pending
}

// issue signs the ticket of cand, stores it and offers it. A member that cannot be reached now
// (no stream, or its key rotation is pending: the chain refuses a dispatch entry naming it as
// winner) still gets its ticket, which times out at once: every roster member ranked before the winner must have an
// attempt. It reports whether a ticket went out. Caller holds o.mu.
func (d *Dispatcher) issue(ctx context.Context, o *order, cand dispatchdraw.Candidate) (bool, error) {
	st := o.st
	operator := cand.Member.OperatorAddress
	rtt, measured := d.cfg.Streams.RTT(operator)
	rttMs := uint64(rtt / time.Millisecond)
	if !measured {
		// Without a measurement the slowest tier applies: a fast deadline would only time out a
		// Worker that might have answered.
		rttMs = ^uint64(0)
	}
	tier, timeoutMs := d.cfg.Dispatch.AcceptTimeoutTier(rttMs)
	now := d.clock.Now()
	deadlineMs := uint64(now.UnixMilli()) + timeoutMs
	ticket := d.ticket(o, cand, deadlineMs)
	raw, hash, err := signTicket(d.cfg.Signer, ticket)
	if err != nil {
		return false, err
	}
	reachable := d.cfg.Streams.Connected(operator) && !d.cortexPending(ctx, operator)
	prev := cloneState(st)
	if len(st.Rounds) == 0 || st.Rounds[len(st.Rounds)-1].Number != o.rosterRound {
		rosterRaw, err := marshal(o.roster.Msg)
		if err != nil {
			return false, err
		}
		st.Rounds = append(st.Rounds, roundState{Number: o.rosterRound, RootDigest: append([]byte(nil), o.roster.RootDigest[:]...), Roster: rosterRaw})
	}
	round := &st.Rounds[len(st.Rounds)-1]
	a := attemptState{Ticket: raw, Hash: append([]byte(nil), hash[:]...), Rank: cand.Rank, Operator: operator, DeadlineMs: deadlineMs, Tier: tier, Sent: reachable}
	if !reachable {
		a.Outcome = outcomeTimeout
		st.Skips++
	}
	round.Attempts = append(round.Attempts, a)
	st.Cursor = cand.Rank + 1
	if err := saveState(d.cfg.Store, st); err != nil {
		*st = *prev
		return false, err
	}
	d.indexTicket(o, hash)
	if !reachable {
		d.log.Info("dispatch member unreachable; ticket timed out unsent", "session_id", st.SessionID, "order_sequence", st.Sequence, "rank", cand.Rank, "operator", operator)
		return false, nil
	}
	frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{Ticket: ticket, SignedOrder: o.signed}}}
	if err := d.cfg.Streams.Send(ctx, operator, frame); err != nil {
		d.log.Info("dispatch offer not sent; ticket timed out", "session_id", st.SessionID, "order_sequence", st.Sequence, "operator", operator, "err", err)
		a := &round.Attempts[len(round.Attempts)-1]
		a.Sent = false
		d.timeoutLocked(o, a, false)
		return false, nil
	}
	d.armTimer(o, hash, time.Duration(timeoutMs)*time.Millisecond)
	return true, nil
}

// ticket is the unsigned DispatchTicketV1 of cand. Every field but rank, target, deadline and the
// sticky commitments is shared by all tickets of the order in its epoch and round.
func (d *Dispatcher) ticket(o *order, cand dispatchdraw.Candidate, deadlineMs uint64) *taskv1.DispatchTicketV1 {
	st, signedOrder := o.st, o.signed.GetOrder()
	return &taskv1.DispatchTicketV1{
		SchemaVersion:           schemaVersion,
		ChainId:                 d.cfg.ChainID,
		TaskId:                  mustHex(st.TaskID),
		TaskHash:                mustHex(st.TaskHash),
		SessionId:               append([]byte(nil), signedOrder.GetSessionId()...),
		OrderSequence:           st.Sequence,
		BuilderAddress:          d.cfg.Builder,
		ReferenceHeight:         st.Epoch.ReferenceHeight,
		CandidatePoolSnapshotId: append([]byte(nil), st.Epoch.SnapshotID...),
		VrfEpoch:                st.Epoch.Number,
		VrfOutput:               append([]byte(nil), st.Epoch.VRFOutput...),
		VrfProof:                append([]byte(nil), st.Epoch.VRFProof...),
		RandomnessScheme:        taskv1.DispatchRandomnessSchemeV1_DISPATCH_RANDOMNESS_SCHEME_V1_BUILDER_VRF,
		RosterHash:              append([]byte(nil), o.roster.Hash[:]...),
		HandraiseRootDigest:     append([]byte(nil), o.roster.RootDigest[:]...),
		DispatchRound:           o.rosterRound,
		Rank:                    cand.Rank,
		Target:                  memberRef(st.Epoch.SnapshotID, cand.Member),
		AcceptDeadlineMs:        deadlineMs,
		InputHash:               append([]byte(nil), signedOrder.GetInputHash()...),
		BoundChangeHeight:       st.BoundChangeHeight,
		StickyAnchorSequence:    cand.StickyAnchorSequence,
		StickyRunCount:          cand.StickyRunCount,
	}
}

func (d *Dispatcher) armTimer(o *order, hash [32]byte, after time.Duration) {
	if o.timer != nil {
		o.timer.Stop()
	}
	key := o.key()
	o.timer = d.clock.AfterFunc(max(after, 0), func() { d.onTimeout(key, hash) })
}

// onTimeout ends a ticket still out at its accept deadline and walks on.
func (d *Dispatcher) onTimeout(key string, hash [32]byte) {
	d.mu.Lock()
	stopped := d.stopped
	d.mu.Unlock()
	o := d.get(key)
	if o == nil || stopped {
		return
	}
	o.mu.Lock()
	a := o.st.pending()
	if a == nil || string(a.Hash) != string(hash[:]) {
		o.mu.Unlock()
		return
	}
	if now := uint64(d.clock.Now().UnixMilli()); now < a.DeadlineMs {
		d.armTimer(o, hash, time.Duration(a.DeadlineMs-now)*time.Millisecond)
		o.mu.Unlock()
		return
	}
	d.timeoutLocked(o, a, true)
	out := d.step(context.Background(), o)
	o.mu.Unlock()
	d.finish(context.Background(), out)
}

// timeoutLocked marks a ticket TIMEOUT. A ticket the Worker received counts in its reject-rate
// denominator as not rejected. Caller holds o.mu.
func (d *Dispatcher) timeoutLocked(o *order, a *attemptState, received bool) {
	a.Outcome = outcomeTimeout
	o.st.Skips++
	if err := saveState(d.cfg.Store, o.st); err != nil {
		d.log.Error("ticket timeout not written", "session_id", o.st.SessionID, "order_sequence", o.st.Sequence, "err", err)
	}
	if received {
		d.recordOutcome(a.Operator, false)
	}
}

// recordOutcome feeds the Worker's reject rate: every ticket it received counts, and rejected is
// a signed reject while it advertised a free slot.
func (d *Dispatcher) recordOutcome(operator string, rejected bool) {
	if err := d.cfg.Handraises.RecordOutcome(operator, d.cfg.Sessions.Head(), rejected); err != nil {
		d.log.Warn("reject-rate outcome not recorded", "operator", operator, "err", err)
	}
}

// fail ends the order without a winner. The sequence is not used; its ledger entry fails, so a
// resend is a retry. Caller holds o.mu.
func (d *Dispatcher) fail(o *order, reason error) done {
	st := o.st
	if o.timer != nil {
		o.timer.Stop()
	}
	st.Phase, st.FailReason = phaseFailed, reason.Error()
	o.parked = false
	if err := saveState(d.cfg.Store, st); err != nil {
		d.log.Error("failed dispatch not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
	}
	if err := d.cfg.Ledger.MarkFailed(st.SessionID, st.Sequence); err != nil && !errors.Is(err, inflight.ErrUnknownOrder) {
		d.log.Error("failed dispatch not written to the ledger", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
	}
	d.log.Info("dispatch failed", "session_id", st.SessionID, "order_sequence", st.Sequence, "reason", reason)
	return done{failed: reason, session: st.SessionID, sequence: st.Sequence, taskID: st.TaskID}
}

// onBound applies a binding change of a session. Bound to another Builder, its orders fail; bound
// here at a new bound_change_height, the tickets of the current round, out or accepted but not
// recorded, are VOIDED and the next ticket opens a new round committing the new height.
func (d *Dispatcher) onBound(ctx context.Context, sessionID, builder string, boundChangeHeight uint64) {
	for _, o := range d.sessionOrders(sessionID) {
		o.mu.Lock()
		st := o.st
		if st.Phase == phaseFailed || builder == d.cfg.Builder && st.BoundChangeHeight == boundChangeHeight {
			o.mu.Unlock()
			continue
		}
		if builder == d.cfg.Builder && len(st.Rounds) == 0 && st.Phase == phaseDispatching {
			// No ticket yet: nothing to void, but the first ticket must commit the new height even
			// if the session state read lags behind this event.
			st.BoundChangeHeight = max(st.BoundChangeHeight, boundChangeHeight)
			if err := saveState(d.cfg.Store, st); err != nil {
				d.log.Error("binding change not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
			o.mu.Unlock()
			continue
		}
		var out done
		out.session, out.sequence, out.taskID = st.SessionID, st.Sequence, st.TaskID
		if a := st.pending(); a != nil {
			a.Outcome = outcomeVoided
			if o.timer != nil {
				o.timer.Stop()
			}
		}
		if w := st.winner(); w != nil && st.Phase == phaseAccepted {
			// Withdrawn before anything of the new state is written: after a crash in between the
			// Recorder must not still send an entry the stored state no longer stands behind.
			d.cfg.Recorder.Withdraw(ctx, st.SessionID, st.Sequence, [32]byte(w.Hash))
			w.Outcome = outcomeVoided
			st.Phase, st.Accept, st.AcceptDigest, st.Record = phaseDispatching, nil, nil, nil
			if err := d.cfg.Ledger.MarkDispatching(st.SessionID, st.Sequence); err != nil {
				d.log.Error("voided accept not written to the ledger", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
		}
		if builder != d.cfg.Builder {
			failed := d.fail(o, fmt.Errorf("%w: bound to %s", ErrBoundElsewhere, builder))
			out.failed = failed.failed
		} else {
			st.NewRound = true
			if err := saveState(d.cfg.Store, st); err != nil {
				d.log.Error("voided tickets not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
			d.log.Info("binding changed; tickets voided, new round", "session_id", st.SessionID, "order_sequence", st.Sequence, "bound_change_height", boundChangeHeight)
			stepOut := d.step(ctx, o)
			out.accepted, out.failed = stepOut.accepted, stepOut.failed
		}
		o.mu.Unlock()
		d.finish(ctx, out)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
