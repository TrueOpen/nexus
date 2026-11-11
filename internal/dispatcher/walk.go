package dispatcher

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
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

// liveRecordDeadline is the last height the order can be recorded at: its recordDeadline (never
// past order_expire_height) and,
// while another Builder's takeover of its session is registered, the takeover's activation
// height (records of that block are admitted before EndBlock moves the binding; a later record
// is refused and its Worker claims compensation).
// A session state that cannot be read leaves the recordDeadline. Caller holds o.mu.
func (d *Dispatcher) liveRecordDeadline(ctx context.Context, o *order) (uint64, bool) {
	entry, ok := d.cfg.Ledger.Get(o.st.SessionID, o.st.Sequence)
	if !ok {
		return 0, false
	}
	deadline := d.recordDeadline(o, entry)
	if s, _, err := d.cfg.Sessions.Lookup(ctx, o.st.SessionID); err == nil && s.Found {
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
	// readHead asks for a chain head read: the order waits for its earliest_submit_height.
	readHead bool
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
// no order locked. The winner of an accepted order is already in the attempt book.
func (d *Dispatcher) finish(ctx context.Context, out done) {
	if out.readHead {
		d.readHeadLater()
	}
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

// finishLater runs finish off the caller's goroutine. The accept handler uses it so the stream
// acknowledges the accept and reads the Worker's next frame, its input request, without waiting
// for the observer's and the Recorder's writes. A crash before they ran loses nothing the restart
// does not rebuild: recover hands every accepted order to the Recorder again, and the observer's
// DISPATCH_ACCEPTED event was never kept across a crash between the accept and its write.
func (d *Dispatcher) finishLater(out done) {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		d.finish(context.Background(), out)
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	run := func() {
		defer d.wg.Done()
		d.finish(context.Background(), out)
	}
	if d.cfg.Background != nil {
		d.cfg.Background(run)
		return
	}
	go run()
}

// accepted hands an accepted order's winner to the attempt book.
func (d *Dispatcher) accepted(b *Bundle) {
	w := attempt.Winner{
		SessionID: b.SessionID, Sequence: b.Sequence, User: b.Entry.GetSignedOrder().GetOrder().GetUserAddress(),
		Ticket: b.Entry.GetWinnerTicket(), Accept: b.Entry.GetAccept(),
	}
	d.book(w)
}

// book hands w to the attempt book. A failure other than a task recorded with another ticket is
// retried on the next block: until the book holds the winner its Worker cannot stream.
func (d *Dispatcher) book(w attempt.Winner) {
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	err := d.cfg.Attempts.Accepted(w)
	d.unbookedMu.Lock()
	defer d.unbookedMu.Unlock()
	switch {
	case err == nil, errors.Is(err, attempt.ErrRecordedWithAnotherTicket):
		if err != nil {
			d.log.Warn("accepted winner not booked: the task is recorded with another ticket", "session_id", w.SessionID, "order_sequence", w.Sequence, "err", err)
		}
		if cur, ok := d.unbooked[taskID]; ok && proto.Equal(cur.Ticket, w.Ticket) {
			delete(d.unbooked, taskID)
		}
	default:
		d.log.Error("accepted winner not given to the attempt book; retried on the next block", "session_id", w.SessionID, "order_sequence", w.Sequence, "err", err)
		if d.unbooked == nil {
			d.unbooked = map[string]attempt.Winner{}
		}
		d.unbooked[taskID] = w
	}
}

// retryUnbooked hands the attempt book the winners it could not take before.
func (d *Dispatcher) retryUnbooked() {
	d.unbookedMu.Lock()
	winners := make([]attempt.Winner, 0, len(d.unbooked))
	for _, w := range d.unbooked {
		winners = append(winners, w)
	}
	d.unbookedMu.Unlock()
	for _, w := range winners {
		d.book(w)
	}
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
	d.retryUnbooked()
	for _, o := range d.allOrders() {
		o.mu.Lock()
		parked := o.parked
		o.mu.Unlock()
		if parked {
			d.kick(o.key())
		}
	}
}

// kickESHWaiters lets the orders parked for their earliest_submit_height try again: a head read
// raised the head.
func (d *Dispatcher) kickESHWaiters() {
	for _, o := range d.allOrders() {
		o.mu.Lock()
		waits := o.parked && !o.eshWaitSince.IsZero()
		o.mu.Unlock()
		if waits {
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
// its record deadline is ahead, this Builder does not drain (unless the order is a takeover's)
// and its key may sign for the order: while its rotation is pending, only an order below the
// effective height (one at or above it waits for the cutover); while it is revoked, none (the
// order fails as no capacity, a takeover's too, since no ticket can be signed for it). It walks past members
// that cannot be reached until one is offered or the order fails. A pending Builder keeps signing
// roots below the effective height with its current key, so a round opened during the wait binds
// a fresh root. Caller holds o.mu.
func (d *Dispatcher) step(ctx context.Context, o *order) done {
	st := o.st
	o.parked = false
	for {
		if st.Phase != phaseDispatching || st.pending() != nil {
			return done{}
		}
		if deadline, ok := d.liveRecordDeadline(ctx, o); ok && TooLateToRecord(d.cfg.Sessions.Head(), deadline) {
			return d.fail(o, fmt.Errorf("%w: deadline %d", ErrRecordDeadline, deadline))
		}
		if d.draining() && !d.takeoverOrder(o) {
			return d.fail(o, fmt.Errorf("%w: %w", dispatchdraw.ErrNoCapacity, ErrDraining))
		}
		var rotation *handraise.RotationPendingError
		if err := d.cfg.Keys.CheckBuilderKey(ctx); err != nil && !(errors.As(err, &rotation) && o.signed.GetOrder().GetEarliestSubmitHeight() < rotation.EffectiveHeight) {
			switch {
			case errors.Is(err, servicekey.ErrRevoked):
				return d.fail(o, fmt.Errorf("%w: %w", dispatchdraw.ErrNoCapacity, err))
			case errors.Is(err, handraise.ErrBuilderRotationPending):
				d.log.Info("no ticket issued: the order waits for this Builder's service key cutover", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
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
			return d.fail(o, fmt.Errorf("%w: %d skips (%s)", dispatchdraw.ErrNoCapacity, st.Skips, st.skipSummary()))
		}
		cand, ok := o.draw.Next(o.roster, st.Cursor)
		if !ok {
			d.cfg.Metrics.Add(opsmetrics.CounterSkips, opsmetrics.SkipNotInRoster, uint64(len(o.draw.Members))-min(uint64(st.Cursor), uint64(len(o.draw.Members))))
			return d.fail(o, fmt.Errorf("%w: no member of round %d left after rank %d (%s)", dispatchdraw.ErrNoCapacity, o.rosterRound, st.Cursor, st.skipSummary()))
		}
		d.cfg.Metrics.Add(opsmetrics.CounterSkips, opsmetrics.SkipNotInRoster, uint64(cand.Rank-min(cand.Rank, st.Cursor)))
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

// takeoverOrder reports whether o is the order of a takeover that took effect: the takeover was
// on chain before a drain could stop it, so its order is walked through a drain. Caller holds
// o.mu.
func (d *Dispatcher) takeoverOrder(o *order) bool {
	entry, ok := d.cfg.Ledger.Get(o.st.SessionID, o.st.Sequence)
	return ok && entry.Takeover && entry.TaskHash == o.st.TaskHash
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
	// The precheck admits an order whose earliest_submit_height is at most one block above the
	// head, and it is dispatched at once: its record lands at earliest_submit_height at the
	// earliest anyway. A round never opens earlier, so a root that can prove an omission (at least
	// two blocks below earliest_submit_height) was signed before the round opened. The cached head
	// follows the chain's height events, which may trail the chain by a poll interval: the order
	// parks and asks for a head read, made once its lock is released (readHeadLater); a read that
	// raises the head tries it again before the next event.
	if head+1 < esh {
		if o.eshWaitSince.IsZero() {
			o.eshWaitSince = d.clock.Now()
			d.log.Debug("order waits for its earliest_submit_height", "session_id", st.SessionID, "order_sequence", st.Sequence,
				"earliest_submit_height", esh, "head", head)
		}
		o.parked = true
		return false, done{readHead: true}
	}
	if !o.eshWaitSince.IsZero() {
		d.log.Info("order waited for its earliest_submit_height", "session_id", st.SessionID, "order_sequence", st.Sequence,
			"earliest_submit_height", esh, "head", head, "wait_ms", d.clock.Now().Sub(o.eshWaitSince).Milliseconds())
		o.eshWaitSince = time.Time{}
	}
	if !o.waited && !o.takenAt.IsZero() {
		d.cfg.Metrics.ObserveStage(opsmetrics.StageWaitESH, d.clock.Now().Sub(o.takenAt))
	}
	o.waited = true
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
	drawStart := d.clock.Now()
	draw, err := d.cfg.Drawer.Draw(ctx, [32]byte(signedOrder.GetSessionId()), st.Sequence, esh, profile, params.MaxDrawAttempts)
	d.cfg.Metrics.ObserveStage(opsmetrics.StageDraw, d.clock.Now().Sub(drawStart))
	if errors.Is(err, dispatchdraw.ErrNoCapacity) {
		return false, d.fail(o, err)
	}
	if err != nil {
		d.log.Warn("order waits: draw failed", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
		o.parked = true
		return false, done{}
	}
	// bound_change_height only grows; a binding event may have been seen before the session read.
	bound := max(st.BoundChangeHeight, session.BoundChangeHeight)
	if stored, ok := roundsBinding(st); ok && stored != bound && !st.NewRound {
		// The session read shows a binding change before its event (which onBound then skips, the
		// order holding its height already): the generation ends here as onBound would end it,
		// stored with its evidence before the restart below drops its rounds.
		if err := d.endGeneration(ctx, o, bound); err != nil {
			d.log.Error("order waits: tickets of the ended binding generation not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			o.parked = true
			return false, done{}
		}
		d.log.Info("binding changed before its event; tickets voided, rounds restart", "session_id", st.SessionID, "order_sequence", st.Sequence, "bound_change_height", bound)
	}
	// A new epoch, or a binding generation other than the stored rounds' (a takeover took effect,
	// also one back to this Builder), restarts the order: its order, roster, rounds and counts
	// start from scratch under the same VRF output. The earlier generation's evidence was stored
	// when it ended (the order failed, or the binding change voided its tickets). Stickiness is
	// decided against the roster round 0 binds. Until round 0 holds a ticket (a first ticket not
	// issued, or a restart with the draw stored but no round) it is decided again.
	fresh := o.draw == nil || st.Epoch == nil || st.Epoch.Number != draw.Epoch.Number || len(st.Rounds) == 0
	if stored, ok := roundsBinding(st); !ok || stored != bound {
		fresh = true
	}
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
	if root != nil && root.Root.GetServiceAuthorizationNonce() != d.cfg.Signer.Key().Nonce {
		// A cutover just made another key current; the registry signs the same leaves again
		// under it, and a root of the retired key cannot prove an order at or above the cutover.
		d.log.Info("order waits: the latest handraise root is not signed by the current service key yet",
			"session_id", st.SessionID, "order_sequence", st.Sequence, "root_nonce", root.Root.GetServiceAuthorizationNonce())
		o.parked = true
		return false, done{}
	}
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
	st.BoundChangeHeight, st.NewRound = bound, false
	return true, done{}
}

// headRefreshTimeout bounds one chain head read of readHeadLater.
const headRefreshTimeout = time.Second

// readHeadLater reads the chain head off the caller's goroutine for the orders waiting for their
// earliest_submit_height, and tries them again when the read raised the head. It runs with no
// order locked, so a slow chain holds up no block event and no decided order kicking them; one
// read at most is under way, and the session cache spaces the reads of all orders
// (inflight.HeadRefreshInterval). An order parked while a read is under way is tried again when
// that read raised the head, or at the next block event.
func (d *Dispatcher) readHeadLater() {
	r, ok := d.cfg.Sessions.(headRefresher)
	if !ok || !d.headReading.CompareAndSwap(false, true) {
		return
	}
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		d.headReading.Store(false)
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	run := func() {
		defer d.wg.Done()
		before := d.cfg.Sessions.Head()
		ctx, cancel := context.WithTimeout(context.Background(), headRefreshTimeout)
		head, err := r.RefreshHead(ctx)
		cancel()
		d.headReading.Store(false)
		if err != nil {
			d.log.Debug("chain head not read for the orders waiting for their earliest_submit_height", "err", err)
		}
		if head > before {
			d.kickESHWaiters()
		}
	}
	if d.cfg.Background != nil {
		d.cfg.Background(run)
		return
	}
	go run()
}

// roundsBinding is the bound_change_height the stored rounds' tickets commit: every round of an
// order belongs to one binding generation. False without a stored ticket, or one that does not
// decode.
func roundsBinding(st *orderState) (uint64, bool) {
	for _, r := range st.Rounds {
		for _, a := range r.Attempts {
			var ticket taskv1.DispatchTicketV1
			if proto.Unmarshal(a.Ticket, &ticket) != nil {
				return 0, false
			}
			return ticket.GetBoundChangeHeight(), true
		}
	}
	return 0, false
}

func nextRound(st *orderState) uint32 {
	if len(st.Rounds) == 0 {
		return 0
	}
	return st.Rounds[len(st.Rounds)-1].Number + 1
}

// cortexPending reports whether operator's pending key rotation takes effect at or below esh: its
// answer, signed with its current key, no longer proves an order recorded after its cutover, and
// the next key cannot sign before it. An unreadable key counts as pending, so no ticket goes to a
// Worker whose answer may not verify.
func (d *Dispatcher) cortexPending(ctx context.Context, operator string, esh uint64) bool {
	effective, err := d.cfg.Keys.CortexRotation(ctx, operator)
	if err != nil {
		d.log.Warn("Cortex key unreadable; its ticket times out unsent", "operator", operator, "err", err)
		return true
	}
	return effective != 0 && esh >= effective
}

// issue signs the ticket of cand, stores it and offers it. A member that cannot be reached now
// (no stream, or its key rotation takes effect at or below the order's earliest_submit_height)
// still gets its ticket, which times out at once: every roster member ranked before the winner
// must have an attempt. A rotation pending when the round's root was signed already kept the
// member out of the roster (a not-admitted leaf); this covers one registered since. It reports
// whether a ticket went out. Caller holds o.mu.
//
// The accept window is the candidate's: accept_deadline_ms is stamped after everything that does
// not need it (the reachability check with its chain read of the Cortex key, the round's roster),
// so only signing the ticket, storing the order's state with it and handing the offer to the
// stream come out of the window; the ticket times out at that deadline. The order's evidence goes
// to the group sync after the offer.
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
	skip := ""
	switch {
	case !d.cfg.Streams.Connected(operator):
		skip = opsmetrics.SkipUnreachable
	case d.cortexPending(ctx, operator, o.signed.GetOrder().GetEarliestSubmitHeight()):
		skip = opsmetrics.SkipRotationPending
	}
	reachable := skip == ""
	var newRound *roundState
	if len(st.Rounds) == 0 || st.Rounds[len(st.Rounds)-1].Number != o.rosterRound {
		rosterRaw, err := marshal(o.roster.Msg)
		if err != nil {
			return false, err
		}
		newRound = &roundState{Number: o.rosterRound, EarliestSubmitHeight: o.signed.GetOrder().GetEarliestSubmitHeight(),
			RootDigest: append([]byte(nil), o.roster.RootDigest[:]...), Roster: rosterRaw}
	}
	now := d.clock.Now()
	deadlineMs := uint64(now.UnixMilli()) + timeoutMs
	ticket := d.ticket(o, cand, deadlineMs)
	raw, hash, err := signTicket(d.cfg.Signer.Key(), ticket)
	if err != nil {
		return false, err
	}
	prev := cloneState(st)
	if newRound != nil {
		st.Rounds = append(st.Rounds, *newRound)
	}
	round := &st.Rounds[len(st.Rounds)-1]
	a := attemptState{Ticket: raw, Hash: append([]byte(nil), hash[:]...), Rank: cand.Rank, Operator: operator, DeadlineMs: deadlineMs, Tier: tier, Sent: reachable}
	if !reachable {
		a.Outcome = outcomeTimeout
		st.Skips++
	}
	round.Attempts = append(round.Attempts, a)
	st.Cursor = cand.Rank + 1
	// The ticket of a reachable member is stored without waiting for the disk: the stream hub
	// stores the offer with a synced write before the offer can leave the process, which makes
	// the ticket durable first (kv.WriteDeferred). A crash before that loses a ticket nobody saw,
	// and the restart offers the candidate a new one. A ticket timed out unsent goes to the group
	// sync at once, so it is stored synced.
	save := saveState
	if reachable {
		save = saveStateDeferred
	}
	if err := save(d.cfg.Store, st); err != nil {
		*st = *prev
		return false, err
	}
	d.indexTicket(o, hash)
	o.ticketAt = now
	if !reachable {
		d.syncOrder(st)
		d.cfg.Metrics.Inc(opsmetrics.CounterSkips, skip)
		d.cfg.Metrics.WorkerOutcome(operator, tier, opsmetrics.OutcomeUnsent)
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
	// The ticket times out at its deadline, not a full window after the offer was queued.
	d.armTimer(o, hash, time.UnixMilli(int64(deadlineMs)).Sub(d.clock.Now()))
	d.syncOrder(st)
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
// denominator as not rejected; one that was never sent is an unreachable skip. Caller holds o.mu.
func (d *Dispatcher) timeoutLocked(o *order, a *attemptState, received bool) {
	a.Outcome = outcomeTimeout
	o.st.Skips++
	if err := d.save(o.st); err != nil {
		d.log.Error("ticket timeout not written", "session_id", o.st.SessionID, "order_sequence", o.st.Sequence, "err", err)
	}
	if received {
		d.cfg.Metrics.Inc(opsmetrics.CounterSkips, opsmetrics.SkipTimeout)
		d.recordOutcome(a, opsmetrics.OutcomeTimeout)
		return
	}
	d.cfg.Metrics.Inc(opsmetrics.CounterSkips, opsmetrics.SkipUnreachable)
	d.cfg.Metrics.WorkerOutcome(a.Operator, a.Tier, opsmetrics.OutcomeUnsent)
}

// recordOutcome feeds the Worker's reject rate and its statistics with a ticket it received:
// every such ticket counts, and only a signed reject while it advertised a free slot
// (OutcomeRejected) is a reject.
func (d *Dispatcher) recordOutcome(a *attemptState, outcome opsmetrics.Outcome) {
	d.cfg.Metrics.WorkerOutcome(a.Operator, a.Tier, outcome)
	if err := d.cfg.Handraises.RecordOutcome(a.Operator, d.cfg.Sessions.Head(), outcome == opsmetrics.OutcomeRejected); err != nil {
		d.log.Warn("reject-rate outcome not recorded", "operator", a.Operator, "err", err)
	}
}

// orderLeft counts a dispatch attempt of an order that ended, accepted or failed, with the tickets
// it took so far: a retry of a failed sequence (an SDK resend) is counted again, with its earlier
// tickets.
func (d *Dispatcher) orderLeft(st *orderState, outcome string) {
	if d.cfg.Metrics == nil {
		return
	}
	tickets := 0
	for _, r := range st.Rounds {
		tickets += len(r.Attempts)
	}
	label := strconv.Itoa(tickets)
	if tickets > 9 {
		label = "10+"
	}
	d.cfg.Metrics.Inc(opsmetrics.CounterTicketsPerOrder, label)
	d.cfg.Metrics.Inc(opsmetrics.CounterOrders, outcome)
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
	if err := d.saveWithEvidence(st); err != nil {
		d.log.Error("failed dispatch not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
	}
	if err := d.cfg.Ledger.MarkFailed(st.SessionID, st.Sequence); err != nil && !errors.Is(err, inflight.ErrUnknownOrder) {
		d.log.Error("failed dispatch not written to the ledger", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
	}
	d.orderLeft(st, "failed")
	d.log.Info("dispatch failed", "session_id", st.SessionID, "order_sequence", st.Sequence, "reason", reason)
	return done{failed: reason, session: st.SessionID, sequence: st.Sequence, taskID: st.TaskID}
}

// onBound applies a binding change of a session. Bound to another Builder, its orders fail; bound
// here at a new bound_change_height, the tickets of the current round, out or accepted but not
// recorded, are VOIDED and stored as the evidence of the generation that ended, and the order
// restarts from round 0 committing the new height.
func (d *Dispatcher) onBound(ctx context.Context, sessionID, builder string, boundChangeHeight uint64) {
	for _, o := range d.sessionOrders(sessionID) {
		o.mu.Lock()
		st := o.st
		// bound_change_height only grows: an event of this Builder at or below the order's height is
		// a replay or out of order, and voids nothing.
		if st.Phase == phaseFailed || builder == d.cfg.Builder && st.BoundChangeHeight >= boundChangeHeight {
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
		if builder != d.cfg.Builder {
			d.voidGeneration(ctx, o)
			failed := d.fail(o, fmt.Errorf("%w: bound to %s", ErrBoundElsewhere, builder))
			out.failed = failed.failed
		} else {
			if err := d.endGeneration(ctx, o, boundChangeHeight); err != nil {
				d.log.Error("voided tickets not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
			d.log.Info("binding changed; tickets voided, rounds restart", "session_id", st.SessionID, "order_sequence", st.Sequence, "bound_change_height", boundChangeHeight)
			stepOut := d.step(ctx, o)
			out.accepted, out.failed, out.readHead = stepOut.accepted, stepOut.failed, stepOut.readHead
		}
		o.mu.Unlock()
		d.finish(ctx, out)
	}
}

// voidGeneration voids the undecided tickets of the order's binding generation: the ticket out,
// and an accepted, unrecorded winner, which is withdrawn from the Recorder and the attempt book.
// Caller holds o.mu.
func (d *Dispatcher) voidGeneration(ctx context.Context, o *order) {
	st := o.st
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
		d.cfg.Attempts.Voided(st.TaskID, [32]byte(w.Hash))
		w.Outcome = outcomeVoided
		st.Phase, st.Accept, st.AcceptDigest, st.Record = phaseDispatching, nil, nil, nil
		if err := d.cfg.Ledger.MarkDispatching(st.SessionID, st.Sequence); err != nil {
			d.log.Error("voided accept not written to the ledger", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
		}
	}
}

// endGeneration ends the order's binding generation at a new bound_change_height of this
// Builder: its undecided tickets are voided and it is stored, and handed to the group sync, as
// evidence (with a record without a winner) together with the new height, so the restart from
// round 0 that follows loses none of its tickets. The new height is taken now, not only when the
// order restarts: the next step (and one after a restart) judges the record deadline with it.
// Caller holds o.mu.
func (d *Dispatcher) endGeneration(ctx context.Context, o *order, boundChangeHeight uint64) error {
	d.voidGeneration(ctx, o)
	st := o.st
	st.NewRound, st.BoundChangeHeight = true, max(st.BoundChangeHeight, boundChangeHeight)
	return d.saveWithEvidence(st)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
