// Package dispatcher is the direct dispatch state machine of a Builder.
//
// For every order the in-flight precheck admitted (its earliest_submit_height at most one block
// above the local chain head), the dispatcher at once draws the order's complete Worker order with
// the Builder VRF, builds the first round's roster from the latest signed handraise root and decides
// session stickiness once. It then walks the order: for each member of the round's roster, in rank
// order, it signs one DispatchTicketV1 and offers it with the signed order on that Cortex's
// dispatch stream, one ticket at a time. A verified reject or the ticket's accept deadline moves
// to the next member; the first valid accept ends the walk. The accepted order's DispatchRecordV1
// is signed and the dispatch entry handed to the Recorder.
//
// Rejects and timeouts count against max_skips; past it the order fails as NO_CAPACITY without
// using its sequence. A retry of a failed sequence in the same epoch is a new round that binds the
// latest root and continues the order where it stopped. A change of the session's
// bound_change_height voids the tickets of the current round, accepted or not, and starts a new
// round. While this Builder's own service key rotation is pending no ticket is issued.
//
// Every ticket is persisted as the exact signed bytes before it is offered, with the round, cursor,
// skip count, the rejects and the accept received, so a restart resumes an order without signing
// different bytes for a ticket that may be out.
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/types"
)

var (
	// ErrDispatchUnavailable refuses new orders on a Builder that cannot run them to the end: no
	// direct dispatch configured.
	ErrDispatchUnavailable = errors.New("NEXUS_INGRESS_DISPATCH_UNAVAILABLE")
	// ErrNotReserved refuses an order the in-flight precheck did not reserve for dispatch.
	ErrNotReserved = errors.New("order is not reserved for dispatch")
	// ErrTicketClosed refuses an accept that came after its ticket's accept deadline, or for a
	// ticket that is no longer out (answered, timed out or voided). It is not recorded and gives
	// the Worker no claim.
	ErrTicketClosed = errors.New("DISPATCH_TICKET_CLOSED")
	// ErrUnknownTicket refuses an answer to a ticket this Builder does not hold.
	ErrUnknownTicket = errors.New("unknown dispatch ticket")
	// ErrAnswerInvalid refuses an answer whose task, order version or member is not its ticket's.
	ErrAnswerInvalid = errors.New("dispatch answer does not match its ticket")
	// ErrInputRefused refuses an input request that does not name the accept this Builder holds.
	ErrInputRefused = errors.New("dispatch input request refused")
	// ErrRecordDeadline fails an order that could not be dispatched before its record deadline.
	ErrRecordDeadline = errors.New("record deadline passed before a Worker accepted")
	// ErrBoundElsewhere fails the orders of a session the chain bound to another Builder.
	ErrBoundElsewhere = errors.New("NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE")
	// ErrRecordRejected fails the orders of a session from a sequence whose dispatch entry the
	// chain refused or did not record by its deadline: none of them can be recorded before it.
	ErrRecordRejected = errors.New("RECORD_REJECTED")
	// ErrCompensationBelowMin is the Keys gate while this Builder's compensation account is below
	// builder_compensation_account_min_balance: the chain refuses every record it sends, so no new
	// order is taken and no ticket issued.
	ErrCompensationBelowMin = errors.New("builder compensation account below its minimum balance")
	// ErrDraining refuses new orders and tickets while this Builder drains before a service key
	// rotation; it comes wrapped in dispatchdraw.ErrNoCapacity, like a pending rotation.
	ErrDraining = errors.New("Builder is draining before a service key rotation")
	// ErrCompensationUnread is the Keys gate until this Builder's compensation account was read
	// once: no ticket is issued on an account that may be below the minimum.
	ErrCompensationUnread = errors.New("builder compensation account not read yet")
)

// Params are the chain parameters the walk reads.
type Params struct {
	// MaxSkips bounds the REJECTED plus TIMEOUT attempts of a recordable order (max_skips).
	MaxSkips uint32
	Sticky   dispatchdraw.StickyParams
	// MaxRosterBytes is max_dispatch_roster_bytes.
	MaxRosterBytes uint64
	// MaxDrawAttempts is max_weighted_draw_attempts_per_selection.
	MaxDrawAttempts uint32
	// RecordDeadlineBlocks is record_deadline_blocks; with it the record deadline follows the
	// current params as the Recorder's does (EffectiveRecordDeadline).
	RecordDeadlineBlocks uint64
}

// ParamsFromChain takes the walk's params from task params dispatch and weights.
func ParamsFromChain(dispatch *taskv1.DispatchParamsV1, weights *taskv1.CandidateWeightParamsV1) (Params, error) {
	p := Params{
		MaxSkips:             dispatch.GetMaxSkips(),
		Sticky:               dispatchdraw.StickyParams{MaxOrders: dispatch.GetStickyMaxOrders(), WindowBlocks: dispatch.GetStickyWindowBlocks()},
		MaxRosterBytes:       dispatch.GetMaxDispatchRosterBytes(),
		MaxDrawAttempts:      weights.GetMaxWeightedDrawAttemptsPerSelection(),
		RecordDeadlineBlocks: dispatch.GetRecordDeadlineBlocks(),
	}
	if p.MaxRosterBytes == 0 || p.MaxDrawAttempts == 0 {
		return Params{}, fmt.Errorf("dispatch params: max_dispatch_roster_bytes %d and max_weighted_draw_attempts_per_selection %d must be set",
			p.MaxRosterBytes, p.MaxDrawAttempts)
	}
	return p, nil
}

// Streams is the Cortex stream hub the dispatcher offers tickets and input through.
type Streams interface {
	Send(ctx context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error
	Connected(operator string) bool
	RTT(operator string) (time.Duration, bool)
}

// Handraises is the standing handraise registry.
type Handraises interface {
	LatestRoot() (*handraise.IssuedRoot, bool)
	Current(operator string) (*taskv1.StandingHandraiseV1, bool)
	RecordOutcome(operator string, height uint64, rejected bool) error
}

// Drawer draws an order's randomness and complete pool order (dispatchdraw.Drawer).
type Drawer interface {
	// EpochOf resolves the epoch of an order's earliest_submit_height; an epoch that cannot
	// dispatch yet fails with a *dispatchdraw.NotReadyError.
	EpochOf(ctx context.Context, earliestSubmitHeight uint64) (dispatchdraw.Epoch, error)
	Draw(ctx context.Context, sessionID [32]byte, sequence, earliestSubmitHeight uint64, profile dispatchdraw.Profile, maxAttempts uint32) (*dispatchdraw.Draw, error)
}

// Sessions reads session states and the head (inflight.SessionCache).
type Sessions interface {
	Lookup(ctx context.Context, sessionID string) (inflight.Session, uint64, error)
	Head() uint64
}

// Keys reads service key bindings from the chain and gates ticket issuance.
type Keys interface {
	// CheckBuilderKey fails with handraise.ErrBuilderRotationPending while this Builder's own
	// replacement key is pending, with ErrCompensationBelowMin while its compensation account is
	// below the minimum, and fails when its current key cannot be confirmed.
	CheckBuilderKey(ctx context.Context) error
	// CortexRotationPending reports whether operator's CORTEX key replacement is pending.
	CortexRotationPending(ctx context.Context, operator string) (bool, error)
}

// Inputs opens the stored INPUT of an order version.
type Inputs interface {
	OpenInput(ctx context.Context, sessionID, taskID, taskHash string) (io.ReadCloser, uint64, error)
}

// Observer is told what happened to the orders it handed over; the coordinator implements it.
type Observer interface {
	DispatchAccepted(sessionID, taskID string, ticketHash [32]byte, worker string)
	DispatchFailed(sessionID, taskID string, reason error)
}

// Bundle is the dispatch entry of an accepted order: the signed order, the signed record, the
// winner ticket and the Worker's accept, all as the exact bytes signed.
type Bundle struct {
	SessionID string
	Sequence  uint64
	TaskID    string
	// Deadline is the last height the entry can be recorded at.
	Deadline uint64
	Entry    *taskv1.DispatchEntryV1
}

// Recorder records accepted orders on chain.
//
// Record and Withdraw of one winner ticket may arrive in either order: an accept hands its entry
// to Record after the order's lock is released, so a binding change in between can Withdraw the
// ticket first. Withdraw is called with the order's lock held, so an implementation must not wait
// on the dispatcher inside it. An implementation keys both by the winner's dispatch_ticket_hash and must not
// record an entry whose ticket was already withdrawn.
type Recorder interface {
	// Record queues the entry for the next MsgRecordDispatch. It may be called again with the same
	// bytes after a restart and must treat that as the same entry.
	Record(ctx context.Context, b *Bundle) error
	// Withdraw drops a queued entry whose winner ticket was voided before it was recorded, or
	// marks the ticket so a later Record of it is dropped.
	Withdraw(ctx context.Context, sessionID string, sequence uint64, ticketHash [32]byte)
}

// Attempts follows the winner of each accepted order until the chain decides its record
// (attempt.Book): the output data plane trusts it before the chain knows the task.
type Attempts interface {
	// Accepted makes the winner its task's current attempt. It may be called again with the same
	// winner after a restart.
	Accepted(w attempt.Winner) error
	// Voided drops the attempt of a winner ticket a binding change voided; it may come before the
	// Accepted of that ticket.
	Voided(taskID string, ticketHash [32]byte)
}

// Timer is a pending clock callback.
type Timer interface{ Stop() bool }

// Clock is the Builder's local clock; accept deadlines are absolute times on it.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Timer
}

type systemClock struct{}

func (systemClock) Now() time.Time                            { return time.Now() }
func (systemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// Config wires a Dispatcher.
type Config struct {
	ChainID string
	// Builder is this Builder's operator address.
	Builder string
	// Dispatch holds the accept timeouts by RTT tier.
	Dispatch config.DispatchConfig
	// InputChunkBytes bounds the input bytes of one DispatchInputResponseV1.
	InputChunkBytes uint64
	// Signer is the Builder service key that signs tickets, records and input responses; tickets
	// and records carry its authorization nonce.
	Signer     servicekey.Signer
	Store      kv.Store
	Ledger     *inflight.Ledger
	Sessions   Sessions
	Streams    Streams
	Handraises Handraises
	Drawer     Drawer
	Keys       Keys
	Inputs     Inputs
	Recorder   Recorder
	Observer   Observer
	Attempts   Attempts
	// Evidence keeps every order's evidence once it is accepted, failed or recorded; nil keeps
	// none (claims on its tickets then cannot be rebutted).
	Evidence Evidence
	// Sync hands every stored change of an order to the other members of its Task Builders group;
	// nil syncs nothing.
	Sync OrderSync
	// Metrics takes the stage timings, skips and Worker outcomes of the walk; nil keeps none.
	Metrics *opsmetrics.Registry
	// Draining reports a service key rotation drain: no new order is taken and no ticket issued,
	// so an order that needs its next ticket fails as NO_CAPACITY; tickets out still win, and the
	// order of a takeover (registered on chain before the drain) is walked as usual. nil never
	// drains.
	Draining func() bool
	// Clock is nil for the system clock.
	Clock Clock
	// Background runs order work off the caller's goroutine; nil runs it on a new goroutine.
	Background func(func())
	Log        *slog.Logger
}

// Dispatcher walks the orders this Builder dispatches.
type Dispatcher struct {
	cfg    Config
	log    *slog.Logger
	clock  Clock
	params atomic.Pointer[Params]
	slots  slotBook

	mu      sync.Mutex
	stopped bool
	orders  map[string]*order // stateKey -> order
	byTask  map[string]*order // task_id -> order
	tickets map[string]*order // dispatch_ticket_hash -> order
	wg      sync.WaitGroup

	// unbooked holds the winners the attempt book could not take, by task; each block retries them.
	unbookedMu sync.Mutex
	unbooked   map[string]attempt.Winner
}

// order is one order's state with what is rebuilt from it in memory. Locks: an order's mutex may
// be held while taking the mutex of an order of the same session with a lower sequence, never the
// other way round; Dispatcher.mu is taken last.
type order struct {
	mu     sync.Mutex
	st     *orderState
	signed *taskv1.SignedOrderV2
	// draw is the complete order once drawn; roster the round's roster in use and rosterRound its
	// number (stored with the round once its first ticket is issued).
	draw        *dispatchdraw.Order
	roster      *dispatchdraw.Roster
	rosterRound uint32
	timer       Timer
	// parked is set while the order waits for the chain: an earlier order of the session, a
	// readable chain (its epoch included), or the end of this Builder's key rotation.
	parked bool
	// takenAt is when this run took the order (zero for an order resumed after a restart) and
	// waited whether the wait for its first round was timed; ticketAt is when the ticket out
	// was issued. They only feed the stage timings.
	takenAt  time.Time
	waited   bool
	ticketAt time.Time
}

func (o *order) key() string { return stateKey(o.st.SessionID, o.st.Sequence) }

// New builds a Dispatcher. Start resumes the orders a previous run left.
func New(cfg Config, params Params) (*Dispatcher, error) {
	switch {
	case cfg.ChainID == "" || cfg.Builder == "" || cfg.Signer == nil || cfg.Store == nil || cfg.Ledger == nil:
		return nil, fmt.Errorf("dispatcher needs the chain id, Builder address, service signer, store and ledger")
	case cfg.Sessions == nil || cfg.Streams == nil || cfg.Handraises == nil || cfg.Drawer == nil || cfg.Keys == nil || cfg.Inputs == nil:
		return nil, fmt.Errorf("dispatcher needs the sessions, streams, handraises, drawer, keys and inputs")
	case cfg.Recorder == nil || cfg.Observer == nil || cfg.Attempts == nil:
		return nil, fmt.Errorf("dispatcher needs a recorder, an observer and the attempt book")
	case len(cfg.Dispatch.AcceptTimeoutMsByRTTTier) == 0 || cfg.InputChunkBytes == 0:
		return nil, fmt.Errorf("dispatcher needs accept timeout tiers and an input chunk size")
	}
	d := &Dispatcher{
		cfg: cfg, log: cfg.Log, clock: cfg.Clock,
		orders: map[string]*order{}, byTask: map[string]*order{}, tickets: map[string]*order{},
	}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	if d.clock == nil {
		d.clock = systemClock{}
	}
	d.slots.used = map[string]slotUse{}
	d.SetParams(params)
	return d, nil
}

func (d *Dispatcher) draining() bool { return d.cfg.Draining != nil && d.cfg.Draining() }

// SetParams replaces the walk's params after a params change on chain.
func (d *Dispatcher) SetParams(p Params) { d.params.Store(&p) }

// Start resumes the orders a previous run left (see recover) and hands the accepted ones to the
// Recorder again.
func (d *Dispatcher) Start(ctx context.Context) error {
	return d.recover(ctx)
}

// Stop stops issuing tickets and waits for running order work. Stored state stays.
func (d *Dispatcher) Stop(context.Context) error {
	d.mu.Lock()
	d.stopped = true
	orders := make([]*order, 0, len(d.orders))
	for _, o := range d.orders {
		orders = append(orders, o)
	}
	d.mu.Unlock()
	for _, o := range orders {
		o.mu.Lock()
		if o.timer != nil {
			o.timer.Stop()
		}
		o.mu.Unlock()
	}
	d.wg.Wait()
	return nil
}

// kick runs one step of the order in the background.
func (d *Dispatcher) kick(key string) {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	run := func() {
		defer d.wg.Done()
		d.advance(context.Background(), key)
	}
	if d.cfg.Background != nil {
		d.cfg.Background(run)
		return
	}
	go run()
}

func (d *Dispatcher) get(key string) *order {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.orders[key]
}

func (d *Dispatcher) register(o *order) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.orders[o.key()] = o
	d.byTask[o.st.TaskID] = o
	for _, r := range o.st.Rounds {
		for _, a := range r.Attempts {
			d.tickets[string(a.Hash)] = o
		}
	}
}

func (d *Dispatcher) indexTicket(o *order, hash [32]byte) {
	d.mu.Lock()
	d.tickets[string(hash[:])] = o
	d.mu.Unlock()
}

func (d *Dispatcher) forget(o *order) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.orders[o.key()] == o {
		delete(d.orders, o.key())
	}
	if d.byTask[o.st.TaskID] == o {
		delete(d.byTask, o.st.TaskID)
	}
	for _, r := range o.st.Rounds {
		for _, a := range r.Attempts {
			if d.tickets[string(a.Hash)] == o {
				delete(d.tickets, string(a.Hash))
			}
		}
	}
}

// sessionOrders lists the orders of one session.
func (d *Dispatcher) sessionOrders(sessionID string) []*order {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*order
	for _, o := range d.orders {
		if o.st.SessionID == sessionID {
			out = append(out, o)
		}
	}
	return out
}

// Dispatch takes over an order the in-flight precheck reserved (or a retry of a failed one): it
// stores the order's dispatch state, commits the ledger reservation and starts walking it in the
// background. Nothing is offered before both are written, so an order whose commit was lost by a
// crash has no ticket out and is dropped on restart.
func (d *Dispatcher) Dispatch(ctx context.Context, o types.Order) error {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(o.SignedOrder, &signed); err != nil || signed.GetOrder() == nil {
		return fmt.Errorf("dispatch order: signed order does not decode")
	}
	entry, ok := d.cfg.Ledger.Get(o.SessionID, o.OrderSequence)
	if !ok || entry.TaskHash != o.TaskHash || entry.State != inflight.StateDispatching {
		return fmt.Errorf("%w: session %s sequence %d", ErrNotReserved, o.SessionID, o.OrderSequence)
	}
	key := stateKey(o.SessionID, o.OrderSequence)
	existing := d.get(key)
	if existing != nil {
		existing.mu.Lock()
		switch {
		case existing.st.Phase != phaseFailed && existing.st.TaskHash == o.TaskHash:
			existing.mu.Unlock()
			return nil
		case existing.st.Phase != phaseFailed:
			existing.mu.Unlock()
			return fmt.Errorf("%w: sequence %d is being dispatched with task_hash %s", inflight.ErrOrderReplacementUnsupported, o.OrderSequence, existing.st.TaskHash)
		}
		prev := cloneState(existing.st)
		st := existing.st
		st.TaskID, st.TaskHash, st.SignedOrder = o.TaskID, o.TaskHash, o.SignedOrder
		st.Phase, st.FailReason, st.NewRound = phaseDispatching, "", true
		st.Accept, st.AcceptDigest, st.Record = nil, nil, nil
		if err := saveState(d.cfg.Store, st); err != nil {
			existing.st = prev
			existing.mu.Unlock()
			return err
		}
		existing.signed, existing.roster = &signed, nil
		existing.takenAt, existing.waited = d.clock.Now(), false
		existing.mu.Unlock()
		d.mu.Lock()
		d.byTask[o.TaskID] = existing
		d.mu.Unlock()
	} else {
		st := &orderState{
			SessionID: o.SessionID, Sequence: o.OrderSequence, TaskID: o.TaskID, TaskHash: o.TaskHash,
			SignedOrder: o.SignedOrder, Phase: phaseDispatching,
		}
		if err := saveState(d.cfg.Store, st); err != nil {
			return err
		}
		existing = &order{st: st, signed: &signed, takenAt: d.clock.Now()}
		d.register(existing)
	}
	if err := d.cfg.Ledger.Commit(&inflight.Reservation{SessionID: o.SessionID, Sequence: o.OrderSequence, TaskHash: o.TaskHash}); err != nil {
		existing.mu.Lock()
		existing.st.Phase, existing.st.FailReason = phaseFailed, err.Error()
		if saveErr := saveState(d.cfg.Store, existing.st); saveErr != nil {
			d.log.Error("dispatch state of an uncommitted order not written", "session_id", o.SessionID, "order_sequence", o.OrderSequence, "err", saveErr)
		}
		existing.mu.Unlock()
		return fmt.Errorf("commit in-flight order: %w", err)
	}
	d.kick(key)
	return nil
}

// Probe refuses, before the input of a new order is stored, an order no Worker can take now: this
// Builder drains, its key rotation is pending or its compensation account is below the minimum (it
// takes no new order; the session moves by takeover), the order's epoch cannot dispatch yet
// (dispatchdraw.ErrDispatchNotReady: the user retries this Builder later, so it is checked before
// any NO_CAPACITY answer) or the latest handraise root holds no admitted, unexpired handraise with a
// free slot for the order's profile. The walk decides the rest.
func (d *Dispatcher) Probe(ctx context.Context, o types.Order) error {
	if d.draining() {
		return fmt.Errorf("%w: %w", dispatchdraw.ErrNoCapacity, ErrDraining)
	}
	if err := d.cfg.Keys.CheckBuilderKey(ctx); err != nil {
		if errors.Is(err, handraise.ErrBuilderRotationPending) || errors.Is(err, ErrCompensationBelowMin) {
			return fmt.Errorf("%w: %v", dispatchdraw.ErrNoCapacity, err)
		}
		return fmt.Errorf("%w: %v", inflight.ErrUnavailable, err)
	}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(o.SignedOrder, &signed); err != nil {
		return fmt.Errorf("probe order: signed order does not decode")
	}
	if _, err := d.cfg.Drawer.EpochOf(ctx, signed.GetOrder().GetEarliestSubmitHeight()); err != nil {
		if errors.Is(err, dispatchdraw.ErrDispatchNotReady) {
			return err
		}
		return fmt.Errorf("%w: epoch of the order: %v", inflight.ErrUnavailable, err)
	}
	root, ok := d.cfg.Handraises.LatestRoot()
	if !ok {
		return fmt.Errorf("%w: no handraise root yet", dispatchdraw.ErrNoCapacity)
	}
	head := d.cfg.Sessions.Head()
	for _, leaf := range root.Leaves {
		h := leaf.GetHandraise()
		if leaf.GetAdmitted() && h.GetFreeSlotCount() > 0 && h.GetExpiryHeight() >= head && servesOrder(h, signed.GetOrder()) {
			return nil
		}
	}
	return fmt.Errorf("%w: no admitted handraise for the order's profile", dispatchdraw.ErrNoCapacity)
}

func servesOrder(h *taskv1.StandingHandraiseV1, o *taskv1.TaskOrderV3) bool {
	for _, p := range h.GetProfiles() {
		if p.GetProfileVersion() == o.GetProfileVersion() && string(p.GetModelId()) == string(o.GetModelId()) {
			return true
		}
	}
	return false
}

// Recorded forgets an order whose dispatch entry the chain admitted at height. Its evidence is
// marked recorded in the same write that deletes its dispatch state.
func (d *Dispatcher) Recorded(sessionID string, sequence, height uint64) error {
	o := d.get(stateKey(sessionID, sequence))
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.timer != nil {
		o.timer.Stop()
	}
	err := d.putEvidence(o.st, height, deleteStateOp(sessionID, sequence), func() error {
		return deleteState(d.cfg.Store, sessionID, sequence)
	})
	o.mu.Unlock()
	if err != nil {
		return fmt.Errorf("delete dispatch state: %w", err)
	}
	d.forget(o)
	d.kickParked(sessionID)
	return nil
}

// RecordRejected marks an accepted order whose dispatch entry the chain refused: its winner ticket
// is VOIDED and the order failed, so a resend of the sequence is a new round that continues it.
// The ledger's suspension is the Recorder's.
func (d *Dispatcher) RecordRejected(sessionID string, sequence uint64, reason error) error {
	o := d.get(stateKey(sessionID, sequence))
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return d.rejectAcceptedLocked(o, reason)
}

// rejectAcceptedLocked fails an accepted order with its winner ticket VOIDED. Caller holds o.mu.
func (d *Dispatcher) rejectAcceptedLocked(o *order, reason error) error {
	if o.st.Phase != phaseAccepted {
		return nil
	}
	if w := o.st.winner(); w != nil {
		w.Outcome = outcomeVoided
	}
	o.st.Phase, o.st.FailReason = phaseFailed, reason.Error()
	o.st.Accept, o.st.AcceptDigest, o.st.Record = nil, nil, nil
	return d.saveWithEvidence(o.st)
}

// Suspend fails every order of the session from sequence from on, after the record of from was
// refused or missed its deadline: the chain cannot admit a later order before it. An accepted
// order is failed as RecordRejected does; a dispatching one stops walking, its ticket still out
// VOIDED, and the observer is told reason. The ledger's suspension is the Recorder's.
func (d *Dispatcher) Suspend(ctx context.Context, sessionID string, from uint64, reason error) {
	for _, o := range d.sessionOrders(sessionID) {
		var out done
		o.mu.Lock()
		switch st := o.st; {
		case st.Sequence < from || st.Phase == phaseFailed:
		case st.Phase == phaseAccepted:
			if err := d.rejectAcceptedLocked(o, reason); err != nil {
				d.log.Error("suspended order not written", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
			}
		default:
			if a := st.pending(); a != nil {
				a.Outcome = outcomeVoided
			}
			out = d.fail(o, reason)
		}
		o.mu.Unlock()
		d.finish(ctx, out)
	}
}

// RecordDeadline returns the last height the order of (session, sequence) can be recorded at: the
// in-flight ledger's deadline moved by the current params and binding as the Recorder moves it.
func (d *Dispatcher) RecordDeadline(sessionID string, sequence uint64) (uint64, bool) {
	e, ok := d.cfg.Ledger.Get(sessionID, sequence)
	if !ok {
		return 0, false
	}
	o := d.get(stateKey(sessionID, sequence))
	if o == nil {
		return e.Deadline, true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return d.recordDeadline(o, e.Deadline), true
}

// EffectiveRecordDeadline is the last height an entry can be recorded at:
// max(earliest_submit_height, bound_change_height) + record_deadline_blocks with the current
// params, never earlier than the deadline handed over (stored), and never past orderExpire, the
// order's order_expire_height (the last height the Keeper admits it at; zero bounds nothing). The
// Recorder and the dispatcher both decide with it, so an entry one of them still takes the other
// does not give up on.
func EffectiveRecordDeadline(stored, earliestSubmit, boundChange, deadlineBlocks, orderExpire uint64) uint64 {
	deadline := max(stored, max(earliestSubmit, boundChange)+deadlineBlocks)
	if orderExpire != 0 {
		deadline = min(deadline, orderExpire)
	}
	return deadline
}

// recordDeadline is the order's EffectiveRecordDeadline: its bound_change_height is the current
// round's, the one its winner ticket commits. Caller holds o.mu.
func (d *Dispatcher) recordDeadline(o *order, stored uint64) uint64 {
	return EffectiveRecordDeadline(stored, o.signed.GetOrder().GetEarliestSubmitHeight(), o.st.BoundChangeHeight,
		d.params.Load().RecordDeadlineBlocks, o.signed.GetOrder().GetOrderExpireHeight())
}

func cloneState(s *orderState) *orderState {
	out := *s
	out.Members = append(s.Members[:0:0], s.Members...)
	out.Rounds = make([]roundState, len(s.Rounds))
	for i, r := range s.Rounds {
		out.Rounds[i] = r
		out.Rounds[i].Attempts = append(r.Attempts[:0:0], r.Attempts...)
	}
	return &out
}
