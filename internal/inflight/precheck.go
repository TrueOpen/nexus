package inflight

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/registeredkey"
)

// Params are the task dispatch params the precheck reads.
type Params struct {
	RecordDeadlineBlocks       uint64
	OrderFreshnessMarginBlocks uint64
	// BuilderMaxInflightPerSession and MaxPendingPerSession bound a session's in-flight orders;
	// zero admits none (a missing param never lifts the bound).
	BuilderMaxInflightPerSession uint32
	MaxPendingPerSession         uint32
}

// validate checks that the freshness margin is below record_deadline_blocks, otherwise an order
// could be admitted after its record deadline, and that both in-flight limits are set: a zero
// limit would admit no order.
func (p Params) validate() error {
	if p.RecordDeadlineBlocks == 0 || p.OrderFreshnessMarginBlocks >= p.RecordDeadlineBlocks {
		return fmt.Errorf("dispatch params: order_freshness_margin_blocks %d must be below record_deadline_blocks %d",
			p.OrderFreshnessMarginBlocks, p.RecordDeadlineBlocks)
	}
	if p.BuilderMaxInflightPerSession == 0 || p.MaxPendingPerSession == 0 {
		return fmt.Errorf("dispatch params: builder_max_inflight_per_session %d and max_pending_per_session %d must be set",
			p.BuilderMaxInflightPerSession, p.MaxPendingPerSession)
	}
	return nil
}

// ParamsFromChain takes the precheck params from task params dispatch. The freshness margin must
// be below record_deadline_blocks, otherwise an order could be admitted after its record deadline.
func ParamsFromChain(p *taskv1.DispatchParamsV1) (Params, error) {
	out := Params{
		RecordDeadlineBlocks:         p.GetRecordDeadlineBlocks(),
		OrderFreshnessMarginBlocks:   p.GetOrderFreshnessMarginBlocks(),
		BuilderMaxInflightPerSession: p.GetBuilderMaxInflightPerSession(),
		MaxPendingPerSession:         p.GetMaxPendingPerSession(),
	}
	if err := out.validate(); err != nil {
		return Params{}, err
	}
	return out, nil
}

// Order is what the precheck reads of an OpenTask order.
type Order struct {
	SessionID string // lowercase hex, no 0x
	Sequence  uint64
	TaskID    string
	TaskHash  string
	User      string // the order's user_address
	// MaxFee is the order's max_fee in atomic units.
	MaxFee               uint64
	EarliestSubmitHeight uint64
	ExpireHeight         uint64
	SessionAnchorHeight  uint64
	// SessionKey is the address the order signature recovers to when it is not the user's wallet,
	// that is the session's registered key; nil for a wallet order.
	SessionKey *[20]byte
	// Takeover marks the order this Builder took the session over with: it keeps its
	// earliest_submit_height and its record deadline runs from the activation height, so the
	// freshness check does not apply to it.
	Takeover bool
}

// Binding says which Builder the session is bound to.
type Binding uint8

const (
	// BoundHere: the session is bound to this Builder; the precheck ran to the end.
	BoundHere Binding = iota + 1
	// BoundElsewhere: the session is bound to another Builder (Session.BoundBuilder). Only what a
	// takeover registration in the next block needs was checked (session, session key, expiry,
	// earliest_submit_height): the takeover path decides the rest.
	BoundElsewhere
)

// Result is a passed precheck.
type Result struct {
	Binding Binding
	// Session is the session state the order was judged against.
	Session Session
	// Head is the height the order was judged at.
	Head uint64
	// Deadline is max(earliest_submit_height, bound_change_height) + record_deadline_blocks: the
	// last height the order's dispatch entry can be recorded at.
	Deadline uint64
	// Existing is set when this Builder already dispatches, dispatched or recorded the same order
	// (same task_hash): it is not dispatched again, the caller answers with its state.
	Existing *Entry
	// Retry is set when an earlier attempt at this sequence failed without a record: the order is
	// dispatched as a new round, not refused as a replacement.
	Retry bool
	// Reservation is set when Reserve entered the order in the ledger; the caller releases it if
	// the order does not reach dispatch.
	Reservation *Reservation
}

// OpenTaskStatus is the OpenTask status of an order in this state: DISPATCHING while tickets are
// out, DISPATCHED once a Worker accepted, RECORDED once the chain admitted it.
func (s State) OpenTaskStatus() nexusv1.OpenTaskStatusV1 {
	switch s {
	case StateDispatching:
		return nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_DISPATCHING
	case StateAccepted:
		return nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_DISPATCHED
	case StateRecorded:
		return nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_RECORDED
	}
	return nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_UNSPECIFIED
}

// PrecheckConfig configures a Prechecker.
type PrecheckConfig struct {
	// Builder is this Builder's operator address.
	Builder  string
	Params   Params
	Sessions *SessionCache
	Ledger   *Ledger
}

// Prechecker is the OpenTask precheck of the dispatching Builder. It reads the session state and
// the head from the SessionCache and this Builder's in-flight orders from the Ledger, so a warm
// session costs no chain read. It is a precheck: the Keeper decides at record time, and the
// precheck is at least as strict, so an order it admits fails at record time only through this
// Builder's own fault.
//
// The checks run in this order and the first failure is the answer:
//
//  1. session: known, owned by the order user (else the registered key error ErrKeyInvalid), not
//     closed (ErrSessionClosing); an order signed by the session key passes
//     registeredkey.CheckDispatchOrder with this Builder's in-flight orders signed by the key;
//  2. binding: a session bound to another Builder ends the precheck with BoundElsewhere once the
//     order could register a takeover in the next block: head + 1 < order_expire_height (else
//     ErrOrderExpired) and earliest_submit_height <= head + 1 (else ErrOrderFuture), with a
//     registered key valid at head + 1;
//  3. expiry: the order must stay recordable until its record deadline D = max(
//     earliest_submit_height, bound_change_height) + record_deadline_blocks, so D <
//     order_expire_height (and head + 1 < order_expire_height), else ErrOrderExpired;
//  4. freshness, except for a takeover order: earliest_submit_height >= head -
//     order_freshness_margin_blocks (ErrOrderStale) and <= head + 1 (ErrOrderFuture, returned only
//     after the head was read from the chain again);
//  5. a registered takeover of the session: *TakeoverPendingError;
//  6. local idempotency by (session_id, order_sequence): the same order dispatching, accepted or
//     recorded is Result.Existing, also below the chain's next expected sequence (recorded before
//     this Builder saw the event), but ErrOrderUploading while it is an uncommitted reservation
//     whose input another stream still uploads; another version of it ErrOrderReplacementUnsupported,
//     ErrOrderLocked or ErrTaskTerminal; after a failed attempt the order is a retry;
//  7. suspension after a failed record: only the suspended sequence (ErrSessionSuspended); a
//     registered cancellation of the sequence (ErrOrderSequenceConflict); every sequence from the
//     chain's next expected sequence to sequence-1 in flight and sequence itself not, so a hole an
//     attempt without a record left can be retried (ErrOrderSequenceConflict); in-flight orders below
//     builder_max_inflight_per_session and max_pending_per_session (ErrInflightLimit);
//  8. funds: no CLOSE withdrawal registered (ErrSessionClosing), and balance - frozen_total -
//     pending withdrawal - in-flight max_fee >= max_fee (ErrSessionBalanceInsufficient).
//
// A balance or spend cap refusal is returned only after the session state was read again (once
// per block): the chain releases frozen funds at settlement without a session-level event.
//
// A non-empty dispatch roster is checked by the dispatcher.
type Prechecker struct {
	cfg PrecheckConfig

	mu     sync.Mutex
	params Params

	afterLookup func() // test hook: runs between the session lookup and the ledger lock
}

// lookupAttempts bounds the session lookups of one precheck when the session keeps changing
// between the lookup and the ledger lock.
const lookupAttempts = 3

// NewPrechecker builds a Prechecker.
func NewPrechecker(cfg PrecheckConfig) (*Prechecker, error) {
	if cfg.Builder == "" || cfg.Sessions == nil || cfg.Ledger == nil {
		return nil, fmt.Errorf("precheck needs the Builder address, a session cache and a ledger")
	}
	if err := cfg.Params.validate(); err != nil {
		return nil, err
	}
	return &Prechecker{cfg: cfg, params: cfg.Params}, nil
}

// SetParams replaces the params, after a params change on chain. Params whose freshness margin is
// not below record_deadline_blocks, or with a zero in-flight limit, are refused and the current
// ones kept.
func (p *Prechecker) SetParams(params Params) error {
	if err := params.validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.params = params
	return nil
}

func (p *Prechecker) currentParams() Params {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.params
}

// Check runs the precheck without changing anything.
func (p *Prechecker) Check(ctx context.Context, o Order) (Result, error) {
	return p.run(ctx, o, false)
}

// Reserve runs the precheck and, when the order is bound here, new and admitted, enters it in the
// ledger as an uncommitted DISPATCHING entry in the same step (Result.Reservation), so two
// concurrent orders cannot both take the same sequence or the same funds. The caller commits the
// reservation once the dispatcher took the order and releases it otherwise. Admitting the resend
// of a suspended sequence ends the suspension.
func (p *Prechecker) Reserve(ctx context.Context, o Order) (Result, error) {
	return p.run(ctx, o, true)
}

// Commit marks a reservation's order as handed to the dispatcher; see Ledger.Commit.
func (p *Prechecker) Commit(r *Reservation) error {
	return p.cfg.Ledger.Commit(r)
}

// Release undoes a reservation whose order did not reach dispatch; see Ledger.Release.
func (p *Prechecker) Release(r *Reservation) error {
	return p.cfg.Ledger.Release(r)
}

// run judges the order against one session state and the ledger as it was when that state was
// current. An event updates the cached state and then the ledger in two steps (an order
// cancellation moves next, then fails the order); a state read before the first step judged with
// the ledger after the second would be wrong, so the lookup is repeated when the session changed
// before the ledger lock was taken.
func (p *Prechecker) run(ctx context.Context, o Order, reserve bool) (Result, error) {
	res, err := p.attempt(ctx, o, reserve)
	// The cached head trails the chain, so an order built on a newer head looks like it is from
	// the future; the head is read again once before saying so. Stale and expired verdicts only
	// get stricter with a newer head.
	if errors.Is(err, ErrOrderFuture) {
		moved, headErr := p.cfg.Sessions.readHead(ctx)
		switch {
		case headErr != nil:
			return Result{}, headErr // no verdict: the order may well be current
		case moved:
			res, err = p.attempt(ctx, o, reserve)
		}
	}
	// Settlement and refunds release frozen funds without a session-level event, so the cached
	// state can hold funds the chain already released; it is read again once before the order is
	// refused for them.
	if (errors.Is(err, ErrSessionBalanceInsufficient) || errors.Is(err, registeredkey.ErrSpendCapExceeded)) &&
		p.cfg.Sessions.reload(ctx, o.SessionID) {
		res, err = p.attempt(ctx, o, reserve)
	}
	return res, err
}

func (p *Prechecker) attempt(ctx context.Context, o Order, reserve bool) (Result, error) {
	for attempt := 1; ; attempt++ {
		session, head, gen, err := p.cfg.Sessions.lookup(ctx, o.SessionID)
		if err != nil {
			return Result{}, err
		}
		if p.afterLookup != nil {
			p.afterLookup()
		}
		params := p.currentParams()
		l := p.cfg.Ledger
		l.mu.Lock()
		if !p.cfg.Sessions.current(o.SessionID, gen) {
			l.mu.Unlock()
			if attempt < lookupAttempts {
				continue
			}
			return Result{}, fmt.Errorf("%w: session %s kept changing during the precheck", ErrUnavailable, o.SessionID)
		}
		res, err := p.judgeLocked(o, session, head, params, reserve)
		l.mu.Unlock()
		return res, err
	}
}

// judgeLocked evaluates the order and, for Reserve, enters it; the caller holds the ledger lock.
func (p *Prechecker) judgeLocked(o Order, session Session, head uint64, params Params, reserve bool) (Result, error) {
	l := p.cfg.Ledger
	ls := l.sessions[o.SessionID]
	if ls == nil {
		ls = &sessionLedger{}
	}
	res, err := p.evaluate(o, session, head, params, ls)
	if err != nil || !reserve || res.Binding != BoundHere || res.Existing != nil {
		return res, err
	}
	entry := Entry{
		Sequence: o.Sequence, TaskID: o.TaskID, TaskHash: o.TaskHash, MaxFee: o.MaxFee,
		SessionKey: o.SessionKey != nil, Deadline: res.Deadline, State: StateDispatching, Takeover: o.Takeover,
	}
	op, err := putOp(o.SessionID, entry)
	if err != nil {
		return Result{}, err
	}
	reservation := &Reservation{SessionID: o.SessionID, Sequence: o.Sequence, TaskHash: o.TaskHash}
	if prev := ls.orders[o.Sequence]; prev != nil {
		replaced := *prev
		reservation.replaced = &replaced
	}
	ops := []kv.WriteOp{op}
	meta := ls.meta
	if meta.SuspendedFrom != nil && *meta.SuspendedFrom == o.Sequence {
		resumed := *meta.SuspendedFrom
		reservation.resumed = &resumed
		meta.SuspendedFrom = nil
		op, err := metaOp(o.SessionID, meta)
		if err != nil {
			return Result{}, err
		}
		ops = append(ops, op)
	}
	if err := l.store.WriteBatch(ops...); err != nil {
		return Result{}, fmt.Errorf("write in-flight order: %w", err)
	}
	stored := l.sessionLocked(o.SessionID)
	stored.orders[o.Sequence] = &entry
	stored.meta = meta
	res.Reservation = reservation
	return res, nil
}

func (p *Prechecker) evaluate(o Order, s Session, head uint64, params Params, ls *sessionLedger) (Result, error) {
	if !s.Found || s.Owner != o.User {
		return Result{}, fmt.Errorf("%w: the order user does not own session %s", registeredkey.ErrKeyInvalid, o.SessionID)
	}
	if s.Closed {
		return Result{}, fmt.Errorf("%w: session %s is closed", ErrSessionClosing, o.SessionID)
	}
	res := Result{Binding: BoundHere, Session: s, Head: head,
		Deadline: saturatingAdd(max(o.EarliestSubmitHeight, s.BoundChangeHeight), params.RecordDeadlineBlocks)}
	bound := s.BoundBuilder == p.cfg.Builder
	// A takeover entry is judged when it registers, in the next block; the order is judged again
	// in full before it is dispatched once the takeover took effect.
	keyDeadline := res.Deadline
	if !bound {
		keyDeadline = head + 1
	}
	inFlight := ls.inFlight(s.NextExpectedSequence)
	if o.SessionKey != nil {
		err := registeredkey.CheckDispatchOrder(keyState(s), registeredkey.DispatchOrder{
			User: o.User, Recovered: *o.SessionKey, AnchorHeight: o.SessionAnchorHeight,
			MaxFee: fmt.Sprint(o.MaxFee), Height: head, Deadline: keyDeadline,
			InFlight: inFlight.sessionKeyMaxFee.String(),
		})
		if err != nil {
			return Result{}, err
		}
	}
	if !bound {
		if head+1 >= o.ExpireHeight {
			return Result{}, fmt.Errorf("%w: order_expire_height %d is not after the next height (head %d)", ErrOrderExpired, o.ExpireHeight, head)
		}
		if o.EarliestSubmitHeight > head+1 {
			return Result{}, fmt.Errorf("%w: earliest_submit_height %d is above the head %d plus one", ErrOrderFuture, o.EarliestSubmitHeight, head)
		}
		res.Binding = BoundElsewhere
		return res, nil
	}
	// The Keeper refuses a record at or after order_expire_height, and this Builder guarantees the
	// record only by the deadline: an order expiring earlier could fail at record time through
	// this precheck's fault.
	if head+1 >= o.ExpireHeight || res.Deadline >= o.ExpireHeight {
		return Result{}, fmt.Errorf("%w: order_expire_height %d is not after the record deadline %d (head %d)",
			ErrOrderExpired, o.ExpireHeight, res.Deadline, head)
	}
	takeover := o.Takeover
	if e := ls.orders[o.Sequence]; e != nil && e.Takeover && e.TaskHash == o.TaskHash {
		takeover = true // a resend of the order taken over
	}
	if !takeover && head > params.OrderFreshnessMarginBlocks && o.EarliestSubmitHeight < head-params.OrderFreshnessMarginBlocks {
		return Result{}, fmt.Errorf("%w: earliest_submit_height %d is more than %d blocks below the head %d",
			ErrOrderStale, o.EarliestSubmitHeight, params.OrderFreshnessMarginBlocks, head)
	}
	if o.EarliestSubmitHeight > head+1 {
		return Result{}, fmt.Errorf("%w: earliest_submit_height %d is above the head %d plus one",
			ErrOrderFuture, o.EarliestSubmitHeight, head)
	}
	if t := s.PendingTakeover; t != nil {
		return Result{}, &TakeoverPendingError{Candidate: t.CandidateBuilder, ActivationHeight: t.ActivationHeight}
	}
	if e := ls.orders[o.Sequence]; e != nil {
		below := o.Sequence < s.NextExpectedSequence
		switch {
		case e.State == StateFailed:
			res.Retry = !below
		case e.TaskHash == o.TaskHash && e.State == StateDispatching && !e.Committed:
			return Result{}, fmt.Errorf("%w: sequence %d is reserved and its input is still being uploaded; retry",
				ErrOrderUploading, o.Sequence)
		case e.TaskHash == o.TaskHash:
			// Below next a live order is one the chain recorded before this Builder saw the event.
			existing := *e
			res.Existing = &existing
			return res, nil
		case below && e.State != StateRecorded:
			// Another version of a consumed sequence: the sequence check refuses it.
		case e.State == StateDispatching:
			return Result{}, fmt.Errorf("%w: sequence %d is being dispatched with task_hash %s", ErrOrderReplacementUnsupported, o.Sequence, e.TaskHash)
		case e.State == StateAccepted:
			return Result{}, fmt.Errorf("%w: a Worker accepted sequence %d with task_hash %s", ErrOrderLocked, o.Sequence, e.TaskHash)
		default:
			return Result{}, fmt.Errorf("%w: sequence %d was recorded with task_hash %s", ErrTaskTerminal, o.Sequence, e.TaskHash)
		}
	}
	if from := ls.meta.SuspendedFrom; from != nil && *from >= s.NextExpectedSequence && o.Sequence != *from {
		return Result{}, fmt.Errorf("%w: dispatch is suspended until sequence %d is sent again", ErrSessionSuspended, *from)
	}
	if _, cancelling := ls.meta.CancelRequested[o.Sequence]; cancelling {
		return Result{}, fmt.Errorf("%w: a cancellation of sequence %d is registered", ErrOrderSequenceConflict, o.Sequence)
	}
	if !sequenceOpen(ls, s.NextExpectedSequence, o.Sequence, inFlight.count) {
		return Result{}, fmt.Errorf("%w: sequence %d is not the first free sequence after next %d and %d in-flight orders",
			ErrOrderSequenceConflict, o.Sequence, s.NextExpectedSequence, inFlight.count)
	}
	if limit := params.BuilderMaxInflightPerSession; inFlight.count >= uint64(limit) {
		return Result{}, fmt.Errorf("%w: %d orders in flight, builder_max_inflight_per_session %d", ErrInflightLimit, inFlight.count, limit)
	}
	if limit := params.MaxPendingPerSession; inFlight.count >= uint64(limit) {
		return Result{}, fmt.Errorf("%w: %d orders in flight, max_pending_per_session %d", ErrInflightLimit, inFlight.count, limit)
	}
	if s.PendingWithdrawKind == taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE {
		return Result{}, fmt.Errorf("%w: a close of session %s takes effect at height %d", ErrSessionClosing, o.SessionID, s.PendingWithdrawEffectiveHeight)
	}
	available, err := availableFunds(s, inFlight.maxFee)
	if err != nil {
		return Result{}, err
	}
	if available.Cmp(new(big.Int).SetUint64(o.MaxFee)) < 0 {
		return Result{}, fmt.Errorf("%w: %s available after frozen, pending withdrawal and %d in-flight orders, max_fee %d",
			ErrSessionBalanceInsufficient, available, inFlight.count, o.MaxFee)
	}
	return res, nil
}

// CheckTakeoverFunds is the funds check of a takeover order against the session state s: no close
// registered or effective (ErrSessionClosing), and balance - frozen_total - pending withdrawal >=
// max_fee (ErrSessionBalanceInsufficient). A Builder taking a session over has no in-flight
// order of it.
func CheckTakeoverFunds(s Session, maxFee uint64) error {
	if s.Closed || s.PendingWithdrawKind == taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE {
		return fmt.Errorf("%w: the session is closed or closing", ErrSessionClosing)
	}
	available, err := availableFunds(s, new(big.Int))
	if err != nil {
		return err
	}
	if available.Cmp(new(big.Int).SetUint64(maxFee)) < 0 {
		return fmt.Errorf("%w: %s available after frozen and pending withdrawal, max_fee %d", ErrSessionBalanceInsufficient, available, maxFee)
	}
	return nil
}

// sequenceOpen reports whether a new order may take seq, given next, the chain's next expected
// sequence, and count, the live orders at or above it.
//
// The live orders at or above next need not be contiguous: an attempt that ends without a record
// (no capacity, revoked, released before dispatch) leaves a hole, and later orders stay live. The
// chain admits nothing past a hole until its sequence is recorded, so a hole is filled only by a
// new order for it. A new order is therefore admitted at seq when every sequence from next to
// seq-1 has a live order and seq has none: the sequence right after the run of live orders, or a
// hole at the end of that run being retried. Any order past a hole is refused.
func sequenceOpen(ls *sessionLedger, next, seq, count uint64) bool {
	if seq < next || seq-next > count {
		return false
	}
	for q := next; q < seq; q++ {
		if e := ls.orders[q]; e == nil || !e.State.live() {
			return false
		}
	}
	e := ls.orders[seq]
	return e == nil || !e.State.live()
}

// availableFunds is balance - frozen_total - pending withdrawal amount - in-flight max_fee; it may
// be negative.
func availableFunds(s Session, inFlight *big.Int) (*big.Int, error) {
	available, err := parseAmount("balance", s.Balance)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct{ name, value string }{
		{"frozen_total", s.FrozenTotal}, {"pending_withdraw_amount", s.PendingWithdrawAmount},
	} {
		v, err := parseAmount(field.name, field.value)
		if err != nil {
			return nil, err
		}
		available.Sub(available, v)
	}
	return available.Sub(available, inFlight), nil
}

func parseAmount(field, value string) (*big.Int, error) {
	if value == "" {
		return new(big.Int), nil
	}
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("%w: session %s %q is not a decimal amount", ErrUnavailable, field, value)
	}
	return n, nil
}

func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// keyState is the registered key part of a session state, with its pending change.
func keyState(s Session) registeredkey.State {
	state := registeredkey.State{
		Found: s.Found, Owner: s.Owner, Closed: s.Closed, ExpiryHeight: s.ExpiryHeight, SetHeight: s.SetHeight,
		SpendCap: s.SpendCap, Spent: s.Spent,
	}
	if len(s.Key) == 20 {
		state.Key = (*[20]byte)(s.Key)
	}
	if c := s.PendingKeyChange; c != nil {
		pending := &registeredkey.PendingChange{
			Clear:           c.Kind == taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR,
			ExpiryHeight:    c.ExpiryHeight,
			SpendCap:        c.SpendCap,
			EffectiveHeight: c.EffectiveHeight,
		}
		if len(c.Key) == 20 {
			pending.Key = (*[20]byte)(c.Key)
		}
		state.Pending = pending
	}
	return state
}
