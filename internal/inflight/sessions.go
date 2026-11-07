package inflight

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/stagetiming"
)

// refreshTimeout bounds a background refresh of one session's state.
const refreshTimeout = 10 * time.Second

// Defaults of the session cache.
const (
	// DefaultStateTTLBlocks is how many blocks a session state is served before it is read again
	// without any event asking for it.
	DefaultStateTTLBlocks = uint64(20)
	// DefaultNegativeTTLBlocks is how many blocks a session the chain does not know is remembered
	// as unknown; DefaultNegativeSize bounds those sessions, oldest dropped first.
	DefaultNegativeTTLBlocks = uint64(2)
	DefaultNegativeSize      = 1024
	// DefaultLookupsPerSecond bounds the chain reads of lookups that find no kept state.
	DefaultLookupsPerSecond = uint32(20)
)

// fundsReleasingTaskEvents are the task-level events after which the session's frozen_total may
// be lower: settlement, timeouts and deadline sweeps that refund. None of them has a session-level
// counterpart.
var fundsReleasingTaskEvents = map[string]bool{
	"TASK_SETTLED": true, "DEADLINE_SWEPT": true, "WORKER_TIMEOUT": true, "VERIFY_OPEN_TIMEOUT": true,
}

// Session is a session's chain state as the precheck reads it. Found is false when the chain has
// no such session. Pointer and slice fields are shared between copies and never modified.
type Session struct {
	chaincli.SessionState
	Found bool
}

// SessionCacheConfig configures a SessionCache.
type SessionCacheConfig struct {
	// Read returns the session's StreamState; chaincli.ErrNotFound when the chain has no such
	// session.
	Read func(ctx context.Context, sessionID string) (chaincli.SessionState, error)
	// LatestHeight reads the head; it is asked until a height arrives with a chain event, and
	// again before an order is refused as from the future.
	LatestHeight func(ctx context.Context) (uint64, error)
	// Tracker, when set, is asked to follow the session-level events of every session the chain
	// knows on its first lookup. Without it no state is kept and every lookup reads the chain.
	Tracker chaincli.SessionEventTracker
	// Ledger receives the order cancellations and records the events report.
	Ledger *Ledger
	// Background runs a state refresh; nil runs it on a new goroutine.
	Background func(func())
	// StateTTLBlocks: a state read this many blocks ago is read again in the background on the
	// next lookup; 0 is DefaultStateTTLBlocks. It bounds how long a change no event reports (funds
	// a settlement released) stays unseen.
	StateTTLBlocks uint64
	// NegativeTTLBlocks and NegativeSize bound how long and how many sessions the chain does not
	// know are remembered; 0 is the default.
	NegativeTTLBlocks uint64
	NegativeSize      int
	// LookupsPerSecond bounds the chain reads of lookups without a kept state and of reloads (a
	// burst of two seconds' worth); 0 is DefaultLookupsPerSecond. A read over the budget is
	// ErrUnavailable. Concurrent lookups of one session share a read.
	LookupsPerSecond uint32
	Now              func() time.Time
}

// SessionCache keeps the chain state of the sessions this Builder receives orders for, and the
// head, so the OpenTask precheck reads no chain on its hot path.
//
// A session's state is kept only while its event stream is up (chaincli.SessionStreamObserver):
// events would be missed otherwise. It is then updated from the session's events where an event
// carries the new value (deposits, withdrawals, binding, takeover registration, cancellations, a
// registered key clear) and dropped where it does not (a registered key set or update, a resync);
// the next lookup reads the chain once. A record of an order the ledger holds keeps the state:
// the ledger counts the order until the state includes it, so the old state and the ledger agree
// with the new state; a refresh is started in the background. Settlement and refunds lower
// frozen_total with task-level events only: those of the session's tasks start a refresh too, a
// state older than StateTTLBlocks is refreshed regardless, and the precheck reads the state again
// before refusing an order for its funds (reload). Events at or below the height a state was read
// at are already in it and are skipped.
type SessionCache struct {
	cfg  SessionCacheConfig
	head atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*cachedSession
	gen      uint64                  // bumped on every change; a read is kept only if its session did not change meanwhile
	reads    map[string]*sessionRead // the cold read under way per session
	unknown  map[string]*list.Element
	unknowns *list.List // of unknownSession, oldest at the front
	budget   readBudget

	// headMu guards the RefreshHead read under way and when the last one started.
	headMu     sync.Mutex
	headCall   *headRead
	headReadAt time.Time
}

// sessionRead is a cold read other lookups of the session wait for.
type sessionRead struct {
	done    chan struct{}
	waiters int // guarded by SessionCache.mu
	state   Session
	gen     uint64
	err     error
}

type unknownSession struct {
	sessionID  string
	readHeight uint64
}

type cachedSession struct {
	tracked    bool // this cache asked the Tracker to follow the session
	up         bool // the session's event stream is connected
	have       bool // state holds a state read while the stream was up
	state      Session
	readHeight uint64 // the head when state was read; the state includes every event up to it
	gen        uint64
	refreshDue bool
	refreshing bool
	// reloadHeight is the head at the last reload; one reload per block at most.
	reloadHeight uint64
}

// NewSessionCache builds a SessionCache.
func NewSessionCache(cfg SessionCacheConfig) (*SessionCache, error) {
	if cfg.Read == nil || cfg.LatestHeight == nil || cfg.Ledger == nil {
		return nil, fmt.Errorf("session cache needs a state reader, a height reader and a ledger")
	}
	if cfg.Background == nil {
		cfg.Background = func(f func()) { go f() }
	}
	if cfg.StateTTLBlocks == 0 {
		cfg.StateTTLBlocks = DefaultStateTTLBlocks
	}
	if cfg.NegativeTTLBlocks == 0 {
		cfg.NegativeTTLBlocks = DefaultNegativeTTLBlocks
	}
	if cfg.NegativeSize <= 0 {
		cfg.NegativeSize = DefaultNegativeSize
	}
	if cfg.LookupsPerSecond == 0 {
		cfg.LookupsPerSecond = DefaultLookupsPerSecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &SessionCache{
		cfg: cfg, sessions: make(map[string]*cachedSession), reads: make(map[string]*sessionRead),
		unknown: make(map[string]*list.Element), unknowns: list.New(), budget: newReadBudget(cfg.LookupsPerSecond, cfg.Now()),
	}, nil
}

// Prewarm follows the session-level events of every session the ledger holds, as after a
// restart: their cancellations and records must be seen again, and their state is read as soon
// as their stream is up, before an order arrives.
func (c *SessionCache) Prewarm() {
	if c.cfg.Tracker == nil {
		return
	}
	for _, sessionID := range c.cfg.Ledger.Sessions() {
		c.mu.Lock()
		e := c.sessions[sessionID]
		if e == nil {
			e = &cachedSession{gen: c.bumpLocked()}
			c.sessions[sessionID] = e
		}
		track := !e.tracked
		e.tracked = true
		c.mu.Unlock()
		if track {
			if err := c.cfg.Tracker.TrackSessionEvents(sessionID); err != nil {
				c.untracked(sessionID)
			}
		}
	}
}

// BoundTo counts the cached sessions bound to builder.
func (c *SessionCache) BoundTo(builder string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.sessions {
		if s.have && s.state.Found && s.state.BoundBuilder == builder {
			n++
		}
	}
	return n
}

// Head returns the latest height seen, 0 before any.
func (c *SessionCache) Head() uint64 { return c.head.Load() }

// ObserveHeight raises the head to height; it never goes back.
func (c *SessionCache) ObserveHeight(height uint64) {
	for {
		current := c.head.Load()
		if height <= current || c.head.CompareAndSwap(current, height) {
			return
		}
	}
}

// CurrentHeight returns the head, reading the chain only while no height has been seen. It lets
// the cache serve as the height source of request verification.
func (c *SessionCache) CurrentHeight(ctx context.Context) (uint64, error) {
	if head := c.Head(); head != 0 {
		return head, nil
	}
	height, err := c.cfg.LatestHeight(ctx)
	if err != nil || height == 0 {
		return 0, fmt.Errorf("%w: latest height: %v", ErrUnavailable, err)
	}
	c.ObserveHeight(height)
	return c.Head(), nil
}

// HeadRefreshInterval is the least time between two chain reads of RefreshHead, shared by all its
// callers.
const HeadRefreshInterval = 250 * time.Millisecond

// headRead is a RefreshHead read other callers wait for.
type headRead struct {
	done chan struct{}
	err  error
}

// RefreshHead reads the head from the chain, raises the cached head to it and returns the cached
// head; a failed read is ErrUnavailable and leaves the head as it was. Concurrent callers share
// one read, and a call within HeadRefreshInterval of the start of the last read reads nothing and
// returns the cached head. A caller whose ctx ends while it waits for another's read returns at
// once.
func (c *SessionCache) RefreshHead(ctx context.Context) (uint64, error) {
	c.headMu.Lock()
	if call := c.headCall; call != nil {
		c.headMu.Unlock()
		select {
		case <-call.done:
			return c.Head(), call.err
		case <-ctx.Done():
			return c.Head(), fmt.Errorf("%w: latest height: %v", ErrUnavailable, ctx.Err())
		}
	}
	now := c.cfg.Now()
	if !c.headReadAt.IsZero() && now.Sub(c.headReadAt) < HeadRefreshInterval {
		c.headMu.Unlock()
		return c.Head(), nil
	}
	call := &headRead{done: make(chan struct{})}
	c.headCall, c.headReadAt = call, now
	c.headMu.Unlock()
	_, call.err = c.readHead(ctx)
	c.headMu.Lock()
	c.headCall = nil
	c.headMu.Unlock()
	close(call.done)
	return c.Head(), call.err
}

// readHead reads the head from the chain and reports whether it is above the cached one; a
// failed read is ErrUnavailable.
func (c *SessionCache) readHead(ctx context.Context) (bool, error) {
	height, err := c.cfg.LatestHeight(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: latest height: %v", ErrUnavailable, err)
	}
	if height <= c.Head() {
		return false, nil
	}
	c.ObserveHeight(height)
	return true, nil
}

// Lookup returns the session's state and the head it is judged at.
func (c *SessionCache) Lookup(ctx context.Context, sessionID string) (Session, uint64, error) {
	state, head, _, err := c.lookup(ctx, sessionID)
	return state, head, err
}

// lookup is Lookup that also returns the generation of the state: while current(sessionID, gen)
// holds, no event or stored read changed the session since.
func (c *SessionCache) lookup(ctx context.Context, sessionID string) (Session, uint64, uint64, error) {
	head, err := c.CurrentHeight(ctx)
	if err != nil {
		return Session{}, 0, 0, err
	}
	c.mu.Lock()
	e := c.sessions[sessionID]
	if e != nil && e.up && e.have {
		state, gen := e.state, e.gen
		if head >= e.readHeight+c.cfg.StateTTLBlocks {
			e.refreshDue = true
		}
		refresh := c.takeRefreshLocked(sessionID, e)
		c.mu.Unlock()
		if refresh != nil {
			c.cfg.Background(refresh)
		}
		return state, head, gen, nil
	}
	gen := uint64(0)
	if e != nil {
		gen = e.gen
	}
	if u, ok := c.unknown[sessionID]; ok && head < u.Value.(unknownSession).readHeight+c.cfg.NegativeTTLBlocks {
		c.mu.Unlock()
		return Session{}, head, gen, nil
	}
	if pending := c.reads[sessionID]; pending != nil {
		pending.waiters++
		c.mu.Unlock()
		select {
		case <-pending.done:
		case <-ctx.Done():
			return Session{}, 0, 0, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
		}
		return pending.state, head, pending.gen, pending.err
	}
	if !c.budget.take(c.cfg.Now()) {
		c.mu.Unlock()
		return Session{}, 0, 0, fmt.Errorf("%w: session state read budget exhausted", ErrUnavailable)
	}
	pending := &sessionRead{done: make(chan struct{})}
	c.reads[sessionID] = pending
	c.mu.Unlock()

	state, gen, err := c.coldRead(ctx, sessionID, head, gen)
	c.mu.Lock()
	delete(c.reads, sessionID)
	pending.state, pending.gen, pending.err = state, gen, err
	close(pending.done)
	c.mu.Unlock()
	if err != nil {
		return Session{}, 0, 0, err
	}
	return state, head, gen, nil
}

// coldRead reads a session without a kept state, keeps it when its stream is up and the session
// did not change since gen, and returns it with its generation.
func (c *SessionCache) coldRead(ctx context.Context, sessionID string, head, gen uint64) (Session, uint64, error) {
	state, err := c.read(ctx, sessionID)
	if err != nil {
		return Session{}, 0, err
	}
	c.mu.Lock()
	if !state.Found {
		c.rememberUnknownLocked(sessionID, head)
		c.mu.Unlock()
		return state, gen, nil
	}
	c.forgetUnknownLocked(sessionID)
	e := c.sessions[sessionID]
	if e == nil && c.cfg.Tracker != nil {
		// No event of the session could have been applied before the entry existed.
		e = &cachedSession{gen: c.bumpLocked()}
		c.sessions[sessionID] = e
		gen = e.gen
	}
	track := e != nil && !e.tracked && c.cfg.Tracker != nil
	if track {
		e.tracked = true
	}
	stored := e != nil && e.up && e.gen == gen
	if stored {
		e.state, e.have, e.readHeight, e.refreshDue = state, true, head, false
		e.gen = c.bumpLocked()
		gen = e.gen
	}
	c.mu.Unlock()
	if track {
		if err := c.cfg.Tracker.TrackSessionEvents(sessionID); err != nil {
			c.untracked(sessionID)
		}
	}
	if stored {
		c.prune(sessionID, state.NextExpectedSequence, head, gen)
	}
	return state, gen, nil
}

func (c *SessionCache) rememberUnknownLocked(sessionID string, head uint64) {
	c.forgetUnknownLocked(sessionID)
	for c.unknowns.Len() >= c.cfg.NegativeSize {
		oldest := c.unknowns.Front()
		c.unknowns.Remove(oldest)
		delete(c.unknown, oldest.Value.(unknownSession).sessionID)
	}
	c.unknown[sessionID] = c.unknowns.PushBack(unknownSession{sessionID: sessionID, readHeight: head})
}

func (c *SessionCache) forgetUnknownLocked(sessionID string) {
	if u, ok := c.unknown[sessionID]; ok {
		c.unknowns.Remove(u)
		delete(c.unknown, sessionID)
	}
}

// joiners returns how many lookups wait for the session's cold read under way.
func (c *SessionCache) joiners(sessionID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pending := c.reads[sessionID]; pending != nil {
		return pending.waiters
	}
	return 0
}

// current reports whether the session did not change since gen, a generation lookup returned.
// It takes c.mu: callers may hold the ledger lock (the lock order is ledger, then cache).
func (c *SessionCache) current(sessionID string, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.sessions[sessionID]
	if e == nil {
		return gen == 0
	}
	return e.gen == gen
}

// prune drops the ledger state a stored session state includes, unless the session changed since
// that state was stored at gen: a prune against an older or newer state than the cached one
// could drop an order the cached state does not include yet.
func (c *SessionCache) prune(sessionID string, next, head, gen uint64) {
	_ = c.cfg.Ledger.pruneIf(sessionID, next, head, func() bool { return c.current(sessionID, gen) })
}

func (c *SessionCache) read(ctx context.Context, sessionID string) (Session, error) {
	start := time.Now()
	state, err := c.cfg.Read(ctx, sessionID)
	stagetiming.From(ctx).Since("chain_session_state", start)
	if errors.Is(err, chaincli.ErrNotFound) {
		return Session{}, nil
	}
	if err != nil {
		return Session{}, fmt.Errorf("%w: session state: %v", ErrUnavailable, err)
	}
	return Session{SessionState: state, Found: true}, nil
}

func (c *SessionCache) bumpLocked() uint64 {
	c.gen++
	return c.gen
}

func (c *SessionCache) untracked(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.sessions[sessionID]; e != nil {
		e.tracked = false
	}
}

// takeRefreshLocked returns the refresh a record asked for, if none is under way; the caller
// runs it in the background once c.mu is released.
func (c *SessionCache) takeRefreshLocked(sessionID string, e *cachedSession) func() {
	if !e.refreshDue || e.refreshing {
		return nil
	}
	e.refreshing = true
	gen, head := e.gen, c.Head()
	return func() { c.refresh(sessionID, gen, head) }
}

func (c *SessionCache) refresh(sessionID string, gen, head uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	var err error
	if head == 0 { // no height seen yet: the state must not look older than it is
		head, err = c.CurrentHeight(ctx)
	}
	var state Session
	if err == nil {
		state, err = c.read(ctx, sessionID)
	}
	c.mu.Lock()
	e := c.sessions[sessionID]
	if e == nil {
		c.mu.Unlock()
		return
	}
	e.refreshing = false
	stored := err == nil && state.Found && e.up && e.gen == gen
	if stored {
		e.state, e.have, e.readHeight, e.refreshDue = state, true, head, false
		e.gen = c.bumpLocked()
		gen = e.gen
	}
	c.mu.Unlock()
	if stored {
		c.prune(sessionID, state.NextExpectedSequence, head, gen)
	}
}

// reload reads a kept session state again now, before the precheck refuses an order for its
// funds, and reports whether it did. A session is reloaded at most once per block.
func (c *SessionCache) reload(ctx context.Context, sessionID string) bool {
	head := c.Head()
	c.mu.Lock()
	e := c.sessions[sessionID]
	if e == nil || !e.up || !e.have || e.reloadHeight >= head || !c.budget.take(c.cfg.Now()) {
		c.mu.Unlock()
		return false
	}
	e.reloadHeight = head
	gen := e.gen
	c.mu.Unlock()
	state, err := c.read(ctx, sessionID)
	if err != nil || !state.Found {
		return false
	}
	c.mu.Lock()
	e = c.sessions[sessionID]
	stored := e != nil && e.up && e.gen == gen
	if stored {
		e.state, e.have, e.readHeight, e.refreshDue = state, true, head, false
		e.gen = c.bumpLocked()
		gen = e.gen
	}
	c.mu.Unlock()
	if stored {
		c.prune(sessionID, state.NextExpectedSequence, head, gen)
	}
	// Not stored: an event changed the session meanwhile, which a new attempt sees as well.
	return true
}

// taskEnded asks for a refresh of the session after a task-level event that may release funds.
func (c *SessionCache) taskEnded(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.sessions[sessionID]; e != nil && e.have {
		e.refreshDue = true
	}
}

// invalidate drops the session's state; the next lookup reads the chain.
func (c *SessionCache) invalidate(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.sessions[sessionID]; e != nil {
		e.have, e.gen = false, c.bumpLocked()
	}
}

// apply updates the session's state with an event at height.
func (c *SessionCache) apply(sessionID string, height int64, update func(*Session)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.sessions[sessionID]
	if e == nil {
		return
	}
	e.gen = c.bumpLocked()
	if !e.have || height <= 0 || uint64(height) <= e.readHeight {
		return
	}
	state := e.state
	update(&state)
	e.state = state
}

// SessionStreamUp implements chaincli.SessionStreamObserver: from now on events arrive; updates of
// the gap were missed, so the state is read again, at once in the background for a session this
// cache follows.
func (c *SessionCache) SessionStreamUp(sessionID string) {
	c.mu.Lock()
	e := c.sessions[sessionID]
	if e == nil {
		// Streams opened for other reasons (the session's tasks) count too.
		e = &cachedSession{}
		c.sessions[sessionID] = e
	}
	e.up, e.have, e.gen = true, false, c.bumpLocked()
	var load func()
	if e.tracked && !e.refreshing {
		e.refreshing = true
		gen, head := e.gen, c.Head()
		load = func() { c.refresh(sessionID, gen, head) }
	}
	c.mu.Unlock()
	if load != nil {
		c.cfg.Background(load)
	}
}

// SessionStreamDown implements chaincli.SessionStreamObserver: until the stream is up again,
// nothing is kept.
func (c *SessionCache) SessionStreamDown(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.sessions[sessionID]; e != nil {
		e.up, e.have, e.gen = false, false, c.bumpLocked()
	}
}

// SessionStreamClosed implements chaincli.SessionStreamObserver: the session is no longer
// followed.
func (c *SessionCache) SessionStreamClosed(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, sessionID)
}

// SessionKeyUpdated implements chaincli.SessionStreamObserver: a registered key change took
// effect.
func (c *SessionCache) SessionKeyUpdated(sessionID string) { c.invalidate(sessionID) }

// HandleChainEvent follows the head and the sessions' events. The caller feeds it every chain
// event; an error is a ledger write that failed.
func (c *SessionCache) HandleChainEvent(ev chaincli.ChainEvent) error {
	if ev.Height > 0 {
		c.ObserveHeight(uint64(ev.Height))
	}
	if ev.Type == chaincli.EventResyncRequired && ev.SessionID != "" {
		c.invalidate(ev.SessionID)
		return nil
	}
	if ev.TaskID != "" && ev.SessionID != "" && fundsReleasingTaskEvents[ev.EventCode] {
		c.taskEnded(ev.SessionID)
	}
	switch t := ev.Typed.(type) {
	case chaincli.SessionDeposited:
		c.apply(t.SessionID, ev.Height, func(s *Session) { s.Balance = t.Balance })
	case chaincli.SessionWithdrawRequested:
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			s.PendingWithdrawKind, s.PendingWithdrawAmount, s.PendingWithdrawEffectiveHeight = t.Kind, t.Amount, t.EffectiveHeight
		})
	case chaincli.SessionWithdrawEffective:
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			s.Balance = t.RemainingBalance
			s.PendingWithdrawKind = taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_UNSPECIFIED
			s.PendingWithdrawAmount, s.PendingWithdrawEffectiveHeight = "0", 0
			if t.Kind == taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE {
				s.Closed = true
			}
		})
	case chaincli.SessionKeyChangeRequested:
		if t.Kind != taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR {
			c.invalidate(t.SessionID) // the event does not carry the key a SET installs
			return nil
		}
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			s.PendingKeyChange = &chaincli.PendingSessionKeyChange{Kind: t.Kind, EffectiveHeight: t.EffectiveHeight}
		})
	case chaincli.SessionBuilderBound:
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			s.BoundBuilder, s.BoundChangeHeight, s.PendingTakeover = t.NewBuilder, t.BoundChangeHeight, nil
		})
	case chaincli.SessionTakeoverRegistered:
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			s.PendingTakeover = &chaincli.PendingTakeover{
				CandidateBuilder: t.CandidateBuilder, OrderSequence: t.OrderSequence,
				RegisteredHeight: t.RegisteredHeight, ActivationHeight: t.ActivationHeight,
			}
		})
	case chaincli.SessionTakeoverVoided:
		c.apply(t.SessionID, ev.Height, func(s *Session) { s.PendingTakeover = nil })
	case chaincli.OrderCancelRequested:
		c.apply(t.SessionID, ev.Height, func(*Session) {})
		return c.cfg.Ledger.cancelRequested(t.SessionID, t.OrderSequence, t.CancelEffectiveHeight)
	case chaincli.OrderCancelled:
		c.apply(t.SessionID, ev.Height, func(s *Session) {
			if s.NextExpectedSequence <= t.OrderSequence {
				s.NextExpectedSequence = t.OrderSequence + 1
			}
		})
		return c.cfg.Ledger.cancelled(t.SessionID, t.OrderSequence)
	case chaincli.DispatchRecorded:
		return c.recorded(t, ev.Height)
	}
	return nil
}

// recorded handles the admission of a dispatch entry of the session. The ledger is updated before
// c.mu is taken (the lock order is ledger, then cache); a recorded order still counts, so a
// precheck in between judges the old state consistently.
func (c *SessionCache) recorded(t chaincli.DispatchRecorded, height int64) error {
	entry, held := c.cfg.Ledger.Get(t.SessionID, t.OrderSequence)
	held = held && entry.State.live()
	if held {
		if err := c.cfg.Ledger.MarkRecorded(t.SessionID, t.OrderSequence); err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.sessions[t.SessionID]
	if e != nil {
		e.gen = c.bumpLocked()
	}
	if e == nil || !e.have || height > 0 && uint64(height) <= e.readHeight || t.OrderSequence < e.state.NextExpectedSequence {
		return nil
	}
	if !held {
		e.have = false
		return nil
	}
	e.refreshDue = true
	return nil
}
