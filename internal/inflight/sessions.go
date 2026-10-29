package inflight

import (
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
// with the new state; a refresh is started in the background. Events at or below the height a
// state was read at are already in it and are skipped.
type SessionCache struct {
	cfg  SessionCacheConfig
	head atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*cachedSession
	gen      uint64 // bumped on every change; a read is kept only if its session did not change meanwhile
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
}

// NewSessionCache builds a SessionCache.
func NewSessionCache(cfg SessionCacheConfig) (*SessionCache, error) {
	if cfg.Read == nil || cfg.LatestHeight == nil || cfg.Ledger == nil {
		return nil, fmt.Errorf("session cache needs a state reader, a height reader and a ledger")
	}
	if cfg.Background == nil {
		cfg.Background = func(f func()) { go f() }
	}
	return &SessionCache{cfg: cfg, sessions: make(map[string]*cachedSession)}, nil
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

// readHead reads the head from the chain and reports whether it is above the cached one.
func (c *SessionCache) readHead(ctx context.Context) bool {
	height, err := c.cfg.LatestHeight(ctx)
	if err != nil || height <= c.Head() {
		return false
	}
	c.ObserveHeight(height)
	return true
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
	c.mu.Unlock()

	state, err := c.read(ctx, sessionID)
	if err != nil {
		return Session{}, 0, 0, err
	}
	if !state.Found {
		return state, head, gen, nil
	}
	c.mu.Lock()
	e = c.sessions[sessionID]
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
	return state, head, gen, nil
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
	state, err := c.read(ctx, sessionID)
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
// the gap were missed, so the state is read again.
func (c *SessionCache) SessionStreamUp(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.sessions[sessionID]
	if e == nil {
		// Streams opened for other reasons (the session's tasks) count too.
		e = &cachedSession{}
		c.sessions[sessionID] = e
	}
	e.up, e.have, e.gen = true, false, c.bumpLocked()
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
