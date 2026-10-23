package registeredkey

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

// Defaults of the ingress registered key cache.
const (
	DefaultTTLBlocks        = uint64(5)
	MaxTTLBlocks            = uint64(10)
	DefaultLookupsPerSecond = uint32(20)
	// DefaultSize bounds sessions with a registered key; DefaultNegativeSize bounds sessions without
	// one (or unknown to the chain), so signatures that recover to nobody cannot push out the
	// sessions real users sign for.
	DefaultSize         = 4096
	DefaultNegativeSize = 1024

	lookupBurstSeconds int64 = 2
)

// CacheConfig configures a Cache.
type CacheConfig struct {
	// Read returns a session's state from the chain: Found false when the chain has no such
	// session, an error only when it cannot be read.
	Read func(ctx context.Context, sessionID string) (State, error)
	// TTLBlocks is how many blocks an entry is used for after the height it was read at; 0 is
	// DefaultTTLBlocks.
	TTLBlocks uint64
	// LookupsPerSecond bounds chain reads on cache misses (a burst of two seconds' worth); 0 is
	// DefaultLookupsPerSecond. A miss over the budget is ErrUnavailable.
	LookupsPerSecond uint32
	// Size and NegativeSize bound the entries with and without a registered key, least recently
	// used evicted first; 0 is the default.
	Size, NegativeSize int
	Now                func() time.Time
}

// Cache keeps session states, found or not, for a few blocks so that requests signed by a
// registered key, and requests whose signatures recover to nobody, do not each cost a chain read.
//
// The caller passes the current height it already read; an entry read at height h is used while
// height < h + TTLBlocks. The cache is a chaincli.SessionStreamObserver: for a session whose task
// events this Builder follows, a key update or a stream reconnect drops the entry, and while the
// stream is down nothing is kept. Other sessions have no event stream and rely on the block
// expiry alone. A miss that cannot be filled is an error, never a pass.
type Cache struct {
	cfg CacheConfig

	mu      sync.Mutex
	entries map[string]*list.Element
	keyed   *list.List // entries with a registered key, most recently used at the front
	unkeyed *list.List // entries without one
	down    map[string]struct{}
	// inflight holds the read under way per session. Invalidating a session marks its read stale
	// and removes it, so the read is neither stored nor joined by later lookups.
	inflight map[string]*lookup
	tokens   int64
	refill   time.Time
}

type entry struct {
	sessionID  string
	state      State
	readHeight uint64
}

type lookup struct {
	done  chan struct{}
	stale bool // guarded by Cache.mu
	state State
	err   error
}

// NewCache builds a Cache.
func NewCache(cfg CacheConfig) (*Cache, error) {
	if cfg.Read == nil {
		return nil, fmt.Errorf("registered key cache needs a state reader")
	}
	if cfg.TTLBlocks == 0 {
		cfg.TTLBlocks = DefaultTTLBlocks
	}
	if cfg.TTLBlocks > MaxTTLBlocks {
		return nil, fmt.Errorf("registered key cache ttl %d blocks is above %d", cfg.TTLBlocks, MaxTTLBlocks)
	}
	if cfg.LookupsPerSecond == 0 {
		cfg.LookupsPerSecond = DefaultLookupsPerSecond
	}
	if cfg.Size <= 0 {
		cfg.Size = DefaultSize
	}
	if cfg.NegativeSize <= 0 {
		cfg.NegativeSize = DefaultNegativeSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cache{
		cfg: cfg, entries: make(map[string]*list.Element), keyed: list.New(), unkeyed: list.New(),
		down: make(map[string]struct{}), inflight: make(map[string]*lookup),
		tokens: int64(cfg.LookupsPerSecond) * lookupBurstSeconds, refill: cfg.Now(),
	}, nil
}

// Lookup returns the session's state as of no earlier than height, the latest committed height
// the caller read.
func (c *Cache) Lookup(ctx context.Context, sessionID string, height uint64) (State, error) {
	if height == 0 {
		return State{}, fmt.Errorf("%w: current height", ErrUnavailable)
	}
	c.mu.Lock()
	_, isDown := c.down[sessionID]
	if element, ok := c.entries[sessionID]; ok && !isDown {
		e := element.Value.(*entry)
		if height < e.readHeight+c.cfg.TTLBlocks {
			c.listFor(e.state).MoveToFront(element)
			c.mu.Unlock()
			return e.state, nil
		}
	}
	// Join the read already under way; one an invalidation overtook is no longer listed.
	if pending, ok := c.inflight[sessionID]; ok {
		c.mu.Unlock()
		select {
		case <-pending.done:
		case <-ctx.Done():
			return State{}, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
		}
		return pending.state, pending.err
	}
	if !c.takeTokenLocked() {
		c.mu.Unlock()
		return State{}, fmt.Errorf("%w: session state read budget exhausted", ErrUnavailable)
	}
	pending := &lookup{done: make(chan struct{})}
	c.inflight[sessionID] = pending
	c.mu.Unlock()

	// height was read before the state, so the state is at least as new as height.
	state, err := c.cfg.Read(ctx, sessionID)
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.mu.Lock()
	if c.inflight[sessionID] == pending {
		delete(c.inflight, sessionID)
	}
	_, isDown = c.down[sessionID]
	if err == nil && !isDown && !pending.stale {
		c.storeLocked(&entry{sessionID: sessionID, state: state, readHeight: height})
	}
	pending.state, pending.err = state, err
	close(pending.done)
	c.mu.Unlock()
	return state, err
}

// Invalidate drops the session's entry.
func (c *Cache) Invalidate(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateLocked(sessionID)
}

// SessionKeyUpdated drops the session's entry: its registered key changed.
func (c *Cache) SessionKeyUpdated(sessionID string) { c.Invalidate(sessionID) }

// SessionStreamDown marks the session's event stream as down: until it is up again, key updates
// would be missed, so nothing is kept and every lookup reads the chain.
func (c *Cache) SessionStreamDown(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.down[sessionID] = struct{}{}
	c.invalidateLocked(sessionID)
}

// SessionStreamUp ends SessionStreamDown. The entry is dropped once more: updates from the gap
// were missed.
func (c *Cache) SessionStreamUp(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.down, sessionID)
	c.invalidateLocked(sessionID)
}

// SessionStreamClosed: the session is no longer tracked. Its entry falls back to expiring by
// blocks alone, like any untracked session.
func (c *Cache) SessionStreamClosed(sessionID string) { c.SessionStreamUp(sessionID) }

func (c *Cache) invalidateLocked(sessionID string) {
	if pending, ok := c.inflight[sessionID]; ok {
		pending.stale = true
		delete(c.inflight, sessionID)
	}
	c.removeLocked(sessionID)
}

func (c *Cache) listFor(s State) *list.List {
	if s.Found && s.Key != nil {
		return c.keyed
	}
	return c.unkeyed
}

func (c *Cache) removeLocked(sessionID string) {
	if element, ok := c.entries[sessionID]; ok {
		c.listFor(element.Value.(*entry).state).Remove(element)
		delete(c.entries, sessionID)
	}
}

func (c *Cache) storeLocked(e *entry) {
	c.removeLocked(e.sessionID)
	l, limit := c.keyed, c.cfg.Size
	if l != c.listFor(e.state) {
		l, limit = c.unkeyed, c.cfg.NegativeSize
	}
	for l.Len() >= limit {
		oldest := l.Back()
		l.Remove(oldest)
		delete(c.entries, oldest.Value.(*entry).sessionID)
	}
	c.entries[e.sessionID] = l.PushFront(e)
}

// takeTokenLocked spends one chain read from a token bucket refilled at LookupsPerSecond.
func (c *Cache) takeTokenLocked() bool {
	now := c.cfg.Now()
	rate := int64(c.cfg.LookupsPerSecond)
	if elapsed := now.Sub(c.refill); elapsed > 0 {
		add := elapsed.Nanoseconds() * rate / int64(time.Second)
		if add > 0 {
			c.tokens += add
			c.refill = c.refill.Add(time.Duration(add * int64(time.Second) / rate))
		}
	}
	if burst := rate * lookupBurstSeconds; c.tokens >= burst {
		c.tokens = burst
		c.refill = now
	}
	if c.tokens <= 0 {
		return false
	}
	c.tokens--
	return true
}
