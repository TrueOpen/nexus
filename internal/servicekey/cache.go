package servicekey

import (
	"context"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// DefaultCacheTTL bounds how long a cached current service key may be served when the rotation
// event that should drop it was missed.
const DefaultCacheTTL = 3 * time.Second

// Cache is a Resolver that keeps successful current service key reads for a short TTL. Uplink
// messages, handraises and roots each check a signer's current key and authorization nonce; without
// it every one of them is a chain query. A rotation event drops the operator's entries
// at once (ObserveEvent); the TTL only bounds staleness when such an event is lost. Failed reads
// are never cached, so a new registration is seen on the next read.
type Cache struct {
	resolver Resolver
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
	// generation counts invalidations; a read that started before one does not store its result.
	generation uint64
}

type cacheKey struct{ participantType, operator string }

type cacheEntry struct {
	state   chaincli.ServiceKeyState
	expires time.Time
}

// NewCache caches reads of resolver for ttl (DefaultCacheTTL when ttl is not positive).
func NewCache(resolver Resolver, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{resolver: resolver, ttl: ttl, now: time.Now, entries: map[cacheKey]cacheEntry{}}
}

// QueryCurrentServiceKey implements Resolver.
func (c *Cache) QueryCurrentServiceKey(ctx context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	key := cacheKey{participantType, operator}
	c.mu.Lock()
	entry, ok := c.entries[key]
	generation := c.generation
	c.mu.Unlock()
	if ok && c.now().Before(entry.expires) {
		return entry.state, nil
	}
	state, err := c.resolver.QueryCurrentServiceKey(ctx, participantType, operator)
	if err != nil {
		return chaincli.ServiceKeyState{}, err
	}
	c.mu.Lock()
	if c.generation == generation {
		c.entries[key] = cacheEntry{state: state, expires: c.now().Add(c.ttl)}
	}
	c.mu.Unlock()
	return state, nil
}

// Invalidate drops every cached key of operator, in all participant domains.
func (c *Cache) Invalidate(operator string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	for key := range c.entries {
		if key.operator == operator {
			delete(c.entries, key)
		}
	}
}

// InvalidateAll drops every cached key.
func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.entries = map[cacheKey]cacheEntry{}
}

// ObserveEvent drops the keys a chain event made stale: a SERVICE_KEY_ROTATED event (the new key
// became current) or a SERVICE_KEY_ROTATION_REGISTERED event (a replacement is now pending) drops
// its operator's keys, or every key when the event arrived without a readable operator.
func (c *Cache) ObserveEvent(ev chaincli.ChainEvent) {
	if ev.Type != chaincli.EventHubOperational {
		return
	}
	var operator string
	switch ev.EventCode {
	case "SERVICE_KEY_ROTATED":
		if rotated, ok := ev.Typed.(chaincli.ServiceKeyRotated); ok {
			operator = rotated.Operator
		}
	case "SERVICE_KEY_ROTATION_REGISTERED":
		if registered, ok := ev.Typed.(chaincli.ServiceKeyRotationRegistered); ok {
			operator = registered.Operator
		}
	default:
		return
	}
	if operator == "" {
		c.InvalidateAll()
		return
	}
	c.Invalidate(operator)
}
