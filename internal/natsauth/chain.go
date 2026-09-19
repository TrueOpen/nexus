package natsauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// ChainQueries is the callout service's minimal chain dependency: the existing chaincli.Client satisfies it; tests use a fake.
type ChainQueries interface {
	QueryCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chaincli.ServiceKeyState, error)
	QueryCortexNode(ctx context.Context, operatorAddress string) (chaincli.CortexNodeState, error)
}

// ChainReader is the chain view seen by the verifier. ErrNotFound passes through; every other error is wrapped as CHAIN_UNAVAILABLE.
type ChainReader interface {
	CurrentServiceKey(ctx context.Context, operatorAddress string) (chaincli.ServiceKeyState, error)
	CortexNode(ctx context.Context, operatorAddress string) (chaincli.CortexNodeState, error)
}

const participantCortex = "CORTEX"

type cacheEntry[T any] struct {
	value   T
	expires time.Time
}

// CachedChain caches chain queries per §5.14.3: only successful results are cached; negative results and chain
// unavailability are not. After expiry, an unreachable chain means rejection; stale results never let a request through. ttl 0 disables caching.
type CachedChain struct {
	chain ChainQueries
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	keys  map[string]cacheEntry[chaincli.ServiceKeyState]
	nodes map[string]cacheEntry[chaincli.CortexNodeState]
}

// NewCachedChain constructs a caching chain reader. now defaults to time.Now when nil.
func NewCachedChain(chain ChainQueries, ttl time.Duration, now func() time.Time) *CachedChain {
	if now == nil {
		now = time.Now
	}
	return &CachedChain{
		chain: chain, ttl: ttl, now: now,
		keys:  map[string]cacheEntry[chaincli.ServiceKeyState]{},
		nodes: map[string]cacheEntry[chaincli.CortexNodeState]{},
	}
}

// CurrentServiceKey queries the Cortex participant's current service key row; participantType is fixed to CORTEX.
func (c *CachedChain) CurrentServiceKey(ctx context.Context, operatorAddress string) (chaincli.ServiceKeyState, error) {
	return lookup(c, c.keys, operatorAddress, func() (chaincli.ServiceKeyState, error) {
		return c.chain.QueryCurrentServiceKey(ctx, participantCortex, operatorAddress)
	})
}

// CortexNode queries the Cortex stable identity row.
func (c *CachedChain) CortexNode(ctx context.Context, operatorAddress string) (chaincli.CortexNodeState, error) {
	return lookup(c, c.nodes, operatorAddress, func() (chaincli.CortexNodeState, error) {
		return c.chain.QueryCortexNode(ctx, operatorAddress)
	})
}

// lookup is the cache logic shared by both queries: an unexpired hit is returned from cache; otherwise the chain is queried
// and only success is written back. ErrNotFound passes through uncached; other errors are wrapped as CHAIN_UNAVAILABLE, also uncached.
func lookup[T any](c *CachedChain, table map[string]cacheEntry[T], key string, query func() (T, error)) (T, error) {
	now := c.now()
	if c.ttl > 0 {
		c.mu.Lock()
		entry, ok := table[key]
		c.mu.Unlock()
		if ok && now.Before(entry.expires) {
			return entry.value, nil
		}
	}
	value, err := query()
	switch {
	case err == nil:
		if c.ttl > 0 {
			expires := c.now().Add(c.ttl)
			c.mu.Lock()
			if old, ok := table[key]; !ok || expires.After(old.expires) {
				table[key] = cacheEntry[T]{value: value, expires: expires}
			}
			c.mu.Unlock()
		}
		return value, nil
	case errors.Is(err, chaincli.ErrNotFound):
		var zero T
		return zero, err
	default:
		var zero T
		// Detail is fixed text without the raw chain error, so internal error details do not leak to the caller;
		// err is attached only as Cause for logs and errors.Is.
		return zero, RejectWithCause(CodeChainUnavailable, err, "chain query failed")
	}
}

var _ ChainReader = (*CachedChain)(nil)
