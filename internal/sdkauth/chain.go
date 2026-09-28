package sdkauth

import (
	"context"
	"sync"
)

// DefaultAccountKeyCacheSize bounds how many account keys CachedChain keeps.
const DefaultAccountKeyCacheSize = 4096

// CachedChain is a Chain over plain chain reads that caches the account keys it finds.
//
// An account's public key never changes once it is on chain, so a found key is kept until the cache is
// full and the oldest entry is evicted; it never expires by time. "No account or no key yet" is never
// cached: a user's key reaches the chain with their first transaction, and a cached miss would keep
// them from ordering after it.
type CachedChain struct {
	height   func(ctx context.Context) (uint64, error)
	lookup   func(ctx context.Context, address string) ([]byte, error)
	notFound func(error) bool
	capacity int

	mu    sync.Mutex
	keys  map[string][]byte
	order []string
}

// NewCachedChain builds a CachedChain. lookup reads an account's key; notFound tells its "no account or
// no key" error apart from a failed read.
func NewCachedChain(
	height func(ctx context.Context) (uint64, error),
	lookup func(ctx context.Context, address string) ([]byte, error),
	notFound func(error) bool,
	capacity int,
) *CachedChain {
	if capacity <= 0 {
		capacity = DefaultAccountKeyCacheSize
	}
	return &CachedChain{height: height, lookup: lookup, notFound: notFound, capacity: capacity, keys: make(map[string][]byte)}
}

func (c *CachedChain) CurrentHeight(ctx context.Context) (uint64, error) {
	return c.height(ctx)
}

func (c *CachedChain) AccountPubKey(ctx context.Context, address string) ([]byte, error) {
	c.mu.Lock()
	if key, ok := c.keys[address]; ok {
		c.mu.Unlock()
		return key, nil
	}
	c.mu.Unlock()
	key, err := c.lookup(ctx, address)
	if err != nil {
		if c.notFound(err) {
			return nil, ErrNoAccountKey
		}
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.keys[address]; !ok {
		if len(c.order) >= c.capacity {
			delete(c.keys, c.order[0])
			c.order = c.order[1:]
		}
		c.keys[address] = append([]byte(nil), key...)
		c.order = append(c.order, address)
	}
	return key, nil
}
