package natsauth

import (
	"context"
	"errors"
	"net/http/httptrace"
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

// DefaultLookupTimeout bounds one shared chain query. It is independent of any caller's deadline,
// because several callers may be waiting on the same query.
const DefaultLookupTimeout = 10 * time.Second

type cacheEntry[T any] struct {
	value   T
	expires time.Time
}

// flight is one chain query in progress; callers that miss the cache for the same key wait on it
// instead of sending their own.
type flight[T any] struct {
	started time.Time
	done    chan struct{}
	value   T
	err     error
	newConn bool
}

type table[T any] struct {
	entries map[string]cacheEntry[T]
	flights map[string]*flight[T]
}

func newTable[T any]() *table[T] {
	return &table[T]{entries: map[string]cacheEntry[T]{}, flights: map[string]*flight[T]{}}
}

// CachedChain caches chain queries per §5.14.3: only successful results are cached; negative results and chain
// unavailability are not. After expiry, an unreachable chain means rejection; stale results never let a request through. ttl 0 disables caching.
//
// Concurrent misses for the same key share one chain query. The sharing never weakens the rules above:
//   - only a query still in progress is shared, its result goes only to the callers already waiting on it, and it
//     leaves the in-progress table the moment it ends; a failure is never cached;
//   - a caller that found an expired entry joins a query only if that query started at or after the moment the
//     entry expired, so a result fetched before expiry is never handed out after it;
//   - the query runs under its own context and timeout, not under one caller's, so one caller giving up does not
//     fail the others; each caller still stops waiting when its own context ends;
//   - the key holds every input of the query: the participant type and the operator address.
//
// Because the service key signature is checked only after the chain lookups, a caller without any credential can
// make them happen by naming an operator address, and a failed lookup is not cached. The service's in-flight limit
// and the sharing above bound this; rate limiting, if ever needed, belongs here.
type CachedChain struct {
	chain   ChainQueries
	ttl     time.Duration
	now     func() time.Time
	timeout time.Duration

	mu    sync.Mutex
	keys  *table[chaincli.ServiceKeyState]
	nodes *table[chaincli.CortexNodeState]
}

// NewCachedChain constructs a caching chain reader. now defaults to time.Now when nil.
func NewCachedChain(chain ChainQueries, ttl time.Duration, now func() time.Time) *CachedChain {
	if now == nil {
		now = time.Now
	}
	return &CachedChain{
		chain: chain, ttl: ttl, now: now, timeout: DefaultLookupTimeout,
		keys: newTable[chaincli.ServiceKeyState](), nodes: newTable[chaincli.CortexNodeState](),
	}
}

// CurrentServiceKey queries the Cortex participant's current service key row; participantType is fixed to CORTEX.
func (c *CachedChain) CurrentServiceKey(ctx context.Context, operatorAddress string) (chaincli.ServiceKeyState, error) {
	return lookup(ctx, c, c.keys, "service_key", participantCortex+"|"+operatorAddress, func(qctx context.Context) (chaincli.ServiceKeyState, error) {
		return c.chain.QueryCurrentServiceKey(qctx, participantCortex, operatorAddress)
	})
}

// CortexNode queries the Cortex stable identity row.
func (c *CachedChain) CortexNode(ctx context.Context, operatorAddress string) (chaincli.CortexNodeState, error) {
	return lookup(ctx, c, c.nodes, "cortex_node", operatorAddress, func(qctx context.Context) (chaincli.CortexNodeState, error) {
		return c.chain.QueryCortexNode(qctx, operatorAddress)
	})
}

// lookup is the cache logic shared by both queries: an unexpired hit is returned from cache; otherwise the caller
// joins a query in progress that it may share (see CachedChain) or starts one, and only success is written back.
// ErrNotFound passes through uncached; other errors are wrapped as CHAIN_UNAVAILABLE, also uncached.
func lookup[T any](ctx context.Context, c *CachedChain, t *table[T], name, key string, query func(context.Context) (T, error)) (T, error) {
	begin := c.now()
	stat := LookupStat{Name: name}
	defer func() {
		stat.Duration = c.now().Sub(begin)
		statsFrom(ctx).add(stat)
	}()

	c.mu.Lock()
	entry, cached := t.entries[key]
	if c.ttl > 0 && cached && begin.Before(entry.expires) {
		c.mu.Unlock()
		stat.CacheHit = true
		return entry.value, nil
	}
	f, running := t.flights[key]
	if running && cached && f.started.Before(entry.expires) {
		running = false // it began before the entry expired; its result must not answer this caller
	}
	if running {
		stat.Joined = true
	} else {
		f = &flight[T]{started: c.now(), done: make(chan struct{})}
		t.flights[key] = f // an older, unjoinable query keeps running but no longer takes new callers
		go runQuery(c, t, key, f, query)
	}
	c.mu.Unlock()

	select {
	case <-f.done:
	case <-ctx.Done():
		var zero T
		return zero, RejectWithCause(CodeChainUnavailable, ctx.Err(), "chain query failed")
	}
	stat.NewConn = f.newConn && !stat.Joined
	switch err := f.err; {
	case err == nil:
		return f.value, nil
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

// runQuery performs one shared query under its own timeout, records whether it had to open a new connection to
// the chain, caches a success, and removes the query from the in-progress table as it ends.
func runQuery[T any](c *CachedChain, t *table[T], key string, f *flight[T], query func(context.Context) (T, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var newConn bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { newConn = !info.Reused },
	})
	value, err := query(ctx)

	c.mu.Lock()
	f.value, f.err, f.newConn = value, err, newConn
	if t.flights[key] == f {
		delete(t.flights, key)
	}
	if err == nil && c.ttl > 0 {
		// Valid from the moment the query was sent, not from when the answer came back.
		expires := f.started.Add(c.ttl)
		if old, ok := t.entries[key]; !ok || expires.After(old.expires) {
			t.entries[key] = cacheEntry[T]{value: value, expires: expires}
		}
	}
	c.mu.Unlock()
	close(f.done)
}

var _ ChainReader = (*CachedChain)(nil)
