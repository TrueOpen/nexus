package registeredkey

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeChain struct {
	mu      sync.Mutex
	height  uint64
	reads   atomic.Int32
	states  map[string]State
	readErr error
	// block, when set, holds every read until it is closed.
	block chan struct{}
}

func (f *fakeChain) Read(context.Context, string) (State, error) {
	f.reads.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return State{}, f.readErr
	}
	return f.states["s"], nil
}

func (f *fakeChain) set(height uint64, state State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.height = height
	f.states = map[string]State{"s": state}
}

func newTestCache(t *testing.T, chain *fakeChain, cfg CacheConfig) *Cache {
	t.Helper()
	cfg.Read = chain.Read
	c, err := NewCache(cfg)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c
}

func (f *fakeChain) at() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height
}

func lookupState(t *testing.T, c *Cache, chain *fakeChain) State {
	t.Helper()
	state, err := c.Lookup(context.Background(), "s", chain.at())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return state
}

func TestCacheExpiresByBlocks(t *testing.T) {
	chain := &fakeChain{}
	chain.set(100, State{Found: true, Owner: "a"})
	c := newTestCache(t, chain, CacheConfig{TTLBlocks: 3})
	lookupState(t, c, chain)
	chain.set(102, State{Found: true, Owner: "b"})
	if got := lookupState(t, c, chain); got.Owner != "a" || chain.reads.Load() != 1 {
		t.Fatalf("at read height + 2 the entry must be used: owner %q, reads %d", got.Owner, chain.reads.Load())
	}
	chain.set(103, State{Found: true, Owner: "b"})
	if got := lookupState(t, c, chain); got.Owner != "b" || chain.reads.Load() != 2 {
		t.Fatalf("at read height + ttl the entry must be re-read: owner %q, reads %d", got.Owner, chain.reads.Load())
	}
}

// "No such session" is cached too, so signatures that recover to nobody do not each read the chain.
func TestCacheKeepsMisses(t *testing.T) {
	chain := &fakeChain{}
	chain.set(100, State{})
	c := newTestCache(t, chain, CacheConfig{})
	for i := 0; i < 5; i++ {
		if lookupState(t, c, chain).Found {
			t.Fatal("unexpected session")
		}
	}
	if chain.reads.Load() != 1 {
		t.Fatalf("reads = %d, want 1", chain.reads.Load())
	}
}

func TestCacheInvalidateAndStreams(t *testing.T) {
	chain := &fakeChain{}
	chain.set(100, State{Found: true, Owner: "a"})
	c := newTestCache(t, chain, CacheConfig{})
	lookupState(t, c, chain)
	chain.set(100, State{Found: true, Owner: "b"})
	c.Invalidate("s")
	if got := lookupState(t, c, chain); got.Owner != "b" {
		t.Fatalf("after Invalidate owner = %q, want the re-read b", got.Owner)
	}
	// While the stream is down every lookup reads the chain and nothing is kept.
	c.SessionStreamDown("s")
	before := chain.reads.Load()
	lookupState(t, c, chain)
	lookupState(t, c, chain)
	if got := chain.reads.Load() - before; got != 2 {
		t.Fatalf("reads while the stream is down = %d, want 2", got)
	}
	c.SessionStreamUp("s")
	before = chain.reads.Load()
	lookupState(t, c, chain)
	lookupState(t, c, chain)
	if got := chain.reads.Load() - before; got != 1 {
		t.Fatalf("reads after the stream is up = %d, want 1", got)
	}
}

// A read that started before an invalidation is neither stored nor joined by later lookups.
func TestCacheDropsReadsOverlappingAnInvalidation(t *testing.T) {
	chain := &fakeChain{block: make(chan struct{})}
	chain.set(100, State{Found: true, Owner: "old"})
	c := newTestCache(t, chain, CacheConfig{})
	first := make(chan State)
	go func() {
		state, _ := c.Lookup(context.Background(), "s", 100)
		first <- state
	}()
	for chain.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	c.Invalidate("s")
	second := make(chan State)
	go func() {
		state, _ := c.Lookup(context.Background(), "s", 100)
		second <- state
	}()
	for chain.reads.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	chain.set(100, State{Found: true, Owner: "new"})
	close(chain.block)
	<-first
	if got := <-second; got.Owner != "new" {
		t.Fatalf("lookup after the invalidation = %q, want new", got.Owner)
	}
	chain.block = nil
	if got := lookupState(t, c, chain); got.Owner != "new" {
		t.Fatalf("cached owner = %q, want new", got.Owner)
	}
}

func TestCacheSharesOneRead(t *testing.T) {
	chain := &fakeChain{block: make(chan struct{})}
	chain.set(100, State{Found: true})
	c := newTestCache(t, chain, CacheConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Lookup(context.Background(), "s", 100)
		}()
	}
	for chain.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(chain.block)
	wg.Wait()
	if chain.reads.Load() != 1 {
		t.Fatalf("reads = %d, want 1", chain.reads.Load())
	}
}

func TestCacheReadFailureIsUnreadableAndNotKept(t *testing.T) {
	chain := &fakeChain{readErr: errors.New("node down")}
	chain.set(100, State{})
	chain.readErr = errors.New("node down")
	c := newTestCache(t, chain, CacheConfig{})
	if _, err := c.Lookup(context.Background(), "s", 100); !errors.Is(err, ErrChainUnreadable) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Lookup = %v, want unreadable", err)
	}
	chain.mu.Lock()
	chain.readErr = nil
	chain.mu.Unlock()
	if _, err := c.Lookup(context.Background(), "s", 100); err != nil || chain.reads.Load() != 2 {
		t.Fatalf("Lookup after recovery = %v, reads %d", err, chain.reads.Load())
	}
}

func TestCacheReadBudget(t *testing.T) {
	now := time.Unix(1000, 0)
	chain := &fakeChain{}
	chain.set(100, State{})
	c := newTestCache(t, chain, CacheConfig{LookupsPerSecond: 2, Now: func() time.Time { return now }})
	// Every lookup is a miss after an invalidation; the burst is two seconds' worth.
	for i := 0; i < 4; i++ {
		c.Invalidate("s")
		if _, err := c.Lookup(context.Background(), "s", 100); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	c.Invalidate("s")
	if _, err := c.Lookup(context.Background(), "s", 100); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrChainUnreadable) {
		t.Fatalf("over budget = %v, want unavailable", err)
	}
	now = now.Add(500 * time.Millisecond)
	if _, err := c.Lookup(context.Background(), "s", 100); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

// Entries are evicted least recently used first, and sessions without a registered key have
// their own bound, so they cannot push out sessions with one.
func TestCacheEvictionIsLRUAndSplit(t *testing.T) {
	key := [20]byte{1}
	keyed := map[string]bool{"k1": true, "k2": true}
	read := func(_ context.Context, id string) (State, error) {
		if keyed[id] {
			return State{Found: true, Key: &key}, nil
		}
		return State{}, nil
	}
	c, err := NewCache(CacheConfig{Read: read, Size: 2, NegativeSize: 2, LookupsPerSecond: 1000})
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(id string) {
		if _, err := c.Lookup(context.Background(), id, 100); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"k1", "k2", "n1", "n2", "n3", "n4"} {
		lookup(id)
	}
	if _, ok := c.entries["k1"]; !ok {
		t.Fatal("misses evicted a session with a registered key")
	}
	if _, ok := c.entries["n1"]; ok || c.unkeyed.Len() != 2 {
		t.Fatalf("negative entries = %d, want the two newest", c.unkeyed.Len())
	}
	lookup("k1") // k1 is now the most recently used keyed entry
	keyed["k3"] = true
	lookup("k3")
	if _, ok := c.entries["k2"]; ok {
		t.Fatal("k2 should be the least recently used keyed entry")
	}
	if _, ok := c.entries["k1"]; !ok {
		t.Fatal("k1 was used last and must stay")
	}
}

func TestNewCacheRefusesLongTTL(t *testing.T) {
	chain := &fakeChain{}
	if _, err := NewCache(CacheConfig{Read: chain.Read, TTLBlocks: MaxTTLBlocks + 1}); err == nil {
		t.Fatal("a ttl above the maximum must be refused")
	}
}

// A read the session's stream going down overtook is not stored.
func TestCacheDropsReadsOverlappingStreamDown(t *testing.T) {
	chain := &fakeChain{block: make(chan struct{})}
	chain.set(100, State{Found: true, Owner: "old"})
	c := newTestCache(t, chain, CacheConfig{})
	done := make(chan struct{})
	go func() {
		_, _ = c.Lookup(context.Background(), "s", 100)
		close(done)
	}()
	for chain.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	c.SessionStreamDown("s")
	close(chain.block)
	<-done
	c.SessionStreamClosed("s")
	chain.block = nil
	before := chain.reads.Load()
	lookupState(t, c, chain)
	lookupState(t, c, chain)
	if got := chain.reads.Load() - before; got != 1 {
		t.Fatalf("reads after the stream closed = %d, want 1 (nothing stored while down, kept after)", got)
	}
}

func TestCacheJoinedLookupHonoursContext(t *testing.T) {
	chain := &fakeChain{block: make(chan struct{})}
	chain.set(100, State{Found: true})
	c := newTestCache(t, chain, CacheConfig{})
	done := make(chan struct{})
	go func() {
		_, _ = c.Lookup(context.Background(), "s", 100)
		close(done)
	}()
	for chain.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Lookup(ctx, "s", 100); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("joined lookup with a cancelled context = %v, want unavailable", err)
	}
	close(chain.block)
	<-done
}

func TestCacheRefusesHeightZero(t *testing.T) {
	chain := &fakeChain{}
	chain.set(100, State{Found: true})
	c := newTestCache(t, chain, CacheConfig{})
	if _, err := c.Lookup(context.Background(), "s", 0); !errors.Is(err, ErrChainUnreadable) || chain.reads.Load() != 0 {
		t.Fatalf("height 0 = %v after %d reads, want unavailable and no read", err, chain.reads.Load())
	}
}

// Invalidating one session leaves another session's read under way alone: it is still stored.
func TestCacheInvalidationIsPerSession(t *testing.T) {
	chain := &fakeChain{block: make(chan struct{})}
	chain.set(100, State{Found: true, Owner: "a"})
	c := newTestCache(t, chain, CacheConfig{})
	done := make(chan struct{})
	go func() {
		_, _ = c.Lookup(context.Background(), "s", 100)
		close(done)
	}()
	for chain.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	c.SessionKeyUpdated("other")
	c.SessionStreamDown("other")
	c.SessionStreamUp("other")
	close(chain.block)
	<-done
	chain.block = nil
	lookupState(t, c, chain)
	if got := chain.reads.Load(); got != 1 {
		t.Fatalf("reads = %d, want 1: the read of s must have been stored", got)
	}
}
