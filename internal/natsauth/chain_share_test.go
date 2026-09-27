package natsauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// gatedChain holds every query until release is closed, counts them, and remembers whether the context a query
// ran under had ended by the time it was released.
type gatedChain struct {
	mu        sync.Mutex
	calls     int
	release   chan struct{}
	started   chan struct{}
	err       error
	ctxEnded  bool
	lastParty string
}

func newGatedChain() *gatedChain {
	return &gatedChain{release: make(chan struct{}), started: make(chan struct{}, 100)}
}

func (g *gatedChain) QueryCurrentServiceKey(ctx context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	g.mu.Lock()
	g.calls++
	g.lastParty = participantType
	g.mu.Unlock()
	g.started <- struct{}{}
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ctxEnded = ctx.Err() != nil
	if err := ctx.Err(); err != nil {
		return chaincli.ServiceKeyState{}, err
	}
	if g.err != nil {
		return chaincli.ServiceKeyState{}, g.err
	}
	return chaincli.ServiceKeyState{OperatorAddress: operator, Status: "ACTIVE"}, nil
}

func (g *gatedChain) QueryCortexNode(ctx context.Context, operator string) (chaincli.CortexNodeState, error) {
	return chaincli.CortexNodeState{OperatorAddress: operator}, nil
}

func (g *gatedChain) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// waitFlight waits until a query for key is in progress.
func waitFlight(t *testing.T, c *CachedChain, key string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		_, ok := c.keys.flights[key]
		c.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no query in progress")
}

// waitWaiters waits until n callers are waiting on the query in progress for key.
func waitWaiters(t *testing.T, c *CachedChain, key string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		f, ok := c.keys.flights[key]
		got := 0
		if ok {
			got = f.waiters
		}
		c.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fewer than %d callers are waiting on the query", n)
}

// Shared queries end with the service and are capped: once the cap is taken, a new key is rejected at once
// without a chain query; ending the service ends the queries still running.
func TestCachedChainBoundByService(t *testing.T) {
	g := newGatedChain()
	c := NewCachedChain(g, time.Minute, nil)
	life, stop := context.WithCancel(context.Background())
	c.Bind(life, time.Minute, 1)

	first := make(chan error, 1)
	go func() {
		_, err := c.CurrentServiceKey(context.Background(), "a")
		first <- err
	}()
	<-g.started
	_, err := c.CurrentServiceKey(context.Background(), "b")
	var reject *RejectError
	if !errors.As(err, &reject) || reject.Code != CodeChainUnavailable {
		t.Fatalf("error = %v, want CHAIN_UNAVAILABLE while the only place is taken", err)
	}
	if calls := g.callCount(); calls != 1 {
		t.Fatalf("chain queries = %d, want 1", calls)
	}
	stop()
	close(g.release)
	if err := <-first; err == nil {
		t.Fatal("the query should have ended with the service")
	}
	g.mu.Lock()
	ended := g.ctxEnded
	g.mu.Unlock()
	if !ended {
		t.Fatal("the query's context did not end with the service")
	}
}

// Concurrent misses for one key send one chain query and all get its answer.
func TestCachedChainSharesConcurrentMisses(t *testing.T) {
	g := newGatedChain()
	c := NewCachedChain(g, time.Minute, nil)
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := c.CurrentServiceKey(context.Background(), "op")
			if err == nil && key.OperatorAddress != "op" {
				err = errors.New("wrong answer")
			}
			errs <- err
		}()
	}
	<-g.started
	waitWaiters(t, c, participantCortex+"|op", n)
	close(g.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls := g.callCount(); calls != 1 {
		t.Fatalf("chain queries = %d, want 1", calls)
	}
	c.mu.Lock()
	left := len(c.keys.flights)
	c.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d queries still listed as in progress after they ended", left)
	}
}

// A shared query that fails rejects every waiter, is not cached, and the next caller queries again.
func TestCachedChainSharedFailureIsNotCached(t *testing.T) {
	g := newGatedChain()
	g.err = errors.New("node down")
	c := NewCachedChain(g, time.Minute, nil)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.CurrentServiceKey(context.Background(), "op")
			var reject *RejectError
			if !errors.As(err, &reject) || reject.Code != CodeChainUnavailable {
				t.Errorf("error = %v, want CHAIN_UNAVAILABLE", err)
			}
		}()
	}
	<-g.started
	waitWaiters(t, c, participantCortex+"|op", 5)
	close(g.release)
	wg.Wait()

	g.mu.Lock()
	g.err = nil
	g.mu.Unlock()
	if _, err := c.CurrentServiceKey(context.Background(), "op"); err != nil {
		t.Fatal(err)
	}
	if calls := g.callCount(); calls != 2 {
		t.Fatalf("chain queries = %d, want 2: the failure must not answer the later caller", calls)
	}
}

// A caller that found an expired entry does not join a query that started before the entry expired.
func TestCachedChainDoesNotJoinQueryStartedBeforeExpiry(t *testing.T) {
	g := newGatedChain()
	now := time.Unix(1000, 0)
	c := NewCachedChain(g, time.Minute, func() time.Time { return now })
	key := participantCortex + "|op"
	old := &flight[chaincli.ServiceKeyState]{started: now.Add(-2 * time.Second), done: make(chan struct{})}
	c.keys.entries[key] = cacheEntry[chaincli.ServiceKeyState]{expires: now.Add(-time.Second)}
	c.keys.flights[key] = old

	done := make(chan error, 1)
	go func() {
		_, err := c.CurrentServiceKey(context.Background(), "op")
		done <- err
	}()
	<-g.started // a new query was sent instead of waiting on the old one
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, stillListed := c.keys.flights[key]
	c.mu.Unlock()
	if stillListed {
		t.Fatal("the old query should have been replaced in the in-progress table")
	}
}

// One caller giving up ends only its own wait: the shared query keeps running and the others get the answer.
func TestCachedChainCallerCancelDoesNotFailOthers(t *testing.T) {
	g := newGatedChain()
	c := NewCachedChain(g, time.Minute, nil)
	first, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := c.CurrentServiceKey(first, "op")
		firstErr <- err
	}()
	<-g.started
	waitFlight(t, c, participantCortex+"|op")
	secondErr := make(chan error, 1)
	go func() {
		_, err := c.CurrentServiceKey(context.Background(), "op")
		secondErr <- err
	}()
	waitWaiters(t, c, participantCortex+"|op", 2)
	cancel()
	if err := <-firstErr; err == nil {
		t.Fatal("the cancelled caller must stop waiting with an error")
	}
	close(g.release)
	if err := <-secondErr; err != nil {
		t.Fatalf("the other caller failed: %v", err)
	}
	g.mu.Lock()
	ended := g.ctxEnded
	g.mu.Unlock()
	if ended {
		t.Fatal("the shared query ran under the cancelled caller's context")
	}
	if calls := g.callCount(); calls != 1 {
		t.Fatalf("chain queries = %d, want 1", calls)
	}
}

// The key covers every input of the query: the participant type as well as the operator address.
func TestCachedChainKeyIncludesParticipantType(t *testing.T) {
	g := newGatedChain()
	close(g.release)
	c := NewCachedChain(g, time.Minute, nil)
	if _, err := c.CurrentServiceKey(context.Background(), "op"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, ok := c.keys.entries[participantCortex+"|op"]
	c.mu.Unlock()
	if !ok || g.lastParty != participantCortex {
		t.Fatal("service key cache is not keyed by participant type and operator")
	}
}

// Each lookup lands in the request's record: sent to the chain first, answered from cache after.
func TestCachedChainRecordsLookups(t *testing.T) {
	g := newGatedChain()
	close(g.release)
	c := NewCachedChain(g, time.Minute, nil)
	ctx, stats := withStats(context.Background())
	for i := 0; i < 2; i++ {
		if _, err := c.CurrentServiceKey(ctx, "op"); err != nil {
			t.Fatal(err)
		}
	}
	got := stats.String()
	if !strings.Contains(got, "service_key=") || !strings.Contains(got, "(chain") || !strings.Contains(got, "(cache)") {
		t.Fatalf("lookups = %q", got)
	}
}
