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

type fakeChain struct {
	mu    sync.Mutex
	keys  map[string]chaincli.ServiceKeyState
	nodes map[string]chaincli.CortexNodeState
	err   error

	keyCalls  int
	nodeCalls int

	lastKeyParticipantType string
}

func (f *fakeChain) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	f.mu.Lock()
	f.keyCalls++
	f.lastKeyParticipantType = participantType
	f.mu.Unlock()
	if f.err != nil {
		return chaincli.ServiceKeyState{}, f.err
	}
	if participantType != "CORTEX" {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	state, ok := f.keys[operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func (f *fakeChain) QueryCortexNode(_ context.Context, operator string) (chaincli.CortexNodeState, error) {
	f.mu.Lock()
	f.nodeCalls++
	f.mu.Unlock()
	if f.err != nil {
		return chaincli.CortexNodeState{}, f.err
	}
	node, ok := f.nodes[operator]
	if !ok {
		return chaincli.CortexNodeState{}, chaincli.ErrNotFound
	}
	return node, nil
}

func TestCachedChainCachesOnlySuccess(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fake := &fakeChain{keys: map[string]chaincli.ServiceKeyState{"trueopen1a": {Status: "ACTIVE", AuthorizationNonce: 1}}, nodes: map[string]chaincli.CortexNodeState{}}
	cached := NewCachedChain(fake, 60*time.Second, func() time.Time { return now })

	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatal(err)
	}
	if fake.keyCalls != 1 {
		t.Fatalf("success must be served from cache, chain called %d times", fake.keyCalls)
	}
	now = now.Add(61 * time.Second)
	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatal(err)
	}
	if fake.keyCalls != 2 {
		t.Fatalf("expired entry must re-query, chain called %d times", fake.keyCalls)
	}

	// Negative results are not cached: two consecutive not-found lookups both reach the chain.
	for i := 0; i < 2; i++ {
		if _, err := cached.CortexNode(context.Background(), "trueopen1missing"); !errors.Is(err, chaincli.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	}
	if fake.nodeCalls != 2 {
		t.Fatalf("negative results must not be cached, chain called %d times", fake.nodeCalls)
	}
}

func TestCachedChainDoesNotServeStaleOnOutage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fake := &fakeChain{keys: map[string]chaincli.ServiceKeyState{"trueopen1a": {Status: "ACTIVE"}}}
	cached := NewCachedChain(fake, 60*time.Second, func() time.Time { return now })
	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	outage := errors.New("dial tcp: connection refused")
	fake.err = outage
	_, err := cached.CurrentServiceKey(context.Background(), "trueopen1a")
	var rej *RejectError
	if !errors.As(err, &rej) || rej.Code != CodeChainUnavailable {
		t.Fatalf("expired cache during outage must be CHAIN_UNAVAILABLE, got %v", err)
	}
	if strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("response text must not leak chain error text, got %q", err.Error())
	}
	if !errors.Is(err, outage) {
		t.Fatalf("Cause must be unwrappable via errors.Is, got %v", err)
	}

	// A chain outage is only a transient state and must not be recorded as "this key is permanently unavailable": once the failure is
	// cleared, the lookup must succeed again immediately, proving this rejection was not cached as a negative result.
	fake.err = nil
	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatalf("outage must not be memoized, retry after recovery failed: %v", err)
	}
}

func TestCachedChainZeroTTLDisablesCache(t *testing.T) {
	fake := &fakeChain{keys: map[string]chaincli.ServiceKeyState{"trueopen1a": {Status: "ACTIVE"}}}
	cached := NewCachedChain(fake, 0, time.Now)
	for i := 0; i < 3; i++ {
		if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
			t.Fatal(err)
		}
	}
	if fake.keyCalls != 3 {
		t.Fatalf("ttl 0 must query every time, got %d", fake.keyCalls)
	}
}

// TestCachedChainPassesCortexParticipantType confirms CurrentServiceKey always passes
// participantType="CORTEX": the fake returns ErrNotFound for any other value, so success is the proof.
func TestCachedChainPassesCortexParticipantType(t *testing.T) {
	fake := &fakeChain{keys: map[string]chaincli.ServiceKeyState{"trueopen1a": {Status: "ACTIVE"}}}
	cached := NewCachedChain(fake, 60*time.Second, time.Now)
	if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	got := fake.lastKeyParticipantType
	fake.mu.Unlock()
	if got != "CORTEX" {
		t.Fatalf("want participantType CORTEX, got %q", got)
	}
}

// TestCachedChainConcurrentUse verifies under -race that the cache's internal synchronization has no data races when used concurrently.
func TestCachedChainConcurrentUse(t *testing.T) {
	fake := &fakeChain{keys: map[string]chaincli.ServiceKeyState{"trueopen1a": {Status: "ACTIVE"}}}
	cached := NewCachedChain(fake, 60*time.Second, time.Now)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cached.CurrentServiceKey(context.Background(), "trueopen1a"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
