package inflight

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Concurrent head refreshes share one chain read, and a refresh within HeadRefreshInterval of the
// last read reads nothing.
func TestRefreshHeadSharesOneReadAndIsRateLimited(t *testing.T) {
	ledger, err := NewLedger(kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	var reads, inFlight, maxInFlight atomic.Int32
	gate, started := make(chan struct{}), make(chan struct{}, 16)
	var height atomic.Uint64
	height.Store(120)
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	cache, err := NewSessionCache(SessionCacheConfig{
		Read: (&fakeChain{}).read, Ledger: ledger,
		LatestHeight: func(context.Context) (uint64, error) {
			reads.Add(1)
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			started <- struct{}{}
			<-gate
			return height.Load(), nil
		},
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	cache.ObserveHeight(100)

	const callers = 8
	var wg sync.WaitGroup
	heads := make(chan uint64, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			head, err := cache.RefreshHead(context.Background())
			if err != nil {
				t.Error(err)
			}
			heads <- head
		}()
	}
	<-started
	time.Sleep(50 * time.Millisecond) // let the other callers join the read under way
	close(gate)
	wg.Wait()
	close(heads)
	for head := range heads {
		if head != 120 {
			t.Fatalf("refresh returned head %d, want 120", head)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d chain reads for %d concurrent refreshes, want 1", n, callers)
	}
	if n := maxInFlight.Load(); n != 1 {
		t.Fatalf("%d reads in flight at once, want 1", n)
	}

	height.Store(130)
	if head, err := cache.RefreshHead(context.Background()); err != nil || head != 120 {
		t.Fatalf("refresh within the interval = %d, %v; want the cached 120 without a read", head, err)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d chain reads after a refresh within the interval, want 1", n)
	}

	mu.Lock()
	now = now.Add(HeadRefreshInterval)
	mu.Unlock()
	if head, err := cache.RefreshHead(context.Background()); err != nil || head != 130 {
		t.Fatalf("refresh after the interval = %d, %v; want 130", head, err)
	}
	if n := reads.Load(); n != 2 {
		t.Fatalf("%d chain reads after the interval, want 2", n)
	}
}

// A caller whose context ends while it waits for a shared read returns at once, unavailable.
func TestRefreshHeadWaiterHonoursItsContext(t *testing.T) {
	ledger, err := NewLedger(kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	cache, err := NewSessionCache(SessionCacheConfig{
		Read: (&fakeChain{}).read, Ledger: ledger,
		LatestHeight: func(context.Context) (uint64, error) {
			started <- struct{}{}
			<-gate
			return 200, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cache.ObserveHeight(100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cache.RefreshHead(context.Background())
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if head, err := cache.RefreshHead(ctx); err == nil || head != 100 {
		t.Fatalf("waiter with an ended context = %d, %v; want 100 and an error", head, err)
	}
	close(gate)
	<-done
}
