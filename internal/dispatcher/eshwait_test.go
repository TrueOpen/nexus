package dispatcher

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// eshWaitEnv has an order of earliest_submit_height testESH+2 taken while the chain was at
// testESH+2, then restarted with its session cache back at testESH and no ticket issued yet: its
// first round waits for the head to reach testESH+1.
func eshWaitEnv(t *testing.T, latestAfterRestart uint64) (*env, *bytes.Buffer) {
	t.Helper()
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.latest.Store(testESH + 2)
	o := e.orderAt(s, 0, 1, testESH+2)
	e.keys.builderErr = ErrCompensationUnread // no ticket before the restart
	e.dispatch(o)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers before the restart", n)
	}
	e.keys.builderErr = nil
	e.latest.Store(latestAfterRestart)
	if err := e.d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.open(e.store)
	logs := &bytes.Buffer{}
	e.d.log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e, logs
}

// An order whose earliest_submit_height is ahead of the cached head asks for a head read when it
// parks: the chain has moved on, so its first ticket goes out once the read returns instead of at
// the next block event. Its wait lasted only the read.
func TestESHWaitReadsAFreshHeadFirst(t *testing.T) {
	e, logs := eshWaitEnv(t, testESH+2)
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers, want the first ticket without waiting for a block event", n)
	}
	if !strings.Contains(logs.String(), "order waited for its earliest_submit_height") || !strings.Contains(logs.String(), "wait_ms=0") {
		t.Fatalf("the wait for the head read is not logged as such:\n%s", logs)
	}
}

// An order that does wait is logged when it parks and, with the time it waited, when its round
// opens.
func TestESHWaitIsLoggedWithItsDuration(t *testing.T) {
	e, logs := eshWaitEnv(t, testESH)
	if n := len(e.streams.offers()); n != 0 {
		t.Fatalf("%d offers while the head is below earliest_submit_height - 1", n)
	}
	if !strings.Contains(logs.String(), "order waits for its earliest_submit_height") {
		t.Fatalf("no wait logged:\n%s", logs)
	}
	e.clock.advance(300 * time.Millisecond)
	e.sessions.ObserveHeight(testESH + 1)
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers once the head reached it", n)
	}
	if !strings.Contains(logs.String(), "order waited for its earliest_submit_height") || !strings.Contains(logs.String(), "wait_ms=300") {
		t.Fatalf("wait duration not logged:\n%s", logs)
	}
}

// Orders waiting for their earliest_submit_height read the chain head with no order locked, and
// share one read: while a slow read is under way every waiting order can be locked (so a block
// event or a decided order kicking them is not held up) and no second read starts. Once the read
// shows the head moved on, the waiting orders are tried again at once.
func TestESHWaitReadsTheHeadOnceWithNoOrderLocked(t *testing.T) {
	const orders = 6
	e := newEnv(t)
	e.latest.Store(testESH + 2)
	e.keys.builderErr = ErrCompensationUnread // no ticket before the restart
	for i := 0; i < orders; i++ {
		s := e.session(byte(0xa0+i), 0)
		e.dispatch(e.orderAt(s, 0, 1, testESH+2))
	}
	e.keys.builderErr = nil
	e.latest.Store(testESH)
	if err := e.d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.open(e.store)
	e.d.cfg.Background = func(f func()) { go f() }

	var reads, inFlight, maxInFlight atomic.Int32
	gate, started := make(chan struct{}), make(chan struct{}, orders)
	e.onLatest = func() {
		reads.Add(1)
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for m := maxInFlight.Load(); n > m && !maxInFlight.CompareAndSwap(m, n); m = maxInFlight.Load() {
		}
		started <- struct{}{}
		<-gate
	}
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no head read started")
	}
	all := e.d.allOrders()
	if len(all) != orders {
		t.Fatalf("%d orders resumed, want %d", len(all), orders)
	}
	// Every order parks while the read is held, and none is locked across it.
	deadline := time.Now().Add(5 * time.Second)
	for parked := 0; parked < orders; {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d orders parked (or lockable) while the head read is held", parked, orders)
		}
		parked = 0
		for _, o := range all {
			if !o.mu.TryLock() {
				continue
			}
			if o.parked {
				parked++
			}
			o.mu.Unlock()
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d head reads started for %d waiting orders, want 1", n, orders)
	}
	e.latest.Store(testESH + 2)
	close(gate)
	for deadline := time.Now().Add(5 * time.Second); len(e.streams.offers()) < orders; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d offers after the head read showed the chain at earliest_submit_height, want %d", len(e.streams.offers()), orders)
		}
	}
	if err := e.d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := maxInFlight.Load(); n != 1 {
		t.Fatalf("%d head reads in flight at once, want 1", n)
	}
}
