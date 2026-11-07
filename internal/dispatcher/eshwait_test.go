package dispatcher

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
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

// An order whose earliest_submit_height is ahead of the cached head reads the head again before it
// waits: the chain has moved on, so its first ticket goes out at once instead of at the next block
// event.
func TestESHWaitReadsAFreshHeadFirst(t *testing.T) {
	e, logs := eshWaitEnv(t, testESH+2)
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers, want the first ticket without waiting for a block event", n)
	}
	if strings.Contains(logs.String(), "earliest_submit_height") {
		t.Fatalf("an order that did not wait logged a wait:\n%s", logs)
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
