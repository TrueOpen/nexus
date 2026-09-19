package chaincli

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"
)

func TestHeightEventLoopEmitsOnlyMonotonicHeights(t *testing.T) {
	sequence := []uint64{10, 10, 12, 11, 13}
	next := 0
	latest := func(context.Context) (uint64, error) {
		height := sequence[next]
		if next < len(sequence)-1 {
			next++
		}
		return height, nil
	}
	c := &client{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		events: make(chan ChainEvent, len(sequence)),
		stopCh: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.heightEventLoop(ctx, time.Millisecond, latest)
		close(done)
	}()

	got := make([]int64, 0, 3)
	for len(got) < 3 {
		select {
		case event := <-c.events:
			if event.Type != EventNewBlock {
				t.Fatalf("event type = %q", event.Type)
			}
			got = append(got, event.Height)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for height events; got %v", got)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("height event loop did not stop after cancellation")
	}
	if want := []int64{10, 12, 13}; !reflect.DeepEqual(got, want) {
		t.Fatalf("height events = %v, want %v", got, want)
	}
}
