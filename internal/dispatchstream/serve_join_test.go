package dispatchstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// handlerStream behaves like the stream of an HTTP/2 handler: it may not be written once Serve
// returned (net/http panics on such a write). It counts the Sends that start after Serve returned or
// are still running when it returns. Each Send takes a little while, like a real write, so a session
// that ends while frames are queued usually catches one in progress.
type handlerStream struct {
	*memStream
	finished atomic.Bool
	sending  atomic.Int32
	sent     atomic.Int32
	late     atomic.Int32
}

func newHandlerStream() *handlerStream { return &handlerStream{memStream: newMemStream()} }

func (s *handlerStream) Send(*nexusv1.DispatchStreamFrameV1) error {
	s.sending.Add(1)
	defer s.sending.Add(-1)
	if s.finished.Load() {
		s.late.Add(1)
	}
	time.Sleep(20 * time.Microsecond)
	if s.finished.Load() {
		s.late.Add(1)
	}
	s.sent.Add(1)
	return nil
}

// serveReturned marks the end of the handler.
func (s *handlerStream) serveReturned() {
	s.finished.Store(true)
	if s.sending.Load() != 0 {
		s.late.Add(1)
	}
}

// serveOn runs Serve on stream, opened with a fresh binding of operator, and waits until it is bound.
func (h *harness) serveOn(ctx context.Context, stream *handlerStream, operator, nonceLabel string) chan error {
	h.t.Helper()
	nonce := hash32("stream|" + nonceLabel)
	stream.in <- bindingFrame(h.keys.binding(h.t, operator, nonce))
	result := make(chan error, 1)
	go func() {
		err := h.hub.Serve(ctx, stream)
		stream.serveReturned()
		result <- err
	}()
	h.waitConn(operator, true)
	return result
}

// Serve returns only after its sender left the stream, whichever way the session ends and however
// many frames are queued at that moment.
func TestServeNeverReturnsWhileSendingOnTheStream(t *testing.T) {
	cases := []struct {
		name string
		want error
		end  func(h *harness, stream *handlerStream, cancel context.CancelFunc)
	}{
		{"receive error", io.EOF, func(_ *harness, stream *handlerStream, _ context.CancelFunc) { stream.close() }},
		{"protocol error frame", ErrProtocol, func(_ *harness, stream *handlerStream, _ context.CancelFunc) {
			stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: hash32("other stream"),
				Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: 2}}}
		}},
		{"replaced by a newer stream", ErrReplaced, func(h *harness, _ *handlerStream, _ context.CancelFunc) {
			h.open(bindingFrame(h.keys.binding(h.t, cortexA, hash32("stream|newer"))))
		}},
		{"hub stopped", ErrStopped, func(h *harness, _ *handlerStream, _ context.CancelFunc) {
			_ = h.hub.Stop(context.Background())
		}},
		{"binding key retired", ErrBindingKeyRetired, func(h *harness, _ *handlerStream, _ context.CancelFunc) {
			h.hub.endBindings(cortexA, 0, "SERVICE_KEY_REVOKED")
		}},
		{"keepalive timeout", ErrKeepaliveTimeout, func(h *harness, _ *handlerStream, _ context.CancelFunc) {
			for range h.hub.cfg.KeepaliveMisses + 1 {
				h.ticks <- time.Time{}
			}
		}},
		{"context canceled", context.Canceled, func(_ *harness, _ *handlerStream, cancel context.CancelFunc) { cancel() }},
	}
	const iterations = 100
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			late := 0
			for i := range iterations {
				h := newHarness(t)
				ctx, cancel := context.WithCancel(context.Background())
				stream := newHandlerStream()
				result := h.serveOn(ctx, stream, cortexA, fmt.Sprintf("%d", i))
				for j := range 16 {
					if err := h.hub.Send(context.Background(), cortexA, offer(fmt.Sprintf("queued-%d", j))); err != nil {
						t.Fatal(err)
					}
				}
				// More frames keep arriving while the session ends.
				queuing := make(chan struct{})
				go func() {
					defer close(queuing)
					for j := range 16 {
						if h.hub.Send(context.Background(), cortexA, offer(fmt.Sprintf("racing-%d", j))) != nil {
							return
						}
					}
				}()
				tc.end(h, stream, cancel)
				var err error
				select {
				case err = <-result:
				case <-time.After(waitFor):
					t.Fatal("Serve did not return")
				}
				<-queuing
				if !errors.Is(err, tc.want) {
					t.Fatalf("Serve = %v, want %v", err, tc.want)
				}
				// A sender left running would write after the handler's end.
				time.Sleep(time.Millisecond)
				late += int(stream.late.Load())
				_ = h.hub.Stop(context.Background())
				cancel()
			}
			if late != 0 {
				t.Fatalf("%d stream writes during or after the end of Serve in %d sessions", late, iterations)
			}
		})
	}
}

// blockingStream holds every Send until released, like an HTTP/2 write the peer's flow control
// stalls.
type blockingStream struct {
	*memStream
	entered chan struct{}
	release chan struct{}
}

func (s *blockingStream) Send(*nexusv1.DispatchStreamFrameV1) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return nil
}

// A write in progress keeps Serve from returning until the transport lets it go (the IngressAPI
// handler bounds each write with a deadline); the session itself is already gone.
func TestServeWaitsForTheWriteInProgress(t *testing.T) {
	h := newHarness(t)
	stream := &blockingStream{memStream: newMemStream(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	nonce := hash32("stream|blocked")
	stream.in <- bindingFrame(h.keys.binding(t, cortexA, nonce))
	result := make(chan error, 1)
	go func() { result <- h.hub.Serve(context.Background(), stream) }()
	h.waitConn(cortexA, true)
	if err := h.hub.Send(context.Background(), cortexA, offer("stuck")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stream.entered:
	case <-time.After(waitFor):
		t.Fatal("no write started")
	}
	stream.close()
	h.waitConn(cortexA, false)
	select {
	case err := <-result:
		t.Fatalf("Serve returned %v with a write in progress", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(stream.release)
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Serve = %v, want io.EOF", err)
		}
	case <-time.After(waitFor):
		t.Fatal("Serve did not return after the write finished")
	}
}
