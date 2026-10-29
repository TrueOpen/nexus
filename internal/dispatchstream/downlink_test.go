package dispatchstream

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

func mustSend(t *testing.T, h *harness, operator, label string) {
	t.Helper()
	if err := h.hub.Send(context.Background(), operator, offer(label)); err != nil {
		t.Fatalf("send %s: %v", label, err)
	}
}

// receiveOffers reads n business frames and checks they carry stream_nonce and cursors 1..n.
func receiveOffers(t *testing.T, s *served, n int) []string {
	t.Helper()
	var labels []string
	for i := 1; i <= n; i++ {
		f := s.stream.nextBusiness(t)
		if !bytes.Equal(f.GetStreamNonce(), s.nonce) || f.GetCursor() != uint64(i) {
			t.Fatalf("frame %d: stream_nonce %x cursor %d, want %x %d", i, f.GetStreamNonce(), f.GetCursor(), s.nonce, i)
		}
		labels = append(labels, offerLabelOf(t, f))
	}
	return labels
}

// Downlink messages are numbered on the stream from 1; what the Cortex acknowledged is released,
// the rest is sent again on the next stream, renumbered from 1 and with the same message bytes.
func TestUnacknowledgedMessagesAreReplayedOnReconnect(t *testing.T) {
	h := newHarness(t)
	s1 := h.connect(cortexA, "1")
	for _, label := range []string{"a", "b", "c"} {
		mustSend(t, h, cortexA, label)
	}
	first := make([]*nexusv1.DispatchStreamFrameV1, 0, 3)
	for i := 0; i < 3; i++ {
		first = append(first, s1.stream.nextBusiness(t))
	}
	if first[0].GetCursor() != 1 || first[2].GetCursor() != 3 {
		t.Fatalf("cursors %d..%d, want 1..3", first[0].GetCursor(), first[2].GetCursor())
	}
	s1.ack(1)
	waitPending(t, h, cortexA, 2)
	s1.stream.close()
	s1.wait(t)
	h.waitConn(cortexA, false)

	s2 := h.connect(cortexA, "2")
	for i, want := range first[1:] {
		f := s2.stream.nextBusiness(t)
		if !bytes.Equal(f.GetStreamNonce(), s2.nonce) || f.GetCursor() != uint64(i+1) {
			t.Fatalf("replayed frame %d: stream_nonce %x cursor %d", i, f.GetStreamNonce(), f.GetCursor())
		}
		got, _ := proto.Marshal(f.GetOffer())
		sent, _ := proto.Marshal(want.GetOffer())
		if !bytes.Equal(got, sent) {
			t.Fatalf("replayed message %d differs from the one first sent", i)
		}
	}
	mustSend(t, h, cortexA, "d")
	if f := s2.stream.nextBusiness(t); f.GetCursor() != 3 || offerLabelOf(t, f) != "d" {
		t.Fatalf("next frame cursor %d label %s, want 3 d", f.GetCursor(), offerLabelOf(t, f))
	}
	s2.ack(3)
	waitPending(t, h, cortexA, 0)
}

func waitPending(t *testing.T, h *harness, operator string, want int) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		h.hub.mu.Lock()
		got := len(h.hub.pending[operator])
		h.hub.mu.Unlock()
		stored := 0
		_ = h.store.Scan(kv.NSStreamSession, func(key string, _ []byte) bool {
			if bytes.HasPrefix([]byte(key), []byte(outKeyPrefix+operator+"|")) {
				stored++
			}
			return true
		})
		if got == want && stored == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending %d stored %d, want %d", got, stored, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The unacknowledged messages survive a restart and go to the Cortex's next stream.
func TestUnacknowledgedMessagesSurviveARestart(t *testing.T) {
	store, keys := kv.NewMemStore(), newTestKeys()
	h := newHarnessOn(t, store, keys)
	s := h.connect(cortexA, "1")
	mustSend(t, h, cortexA, "a")
	mustSend(t, h, cortexA, "b")
	receiveOffers(t, s, 2)
	_ = h.hub.Stop(context.Background())
	s.wait(t)

	restarted := newHarnessOn(t, store, keys)
	s2 := restarted.connect(cortexA, "2")
	if got := receiveOffers(t, s2, 2); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("replayed after restart %v, want [a b]", got)
	}
	mustSend(t, restarted, cortexA, "c")
	if f := s2.stream.nextBusiness(t); f.GetCursor() != 3 || offerLabelOf(t, f) != "c" {
		t.Fatalf("next frame cursor %d, want 3", f.GetCursor())
	}
}

// The replay filter drops messages that are no longer worth sending, for good.
func TestReplayFilterDropsExpiredMessages(t *testing.T) {
	expired := map[string]bool{"b": true}
	var filtered []string
	h := newHarness(t, WithReplayFilter(func(operator string, f *nexusv1.DispatchStreamFrameV1) bool {
		label := string(f.GetOffer().GetTicket().GetBuilderServiceSignature())[4:]
		filtered = append(filtered, operator+"/"+label)
		return !expired[label]
	}))
	s1 := h.connect(cortexA, "1")
	for _, label := range []string{"a", "b", "c"} {
		mustSend(t, h, cortexA, label)
	}
	receiveOffers(t, s1, 3)
	s1.stream.close()
	s1.wait(t)
	h.waitConn(cortexA, false)

	s2 := h.connect(cortexA, "2")
	if got := receiveOffers(t, s2, 2); !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("replayed %v, want [a c]", got)
	}
	if !slices.Equal(filtered, []string{cortexA + "/a", cortexA + "/b", cortexA + "/c"}) {
		t.Fatalf("filter saw %v", filtered)
	}
	waitPending(t, h, cortexA, 2)
}

// Retention is bounded per Cortex: beyond MaxPending the oldest unacknowledged messages go.
func TestRetentionIsBounded(t *testing.T) {
	h := newHarness(t) // MaxPending 8
	s1 := h.connect(cortexA, "1")
	var labels []string
	for i := 0; i < 10; i++ {
		label := string(rune('a' + i))
		labels = append(labels, label)
		mustSend(t, h, cortexA, label)
	}
	receiveOffers(t, s1, 10)
	waitPending(t, h, cortexA, 8)
	s1.stream.close()
	s1.wait(t)
	h.waitConn(cortexA, false)
	s2 := h.connect(cortexA, "2")
	if got := receiveOffers(t, s2, 8); !slices.Equal(got, labels[2:]) {
		t.Fatalf("replayed %v, want %v", got, labels[2:])
	}
}

func TestSendAllAndErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.hub.SendAll(ctx, offer("x")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("SendAll without streams = %v, want ErrNotConnected", err)
	}
	if err := h.hub.Send(ctx, cortexA, offer("x")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Send without stream = %v, want ErrNotConnected", err)
	}
	a := h.connect(cortexA, "1")
	b := h.connect(cortexB, "1")
	if n, err := h.hub.SendAll(ctx, offer("all")); err != nil || n != 2 {
		t.Fatalf("SendAll = %d, %v", n, err)
	}
	receiveOffers(t, a, 1)
	receiveOffers(t, b, 1)
	notDownlink := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Accept{}}
	if err := h.hub.Send(ctx, cortexA, notDownlink); err == nil {
		t.Fatal("Send accepted a message the Builder does not send")
	}
	if err := h.hub.Send(ctx, cortexA, &nexusv1.DispatchStreamFrameV1{}); err == nil {
		t.Fatal("Send accepted an empty frame")
	}
}

// Keepalives measure the round trip, echo the Cortex's own probes and end a silent stream.
func TestKeepalive(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	if _, ok := h.hub.RTT(cortexA); ok {
		t.Fatal("RTT known before any keepalive")
	}
	h.ticks <- time.Time{}
	probe := s.stream.next(t).GetKeepalive()
	if probe == nil || probe.GetSentAtMs() != uint64(h.clock.Now().UnixMilli()) {
		t.Fatalf("probe = %v", probe)
	}
	h.clock.advance(40 * time.Millisecond)
	s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: probe}}
	waitRTT(t, h, 40*time.Millisecond)

	// The Cortex's own probe comes back unchanged.
	s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: 12345}}}
	if echo := s.stream.next(t).GetKeepalive(); echo.GetSentAtMs() != 12345 {
		t.Fatalf("echo = %v", echo)
	}

	// Unanswered probes end the stream.
	for i := 0; i < DefaultKeepaliveMisses; i++ {
		h.clock.advance(time.Second)
		h.ticks <- time.Time{}
		s.stream.next(t)
	}
	h.ticks <- time.Time{}
	if err := s.wait(t); !errors.Is(err, ErrKeepaliveTimeout) {
		t.Fatalf("Serve = %v, want ErrKeepaliveTimeout", err)
	}
	h.waitConn(cortexA, false)
}

func waitRTT(t *testing.T, h *harness, want time.Duration) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		if got, ok := h.hub.RTT(cortexA); ok && got == want {
			return
		}
		if time.Now().After(deadline) {
			got, ok := h.hub.RTT(cortexA)
			t.Fatalf("RTT = %v %v, want %v", got, ok, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
