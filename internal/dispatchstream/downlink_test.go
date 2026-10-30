package dispatchstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
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
	if b := h.hub.Backlog(); b.Sessions != 1 || b.Unacked != 2 || b.Operators != 1 {
		t.Fatalf("backlog = %+v", b)
	}
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

// Keepalives keep one probe outstanding with increasing odd values, measure the round trip from
// its echo without answering the echo, echo each new Cortex probe once, and end a silent stream.
func TestKeepalive(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	keepalive := func(v uint64) {
		s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
			Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: v}}}
	}
	nextProbe := func() uint64 {
		t.Helper()
		f := s.stream.next(t)
		if f.GetKeepalive() == nil || f.GetCursor() != 0 {
			t.Fatalf("frame = %v, want a keepalive with cursor 0", f)
		}
		return f.GetKeepalive().GetSentAtMs()
	}
	if _, ok := h.hub.RTT(cortexA); ok {
		t.Fatal("RTT known before any keepalive")
	}
	h.ticks <- time.Time{}
	first := nextProbe()
	if first != uint64(h.clock.Now().UnixMilli())|1 {
		t.Fatalf("probe = %d, want the clock in ms made odd", first)
	}
	// A Cortex probe sent in the same millisecond carries the clock as is: it is not our probe's
	// echo, so it is echoed and ours stays outstanding.
	keepalive(uint64(h.clock.Now().UnixMilli()))
	if got := nextProbe(); got != uint64(h.clock.Now().UnixMilli()) {
		t.Fatalf("echo = %d, want the Cortex probe", got)
	}
	// One probe at a time: a tick while it is outstanding sends nothing.
	h.ticks <- time.Time{}
	s.stream.quiet(t)

	// Its echo measures the round trip and is not answered.
	h.clock.advance(40 * time.Millisecond)
	keepalive(first)
	waitRTT(t, h, 40*time.Millisecond)
	s.stream.quiet(t)

	// Probe values increase even when the clock does not.
	h.clock.advance(-40 * time.Millisecond)
	h.ticks <- time.Time{}
	second := nextProbe()
	if second <= first || second%2 != 1 {
		t.Fatalf("second probe %d is not an odd value above the first %d", second, first)
	}

	// A Cortex probe is echoed once, also while our probe is outstanding; repeated or older values
	// are not echoed again.
	peer := uint64(h.clock.Now().UnixMilli()) + 100
	keepalive(peer)
	if got := nextProbe(); got != peer {
		t.Fatalf("echo = %d, want %d", got, peer)
	}
	keepalive(peer)
	keepalive(peer - 1)
	s.stream.quiet(t)
	keepalive(peer + 1)
	if got := nextProbe(); got != peer+1 {
		t.Fatalf("echo = %d, want %d", got, peer+1)
	}
	keepalive(second)
	s.stream.quiet(t)

	// A probe left unanswered for KeepaliveMisses ticks ends the stream.
	h.ticks <- time.Time{}
	nextProbe()
	for i := 1; i < DefaultKeepaliveMisses; i++ {
		h.ticks <- time.Time{}
	}
	s.stream.quiet(t)
	h.ticks <- time.Time{}
	if err := s.wait(t); !errors.Is(err, ErrKeepaliveTimeout) {
		t.Fatalf("Serve = %v, want ErrKeepaliveTimeout", err)
	}
	h.waitConn(cortexA, false)
}

// Probe values follow wire's keepalive example: a new Builder probe is odd, the echo of a Cortex
// probe keeps the Cortex's (even) value.
func TestKeepaliveProbeParityVector(t *testing.T) {
	var file struct {
		Probes struct {
			BuilderNewProbe     uint64 `json:"builder_new_probe"`
			BuilderEchoOfCortex uint64 `json:"builder_echo_of_cortex"`
			CortexNewProbe      uint64 `json:"cortex_new_probe"`
			CortexEchoOfBuilder uint64 `json:"cortex_echo_of_builder"`
		} `json:"keepalive_probes"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/builder_sync_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	p := file.Probes
	if p.BuilderNewProbe%2 != 1 || p.CortexNewProbe%2 != 0 || p.BuilderEchoOfCortex != p.CortexNewProbe || p.CortexEchoOfBuilder != p.BuilderNewProbe {
		t.Fatalf("keepalive example = %+v", p)
	}
	h := newHarness(t)
	h.clock.advance(time.UnixMilli(int64(p.CortexNewProbe)).Sub(h.clock.Now()))
	s := h.connect(cortexA, "1")
	h.ticks <- time.Time{}
	if got := s.stream.next(t).GetKeepalive().GetSentAtMs(); got != p.BuilderNewProbe {
		t.Fatalf("Builder probe = %d, want %d", got, p.BuilderNewProbe)
	}
	s.stream.in <- &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: p.CortexNewProbe}}}
	if got := s.stream.next(t).GetKeepalive().GetSentAtMs(); got != p.BuilderEchoOfCortex {
		t.Fatalf("echo of the Cortex probe = %d, want %d", got, p.BuilderEchoOfCortex)
	}
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

// Transport messages carry no key generation: when a Cortex binds again, each unacknowledged
// message passes the re-signer (which signs it with the current key) and goes out, and is kept,
// as signed again.
func TestReplaySignsTransportMessagesAgain(t *testing.T) {
	store, keys := kv.NewMemStore(), newTestKeys()
	resign := WithResigner(func(f *nexusv1.DispatchStreamFrameV1) error {
		if t := f.GetOffer().GetTicket(); t != nil {
			t.BuilderServiceSignature = append(t.BuilderServiceSignature, '\'')
		}
		return nil
	})
	h := newHarnessOn(t, store, keys, resign)
	s1 := h.connect(cortexA, "1")
	mustSend(t, h, cortexA, "a")
	receiveOffers(t, s1, 1)
	s1.stream.close()
	s1.wait(t)
	h.waitConn(cortexA, false)

	s2 := h.connect(cortexA, "2")
	if got := receiveOffers(t, s2, 1); !slices.Equal(got, []string{"a'"}) {
		t.Fatalf("replayed %v, want [a']", got)
	}
	_ = h.hub.Stop(context.Background())
	s2.wait(t)
	restarted := newHarnessOn(t, store, keys)
	s3 := restarted.connect(cortexA, "3")
	if got := receiveOffers(t, s3, 1); !slices.Equal(got, []string{"a'"}) {
		t.Fatalf("stored after the replay %v, want [a']", got)
	}
}
