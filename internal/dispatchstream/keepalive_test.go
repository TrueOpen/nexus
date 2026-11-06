package dispatchstream

import (
	"context"
	"slices"
	"testing"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// blockingHandraiseSink holds every standing handraise until released, like a sink reading the
// chain; everything else goes to the recording sinks.
type blockingHandraiseSink struct {
	*recordingSinks
	entered chan struct{}
	release chan struct{}
}

func (b *blockingHandraiseSink) HandleStandingHandraise(ctx context.Context, from Origin, m *taskv1.StandingHandraiseV1) error {
	b.entered <- struct{}{}
	<-b.release
	return b.recordingSinks.HandleStandingHandraise(ctx, from, m)
}

func keepaliveFrame(s *served, v uint64) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: v}}}
}

// The echo of our probe is timed when it arrives, also while a slow uplink handler holds the stream
// loop: the RTT measures the network, not the Builder's processing. Cortex probes are echoed
// meanwhile, and the business frames received during the wait are handled afterwards in order.
func TestKeepaliveIsMeasuredWhileAHandlerIsBusy(t *testing.T) {
	h := newHarness(t)
	sink := &blockingHandraiseSink{recordingSinks: h.sinks, entered: make(chan struct{}, 1), release: make(chan struct{})}
	h.hub.SetSinks(Sinks{Handraise: sink, Dispatch: h.sinks, Verifier: h.sinks})
	s := h.connect(cortexA, "1")
	h.ticks <- time.Time{}
	probe := s.stream.next(t).GetKeepalive().GetSentAtMs()

	first := s.send(standingFrame(h.keys.standing(t, cortexA)))
	select {
	case <-sink.entered:
	case <-time.After(waitFor):
		t.Fatal("standing handraise not handled")
	}
	h.clock.advance(40 * time.Millisecond)
	s.stream.in <- keepaliveFrame(s, probe)
	waitRTT(t, h, 40*time.Millisecond)

	peer := uint64(h.clock.Now().UnixMilli()) + 100
	s.stream.in <- keepaliveFrame(s, peer)
	if got := s.stream.next(t).GetKeepalive().GetSentAtMs(); got != peer {
		t.Fatalf("echo = %d, want the Cortex probe %d", got, peer)
	}
	var cursors []uint64
	for _, label := range []string{"n1", "n2", "n3"} {
		cursors = append(cursors, s.send(noticeFrame(h.keys.verifyNotice(t, cortexA, label))))
	}

	h.clock.advance(500 * time.Millisecond)
	close(sink.release)
	for _, want := range append([]uint64{first}, cursors...) {
		if got := s.stream.nextAck(t); got != want {
			t.Fatalf("acked %d, want %d", got, want)
		}
	}
	want := []string{"handraise", "verify_result_submitted", "verify_result_submitted", "verify_result_submitted"}
	if got := h.sinks.kinds(); !slices.Equal(got, want) {
		t.Fatalf("routed %v, want %v", got, want)
	}
	if got, _ := h.hub.RTT(cortexA); got != 40*time.Millisecond {
		t.Fatalf("RTT = %v after the handler finished, want 40ms", got)
	}
}
