package dispatchstream

import (
	"context"
	"testing"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

func openVerify(task string, signature string) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: &nexusv1.OpenVerifyV1{
		TaskId: hash32("task|" + task), VerifyRound: 1, BuilderServiceSignature: []byte(signature),
	}}}
}

func assignment(task string) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_VerifierAssignment{
		VerifierAssignment: &nexusv1.VerifierAssignmentNotifyV1{TaskId: hash32("task|" + task), VerifyRound: 1},
	}}
}

// kindOf names the Verifier broadcast a frame carries; an OpenVerifyV1 also names its signature.
func kindOf(f *nexusv1.DispatchStreamFrameV1) string {
	switch {
	case f.GetOpenVerify() != nil:
		return "open_verify/" + string(f.GetOpenVerify().GetBuilderServiceSignature())
	case f.GetVerifierAssignment() != nil:
		return "verifier_assignment"
	default:
		return "other"
	}
}

func mustBroadcast(t *testing.T, h *harness, f *nexusv1.DispatchStreamFrameV1) {
	t.Helper()
	if err := h.hub.Broadcast(context.Background(), f); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
}

// A Verifier broadcast sent while no stream is connected is not lost: every Cortex that connects
// later gets it once, until the task leaves the round.
func TestBroadcastReachesLateJoinersOnce(t *testing.T) {
	h := newHarness(t)
	mustBroadcast(t, h, openVerify("t1", "ov1"))

	a := h.connect(cortexA, "1")
	if got := kindOf(a.stream.nextBusiness(t)); got != "open_verify/ov1" {
		t.Fatalf("late joiner got %s", got)
	}
	a.ack(1)
	waitPending(t, h, cortexA, 0)
	a.stream.close()
	a.wait(t)
	h.waitConn(cortexA, false)
	again := h.connect(cortexA, "2")
	again.stream.quiet(t) // already delivered and acknowledged

	b := h.connect(cortexB, "1")
	if got := kindOf(b.stream.nextBusiness(t)); got != "open_verify/ov1" {
		t.Fatalf("second late joiner got %s", got)
	}
	// The same signed bytes again reach nobody twice; new bytes reach everyone.
	mustBroadcast(t, h, openVerify("t1", "ov1"))
	again.stream.quiet(t)
	b.stream.quiet(t)
	mustBroadcast(t, h, openVerify("t1", "ov1-resigned"))
	if got := kindOf(again.stream.nextBusiness(t)); got != "open_verify/ov1-resigned" {
		t.Fatalf("re-signed broadcast got %s", got)
	}
	if got := kindOf(b.stream.nextBusiness(t)); got != "open_verify/ov1-resigned" {
		t.Fatalf("re-signed broadcast got %s", got)
	}
}

// The assignment closes the handraise window: a Cortex connecting after it gets the assignment
// only. Retire stops both for later streams.
func TestAssignmentRetiresOpenVerifyAndRetireStopsBoth(t *testing.T) {
	h := newHarness(t)
	mustBroadcast(t, h, openVerify("t1", "ov1"))
	mustBroadcast(t, h, assignment("t1"))
	mustBroadcast(t, h, openVerify("t2", "ov2"))

	a := h.connect(cortexA, "1")
	got := map[string]bool{kindOf(a.stream.nextBusiness(t)): true, kindOf(a.stream.nextBusiness(t)): true}
	if !got["verifier_assignment"] || !got["open_verify/ov2"] {
		t.Fatalf("late joiner got %v", got)
	}
	a.stream.quiet(t)

	h.hub.Retire(hash32("task|t1"), 1)
	h.hub.Retire(hash32("task|t2"), 1)
	b := h.connect(cortexB, "1")
	b.stream.quiet(t)
}

func TestBroadcastCarriesOnlyVerifierMessages(t *testing.T) {
	h := newHarness(t)
	if err := h.hub.Broadcast(context.Background(), offer("x")); err == nil {
		t.Fatal("Broadcast accepted a dispatch offer")
	}
}

// businessKinds reads n business frames and names what each carries.
func businessKinds(t *testing.T, s *served, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		f := s.stream.nextBusiness(t)
		if f.GetOffer() != nil {
			got["offer"]++
			continue
		}
		got[kindOf(f)]++
	}
	return got
}

// A Verifier broadcast counts as given to a Cortex only once that Cortex acknowledged it: one the
// retention bound evicted unacknowledged is given again when the Cortex reconnects.
func TestEvictedBroadcastIsGivenAgainOnReconnect(t *testing.T) {
	h := newHarness(t) // MaxPending 8
	a := h.connect(cortexA, "1")
	mustBroadcast(t, h, openVerify("t1", "ov1"))
	for i := 0; i < 8; i++ {
		mustSend(t, h, cortexA, string(rune('a'+i)))
	}
	businessKinds(t, a, 9)
	waitPending(t, h, cortexA, 8)
	a.stream.close()
	a.wait(t)
	h.waitConn(cortexA, false)

	b := h.connect(cortexA, "2")
	if got := businessKinds(t, b, 9); got["offer"] != 8 || got["open_verify/ov1"] != 1 {
		t.Fatalf("reconnect got %v, want 8 offers and the evicted open_verify", got)
	}
	b.stream.quiet(t)
}

// A broadcast still waiting for its acknowledgement is replayed once on reconnect, not once from
// the retention and once more as a retained broadcast.
func TestUnacknowledgedBroadcastIsReplayedOnce(t *testing.T) {
	h := newHarness(t)
	a := h.connect(cortexA, "1")
	mustBroadcast(t, h, openVerify("t1", "ov1"))
	businessKinds(t, a, 1)
	a.stream.close()
	a.wait(t)
	h.waitConn(cortexA, false)

	b := h.connect(cortexA, "2")
	if got := businessKinds(t, b, 1); got["open_verify/ov1"] != 1 {
		t.Fatalf("reconnect got %v", got)
	}
	b.stream.quiet(t)
	b.ack(1)
	waitPending(t, h, cortexA, 0)
	b.stream.close()
	b.wait(t)
	h.waitConn(cortexA, false)
	c := h.connect(cortexA, "3")
	c.stream.quiet(t)
}
