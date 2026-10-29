package handraise

import (
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

const (
	reasonNone       = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE
	reasonRTT        = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD
	reasonRejectRate = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE
)

func TestRTTOverThresholdIsNotAdmitted(t *testing.T) {
	e := newEnv(t) // builder_rtt_admit_ms = 150
	near := e.addCortex(0x11, 1)
	edge := e.addCortex(0x12, 2)
	far := e.addCortex(0x13, 3)
	unmeasured := e.addCortex(0x14, 4)
	for _, c := range []cortex{near, edge, far, unmeasured} {
		e.mustAccept(c, e.handraise(c, 100, 1))
	}
	e.reg.RecordRTT(near.operator(), 20)
	e.reg.RecordRTT(edge.operator(), 150)
	e.reg.RecordRTT(far.operator(), 151)

	root := e.mustIssue()
	for _, tc := range []struct {
		c        cortex
		admitted bool
		reason   taskv1.AdmitRejectReasonV1
		rtt      uint64
	}{
		{near, true, reasonNone, 0},
		{edge, true, reasonNone, 0},
		{far, false, reasonRTT, 151},
		{unmeasured, true, reasonNone, 0},
	} {
		leaf := leafOf(t, root, tc.c.operator())
		if leaf.GetAdmitted() != tc.admitted || leaf.GetAdmitRejectReason() != tc.reason || leaf.GetBuilderMeasuredRttMs() != tc.rtt {
			t.Fatalf("leaf of slot %d = %v", tc.c.slot, leaf)
		}
	}

	// A better measurement admits it again in the next root.
	e.reg.RecordRTT(far.operator(), 90)
	if leaf := leafOf(t, e.mustIssue(), far.operator()); !leaf.GetAdmitted() {
		t.Fatalf("leaf after a lower RTT = %v", leaf)
	}
}

func TestRTTThresholdZeroAdmitsAll(t *testing.T) {
	e := newEnv(t)
	e.cfg.BuilderRTTAdmitMs = 0
	e.reg = e.open()
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	e.reg.RecordRTT(c.operator(), 5000)
	if leaf := leafOf(t, e.mustIssue(), c.operator()); !leaf.GetAdmitted() {
		t.Fatalf("leaf = %v", leaf)
	}
}

func TestRejectRateSuspendsAdmission(t *testing.T) {
	e := newEnv(t) // threshold 0.5, suspension 100 blocks
	bad := e.addCortex(0x11, 1)
	good := e.addCortex(0x12, 2)
	for _, c := range []cortex{bad, good} {
		e.mustAccept(c, e.handraise(c, 100, 1))
	}
	// Below the minimum sample count nothing happens, however high the rate.
	for i := 0; i < minRejectRateSamples-1; i++ {
		if err := e.reg.RecordOutcome(bad.operator(), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	if leaf := leafOf(t, e.mustIssue(), bad.operator()); !leaf.GetAdmitted() {
		t.Fatal("suspended before the minimum sample count")
	}
	for i := 0; i < minRejectRateSamples; i++ {
		if err := e.reg.RecordOutcome(good.operator(), 100, i%2 == 0); err != nil { // exactly 0.5: not above
			t.Fatal(err)
		}
	}
	if err := e.reg.RecordOutcome(bad.operator(), 100, true); err != nil {
		t.Fatal(err)
	}

	e.height.set(101)
	root := e.mustIssue()
	if leaf := leafOf(t, root, bad.operator()); leaf.GetAdmitted() || leaf.GetAdmitRejectReason() != reasonRejectRate || leaf.GetBuilderMeasuredRttMs() != 0 {
		t.Fatalf("suspended leaf = %v", leaf)
	}
	if leaf := leafOf(t, root, good.operator()); !leaf.GetAdmitted() {
		t.Fatalf("worker at the threshold was suspended: %v", leaf)
	}

	// The suspension outlives a restart and ends after gpu_reject_rate_suspension_blocks.
	e.reg = e.open()
	e.height.set(199)
	e.clock.advance(time.Second)
	e.mustAccept(bad, e.handraise(bad, 199, 1))
	e.mustAccept(good, e.handraise(good, 199, 1))
	if leaf := leafOf(t, e.mustIssue(), bad.operator()); leaf.GetAdmitRejectReason() != reasonRejectRate {
		t.Fatalf("suspension lost: %v", leaf)
	}
	e.height.set(200)
	if leaf := leafOf(t, e.mustIssue(), bad.operator()); !leaf.GetAdmitted() {
		t.Fatalf("suspension did not end: %v", leaf)
	}
}

// Outcomes older than the measuring window no longer count.
func TestRejectRateWindow(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	for i := 0; i < minRejectRateSamples-1; i++ {
		if err := e.reg.RecordOutcome(c.operator(), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.reg.RecordOutcome(c.operator(), 200, true); err != nil {
		t.Fatal(err)
	}
	if leaf := leafOf(t, e.mustIssue(), c.operator()); !leaf.GetAdmitted() {
		t.Fatalf("outcomes outside the window counted: %v", leaf)
	}
}

func TestRejectRateDisabled(t *testing.T) {
	e := newEnv(t)
	e.cfg.GPURejectRateThreshold = 0
	e.reg = e.open()
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	for i := 0; i < 2*minRejectRateSamples; i++ {
		if err := e.reg.RecordOutcome(c.operator(), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	if leaf := leafOf(t, e.mustIssue(), c.operator()); !leaf.GetAdmitted() {
		t.Fatalf("disabled rule suspended: %v", leaf)
	}
}

// Suspension takes precedence over an RTT verdict: the leaf carries one reason.
func TestRejectRateBeforeRTT(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	e.reg.RecordRTT(c.operator(), 900)
	for i := 0; i < minRejectRateSamples; i++ {
		if err := e.reg.RecordOutcome(c.operator(), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	if leaf := leafOf(t, e.mustIssue(), c.operator()); leaf.GetAdmitRejectReason() != reasonRejectRate || leaf.GetBuilderMeasuredRttMs() != 0 {
		t.Fatalf("leaf = %v", leaf)
	}
}

// The latest measured RTT survives a restart.
func TestMeasuredRTTIsKeptAcrossRestart(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.reg.RecordRTT(c.operator(), 400)
	e.reg = e.open()
	e.mustAccept(c, e.handraise(c, 100, 1))
	leaf := leafOf(t, e.mustIssue(), c.operator())
	if leaf.GetAdmitted() || leaf.GetAdmitRejectReason() != taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD ||
		leaf.GetBuilderMeasuredRttMs() != 400 {
		t.Fatalf("leaf after restart = %v", leaf)
	}
}

// gpu_reject_rate_min_samples sets how many tickets the window needs before a rate counts.
func TestRejectRateMinSamplesIsConfigured(t *testing.T) {
	e := newEnv(t)
	e.cfg.GPURejectRateMinSamples = 2
	e.reg = e.open()
	c := e.addCortex(0x11, 4)
	for i := 0; i < 2; i++ {
		if err := e.reg.RecordOutcome(c.operator(), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	e.mustAccept(c, e.handraise(c, 100, 1))
	if leaf := leafOf(t, e.mustIssue(), c.operator()); leaf.GetAdmitRejectReason() != taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE {
		t.Fatalf("leaf = %v, want a reject-rate suspension after two samples", leaf)
	}
}
