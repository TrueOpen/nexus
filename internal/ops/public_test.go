package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

type fakeHandraises struct {
	since time.Time
	root  *handraise.IssuedRoot
}

func (h fakeHandraises) RTTThreshold() (uint64, time.Time) { return 300, h.since }

func (h fakeHandraises) RTTThresholdHistory() ([]handraise.RTTThresholdChange, error) {
	return []handraise.RTTThresholdChange{{ThresholdMs: 500, Since: h.since.Add(-time.Hour)}, {ThresholdMs: 300, Since: h.since}}, nil
}

func (h fakeHandraises) Suspensions(height uint64) map[string]uint64 {
	if height < 200 {
		return map[string]uint64{"trueopen1bad": 200}
	}
	return nil
}

func (h fakeHandraises) LatestRoot() (*handraise.IssuedRoot, bool) { return h.root, h.root != nil }

func leaf(operator string, admitted bool, reason taskv1.AdmitRejectReasonV1) *taskv1.HandraiseRootLeafV1 {
	return &taskv1.HandraiseRootLeafV1{
		Handraise: &taskv1.StandingHandraiseV1{Member: &taskv1.CandidateMemberRefV1{OperatorAddress: operator}},
		Admitted:  admitted, AdmitRejectReason: reason,
	}
}

// The public statistics carry the RTT admission threshold and its history, the timeout and reject
// rate rules, the skips, and per Worker its tickets, rates, reject-rate suspension and admission in
// the latest root; never a session, task or user.
func TestPublicStatsContent(t *testing.T) {
	metrics := opsmetrics.New()
	metrics.WorkerOutcome("trueopen1good", 1, opsmetrics.OutcomeAccepted)
	metrics.WorkerOutcome("trueopen1good", 1, opsmetrics.OutcomeTimeout)
	metrics.WorkerOutcome("trueopen1bad", 2, opsmetrics.OutcomeRejected)
	metrics.WorkerOutcome("trueopen1bad", 2, opsmetrics.OutcomeRejected)
	metrics.Inc(opsmetrics.CounterSkips, opsmetrics.SkipTimeout)
	metrics.Accepted("task-0123456789abcdef")
	metrics.Inc(opsmetrics.CounterRecordOutcomes, "ADMITTED")
	since := time.UnixMilli(1_800_000_000_000).UTC()
	root := &handraise.IssuedRoot{
		Root: &taskv1.SignedHandraiseRootV1{RootHeight: 150, RootVersion: 2},
		Leaves: []*taskv1.HandraiseRootLeafV1{
			leaf("trueopen1good", true, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE),
			leaf("trueopen1bad", false, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE),
			leaf("trueopen1far", false, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD),
		},
	}
	src := PublicSources{
		Builder: "trueopen1builder", Metrics: metrics, Handraises: fakeHandraises{since: since, root: root},
		Height:   func() uint64 { return 150 },
		Dispatch: config.DispatchConfig{BuilderTimeoutRateThreshold: 0.2, GPURejectRateThreshold: 0.5, GPURejectRateSuspensionBlocks: 720, GPURejectRateMinSamples: 10},
	}
	s := BuildPublicStats(src, since.Add(time.Minute))
	if s.Note != PublicStatsNote {
		t.Fatalf("note = %q", s.Note)
	}
	if s.RTTAdmit.ThresholdMs != 300 || !s.RTTAdmit.Since.Equal(since) || len(s.RTTAdmit.History) != 2 {
		t.Fatalf("rtt admit = %+v", s.RTTAdmit)
	}
	if s.TimeoutRate != 0.25 || !s.TimeoutRateExceeded || s.RejectRate.Threshold != 0.5 || s.RejectRate.SuspensionBlocks != 720 {
		t.Fatalf("rates = %v %v %+v", s.TimeoutRate, s.TimeoutRateExceeded, s.RejectRate)
	}
	good, bad, far := s.Workers["trueopen1good"], s.Workers["trueopen1bad"], s.Workers["trueopen1far"]
	if good.TimeoutRate != 0.5 || good.Admitted == nil || !*good.Admitted || good.SuspendedUntil != 0 {
		t.Fatalf("good = %+v", good)
	}
	if bad.RejectRate != 1 || bad.SuspendedUntil != 200 || bad.Admitted == nil || *bad.Admitted || bad.AdmitRejectReason != "REJECT_RATE" {
		t.Fatalf("bad = %+v", bad)
	}
	if far.Received != 0 || far.AdmitRejectReason != "RTT_OVER_THRESHOLD" {
		t.Fatalf("far = %+v", far)
	}
	if s.Root == nil || s.Root.Leaves != 3 || s.Root.NotAdmitted["REJECT_RATE"] != 1 || s.Root.NotAdmitted["RTT_OVER_THRESHOLD"] != 1 {
		t.Fatalf("root = %+v", s.Root)
	}
	if s.Skips[opsmetrics.SkipTimeout] != 1 {
		t.Fatalf("skips = %v", s.Skips)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"task-0123456789abcdef", "session", "task_id", "user", "payload", "ADMITTED", "secret", "private"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("public statistics contain %q: %s", leak, raw)
		}
	}
}

// The handler serves the statistics of the last tick, and nothing before the first.
func TestPublicStatsHandler(t *testing.T) {
	m := New(Config{DataDir: t.TempDir(), Public: func(now time.Time) PublicStats {
		return BuildPublicStats(PublicSources{Builder: "trueopen1builder", Metrics: opsmetrics.New()}, now)
	}})
	rr := httptest.NewRecorder()
	m.PublicStatsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, PublicStatsPath, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("before the first tick: %d", rr.Code)
	}
	m.Tick(context.Background())
	rr = httptest.NewRecorder()
	m.PublicStatsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, PublicStatsPath, nil))
	var got PublicStats
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.Builder != "trueopen1builder" {
		t.Fatalf("stats = %d %s", rr.Code, rr.Body.String())
	}
}
