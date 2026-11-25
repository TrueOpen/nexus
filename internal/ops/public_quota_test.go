package ops

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/workerquota"
)

// The public statistics carry the Worker quota and pause states the Builder decides on, and leave
// the field out when the check is off.
func TestPublicStatsCarryWorkerQuota(t *testing.T) {
	src := PublicSources{Builder: "builder", Metrics: opsmetrics.New()}
	raw, err := json.Marshal(BuildPublicStats(src, time.Unix(1_800_000_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "worker_quota") {
		t.Fatalf("worker_quota published although the check is off: %s", raw)
	}
	src.WorkerQuota = func() []workerquota.View {
		return []workerquota.View{{Operator: "w1", Enforced: true, Period: 4, Quota: 1000, ChainReserved: 300, Remaining: 700, LocalReserved: 200, Paused: true, PauseReasons: workerquota.PauseLateSubmission}}
	}
	stats := BuildPublicStats(src, time.Unix(1_800_000_000, 0))
	if len(stats.WorkerQuota) != 1 || stats.WorkerQuota[0].Operator != "w1" || !stats.WorkerQuota[0].Paused || stats.WorkerQuota[0].LocalReserved != 200 {
		t.Fatalf("worker_quota = %+v", stats.WorkerQuota)
	}
	raw, _ = json.Marshal(stats)
	for _, want := range []string{`"worker_quota"`, `"remaining":700`, `"pause_reasons":1`, `"local_reserved":200`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("public statistics lack %s: %s", want, raw)
		}
	}
}
