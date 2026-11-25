package app

import (
	"context"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
)

type quotaChain struct {
	chaincli.Client
	quota chaincli.WorkerQuota
	err   error
	ratio uint32
	reads int
}

func (c *quotaChain) QueryWorkerQuota(context.Context, string) (chaincli.WorkerQuota, error) {
	return c.quota, c.err
}

func (c *quotaChain) QueryProfile(_ context.Context, modelID string, version uint32) (chaincli.ProfileState, error) {
	c.reads++
	return chaincli.ProfileState{ModelID: modelID, ProfileVersion: version, VerifyRatioBps: c.ratio}, nil
}

// worker_quota_refresh_ms 0 turns the check off: the dispatcher gets a nil interface, not a nil
// ledger inside one.
func TestWorkerQuotaOff(t *testing.T) {
	od := &orderDispatch{}
	q, p := workerQuota(orderDispatchDeps{Config: config.DispatchConfig{}, HubChain: &quotaChain{}}, od)
	if q != nil || p != nil || od.Quota != nil || od.workerQuotaViews() != nil {
		t.Fatalf("quota %v pricing %v ledger %v: the check is not off", q, p, od.Quota)
	}
}

// With the check on, the chain's pause flag and figure reach the dispatcher's decision, and the
// Profile's verify ratio is read once.
func TestWorkerQuotaReadsTheChain(t *testing.T) {
	chain := &quotaChain{quota: chaincli.WorkerQuota{Enforced: true, Quota: 1000, Remaining: 100, Period: 2}, ratio: 1000}
	od := &orderDispatch{}
	q, p := workerQuota(orderDispatchDeps{Config: config.DispatchConfig{WorkerQuotaRefreshMs: 1}, HubChain: chain}, od)
	if q == nil || p == nil || od.Quota == nil {
		t.Fatal("the check is on but no ledger was built")
	}
	if d := q.Admit(context.Background(), "w", "o1", 101, time.Minute); d.OK || d.Reason != "quota" {
		t.Fatalf("an order above the remaining quota = %+v", d)
	}
	if d := q.Admit(context.Background(), "w", "o1", 100, time.Minute); !d.OK {
		t.Fatalf("an order that fits = %+v", d)
	}
	chain.quota.DispatchPaused, chain.quota.PauseReasons = true, 2
	time.Sleep(5 * time.Millisecond)
	if d := q.Admit(context.Background(), "w", "o2", 1, time.Minute); d.OK || d.Reason != "paused" {
		t.Fatalf("a paused Worker = %+v", d)
	}
	for i := 0; i < 3; i++ {
		if bps, err := p.VerifyRatioBps(context.Background(), []byte{1, 2}, 2); err != nil || bps != 1000 {
			t.Fatalf("verify ratio = %d, %v", bps, err)
		}
	}
	if chain.reads != 1 {
		t.Fatalf("the Profile was read %d times, want once", chain.reads)
	}
	if views := od.workerQuotaViews()(); len(views) != 1 || !views[0].Paused {
		t.Fatalf("views = %+v", views)
	}
	// A chain that does not serve the query changes nothing.
	old := &quotaChain{err: chaincli.ErrWorkerQuotaUnsupported}
	q, _ = workerQuota(orderDispatchDeps{Config: config.DispatchConfig{WorkerQuotaRefreshMs: 1}, HubChain: old}, &orderDispatch{})
	if d := q.Admit(context.Background(), "w", "o", 1<<50, time.Minute); !d.OK {
		t.Fatalf("an older chain = %+v", d)
	}
}
