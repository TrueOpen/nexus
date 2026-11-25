package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/workerquota"
)

// workerQuota builds the Worker quota ledger and the Profile pricing reader of the dispatcher.
// The ledger is nil, and nothing is checked, when dispatch.worker_quota_refresh_ms is 0 or the
// chain client cannot read hub.v1.Query/WorkerQuota. The nil interface (not a nil *Ledger in an
// interface) is returned then, so the dispatcher's own nil check holds.
func workerQuota(deps orderDispatchDeps, od *orderDispatch) (dispatcher.Quota, dispatcher.Pricing) {
	if deps.Config.WorkerQuotaRefreshMs == 0 {
		return nil, nil
	}
	chain := deps.HubChain
	if chain == nil {
		chain = deps.TaskChain
	}
	reader, ok := chain.(chaincli.WorkerQuotaReader)
	if !ok {
		return nil, nil
	}
	od.Quota = workerquota.New(quotaSource{reader}, workerquota.Options{Refresh: time.Duration(deps.Config.WorkerQuotaRefreshMs) * time.Millisecond})
	return od.Quota, &profilePricing{chain: chain, ratios: map[string]uint32{}}
}

// workerQuotaViews is the public statistics' reader of the ledger; nil without one.
func (od *orderDispatch) workerQuotaViews() func() []workerquota.View {
	if od == nil || od.Quota == nil {
		return nil
	}
	return od.Quota.Snapshot
}

// quotaSource adapts the chain client to the ledger.
type quotaSource struct{ chain chaincli.WorkerQuotaReader }

func (s quotaSource) WorkerQuota(ctx context.Context, operator string) (workerquota.Facts, error) {
	q, err := s.chain.QueryWorkerQuota(ctx, operator)
	if errors.Is(err, chaincli.ErrWorkerQuotaUnsupported) {
		return workerquota.Facts{}, workerquota.ErrUnsupported
	}
	if err != nil {
		return workerquota.Facts{}, err
	}
	return workerquota.Facts{
		Period: q.Period, Quota: q.Quota, ReservedValue: q.ReservedValue, SettledValue: q.SettledValue, Remaining: q.Remaining,
		Enforced: q.Enforced, Paused: q.DispatchPaused, PauseReasons: q.PauseReasons,
	}, nil
}

// profilePricing reads PricingProfile.verify_ratio_bps of a Profile version once: a registered
// Profile version never changes.
type profilePricing struct {
	chain chaincli.Client

	mu     sync.Mutex
	ratios map[string]uint32
}

func (p *profilePricing) VerifyRatioBps(ctx context.Context, modelID []byte, profileVersion uint32) (uint32, error) {
	key := fmt.Sprintf("%x@%d", modelID, profileVersion)
	p.mu.Lock()
	ratio, ok := p.ratios[key]
	p.mu.Unlock()
	if ok {
		return ratio, nil
	}
	profile, err := p.chain.QueryProfile(ctx, hex.EncodeToString(modelID), profileVersion)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	p.ratios[key] = profile.VerifyRatioBps
	p.mu.Unlock()
	return profile.VerifyRatioBps, nil
}
