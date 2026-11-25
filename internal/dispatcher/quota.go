package dispatcher

import (
	"context"
	"math/bits"
	"strconv"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/workerquota"
)

const (
	// quotaOfferMargin is added to a ticket's accept window for the hold of its quota: the
	// answer's way back and its handling.
	quotaOfferMargin = 5 * time.Second
	// quotaRecordHold is how long an accepted order keeps its quota while its dispatch entry is on
	// the way to the chain. Recorded settles it and a refused record releases it; the bound only
	// ends a reservation nothing else ended.
	quotaRecordHold = 30 * time.Minute
)

// quotaSkip asks the quota ledger whether the order may be offered to operator. It returns the
// skip reason of a member that may not ("" otherwise) and, when the member may, holds the order's
// value for it. Without a ledger nothing is checked. Caller holds o.mu.
func (d *Dispatcher) quotaSkip(ctx context.Context, o *order, operator string, hold time.Duration) string {
	if d.cfg.Quota == nil {
		return ""
	}
	order := o.signed.GetOrder()
	dec := d.cfg.Quota.Admit(ctx, operator, stateKey(o.st.SessionID, o.st.Sequence), d.orderValue(ctx, order), hold)
	switch {
	case dec.OK:
		if !dec.Known {
			d.log.Warn("Worker quota unreadable; the order is offered and the chain decides at record time", "operator", operator)
		}
		return ""
	case dec.Reason == workerquota.ReasonPaused:
		d.log.Info("dispatch member is paused on chain; ticket times out unsent", "operator", operator, "pause_reasons", dec.Facts.PauseReasons)
		return opsmetrics.SkipWorkerPaused
	default:
		d.log.Info("dispatch member has no order quota left for this order; ticket times out unsent", "operator", operator,
			"period", dec.Facts.Period, "quota", dec.Facts.Quota, "remaining", dec.Facts.Remaining, "held_here", dec.Local)
		return opsmetrics.SkipWorkerQuota
	}
}

func (d *Dispatcher) quotaRelease(st *orderState) {
	if d.cfg.Quota != nil {
		d.cfg.Quota.Release(stateKey(st.SessionID, st.Sequence))
	}
}

func (d *Dispatcher) quotaSettle(sessionID string, sequence uint64) {
	if d.cfg.Quota != nil {
		d.cfg.Quota.Settle(stateKey(sessionID, sequence))
	}
}

// orderValue is the value the chain reserves in the Worker's quota for the order: its
// order_value, worker_max + verify_max, derived exactly as the chain derives it. Without the
// Profile's verify ratio the largest possible value is charged (verify share equal to the Worker
// share), never above what max_fee leaves after the transaction fee reserve.
func (d *Dispatcher) orderValue(ctx context.Context, order *taskv1.TaskOrderV3) uint64 {
	ratio, known := uint32(10000), false
	if d.cfg.Pricing != nil {
		if got, err := d.cfg.Pricing.VerifyRatioBps(ctx, order.GetModelId(), order.GetProfileVersion()); err == nil {
			ratio, known = got, true
		}
	}
	price, ok := amountUnits(order.GetPriceBid().GetAtomicUnits())
	if !ok {
		return ^uint64(0)
	}
	value := OrderValue(order.GetGenerationParams().GetMaxOutputTokens(), price, ratio)
	if !known {
		if limit, ok := amountUnits(order.GetMaxFee().GetAtomicUnits()); ok && limit != 0 {
			if reserve, ok := amountUnits(order.GetTxFeeReserve().GetAtomicUnits()); ok && reserve < limit {
				limit -= reserve
			}
			value = min(value, limit)
		}
	}
	return value
}

// OrderValue derives order_value with one floor per step in u64 with a 128-bit intermediate:
// worker_max = floor(max_output_tokens * price_bid / 1e6), verify_max = floor(worker_max *
// verify_ratio_bps / 1e4), order_value = worker_max + verify_max. A step that overflows u64
// saturates: such an order is refused by the chain anyway and fits no quota.
func OrderValue(maxOutputTokens, priceBid uint64, verifyRatioBps uint32) uint64 {
	workerMax, ok := mulDiv(maxOutputTokens, priceBid, 1_000_000)
	if !ok {
		return ^uint64(0)
	}
	verifyMax, ok := mulDiv(workerMax, uint64(verifyRatioBps), 10_000)
	if !ok {
		return ^uint64(0)
	}
	value, carry := bits.Add64(workerMax, verifyMax, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return value
}

// amountUnits parses a shared.v1.Amount's atomic units (a base-10 u64; empty is zero).
func amountUnits(s string) (uint64, bool) {
	if s == "" {
		return 0, true
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func mulDiv(a, b, div uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	if hi >= div {
		return 0, false
	}
	q, _ := bits.Div64(hi, lo, div)
	return q, true
}
