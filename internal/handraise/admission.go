package handraise

import (
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// outcome is one answered ticket of a Worker.
type outcome struct {
	height   uint64
	rejected bool
}

// RTTThresholdChange is one value of the public RTT admission threshold and when it took effect.
type RTTThresholdChange struct {
	ThresholdMs uint64
	Since       time.Time
}

// RecordRTT records the latest RTT this Builder measured to operator's dispatch stream. Roots
// issued afterwards admit or refuse the operator's handraise against builder_rtt_admit_ms; an
// operator without a measurement is admitted. The latest value is kept in the store so a restart
// does not admit a far operator until its stream is measured again; a failed write is logged and
// the value still applies in memory.
func (r *Registry) RecordRTT(operator string, rttMs uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.rtt[operator]; ok && prev == rttMs {
		return
	}
	r.rtt[operator] = rttMs
	if err := r.persistRTT(operator, rttMs); err != nil {
		r.log.Warn("store measured RTT", "operator", operator, "error", err)
	}
}

// RecordOutcome records one ticket the Worker received at height: rejected is a signed reject
// while it advertised a free slot; an accept, a timeout or a reject at no free slot is not a
// reject. The reject rate is rejects over tickets received. When the
// share of rejects among the Worker's outcomes within the last gpu_reject_rate_suspension_blocks
// exceeds gpu_reject_rate_threshold, its handraise is not admitted (REJECT_RATE) until
// gpu_reject_rate_suspension_blocks after height. The error is a failed write of the suspension.
func (r *Registry) RecordOutcome(operator string, height uint64, rejected bool) error {
	cfg := r.opts.Config
	if cfg.GPURejectRateThreshold == 0 || cfg.GPURejectRateSuspensionBlocks == 0 {
		return nil
	}
	window := cfg.GPURejectRateSuspensionBlocks
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, ok := r.suspended[operator]; ok && height < until {
		return nil
	}
	kept := make([]outcome, 0, len(r.outcomes[operator])+1)
	rejects := 0
	for _, o := range append(r.outcomes[operator], outcome{height: height, rejected: rejected}) {
		if o.height+window <= height {
			continue
		}
		kept = append(kept, o)
		if o.rejected {
			rejects++
		}
	}
	if uint64(len(kept)) < cfg.GPURejectRateMinSamples || float64(rejects)/float64(len(kept)) <= cfg.GPURejectRateThreshold {
		r.outcomes[operator] = kept
		return nil
	}
	until := height + window
	if err := r.persistSuspension(operator, until); err != nil {
		r.outcomes[operator] = kept
		return err
	}
	r.suspended[operator] = until
	delete(r.outcomes, operator)
	r.log.Info("handraise suspended for reject rate", "operator", operator, "rejects", rejects, "tickets", len(kept), "until_height", until)
	return nil
}

// RTTThreshold returns the RTT admission threshold in effect and since when, for the public
// statistics.
func (r *Registry) RTTThreshold() (uint64, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.threshold.ThresholdMs, r.threshold.Since
}

// decisionLocked is the admission decision of operator's held handraise at height. A pending
// CORTEX service key rotation comes first: such a Cortex may take no new duty at all. Then a
// reject-rate suspension, then the RTT threshold, whose leaf carries the measured RTT.
func (r *Registry) decisionLocked(operator string, height uint64, rotationPending bool) (bool, taskv1.AdmitRejectReasonV1, uint64) {
	if rotationPending {
		return false, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_SERVICE_KEY_ROTATION_PENDING, 0
	}
	if until, ok := r.suspended[operator]; ok && height < until {
		return false, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE, 0
	}
	if threshold := r.opts.Config.BuilderRTTAdmitMs; threshold > 0 {
		if rtt, ok := r.rtt[operator]; ok && rtt > threshold {
			return false, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD, rtt
		}
	}
	return true, taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE, 0
}
