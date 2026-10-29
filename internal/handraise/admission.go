package handraise

import (
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// minRejectRateSamples is the fewest tickets inside the measuring window before a reject rate
// can suspend a Worker, so one early reject is not a 100% rate. Placeholder until calibrated.
const minRejectRateSamples = 10

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
// operator without a measurement is admitted.
func (r *Registry) RecordRTT(operator string, rttMs uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rtt[operator] = rttMs
}

// RecordOutcome records how a Worker answered a ticket at height: rejected is a signed reject
// (every ticket goes to a member that declared free slots). Timeouts are not outcomes. When the
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
	if len(kept) < minRejectRateSamples || float64(rejects)/float64(len(kept)) <= cfg.GPURejectRateThreshold {
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

// decisionLocked is the admission decision of operator's held handraise at height. A reject-rate
// suspension comes first; then the RTT threshold, whose leaf carries the measured RTT.
func (r *Registry) decisionLocked(operator string, height uint64) (bool, taskv1.AdmitRejectReasonV1, uint64) {
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
