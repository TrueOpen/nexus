package ops

import (
	"strings"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// PublicStatsPath is the public statistics route on the ingress port.
const PublicStatsPath = "/v1/dispatch/stats"

// Handraises is what the public statistics read from the standing handraise registry.
type Handraises interface {
	RTTThreshold() (uint64, time.Time)
	RTTThresholdHistory() ([]handraise.RTTThresholdChange, error)
	Suspensions(height uint64) map[string]uint64
	LatestRoot() (*handraise.IssuedRoot, bool)
}

// PublicSources are what the public statistics are built from.
type PublicSources struct {
	Builder    string
	Dispatch   config.DispatchConfig
	Metrics    *opsmetrics.Registry
	Handraises Handraises
	// Height is the local chain height the reject-rate suspensions are judged at.
	Height func() uint64
}

// PublicStats are this Builder's public dispatch statistics: the RTT admission threshold it
// applies, its timeout and reject rate rules, and per Worker the tickets offered and how they
// ended, the reject-rate suspension and the latest root's admission. They hold operator addresses,
// which are public chain identities, and counts; no session, task, user, payload or secret.
type PublicStats struct {
	Builder     string    `json:"builder_address"`
	GeneratedAt time.Time `json:"generated_at"`
	// Since is when the counts started (the process start).
	Since time.Time `json:"since"`
	// RTTAdmit is builder_rtt_admit_ms in effect, since when, and every value used before.
	RTTAdmit RTTAdmit `json:"builder_rtt_admit_ms"`
	// TimeoutRate is TIMEOUT over tickets the Workers received, against
	// builder_timeout_rate_threshold.
	TimeoutRate          float64 `json:"timeout_rate"`
	TimeoutRateThreshold float64 `json:"builder_timeout_rate_threshold"`
	TimeoutRateExceeded  bool    `json:"timeout_rate_exceeded"`
	// RejectRate is the reject-rate rule: above Threshold, over at least MinSamples tickets in the
	// last SuspensionBlocks blocks, a Worker's handraise is not admitted (REJECT_RATE) for
	// SuspensionBlocks blocks.
	RejectRate RejectRateRule `json:"gpu_reject_rate"`
	// Skips counts skipped roster members by reason.
	Skips   map[string]uint64       `json:"skips"`
	Workers map[string]PublicWorker `json:"workers"`
	// Root is the admission of the latest handraise root, nil before the first.
	Root *PublicRoot `json:"latest_handraise_root,omitempty"`
}

// RTTAdmit is the public RTT admission threshold.
type RTTAdmit struct {
	ThresholdMs uint64           `json:"threshold_ms"`
	Since       time.Time        `json:"since"`
	History     []RTTAdmitChange `json:"history,omitempty"`
}

// RTTAdmitChange is one threshold value and when it took effect.
type RTTAdmitChange struct {
	ThresholdMs uint64    `json:"threshold_ms"`
	Since       time.Time `json:"since"`
}

// RejectRateRule is the reject-rate admission rule.
type RejectRateRule struct {
	Threshold        float64 `json:"threshold"`
	SuspensionBlocks uint64  `json:"suspension_blocks"`
	MinSamples       uint64  `json:"min_samples"`
}

// PublicWorker is one Worker's tickets from this Builder. Received is the denominator of both
// rates.
type PublicWorker struct {
	opsmetrics.WorkerStats
	RejectRate  float64 `json:"reject_rate"`
	TimeoutRate float64 `json:"timeout_rate"`
	// SuspendedUntil is the first height its handraise is admitted again after a reject-rate
	// suspension; 0 when not suspended.
	SuspendedUntil uint64 `json:"reject_rate_suspended_until,omitempty"`
	// Admitted and AdmitRejectReason are its leaf in the latest root; nil when it has none.
	Admitted          *bool  `json:"admitted,omitempty"`
	AdmitRejectReason string `json:"admit_reject_reason,omitempty"`
}

// PublicRoot is the admission of the latest handraise root.
type PublicRoot struct {
	RootHeight  uint64 `json:"root_height"`
	RootVersion uint64 `json:"root_version"`
	Leaves      int    `json:"leaves"`
	// NotAdmitted counts the leaves not admitted by reason.
	NotAdmitted map[string]int `json:"not_admitted"`
}

// BuildPublicStats builds the public statistics now.
func BuildPublicStats(src PublicSources, now time.Time) PublicStats {
	snap := src.Metrics.Snapshot()
	s := PublicStats{
		Builder: src.Builder, GeneratedAt: now, Since: snap.Since,
		TimeoutRateThreshold: src.Dispatch.BuilderTimeoutRateThreshold,
		RejectRate: RejectRateRule{
			Threshold: src.Dispatch.GPURejectRateThreshold, SuspensionBlocks: src.Dispatch.GPURejectRateSuspensionBlocks,
			MinSamples: src.Dispatch.GPURejectRateMinSamples,
		},
		Skips: snap.Counters[opsmetrics.CounterSkips], Workers: map[string]PublicWorker{},
	}
	if s.Skips == nil {
		s.Skips = map[string]uint64{}
	}
	var received, timeouts uint64
	for operator, w := range snap.Workers {
		s.Workers[operator] = PublicWorker{WorkerStats: w, RejectRate: w.RejectRate(), TimeoutRate: w.TimeoutRate()}
		received += w.Received
		timeouts += w.Timeouts
	}
	if received > 0 {
		s.TimeoutRate = float64(timeouts) / float64(received)
	}
	s.TimeoutRateExceeded = s.TimeoutRateThreshold > 0 && s.TimeoutRate > s.TimeoutRateThreshold
	if src.Handraises == nil {
		return s
	}
	s.RTTAdmit.ThresholdMs, s.RTTAdmit.Since = src.Handraises.RTTThreshold()
	if history, err := src.Handraises.RTTThresholdHistory(); err == nil {
		for _, c := range history {
			s.RTTAdmit.History = append(s.RTTAdmit.History, RTTAdmitChange{ThresholdMs: c.ThresholdMs, Since: c.Since})
		}
	}
	var height uint64
	if src.Height != nil {
		height = src.Height()
	}
	for operator, until := range src.Handraises.Suspensions(height) {
		w := s.Workers[operator]
		w.SuspendedUntil = until
		s.Workers[operator] = w
	}
	if root, ok := src.Handraises.LatestRoot(); ok {
		r := &PublicRoot{
			RootHeight: root.Root.GetRootHeight(), RootVersion: root.Root.GetRootVersion(), Leaves: len(root.Leaves),
			NotAdmitted: map[string]int{},
		}
		for _, leaf := range root.Leaves {
			operator := leaf.GetHandraise().GetMember().GetOperatorAddress()
			admitted := leaf.GetAdmitted()
			reason := ""
			if !admitted {
				reason = strings.TrimPrefix(leaf.GetAdmitRejectReason().String(), "ADMIT_REJECT_REASON_V1_")
				r.NotAdmitted[reason]++
			}
			if operator == "" {
				continue
			}
			w := s.Workers[operator]
			w.Admitted, w.AdmitRejectReason = &admitted, reason
			s.Workers[operator] = w
		}
		s.Root = r
	}
	return s
}
