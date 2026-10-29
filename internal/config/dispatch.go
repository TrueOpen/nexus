package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
)

// DispatchConfig holds the off-chain parameters of direct dispatch: standing handraises, handraise
// roots, accept timeouts and the local admission rules. They are not chain parameters, but every
// Builder of a network must use the same handraise timing and accept timeout tiers, because Cortex
// nodes keep one handraise schedule for all Builders they stream to. The defaults are placeholders
// until the network calibrates them.
type DispatchConfig struct {
	// HandraiseHeartbeatMs is how often a Cortex node re-signs an unchanged standing handraise.
	HandraiseHeartbeatMs uint64 `yaml:"handraise_heartbeat_ms"`
	// HandraiseTTLMs is how long a standing handraise stays current without a re-sign; it must
	// exceed the heartbeat plus network margin.
	HandraiseTTLMs uint64 `yaml:"handraise_ttl_ms"`
	// HandraiseMinChangeIntervalMs is the minimum spacing of re-signs caused by a state change
	// (free slots, profiles); not above the heartbeat.
	HandraiseMinChangeIntervalMs uint64 `yaml:"handraise_min_change_interval_ms"`
	// HandraiseRootIntervalMs is how often this Builder signs a new handraise root.
	HandraiseRootIntervalMs uint64 `yaml:"handraise_root_interval_ms"`
	// AcceptTimeoutMsByRTTTier is how long a dispatched ticket waits for an accept or reject, by
	// the candidate's measured RTT. Tiers are ordered by MaxRTTMs; an RTT above the last tier
	// takes the last tier.
	AcceptTimeoutMsByRTTTier []RTTTierConfig `yaml:"accept_timeout_ms_by_rtt_tier"`
	// BuilderRTTAdmitMs is this Builder's public RTT admission threshold: a standing handraise whose
	// measured RTT exceeds it is not admitted and its root leaf carries the RTT. 0 admits every RTT.
	BuilderRTTAdmitMs uint64 `yaml:"builder_rtt_admit_ms"`
	// GPURejectRateThreshold is the share (0..1) of signed rejects among tickets a Worker received
	// above which this Builder stops admitting its handraise; 0 disables the rule.
	GPURejectRateThreshold float64 `yaml:"gpu_reject_rate_threshold"`
	// GPURejectRateSuspensionBlocks is how many blocks such a Worker stays not admitted; it is also
	// the window the reject rate is measured over. 0 disables the rule.
	GPURejectRateSuspensionBlocks uint64 `yaml:"gpu_reject_rate_suspension_blocks"`
	// GPURejectRateMinSamples is the fewest tickets inside the measuring window before a reject
	// rate can suspend a Worker, so one early reject is not a 100% rate.
	GPURejectRateMinSamples uint64 `yaml:"gpu_reject_rate_min_samples"`
	// HandraiseIssuedHeightToleranceBlocks is how far above this Builder's chain height a standing
	// handraise's issued_height may be: a Cortex that follows the chain more closely is not
	// refused for this Builder's lag.
	HandraiseIssuedHeightToleranceBlocks uint64 `yaml:"handraise_issued_height_tolerance_blocks"`
	// BuilderTimeoutRateThreshold is the share (0..1) of TIMEOUT skips among tickets above which the
	// public statistics flag this Builder; it is statistics only.
	BuilderTimeoutRateThreshold float64 `yaml:"builder_timeout_rate_threshold"`
	// RecordGasBase and RecordGasPerEntry give a MsgRecordDispatch transaction its gas limit:
	// RecordGasBase + RecordGasPerEntry for each entry it carries.
	RecordGasBase     uint64 `yaml:"record_gas_base"`
	RecordGasPerEntry uint64 `yaml:"record_gas_per_entry"`
}

// RTTTierConfig is one accept timeout tier: candidates whose RTT is at most MaxRTTMs wait
// AcceptTimeoutMs.
type RTTTierConfig struct {
	MaxRTTMs        uint64 `yaml:"max_rtt_ms"`
	AcceptTimeoutMs uint64 `yaml:"accept_timeout_ms"`
}

func defaultDispatch() DispatchConfig {
	return DispatchConfig{
		HandraiseHeartbeatMs:         2000,
		HandraiseTTLMs:               6000,
		HandraiseMinChangeIntervalMs: 200,
		HandraiseRootIntervalMs:      500,
		AcceptTimeoutMsByRTTTier: []RTTTierConfig{
			{MaxRTTMs: 50, AcceptTimeoutMs: 300},
			{MaxRTTMs: 150, AcceptTimeoutMs: 500},
			{MaxRTTMs: 300, AcceptTimeoutMs: 800},
		},
		BuilderRTTAdmitMs:             300,
		GPURejectRateThreshold:        0.5,
		GPURejectRateSuspensionBlocks: 720,
		GPURejectRateMinSamples:       10,
		BuilderTimeoutRateThreshold:   0.2,

		HandraiseIssuedHeightToleranceBlocks: 3,
		RecordGasBase:                        200_000,
		RecordGasPerEntry:                    300_000,
	}
}

// Upper bounds of the dispatch windows: a value beyond them is a unit mistake (seconds for
// milliseconds, a height for a block count), not a deliberate choice.
const (
	maxDispatchIntervalMs       = 3_600_000 // one hour
	maxDispatchWindowBlocks     = 1_000_000
	maxIssuedHeightTolerance    = 100
	maxRejectRateMinSamples     = 100_000
	maxBuilderRTTAdmitMs        = 60_000
	maxAcceptTimeoutMsByRTTTier = 60_000
	maxRecordGas                = 100_000_000
)

func (c DispatchConfig) Validate() error {
	switch {
	case c.HandraiseHeartbeatMs == 0 || c.HandraiseRootIntervalMs == 0:
		return fmt.Errorf("dispatch handraise_heartbeat_ms and handraise_root_interval_ms must be positive")
	case c.HandraiseTTLMs <= c.HandraiseHeartbeatMs:
		return fmt.Errorf("dispatch handraise_ttl_ms must exceed handraise_heartbeat_ms")
	case c.HandraiseMinChangeIntervalMs > c.HandraiseHeartbeatMs:
		return fmt.Errorf("dispatch handraise_min_change_interval_ms must not exceed handraise_heartbeat_ms")
	case !isShare(c.GPURejectRateThreshold) || !isShare(c.BuilderTimeoutRateThreshold):
		return fmt.Errorf("dispatch gpu_reject_rate_threshold and builder_timeout_rate_threshold must be between 0 and 1")
	case len(c.AcceptTimeoutMsByRTTTier) == 0:
		return fmt.Errorf("dispatch accept_timeout_ms_by_rtt_tier must have at least one tier")
	case c.HandraiseHeartbeatMs > maxDispatchIntervalMs || c.HandraiseTTLMs > maxDispatchIntervalMs ||
		c.HandraiseRootIntervalMs > maxDispatchIntervalMs:
		return fmt.Errorf("dispatch handraise heartbeat, ttl and root interval must not exceed %d ms", maxDispatchIntervalMs)
	case c.BuilderRTTAdmitMs > maxBuilderRTTAdmitMs:
		return fmt.Errorf("dispatch builder_rtt_admit_ms must not exceed %d", maxBuilderRTTAdmitMs)
	case c.GPURejectRateSuspensionBlocks > maxDispatchWindowBlocks:
		return fmt.Errorf("dispatch gpu_reject_rate_suspension_blocks must not exceed %d", maxDispatchWindowBlocks)
	case c.GPURejectRateMinSamples == 0 || c.GPURejectRateMinSamples > maxRejectRateMinSamples:
		return fmt.Errorf("dispatch gpu_reject_rate_min_samples must be between 1 and %d", maxRejectRateMinSamples)
	case c.HandraiseIssuedHeightToleranceBlocks > maxIssuedHeightTolerance:
		return fmt.Errorf("dispatch handraise_issued_height_tolerance_blocks must not exceed %d", maxIssuedHeightTolerance)
	case c.RecordGasBase == 0 || c.RecordGasBase > maxRecordGas || c.RecordGasPerEntry == 0 || c.RecordGasPerEntry > maxRecordGas:
		return fmt.Errorf("dispatch record_gas_base and record_gas_per_entry must be between 1 and %d", maxRecordGas)
	}
	for i, tier := range c.AcceptTimeoutMsByRTTTier {
		if tier.AcceptTimeoutMs == 0 || tier.AcceptTimeoutMs > maxAcceptTimeoutMsByRTTTier {
			return fmt.Errorf("dispatch accept_timeout_ms_by_rtt_tier[%d] accept_timeout_ms must be between 1 and %d", i, maxAcceptTimeoutMsByRTTTier)
		}
		if i == 0 {
			continue
		}
		prev := c.AcceptTimeoutMsByRTTTier[i-1]
		if tier.MaxRTTMs <= prev.MaxRTTMs || tier.AcceptTimeoutMs <= prev.AcceptTimeoutMs {
			return fmt.Errorf("dispatch accept_timeout_ms_by_rtt_tier must increase in max_rtt_ms and accept_timeout_ms (tier %d)", i)
		}
	}
	return nil
}

// AcceptTimeoutMs returns the accept timeout of the first tier covering rttMs, or of the last tier
// when rttMs is above all of them. It returns 0 when no tier is configured.
func (c DispatchConfig) AcceptTimeoutMs(rttMs uint64) uint64 {
	_, ms := c.AcceptTimeoutTier(rttMs)
	return ms
}

// AcceptTimeoutTier returns the tier AcceptTimeoutMs takes for rttMs, numbered from 1 in
// configuration order (a dispatch record's timeout_tier_or_zero), and its accept timeout. Both are
// 0 when no tier is configured.
func (c DispatchConfig) AcceptTimeoutTier(rttMs uint64) (uint32, uint64) {
	for i, tier := range c.AcceptTimeoutMsByRTTTier {
		if rttMs <= tier.MaxRTTMs {
			return uint32(i + 1), tier.AcceptTimeoutMs
		}
	}
	if n := len(c.AcceptTimeoutMsByRTTTier); n > 0 {
		return uint32(n), c.AcceptTimeoutMsByRTTTier[n-1].AcceptTimeoutMs
	}
	return 0, 0
}

func isShare(v float64) bool { return !math.IsNaN(v) && v >= 0 && v <= 1 }

func applyDispatchEnv(c *DispatchConfig) {
	c.HandraiseHeartbeatMs = envUint64("NEXUS_DISPATCH_HANDRAISE_HEARTBEAT_MS", c.HandraiseHeartbeatMs)
	c.HandraiseTTLMs = envUint64("NEXUS_DISPATCH_HANDRAISE_TTL_MS", c.HandraiseTTLMs)
	c.HandraiseMinChangeIntervalMs = envUint64("NEXUS_DISPATCH_HANDRAISE_MIN_CHANGE_INTERVAL_MS", c.HandraiseMinChangeIntervalMs)
	c.HandraiseRootIntervalMs = envUint64("NEXUS_DISPATCH_HANDRAISE_ROOT_INTERVAL_MS", c.HandraiseRootIntervalMs)
	c.BuilderRTTAdmitMs = envUint64("NEXUS_DISPATCH_BUILDER_RTT_ADMIT_MS", c.BuilderRTTAdmitMs)
	c.GPURejectRateThreshold = envFloat64("NEXUS_DISPATCH_GPU_REJECT_RATE_THRESHOLD", c.GPURejectRateThreshold)
	c.GPURejectRateSuspensionBlocks = envUint64("NEXUS_DISPATCH_GPU_REJECT_RATE_SUSPENSION_BLOCKS", c.GPURejectRateSuspensionBlocks)
	c.GPURejectRateMinSamples = envUint64("NEXUS_DISPATCH_GPU_REJECT_RATE_MIN_SAMPLES", c.GPURejectRateMinSamples)
	c.BuilderTimeoutRateThreshold = envFloat64("NEXUS_DISPATCH_BUILDER_TIMEOUT_RATE_THRESHOLD", c.BuilderTimeoutRateThreshold)
	c.HandraiseIssuedHeightToleranceBlocks = envUint64("NEXUS_DISPATCH_HANDRAISE_ISSUED_HEIGHT_TOLERANCE_BLOCKS", c.HandraiseIssuedHeightToleranceBlocks)
}

func envFloat64(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
