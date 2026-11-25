package config

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// DispatchConfig holds the off-chain parameters of direct dispatch: standing handraises, handraise
// roots, accept timeouts and the local admission rules. They are not chain parameters, but every
// Builder of a network must use the same handraise timing and accept timeout tiers, because Cortex
// nodes keep one handraise schedule for all Builders they stream to. The handraise timing defaults
// match the shipped Cortex configuration; all defaults are placeholders until the network
// calibrates them.
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
	// takes the last tier, extended by the excess round trip up to BuilderRTTAdmitMs when that
	// threshold admits RTTs above it. The wait covers the Worker's evaluation of the offer, not only the
	// round trip: the defaults leave it well over a second, since a Worker that answers after
	// the deadline counts as a skip and an order whose every member timed out cannot be
	// dispatched again before the next epoch.
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
	// RejectRateExemptOutputTokens and RejectRateExemptInputBytes bound what every Worker of the
	// network is expected to serve. A signed reject of an order whose max_output_tokens or
	// input_size_bytes is above the bound is left out of the Worker's reject rate (numerator and
	// denominator) and counted on its own in the public statistics: a Worker whose model service
	// runs with a shorter context than the registered model allows must refuse such an order, and
	// whoever sends them must not be able to get the Worker suspended. A Worker gains only the
	// freedom to pick among orders above the bound; below it every reject counts as before. 0
	// leaves the corresponding rule off. Every Builder of a network should run the same values.
	RejectRateExemptOutputTokens uint64 `yaml:"reject_rate_exempt_output_tokens"`
	RejectRateExemptInputBytes   uint64 `yaml:"reject_rate_exempt_input_bytes"`
	// RejectRateExemptByProfile sets the two bounds for one Profile version, keyed
	// "<model_id as 64 lowercase hex>@<profile_version>"; a version listed here does not use the
	// two values above, even where its own value is 0 (no exemption). One pair for every model is
	// either too high for a version served with a short context (orders between a Worker's limit
	// and the bound still count against it) or too low for the others (any Worker may refuse
	// every order above it at no cost), so the bound belongs to the Profile version: set it to
	// what the Workers of that version are required to serve, and have them configure limits
	// that are not below it. The bounds in effect are published in the public statistics.
	RejectRateExemptByProfile map[string]RejectRateExemptBounds `yaml:"reject_rate_exempt_by_profile"`
	// WorkerQuotaRefreshMs is how long this Builder uses a Worker's order quota and pause state
	// read from the chain (hub.v1.Query/WorkerQuota) before reading it again. Before a ticket goes
	// out the Worker must not be paused for dispatch and its remaining quota of the settlement
	// period, less the value of this Builder's own orders still on the way to the chain, must
	// cover the order; otherwise the member's ticket times out unsent. The chain enforces the same
	// at record time, so the check only keeps orders from being accepted that could not be
	// recorded. 0 turns the check off. A chain that does not serve the query, or that has the
	// quota switched off, changes nothing either way.
	WorkerQuotaRefreshMs uint64 `yaml:"worker_quota_refresh_ms"`
	// HandraiseIssuedHeightToleranceBlocks is how far above this Builder's chain height a standing
	// handraise's issued_height may be: a Cortex that follows the chain more closely is not
	// refused for this Builder's lag.
	HandraiseIssuedHeightToleranceBlocks uint64 `yaml:"handraise_issued_height_tolerance_blocks"`
	// BuilderTimeoutRateThreshold is the share (0..1) of TIMEOUT skips among tickets above which the
	// public statistics flag this Builder; it is statistics only.
	BuilderTimeoutRateThreshold float64 `yaml:"builder_timeout_rate_threshold"`
	// RecordGasBase, RecordGasPerEntry and RecordGasPerByte give a MsgRecordDispatch transaction
	// its gas limit: RecordGasBase + RecordGasPerEntry for each entry it carries +
	// RecordGasPerByte for each encoded byte of the Msg (the chain charges most of a record per
	// byte it stores). 0 per byte leaves the size out.
	RecordGasBase     uint64 `yaml:"record_gas_base"`
	RecordGasPerEntry uint64 `yaml:"record_gas_per_entry"`
	RecordGasPerByte  uint64 `yaml:"record_gas_per_byte"`
	// RecordGasMax caps the gas limit of a record transaction, also once out-of-gas refusals
	// raised it: it bounds what one record transaction can cost with chain.gas_price. A batch
	// still out of gas at the cap is split. 0 is DefaultRecordGasMax (RecordGasCap).
	RecordGasMax uint64 `yaml:"record_gas_max"`
	// AnswerGasBase and AnswerGasPerByte give a compensation rebuttal or dispatch challenge
	// response its gas limit: AnswerGasBase + AnswerGasPerByte for each encoded byte of the Msg
	// (it carries a whole record or roster). An answer that runs out of gas goes again with more.
	AnswerGasBase    uint64 `yaml:"answer_gas_base"`
	AnswerGasPerByte uint64 `yaml:"answer_gas_per_byte"`
	// FailedOrderRetention is how long an order this Builder acknowledged and then dropped before
	// it reached the chain (NO_CAPACITY, RECORD_REJECTED, ASSIGN_TIMEOUT, an ended takeover) keeps
	// its owner and event journal readable through GetTaskEvents and GetTaskStatus. It is a local
	// record for the user, measured in wall time, and must be positive.
	FailedOrderRetention time.Duration `yaml:"failed_order_retention"`
}

// RTTTierConfig is one accept timeout tier: candidates whose RTT is at most MaxRTTMs wait
// AcceptTimeoutMs.
type RTTTierConfig struct {
	MaxRTTMs        uint64 `yaml:"max_rtt_ms"`
	AcceptTimeoutMs uint64 `yaml:"accept_timeout_ms"`
}

func defaultDispatch() DispatchConfig {
	return DispatchConfig{
		HandraiseHeartbeatMs:         10000,
		HandraiseTTLMs:               30000,
		HandraiseMinChangeIntervalMs: 500,
		HandraiseRootIntervalMs:      500,
		AcceptTimeoutMsByRTTTier: []RTTTierConfig{
			{MaxRTTMs: 50, AcceptTimeoutMs: 1500},
			{MaxRTTMs: 150, AcceptTimeoutMs: 2000},
			{MaxRTTMs: 300, AcceptTimeoutMs: 2500},
		},
		BuilderRTTAdmitMs:             300,
		GPURejectRateThreshold:        0.5,
		GPURejectRateSuspensionBlocks: 720,
		GPURejectRateMinSamples:       10,
		BuilderTimeoutRateThreshold:   0.2,
		WorkerQuotaRefreshMs:          2000,

		HandraiseIssuedHeightToleranceBlocks: 3,
		RecordGasBase:                        200_000,
		RecordGasPerEntry:                    150_000,
		RecordGasPerByte:                     150,
		RecordGasMax:                         DefaultRecordGasMax,
		AnswerGasBase:                        300_000,
		AnswerGasPerByte:                     30,
		FailedOrderRetention:                 DefaultFailedOrderRetention,
	}
}

// DefaultFailedOrderRetention is the default dispatch.failed_order_retention.
const DefaultFailedOrderRetention = 24 * time.Hour

// maxFailedOrderRetention bounds dispatch.failed_order_retention.
const maxFailedOrderRetention = 30 * 24 * time.Hour

// DefaultRecordGasMax is the record transaction gas cap when dispatch.record_gas_max is unset or 0.
const DefaultRecordGasMax = 20_000_000

// RecordGasCap returns the record transaction gas cap: RecordGasMax, or DefaultRecordGasMax when
// it is 0.
func (c DispatchConfig) RecordGasCap() uint64 {
	if c.RecordGasMax == 0 {
		return DefaultRecordGasMax
	}
	return c.RecordGasMax
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
	maxRecordGasPerByte         = 100_000
)

// RejectRateExemptBounds are the reject-rate exemption bounds of one Profile version; 0 leaves
// the corresponding rule off.
type RejectRateExemptBounds struct {
	OutputTokens uint64 `yaml:"output_tokens" json:"output_tokens"`
	InputBytes   uint64 `yaml:"input_bytes" json:"input_bytes"`
	// SequenceTokens bounds the longest sequence an order allows, the sum a Worker of a Profile
	// with the anchor commitment refuses on: ceil(input_size_bytes / InputBytesPerToken) +
	// max_output_tokens. InputBytesPerToken 0 is 1, the Worker's default. Without it an order
	// under both per-field bounds whose sum is above a Worker's sequence limit still counts.
	SequenceTokens     uint64 `yaml:"sequence_tokens" json:"sequence_tokens"`
	InputBytesPerToken uint64 `yaml:"input_bytes_per_token" json:"input_bytes_per_token"`
}

// Exempts reports whether an order with these terms is above any bound that is set.
func (b RejectRateExemptBounds) Exempts(maxOutputTokens, inputSizeBytes uint64) bool {
	if b.OutputTokens != 0 && maxOutputTokens > b.OutputTokens {
		return true
	}
	if b.InputBytes != 0 && inputSizeBytes > b.InputBytes {
		return true
	}
	if b.SequenceTokens == 0 {
		return false
	}
	per := b.InputBytesPerToken
	if per == 0 {
		per = 1
	}
	prompt := inputSizeBytes / per
	if inputSizeBytes%per != 0 {
		prompt++
	}
	total := prompt + maxOutputTokens
	return total < prompt || total > b.SequenceTokens
}

// RejectRateExemptKey is the RejectRateExemptByProfile key of a Profile version.
func RejectRateExemptKey(modelID []byte, profileVersion uint32) string {
	return fmt.Sprintf("%x@%d", modelID, profileVersion)
}

// RejectRateExempt returns the exemption bounds for orders of a Profile version: its own entry
// when it has one, otherwise the two values for every version.
func (c DispatchConfig) RejectRateExempt(modelID []byte, profileVersion uint32) RejectRateExemptBounds {
	if b, ok := c.RejectRateExemptByProfile[RejectRateExemptKey(modelID, profileVersion)]; ok {
		return b
	}
	return RejectRateExemptBounds{OutputTokens: c.RejectRateExemptOutputTokens, InputBytes: c.RejectRateExemptInputBytes}
}

func validRejectRateExemptKey(key string) bool {
	model, version, ok := strings.Cut(key, "@")
	if !ok || len(model) != 64 || strings.ToLower(model) != model {
		return false
	}
	if _, err := hex.DecodeString(model); err != nil {
		return false
	}
	v, err := strconv.ParseUint(version, 10, 32)
	return err == nil && v != 0 && strconv.FormatUint(v, 10) == version
}

func (c DispatchConfig) Validate() error {
	for key := range c.RejectRateExemptByProfile {
		if !validRejectRateExemptKey(key) {
			return fmt.Errorf("dispatch reject_rate_exempt_by_profile key %q must be <model_id as 64 lowercase hex>@<profile_version>", key)
		}
	}
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
	case c.RecordGasPerByte > maxRecordGasPerByte:
		return fmt.Errorf("dispatch record_gas_per_byte must not exceed %d", maxRecordGasPerByte)
	case c.RecordGasMax != 0 && (c.RecordGasMax < c.RecordGasBase+c.RecordGasPerEntry || c.RecordGasMax > maxRecordGas):
		return fmt.Errorf("dispatch record_gas_max must be between record_gas_base + record_gas_per_entry (%d) and %d",
			c.RecordGasBase+c.RecordGasPerEntry, maxRecordGas)
	case c.AnswerGasBase == 0 || c.AnswerGasBase > maxRecordGas || c.AnswerGasPerByte == 0 || c.AnswerGasPerByte > maxRecordGas:
		return fmt.Errorf("dispatch answer_gas_base and answer_gas_per_byte must be between 1 and %d", maxRecordGas)
	case c.FailedOrderRetention <= 0 || c.FailedOrderRetention > maxFailedOrderRetention:
		return fmt.Errorf("dispatch failed_order_retention must be positive and not exceed %s", maxFailedOrderRetention)
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
//
// An RTT above the last tier takes the last tier. When builder_rtt_admit_ms admits RTTs above that
// tier's max_rtt_ms, its timeout grows by the round trip the tier did not count, up to the
// admission threshold: the tiers budget the Worker's evaluation of the offer on top of the round
// trip, and an operator who raises the threshold alone would otherwise admit Workers whose longer
// round trip is taken out of that budget, so they time out on offers they would have accepted.
// With admission off (0) the last tier applies unchanged; add a tier for the RTTs to be served.
func (c DispatchConfig) AcceptTimeoutTier(rttMs uint64) (uint32, uint64) {
	for i, tier := range c.AcceptTimeoutMsByRTTTier {
		if rttMs <= tier.MaxRTTMs {
			return uint32(i + 1), tier.AcceptTimeoutMs
		}
	}
	n := len(c.AcceptTimeoutMsByRTTTier)
	if n == 0 {
		return 0, 0
	}
	last := c.AcceptTimeoutMsByRTTTier[n-1]
	timeout := last.AcceptTimeoutMs
	if c.BuilderRTTAdmitMs > last.MaxRTTMs {
		timeout += min(rttMs, c.BuilderRTTAdmitMs) - last.MaxRTTMs
	}
	return uint32(n), min(timeout, maxAcceptTimeoutMsByRTTTier)
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
	c.RejectRateExemptOutputTokens = envUint64("NEXUS_DISPATCH_REJECT_RATE_EXEMPT_OUTPUT_TOKENS", c.RejectRateExemptOutputTokens)
	c.RejectRateExemptInputBytes = envUint64("NEXUS_DISPATCH_REJECT_RATE_EXEMPT_INPUT_BYTES", c.RejectRateExemptInputBytes)
	c.BuilderTimeoutRateThreshold = envFloat64("NEXUS_DISPATCH_BUILDER_TIMEOUT_RATE_THRESHOLD", c.BuilderTimeoutRateThreshold)
	c.WorkerQuotaRefreshMs = envUint64("NEXUS_DISPATCH_WORKER_QUOTA_REFRESH_MS", c.WorkerQuotaRefreshMs)
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
