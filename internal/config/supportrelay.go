package config

import (
	"fmt"
	"time"
)

// SupportRelayConfig configures IngressAPI.SubmitModelSupportConfirmation: Cortex nodes hand this
// Builder their service-key-signed model support confirmations, and the Builder account batches
// them into MsgBatchConfirmModelSupport transactions and pays their gas. It needs the Builder
// account signer; without one the RPC is Unimplemented.
type SupportRelayConfig struct {
	// Enabled serves the RPC (default true).
	Enabled bool `yaml:"enabled"`
	// FlushInterval bounds how long an accepted confirmation waits before it is batched; it must
	// leave time for inclusion well before a confirmation's expiry and its epoch's end.
	FlushInterval time.Duration `yaml:"flush_interval"`
	// FlushItems held confirmations start a batch at once.
	FlushItems int `yaml:"flush_items"`
	// MaxQueued bounds the confirmations held; one more is refused with RESOURCE_EXHAUSTED.
	MaxQueued int `yaml:"max_queued"`
	// InclusionMarginBlocks is how many blocks above the current height a confirmation must stay
	// includable (before its expiry and its epoch's end) to be accepted or sent.
	InclusionMarginBlocks uint64 `yaml:"inclusion_margin_blocks"`
	// GasBase + GasPerConfirmation × confirmations + GasPerModel × model ids is a batch's gas
	// limit; a batch that runs out of gas is split, a single confirmation retried with more.
	GasBase            uint64 `yaml:"gas_base"`
	GasPerConfirmation uint64 `yaml:"gas_per_confirmation"`
	GasPerModel        uint64 `yaml:"gas_per_model"`
}

func defaultSupportRelay() SupportRelayConfig {
	return SupportRelayConfig{
		Enabled:               true,
		FlushInterval:         5 * time.Second,
		FlushItems:            64,
		MaxQueued:             4096,
		InclusionMarginBlocks: 3,
		GasBase:               200_000,
		GasPerConfirmation:    100_000,
		GasPerModel:           50_000,
	}
}

// Upper bounds that catch unit mistakes.
const (
	maxSupportRelayFlushInterval = 10 * time.Minute
	maxSupportRelayQueued        = 1_000_000
	maxSupportRelayMarginBlocks  = 10_000
)

// Validate checks a configuration that serves the RPC.
func (c SupportRelayConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch {
	case c.FlushInterval <= 0 || c.FlushInterval > maxSupportRelayFlushInterval:
		return fmt.Errorf("support_relay.flush_interval must be between 0 and %s", maxSupportRelayFlushInterval)
	case c.FlushItems <= 0 || c.MaxQueued <= 0 || c.FlushItems > c.MaxQueued || c.MaxQueued > maxSupportRelayQueued:
		return fmt.Errorf("support_relay.flush_items and max_queued must be positive, flush_items at most max_queued, max_queued at most %d", maxSupportRelayQueued)
	case c.InclusionMarginBlocks == 0 || c.InclusionMarginBlocks > maxSupportRelayMarginBlocks:
		return fmt.Errorf("support_relay.inclusion_margin_blocks must be between 1 and %d", maxSupportRelayMarginBlocks)
	case c.GasBase == 0 || c.GasBase > maxRecordGas || c.GasPerConfirmation == 0 || c.GasPerConfirmation > maxRecordGas ||
		c.GasPerModel == 0 || c.GasPerModel > maxRecordGas:
		return fmt.Errorf("support_relay gas_base, gas_per_confirmation and gas_per_model must be between 1 and %d", maxRecordGas)
	}
	return nil
}

func applySupportRelayEnv(c *SupportRelayConfig) {
	c.Enabled = envBool("NEXUS_SUPPORT_RELAY_ENABLED", c.Enabled)
	c.FlushInterval = envDuration("NEXUS_SUPPORT_RELAY_FLUSH_INTERVAL", c.FlushInterval)
	c.FlushItems = envInt("NEXUS_SUPPORT_RELAY_FLUSH_ITEMS", c.FlushItems)
	c.MaxQueued = envInt("NEXUS_SUPPORT_RELAY_MAX_QUEUED", c.MaxQueued)
	c.InclusionMarginBlocks = envUint64("NEXUS_SUPPORT_RELAY_INCLUSION_MARGIN_BLOCKS", c.InclusionMarginBlocks)
}
