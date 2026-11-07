package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDispatchDefaultsAreValid(t *testing.T) {
	got := defaults().Dispatch
	if got.HandraiseHeartbeatMs != 10000 || got.HandraiseTTLMs != 30000 || got.HandraiseMinChangeIntervalMs != 500 ||
		got.HandraiseRootIntervalMs != 500 || got.BuilderRTTAdmitMs != 300 || got.GPURejectRateThreshold != 0.5 ||
		got.GPURejectRateSuspensionBlocks != 720 || got.BuilderTimeoutRateThreshold != 0.2 ||
		len(got.AcceptTimeoutMsByRTTTier) != 3 || got.GPURejectRateMinSamples != 10 || got.HandraiseIssuedHeightToleranceBlocks != 3 ||
		got.RecordGasBase != 200_000 || got.RecordGasPerEntry != 150_000 || got.RecordGasPerByte != 150 || got.AnswerGasBase != 300_000 || got.AnswerGasPerByte != 30 {
		t.Fatalf("dispatch defaults = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("default dispatch config invalid: %v", err)
	}
}

func TestDispatchValidateRejectsInvalidCombinations(t *testing.T) {
	cases := map[string]func(*DispatchConfig){
		"zero heartbeat":             func(c *DispatchConfig) { c.HandraiseHeartbeatMs = 0 },
		"ttl not above heartbeat":    func(c *DispatchConfig) { c.HandraiseTTLMs = c.HandraiseHeartbeatMs },
		"min change above heartbeat": func(c *DispatchConfig) { c.HandraiseMinChangeIntervalMs = c.HandraiseHeartbeatMs + 1 },
		"zero root interval":         func(c *DispatchConfig) { c.HandraiseRootIntervalMs = 0 },
		"reject rate above one":      func(c *DispatchConfig) { c.GPURejectRateThreshold = 1.5 },
		"negative reject rate":       func(c *DispatchConfig) { c.GPURejectRateThreshold = -0.1 },
		"timeout rate above one":     func(c *DispatchConfig) { c.BuilderTimeoutRateThreshold = 2 },
		"no tiers":                   func(c *DispatchConfig) { c.AcceptTimeoutMsByRTTTier = nil },
		"suspension window too long": func(c *DispatchConfig) { c.GPURejectRateSuspensionBlocks = maxDispatchWindowBlocks + 1 },
		"zero min samples":           func(c *DispatchConfig) { c.GPURejectRateMinSamples = 0 },
		"too many min samples":       func(c *DispatchConfig) { c.GPURejectRateMinSamples = maxRejectRateMinSamples + 1 },
		"tolerance too large":        func(c *DispatchConfig) { c.HandraiseIssuedHeightToleranceBlocks = maxIssuedHeightTolerance + 1 },
		"ttl in microseconds":        func(c *DispatchConfig) { c.HandraiseTTLMs = maxDispatchIntervalMs + 1 },
		"root interval too long":     func(c *DispatchConfig) { c.HandraiseRootIntervalMs = maxDispatchIntervalMs + 1 },
		"rtt threshold too large":    func(c *DispatchConfig) { c.BuilderRTTAdmitMs = maxBuilderRTTAdmitMs + 1 },
		"accept timeout too long": func(c *DispatchConfig) {
			c.AcceptTimeoutMsByRTTTier[2].AcceptTimeoutMs = maxAcceptTimeoutMsByRTTTier + 1
		},
		"zero accept timeout":       func(c *DispatchConfig) { c.AcceptTimeoutMsByRTTTier[0].AcceptTimeoutMs = 0 },
		"zero record gas base":      func(c *DispatchConfig) { c.RecordGasBase = 0 },
		"zero record gas per entry": func(c *DispatchConfig) { c.RecordGasPerEntry = 0 },
		"record gas too large":      func(c *DispatchConfig) { c.RecordGasPerEntry = maxRecordGas + 1 },
		"record gas per byte large": func(c *DispatchConfig) { c.RecordGasPerByte = maxRecordGasPerByte + 1 },
		"zero answer gas base":      func(c *DispatchConfig) { c.AnswerGasBase = 0 },
		"zero answer gas per byte":  func(c *DispatchConfig) { c.AnswerGasPerByte = 0 },
		"answer gas too large":      func(c *DispatchConfig) { c.AnswerGasBase = maxRecordGas + 1 },
		"tier rtt not increasing": func(c *DispatchConfig) {
			c.AcceptTimeoutMsByRTTTier[1].MaxRTTMs = c.AcceptTimeoutMsByRTTTier[0].MaxRTTMs
		},
		"tier timeout not increasing": func(c *DispatchConfig) {
			c.AcceptTimeoutMsByRTTTier[1].AcceptTimeoutMs = c.AcceptTimeoutMsByRTTTier[0].AcceptTimeoutMs
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := defaults().Dispatch
			cfg.AcceptTimeoutMsByRTTTier = append([]RTTTierConfig(nil), cfg.AcceptTimeoutMsByRTTTier...)
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("%s was accepted: %+v", name, cfg)
			}
		})
	}
}

func TestDispatchAcceptTimeoutByTier(t *testing.T) {
	cfg := DispatchConfig{AcceptTimeoutMsByRTTTier: []RTTTierConfig{
		{MaxRTTMs: 50, AcceptTimeoutMs: 300}, {MaxRTTMs: 150, AcceptTimeoutMs: 500},
	}}
	for rtt, want := range map[uint64]uint64{0: 300, 50: 300, 51: 500, 150: 500, 151: 500, 9000: 500} {
		if got := cfg.AcceptTimeoutMs(rtt); got != want {
			t.Fatalf("AcceptTimeoutMs(%d) = %d, want %d", rtt, got, want)
		}
	}
	// Tiers are numbered from 1 in configuration order: 0 is the record's "no timeout".
	for rtt, want := range map[uint64]uint32{0: 1, 50: 1, 51: 2, 9000: 2} {
		if tier, ms := cfg.AcceptTimeoutTier(rtt); tier != want || ms != cfg.AcceptTimeoutMs(rtt) {
			t.Fatalf("AcceptTimeoutTier(%d) = %d, %d; want tier %d", rtt, tier, ms, want)
		}
	}
	if tier, ms := (DispatchConfig{}).AcceptTimeoutTier(10); tier != 0 || ms != 0 {
		t.Fatalf("no tiers: AcceptTimeoutTier = %d, %d", tier, ms)
	}
}

func TestDispatchEnvironment(t *testing.T) {
	t.Setenv("NEXUS_DISPATCH_HANDRAISE_HEARTBEAT_MS", "1000")
	t.Setenv("NEXUS_DISPATCH_HANDRAISE_TTL_MS", "4000")
	t.Setenv("NEXUS_DISPATCH_HANDRAISE_MIN_CHANGE_INTERVAL_MS", "100")
	t.Setenv("NEXUS_DISPATCH_HANDRAISE_ROOT_INTERVAL_MS", "250")
	t.Setenv("NEXUS_DISPATCH_BUILDER_RTT_ADMIT_MS", "120")
	t.Setenv("NEXUS_DISPATCH_GPU_REJECT_RATE_THRESHOLD", "0.25")
	t.Setenv("NEXUS_DISPATCH_GPU_REJECT_RATE_SUSPENSION_BLOCKS", "60")
	t.Setenv("NEXUS_DISPATCH_BUILDER_TIMEOUT_RATE_THRESHOLD", "0.1")
	t.Setenv("NEXUS_DISPATCH_GPU_REJECT_RATE_MIN_SAMPLES", "20")
	t.Setenv("NEXUS_DISPATCH_HANDRAISE_ISSUED_HEIGHT_TOLERANCE_BLOCKS", "5")
	got := Load().Dispatch
	if got.HandraiseHeartbeatMs != 1000 || got.HandraiseTTLMs != 4000 || got.HandraiseMinChangeIntervalMs != 100 ||
		got.HandraiseRootIntervalMs != 250 || got.BuilderRTTAdmitMs != 120 || got.GPURejectRateThreshold != 0.25 ||
		got.GPURejectRateSuspensionBlocks != 60 || got.BuilderTimeoutRateThreshold != 0.1 ||
		got.GPURejectRateMinSamples != 20 || got.HandraiseIssuedHeightToleranceBlocks != 5 {
		t.Fatalf("dispatch environment = %+v", got)
	}
}

func TestLoadFileDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	body := strings.Join([]string{
		"dispatch:",
		"  handraise_ttl_ms: 39000",
		"  builder_rtt_admit_ms: 0",
		"  accept_timeout_ms_by_rtt_tier:",
		"    - max_rtt_ms: 80",
		"      accept_timeout_ms: 400",
		"    - max_rtt_ms: 200",
		"      accept_timeout_ms: 800",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Dispatch
	if got.HandraiseTTLMs != 39000 || got.BuilderRTTAdmitMs != 0 || got.HandraiseHeartbeatMs != 10000 ||
		len(got.AcceptTimeoutMsByRTTTier) != 2 || got.AcceptTimeoutMsByRTTTier[1] != (RTTTierConfig{MaxRTTMs: 200, AcceptTimeoutMs: 800}) {
		t.Fatalf("dispatch yaml = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("dispatch yaml invalid: %v", err)
	}
}

func TestExampleDispatchSettings(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "nexus.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := defaults().Dispatch
	got := cfg.Dispatch
	if got.HandraiseHeartbeatMs != want.HandraiseHeartbeatMs || got.HandraiseTTLMs != want.HandraiseTTLMs ||
		got.HandraiseMinChangeIntervalMs != want.HandraiseMinChangeIntervalMs || got.HandraiseRootIntervalMs != want.HandraiseRootIntervalMs ||
		got.BuilderRTTAdmitMs != want.BuilderRTTAdmitMs || got.GPURejectRateThreshold != want.GPURejectRateThreshold ||
		got.GPURejectRateSuspensionBlocks != want.GPURejectRateSuspensionBlocks || got.BuilderTimeoutRateThreshold != want.BuilderTimeoutRateThreshold ||
		got.GPURejectRateMinSamples != want.GPURejectRateMinSamples ||
		got.HandraiseIssuedHeightToleranceBlocks != want.HandraiseIssuedHeightToleranceBlocks ||
		len(got.AcceptTimeoutMsByRTTTier) != len(want.AcceptTimeoutMsByRTTTier) {
		t.Fatalf("example dispatch = %+v, want the defaults %+v", got, want)
	}
	for i := range want.AcceptTimeoutMsByRTTTier {
		if got.AcceptTimeoutMsByRTTTier[i] != want.AcceptTimeoutMsByRTTTier[i] {
			t.Fatalf("example tier %d = %+v, want %+v", i, got.AcceptTimeoutMsByRTTTier[i], want.AcceptTimeoutMsByRTTTier[i])
		}
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("example dispatch invalid: %v", err)
	}
}
