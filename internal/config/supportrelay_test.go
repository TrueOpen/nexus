package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupportRelayDefaultsAreValid(t *testing.T) {
	got := defaults().SupportRelay
	if !got.Enabled || got.FlushInterval != 5*time.Second || got.FlushItems != 64 || got.MaxQueued != 4096 ||
		got.InclusionMarginBlocks != 3 || got.GasBase != 200_000 || got.GasPerConfirmation != 100_000 || got.GasPerModel != 50_000 {
		t.Fatalf("support relay defaults = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSupportRelayValidate(t *testing.T) {
	for name, edit := range map[string]func(*SupportRelayConfig){
		"zero flush interval":     func(c *SupportRelayConfig) { c.FlushInterval = 0 },
		"flush interval too long": func(c *SupportRelayConfig) { c.FlushInterval = time.Hour },
		"zero flush items":        func(c *SupportRelayConfig) { c.FlushItems = 0 },
		"flush items above queue": func(c *SupportRelayConfig) { c.FlushItems = c.MaxQueued + 1 },
		"zero margin":             func(c *SupportRelayConfig) { c.InclusionMarginBlocks = 0 },
		"zero gas per model":      func(c *SupportRelayConfig) { c.GasPerModel = 0 },
	} {
		c := defaultSupportRelay()
		edit(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		c.Enabled = false
		if err := c.Validate(); err != nil {
			t.Errorf("%s: disabled relay refused: %v", name, err)
		}
	}
}

func TestLoadFileSupportRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	body := strings.Join([]string{
		"support_relay:",
		"  flush_interval: 2s",
		"  max_queued: 100",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_SUPPORT_RELAY_FLUSH_ITEMS", "10")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.SupportRelay
	if !got.Enabled || got.FlushInterval != 2*time.Second || got.MaxQueued != 100 || got.FlushItems != 10 || got.GasBase != 200_000 {
		t.Fatalf("support relay = %+v", got)
	}
}

func TestExampleSupportRelaySettings(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "nexus.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SupportRelay != defaults().SupportRelay {
		t.Fatalf("example support_relay = %+v, want the defaults %+v", cfg.SupportRelay, defaults().SupportRelay)
	}
}
