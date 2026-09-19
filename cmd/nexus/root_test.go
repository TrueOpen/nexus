package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/config"
)

func TestResolveConfigPathUsesAutomaticFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(config.DefaultFile, []byte("chain:\n  grpc_addr: auto:9090\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := resolveConfigPath("", false)
	if err != nil || path != config.DefaultFile {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestResolveConfigPathReturnsEmptyWithoutAutomaticFile(t *testing.T) {
	t.Chdir(t.TempDir())
	path, err := resolveConfigPath("", false)
	if err != nil || path != "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestResolveConfigPathExplicitWins(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(config.DefaultFile, []byte("chain: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(dir, "explicit.yaml")
	if err := os.WriteFile(explicit, []byte("chain: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := resolveConfigPath(explicit, true)
	if err != nil || path != explicit {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestResolveConfigPathRequiresExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := resolveConfigPath(path, true)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error=%v, want missing path", err)
	}
}

func TestResolveConfigPathRejectsExplicitEmptyValue(t *testing.T) {
	_, err := resolveConfigPath("  ", true)
	if err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error=%v, want non-empty path error", err)
	}
}

func TestRootRejectsExplicitEmptyConfig(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"start", "--config="})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error=%v, want non-empty path error", err)
	}
}

func TestLoadCommandConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte(`
log:
  level: info
chain:
  grpc_addr: yaml:9090
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_LOG_LEVEL", "warn")
	t.Setenv("NEXUS_CHAIN_GRPC", "env:9090")

	cfg, selected, err := loadCommandConfig(path, true, configOverrides{LogLevel: "error"})
	if err != nil {
		t.Fatal(err)
	}
	if selected != path || cfg.Log.Level != "error" || cfg.Chain.GRPCAddr != "env:9090" {
		t.Fatalf("selected=%q config=%+v", selected, cfg)
	}
}

func TestVersionIgnoresMalformedAutomaticConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(config.DefaultFile, []byte("invalid: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	oldFlagVersion := flagVersion
	flagVersion = false
	t.Cleanup(func() { flagVersion = oldFlagVersion })

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out.String(), "nexus ") {
		t.Fatalf("output=%q", out.String())
	}
}
