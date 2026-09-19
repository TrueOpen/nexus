package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validNATSAuth(t *testing.T) NATSAuthConfig {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"cortex.nk", "auth.nk", "auth.creds", "nats-ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return NATSAuthConfig{
		NATS:                        NATSConfig{Servers: []string{"tls://127.0.0.1:4222"}, CAFile: filepath.Join(dir, "nats-ca.pem"), CredsFile: filepath.Join(dir, "auth.creds")},
		CortexAccountPublicKey:      "ABQ7Z3XPU6XHZ7EIRI7RNVFXRFEZGE3LM6KFUO3Q5LAXPTMXLRHH6HKD",
		CortexAccountSigningKeyFile: filepath.Join(dir, "cortex.nk"),
		AuthAccountSigningKeyFile:   filepath.Join(dir, "auth.nk"),
		UserJWTTTLMS:                3_600_000,
		ChainQueryCacheTTLMS:        60_000,
		MaxClockSkewMS:              300_000,
	}
}

func TestNATSAuthDefaults(t *testing.T) {
	cfg := defaults().NATSAuth
	if cfg.UserJWTTTLMS != 3_600_000 || cfg.ChainQueryCacheTTLMS != 60_000 || cfg.MaxClockSkewMS != 300_000 {
		t.Fatalf("defaults drifted from §5.14.5: %+v", cfg)
	}
}

func TestNATSAuthValidateAcceptsCompleteConfig(t *testing.T) {
	if err := validNATSAuth(t).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNATSAuthValidateRejections(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "a-directory"), 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*NATSAuthConfig)
		want   []string
	}{
		{"jwt ttl over cap", func(c *NATSAuthConfig) { c.UserJWTTTLMS = 3_600_001 }, []string{"user_jwt_ttl_ms"}},
		{"jwt ttl zero", func(c *NATSAuthConfig) { c.UserJWTTTLMS = 0 }, []string{"user_jwt_ttl_ms"}},
		{"cache ttl over cap", func(c *NATSAuthConfig) { c.ChainQueryCacheTTLMS = 60_001 }, []string{"chain_query_cache_ttl_ms"}},
		{"no servers", func(c *NATSAuthConfig) { c.NATS.Servers = nil }, []string{"nats.servers"}},
		{"plaintext server", func(c *NATSAuthConfig) { c.NATS.Servers = []string{"nats://127.0.0.1:4222"} }, []string{"tls://"}},
		{"no creds", func(c *NATSAuthConfig) { c.NATS.CredsFile = "" }, []string{"creds_file"}},
		{"empty ca_file", func(c *NATSAuthConfig) { c.NATS.CAFile = "" }, []string{"natsauth.nats.ca_file is required"}},
		{"user/password", func(c *NATSAuthConfig) { c.NATS.User = "u" }, []string{"natsauth.nats.user / natsauth.nats.password are not allowed; use natsauth.nats.creds_file"}},
		{"missing cortex key", func(c *NATSAuthConfig) { c.CortexAccountSigningKeyFile = "/nonexistent" }, []string{"cortex_account_signing_key_file"}},
		{"missing auth key", func(c *NATSAuthConfig) { c.AuthAccountSigningKeyFile = "" }, []string{"auth_account_signing_key_file"}},
		{"bad account public key", func(c *NATSAuthConfig) { c.CortexAccountPublicKey = "UXYZ" }, []string{"cortex_account_public_key"}},
		{"directory as key file", func(c *NATSAuthConfig) { c.CortexAccountSigningKeyFile = filepath.Join(dir, "a-directory") }, []string{"natsauth.cortex_account_signing_key_file", "is not a regular file"}},
		{"clock skew over cap", func(c *NATSAuthConfig) { c.MaxClockSkewMS = MaxNATSAuthClockSkewMS + 1 }, []string{"max_clock_skew_ms"}},
		{
			"multi-problem accumulation",
			func(c *NATSAuthConfig) {
				c.UserJWTTTLMS = 0
				c.AuthAccountSigningKeyFile = ""
			},
			[]string{"natsauth.user_jwt_ttl_ms", "natsauth.auth_account_signing_key_file"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validNATSAuth(t)
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("want error mentioning %q, got nil", tc.want)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("want error mentioning %q, got %v", want, err)
				}
			}
		})
	}
}

func TestNATSAuthClockSkewAllowsZero(t *testing.T) {
	cfg := validNATSAuth(t)
	cfg.MaxClockSkewMS = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("zero clock skew must be accepted as a strict setting: %v", err)
	}
}

func TestNATSAuthEnvOverrides(t *testing.T) {
	t.Setenv("NEXUS_NATSAUTH_NATS_SERVERS", "tls://a:4222,tls://b:4222")
	t.Setenv("NEXUS_NATSAUTH_NATS_CA_FILE", "/etc/nexus/natsauth-ca.pem")
	t.Setenv("NEXUS_NATSAUTH_NATS_CREDS_FILE", "/etc/nexus/natsauth-auth.creds")
	t.Setenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_PUBLIC_KEY", "ABQ7Z3XPU6XHZ7EIRI7RNVFXRFEZGE3LM6KFUO3Q5LAXPTMXLRHH6HKD")
	t.Setenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_SIGNING_KEY_FILE", "/etc/nexus/cortex.nk")
	t.Setenv("NEXUS_NATSAUTH_AUTH_ACCOUNT_SIGNING_KEY_FILE", "/etc/nexus/auth.nk")
	t.Setenv("NEXUS_NATSAUTH_USER_JWT_TTL_MS", "1200000")
	t.Setenv("NEXUS_NATSAUTH_CHAIN_QUERY_CACHE_TTL_MS", "30000")
	t.Setenv("NEXUS_NATSAUTH_MAX_CLOCK_SKEW_MS", "600000")
	t.Setenv("NEXUS_NATSAUTH_XKEY_FILE", "/etc/nexus/xkey.nk")

	cfg := Load().NATSAuth
	switch {
	case len(cfg.NATS.Servers) != 2 || cfg.NATS.Servers[0] != "tls://a:4222" || cfg.NATS.Servers[1] != "tls://b:4222":
		t.Fatalf("nats.servers not applied: %+v", cfg.NATS.Servers)
	case cfg.NATS.CAFile != "/etc/nexus/natsauth-ca.pem":
		t.Fatalf("nats.ca_file not applied: %+v", cfg.NATS.CAFile)
	case cfg.NATS.CredsFile != "/etc/nexus/natsauth-auth.creds":
		t.Fatalf("nats.creds_file not applied: %+v", cfg.NATS.CredsFile)
	case cfg.CortexAccountPublicKey != "ABQ7Z3XPU6XHZ7EIRI7RNVFXRFEZGE3LM6KFUO3Q5LAXPTMXLRHH6HKD":
		t.Fatalf("cortex_account_public_key not applied: %+v", cfg.CortexAccountPublicKey)
	case cfg.CortexAccountSigningKeyFile != "/etc/nexus/cortex.nk":
		t.Fatalf("cortex_account_signing_key_file not applied: %+v", cfg.CortexAccountSigningKeyFile)
	case cfg.AuthAccountSigningKeyFile != "/etc/nexus/auth.nk":
		t.Fatalf("auth_account_signing_key_file not applied: %+v", cfg.AuthAccountSigningKeyFile)
	case cfg.UserJWTTTLMS != 1_200_000:
		t.Fatalf("user_jwt_ttl_ms not applied: %+v", cfg.UserJWTTTLMS)
	case cfg.ChainQueryCacheTTLMS != 30_000:
		t.Fatalf("chain_query_cache_ttl_ms not applied: %+v", cfg.ChainQueryCacheTTLMS)
	case cfg.MaxClockSkewMS != 600_000:
		t.Fatalf("max_clock_skew_ms not applied: %+v", cfg.MaxClockSkewMS)
	case cfg.XKeyFile != "/etc/nexus/xkey.nk":
		t.Fatalf("xkey_file not applied: %+v", cfg.XKeyFile)
	}
}

// Relative paths under natsauth in the YAML resolve against the directory holding the YAML, same as nats.creds_file.
func TestLoadFileResolvesNATSAuthPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.yaml")
	body := "" +
		"natsauth:\n" +
		"  nats:\n" +
		"    ca_file: natsauth/ca.pem\n" +
		"    creds_file: natsauth/auth.creds\n" +
		"  cortex_account_signing_key_file: natsauth/cortex.nk\n" +
		"  auth_account_signing_key_file: natsauth/auth.nk\n" +
		"  xkey_file: natsauth/xkey.nk\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if want := filepath.Join(dir, "natsauth", "ca.pem"); cfg.NATSAuth.NATS.CAFile != want {
		t.Fatalf("natsauth.nats.ca_file = %q, want %q", cfg.NATSAuth.NATS.CAFile, want)
	}
	if want := filepath.Join(dir, "natsauth", "auth.creds"); cfg.NATSAuth.NATS.CredsFile != want {
		t.Fatalf("natsauth.nats.creds_file = %q, want %q", cfg.NATSAuth.NATS.CredsFile, want)
	}
	if want := filepath.Join(dir, "natsauth", "cortex.nk"); cfg.NATSAuth.CortexAccountSigningKeyFile != want {
		t.Fatalf("natsauth.cortex_account_signing_key_file = %q, want %q", cfg.NATSAuth.CortexAccountSigningKeyFile, want)
	}
	if want := filepath.Join(dir, "natsauth", "auth.nk"); cfg.NATSAuth.AuthAccountSigningKeyFile != want {
		t.Fatalf("natsauth.auth_account_signing_key_file = %q, want %q", cfg.NATSAuth.AuthAccountSigningKeyFile, want)
	}
	if want := filepath.Join(dir, "natsauth", "xkey.nk"); cfg.NATSAuth.XKeyFile != want {
		t.Fatalf("natsauth.xkey_file = %q, want %q", cfg.NATSAuth.XKeyFile, want)
	}
}
