package config

import (
	"strings"
	"testing"
)

// security.mode=production switches on the production security checks: it rejects plaintext
// chain connections, inline private keys and passphrases in the config, and ingress without TLS. The dev
// default performs none of these checks and leaves behaviour unchanged.

func productionConfig() Config {
	cfg := Load()
	cfg.Security.Mode = SecurityProduction
	cfg.Ingress.TLS.Enabled = true
	cfg.Identity.PublicEndpoint = "https://builder.example:8080"
	cfg.Identity.KeystoreFile = "/etc/nexus/builder.keystore"
	cfg.Identity.KeystorePasswordFile = "/etc/nexus/builder.pass"
	cfg.Identity.PrivateKeyHex = ""
	cfg.Chain.GRPCAddr = "https://node.example:9090"
	return cfg
}

func TestSecurityProductionAcceptsAHardenedConfig(t *testing.T) {
	if err := productionConfig().ValidateSecurity(); err != nil {
		t.Fatalf("hardened production config rejected: %v", err)
	}
}

func TestSecurityProductionAllowsLoopbackChainInPlaintext(t *testing.T) {
	cfg := productionConfig()
	cfg.Chain.GRPCAddr = "127.0.0.1:9090" // loopback on the same host as node is a deployment choice
	if err := cfg.ValidateSecurity(); err != nil {
		t.Fatalf("loopback chain endpoint rejected: %v", err)
	}
}

func TestSecurityProductionRefusesWeakSettings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"plaintext remote chain", func(c *Config) { c.Chain.GRPCAddr = "node.example:9090" }, "chain.grpc_addr"},
		{"plaintext remote hub", func(c *Config) { c.Hub.Enabled, c.Hub.GRPCAddr = true, "hub.example:9090" }, "hub.grpc_addr"},
		{"inline private_key_hex", func(c *Config) {
			c.Identity.PrivateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
		}, "private_key_hex"},
		{"inline private_key", func(c *Config) { c.Identity.PrivateKey = "armored" }, "private_key"},
		{"inline keystore password", func(c *Config) { c.Identity.KeystorePasswordFile, c.Identity.KeystorePassword = "", "pw" }, "keystore_password"},
		{"inline service keystore password", func(c *Config) { c.Identity.ServiceKeystorePassword = "pw" }, "service_keystore_password"},
		{"ingress without tls", func(c *Config) { c.Ingress.TLS.Enabled = false; c.Identity.PublicEndpoint = "http://b:8080" }, "ingress.tls"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := productionConfig()
			tc.mutate(&cfg)
			err := cfg.ValidateSecurity()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateSecurity = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

func TestSecurityDevModeKeepsCurrentBehaviour(t *testing.T) {
	cfg := Load()
	cfg.Identity.PrivateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	if cfg.Security.Mode != SecurityDev {
		t.Fatalf("default security.mode = %q, want dev", cfg.Security.Mode)
	}
	if err := cfg.ValidateSecurity(); err != nil {
		t.Fatalf("dev mode must not reject today's configs: %v", err)
	}
}

func TestSecurityModeEnvironment(t *testing.T) {
	t.Setenv("NEXUS_SECURITY_MODE", "production")
	if got := Load(); got.Security.Mode != SecurityProduction {
		t.Fatalf("environment security = %+v", got.Security)
	}
	t.Setenv("NEXUS_SECURITY_MODE", "loose")
	if err := Load().ValidateSecurity(); err == nil || !strings.Contains(err.Error(), "security.mode") {
		t.Fatalf("unknown security.mode must be rejected, got %v", err)
	}
}
