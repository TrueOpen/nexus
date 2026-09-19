package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIngressTLSDefaultsOff(t *testing.T) {
	cfg := defaults()
	if cfg.Ingress.TLS.Enabled {
		t.Fatal("TLS must default to off so existing deployments keep serving h2c")
	}
}

func TestIngressTLSEnvironment(t *testing.T) {
	t.Setenv("NEXUS_INGRESS_TLS_ENABLED", "true")
	t.Setenv("NEXUS_INGRESS_TLS_CERT_FILE", "/etc/nexus/cert.pem")
	t.Setenv("NEXUS_INGRESS_TLS_KEY_FILE", "/etc/nexus/key.pem")
	cfg := Load()
	if !cfg.Ingress.TLS.Enabled || cfg.Ingress.TLS.CertFile != "/etc/nexus/cert.pem" || cfg.Ingress.TLS.KeyFile != "/etc/nexus/key.pem" {
		t.Fatalf("env not applied: %+v", cfg.Ingress.TLS)
	}
}

// A relative certificate path in the YAML resolves against the directory holding the YAML, same as keystore_file.
func TestLoadFileResolvesIngressTLSPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.yaml")
	body := "ingress:\n  tls:\n    enabled: true\n    cert_file: tls/cert.pem\n    key_file: tls/key.pem\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if want := filepath.Join(dir, "tls", "cert.pem"); cfg.Ingress.TLS.CertFile != want {
		t.Fatalf("cert_file = %q, want %q", cfg.Ingress.TLS.CertFile, want)
	}
	if want := filepath.Join(dir, "tls", "key.pem"); cfg.Ingress.TLS.KeyFile != want {
		t.Fatalf("key_file = %q, want %q", cfg.Ingress.TLS.KeyFile, want)
	}
}

func TestIngressTLSValidate(t *testing.T) {
	cases := map[string]struct {
		cfg     IngressTLSConfig
		wantErr string
	}{
		"off":              {cfg: IngressTLSConfig{}},
		"auto self-signed": {cfg: IngressTLSConfig{Enabled: true}},
		"both files":       {cfg: IngressTLSConfig{Enabled: true, CertFile: "a.pem", KeyFile: "b.pem"}},
		"cert without key": {cfg: IngressTLSConfig{Enabled: true, CertFile: "a.pem"}, wantErr: "cert_file and key_file"},
		"key without cert": {cfg: IngressTLSConfig{Enabled: true, KeyFile: "b.pem"}, wantErr: "cert_file and key_file"},
		"files while off":  {cfg: IngressTLSConfig{CertFile: "a.pem", KeyFile: "b.pem"}, wantErr: "enabled"},
	}
	for name, tc := range cases {
		err := tc.cfg.Validate()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Fatalf("%s: unexpected error %v", name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Fatalf("%s: err = %v, want containing %q", name, err, tc.wantErr)
		}
	}
}

// Once TLS is enabled the public address must be https, otherwise the on-chain descriptor points clients at plaintext.
func TestPublicEndpointMustBeHTTPSWhenTLSEnabled(t *testing.T) {
	cfg := defaults()
	cfg.Ingress.TLS.Enabled = true
	cfg.Identity.PublicEndpoint = "http://builder.example:8080"
	err := cfg.ValidateTransport()
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https requirement, got %v", err)
	}
	cfg.Identity.PublicEndpoint = "https://builder.example:8443"
	if err := cfg.ValidateTransport(); err != nil {
		t.Fatalf("https endpoint must pass: %v", err)
	}
	cfg.Ingress.TLS.Enabled = false
	cfg.Identity.PublicEndpoint = "http://builder.example:8080"
	if err := cfg.ValidateTransport(); err != nil {
		t.Fatalf("plaintext ingress with http endpoint must pass: %v", err)
	}
}

func TestExampleConfigStillLoadsWithTLSSection(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "nexus.example.yaml"))
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if cfg.Ingress.TLS.Enabled {
		t.Fatal("example must ship with TLS off")
	}
}
