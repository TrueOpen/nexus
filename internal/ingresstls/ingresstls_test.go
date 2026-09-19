package ingresstls

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/config"
)

// `nexus start` only loads, never generates: a missing certificate errors and points to `nexus tls init`;
// otherwise a certificate freshly generated at startup would have a fingerprint not on-chain and nobody could connect even with TLS on.
func TestLoadRequiresAnExistingCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := config.IngressTLSConfig{Enabled: true}

	if _, err := Load(cfg, dir); err == nil || !strings.Contains(err.Error(), "nexus tls init") {
		t.Fatalf("Load without a certificate = %v, want an error naming `nexus tls init`", err)
	}
	created, err := LoadOrCreate(cfg, dir, []string{"builder.example"})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	loaded, err := Load(cfg, dir)
	if err != nil {
		t.Fatalf("Load after init: %v", err)
	}
	if loaded.PubKeyHash != created.PubKeyHash || loaded.PubKeyHash == "" {
		t.Fatalf("Load hash = %q, want the initialised certificate %q", loaded.PubKeyHash, created.PubKeyHash)
	}
	disabled, err := Load(config.IngressTLSConfig{}, dir)
	if err != nil || disabled.Enabled() {
		t.Fatalf("Load with TLS disabled = (%v, enabled=%v), want zero material", err, disabled.Enabled())
	}
}

// On first start with no certificate, a self-signed one is generated and persisted; the next start reuses it and the public key hash is unchanged.
func TestLoadOrCreateGeneratesAndReusesSelfSignedCertificate(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.IngressTLSConfig{Enabled: true}

	first, err := LoadOrCreate(cfg, dataDir, []string{"203.0.113.10", "builder.example"})
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if first.Leaf == nil || len(first.Certificate.Certificate) == 0 {
		t.Fatal("expected a loaded certificate with parsed leaf")
	}
	if len(first.PubKeyHash) != 64 {
		t.Fatalf("pubkey hash = %q, want 64 lowercase hex", first.PubKeyHash)
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		info, err := os.Stat(filepath.Join(dataDir, "tls", name))
		if err != nil {
			t.Fatalf("expected %s under <data_dir>/tls: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s perm = %o, want 0600", name, perm)
		}
	}
	if got := first.Leaf.DNSNames; len(got) != 1 || got[0] != "builder.example" {
		t.Fatalf("DNS SANs = %v, want [builder.example]", got)
	}
	if got := first.Leaf.IPAddresses; len(got) != 1 || got[0].String() != "203.0.113.10" {
		t.Fatalf("IP SANs = %v, want [203.0.113.10]", got)
	}

	second, err := LoadOrCreate(cfg, dataDir, nil)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if second.PubKeyHash != first.PubKeyHash {
		t.Fatalf("pubkey hash changed across restarts: %s != %s", second.PubKeyHash, first.PubKeyHash)
	}
}

// Public key hash = sha256(certificate SubjectPublicKeyInfo DER), same algorithm as client-side verification.
func TestPubKeyHashIsSHA256OfSubjectPublicKeyInfo(t *testing.T) {
	material, err := LoadOrCreate(config.IngressTLSConfig{Enabled: true}, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	sum := sha256.Sum256(material.Leaf.RawSubjectPublicKeyInfo)
	if want := hex.EncodeToString(sum[:]); material.PubKeyHash != want {
		t.Fatalf("pubkey hash = %s, want %s", material.PubKeyHash, want)
	}
}

// When certificate files are configured they are used and data_dir is untouched.
func TestLoadOrCreateUsesConfiguredFiles(t *testing.T) {
	source := t.TempDir()
	generated, err := LoadOrCreate(config.IngressTLSConfig{Enabled: true}, source, []string{"builder.example"})
	if err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	dataDir := t.TempDir()
	cfg := config.IngressTLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(source, "tls", "cert.pem"),
		KeyFile:  filepath.Join(source, "tls", "key.pem"),
	}
	material, err := LoadOrCreate(cfg, dataDir, nil)
	if err != nil {
		t.Fatalf("LoadOrCreate with files: %v", err)
	}
	if material.PubKeyHash != generated.PubKeyHash {
		t.Fatalf("configured certificate not used: %s != %s", material.PubKeyHash, generated.PubKeyHash)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tls")); !os.IsNotExist(err) {
		t.Fatalf("data_dir/tls must not be created when files are configured, stat err = %v", err)
	}
}

// No files are generated when TLS is disabled.
func TestLoadOrCreateDisabledProducesNothing(t *testing.T) {
	dataDir := t.TempDir()
	material, err := LoadOrCreate(config.IngressTLSConfig{}, dataDir, nil)
	if err != nil {
		t.Fatalf("LoadOrCreate disabled: %v", err)
	}
	if material.Enabled() {
		t.Fatal("disabled config must yield disabled material")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tls")); !os.IsNotExist(err) {
		t.Fatalf("no files expected, stat err = %v", err)
	}
}

// Hostname is taken from public_endpoint as the certificate SAN; IPs and domain names are recognised separately.
func TestHostsFromEndpoint(t *testing.T) {
	cases := map[string][]string{
		"https://builder.example:8443": {"builder.example"},
		"https://203.0.113.10:443/":    {"203.0.113.10"},
		"http://127.0.0.1:8080":        {"127.0.0.1"},
		"":                             nil,
		"not a url":                    nil,
	}
	for endpoint, want := range cases {
		got := HostsFromEndpoint(endpoint)
		if len(got) != len(want) {
			t.Fatalf("HostsFromEndpoint(%q) = %v, want %v", endpoint, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("HostsFromEndpoint(%q) = %v, want %v", endpoint, got, want)
			}
		}
	}
}
