package builderreg

import (
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/config"
)

const testTLSHash = "8f4c1b2a9d3e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"

// All three endpoints derived from public_endpoint carry the public key hash of the local certificate.
func TestDerivedServiceEndpointsCarryTLSPubKeyHash(t *testing.T) {
	endpoints, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: "https://builder.example:8443"}, testTLSHash)
	if err != nil {
		t.Fatalf("ServiceEndpoints: %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(endpoints))
	}
	for _, endpoint := range endpoints {
		if endpoint.TLSPubKeyHash != testTLSHash {
			t.Fatalf("%s tls_pubkey_hash = %q, want %s", endpoint.Kind, endpoint.TLSPubKeyHash, testTLSHash)
		}
	}
}

// Without a hash (plaintext ingress) the descriptor carries no tls_pubkey_hash, as before.
func TestDerivedServiceEndpointsWithoutTLSHashStayEmpty(t *testing.T) {
	endpoints, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: "http://builder.example:8080"}, "")
	if err != nil {
		t.Fatalf("ServiceEndpoints: %v", err)
	}
	for _, endpoint := range endpoints {
		if endpoint.TLSPubKeyHash != "" {
			t.Fatalf("%s unexpectedly carries tls_pubkey_hash %q", endpoint.Kind, endpoint.TLSPubKeyHash)
		}
	}
}

// For explicitly configured endpoints: https/grpcs entries without a hash get one, entries that already have one are not overwritten, and plaintext URIs get none.
func TestConfiguredServiceEndpointsFillTLSPubKeyHashOnlyForTLSSchemes(t *testing.T) {
	explicit := strings.Repeat("ab", 32)
	identity := config.IdentityConfig{ServiceEndpoints: []config.ServiceEndpointConfig{
		{Kind: "NEXUS_GRPC", URI: "grpcs://builder.example:8443"},
		{Kind: "OBJECT_GATEWAY_HTTPS", URI: "https://builder.example:8443", TLSPubKeyHash: explicit},
		{Kind: "HEALTH_HTTPS", URI: "http://builder.example:8080/healthz"},
	}}
	endpoints, err := ServiceEndpoints(identity, testTLSHash)
	if err != nil {
		t.Fatalf("ServiceEndpoints: %v", err)
	}
	got := map[string]string{}
	for _, endpoint := range endpoints {
		got[endpoint.URI] = endpoint.TLSPubKeyHash
	}
	if got["grpcs://builder.example:8443"] != testTLSHash {
		t.Fatalf("grpcs endpoint hash = %q, want auto-filled", got["grpcs://builder.example:8443"])
	}
	if got["https://builder.example:8443"] != explicit {
		t.Fatalf("explicit hash overwritten: %q", got["https://builder.example:8443"])
	}
	if got["http://builder.example:8080/healthz"] != "" {
		t.Fatalf("plaintext endpoint must not carry a hash: %q", got["http://builder.example:8080/healthz"])
	}
}
