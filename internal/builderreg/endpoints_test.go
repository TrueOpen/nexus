package builderreg

import (
	"strings"
	"testing"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/config"
)

// A trailing slash on public_endpoint must be normalized first: otherwise the same address written two
// ways yields two descriptor_hash values and a restart bumps the on-chain version for nothing.
func TestServiceEndpointsTrimsTrailingSlash(t *testing.T) {
	withSlash, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: "https://builder.example:8080/"}, "")
	if err != nil {
		t.Fatal(err)
	}
	without, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: " https://builder.example:8080 "}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(withSlash) != 3 || withSlash[0].URI != "https://builder.example:8080" {
		t.Fatalf("endpoints = %+v", withSlash)
	}
	for i := range withSlash {
		if withSlash[i] != without[i] {
			t.Fatalf("endpoint %d differs: %+v vs %+v", i, withSlash[i], without[i])
		}
	}
}

// The three derived entries: two point at public_endpoint itself and HEALTH_HTTPS appends /healthz.
func TestServiceEndpointsDerivesThreeKinds(t *testing.T) {
	got, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: "http://10.0.0.1:8080"}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind hubv1.ServiceEndpointKind
		uri  string
	}{
		{hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, "http://10.0.0.1:8080"},
		{hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS, "http://10.0.0.1:8080"},
		{hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS, "http://10.0.0.1:8080/healthz"},
	}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %+v", got)
	}
	for i := range want {
		if got[i].Kind != want[i].kind || got[i].URI != want[i].uri || got[i].ProtocolVersion != "v1" {
			t.Fatalf("endpoint %d = %+v, want %+v", i, got[i], want[i])
		}
		if got[i].TLSPubKeyHash != "" {
			t.Fatalf("derived endpoints must not invent a tls_pubkey_hash: %+v", got[i])
		}
	}
}

// When an explicit configuration exists, the public_endpoint derivation is ignored entirely.
func TestServiceEndpointsPrefersExplicitConfiguration(t *testing.T) {
	got, err := ServiceEndpoints(config.IdentityConfig{
		PublicEndpoint: "https://ignored.example",
		ServiceEndpoints: []config.ServiceEndpointConfig{
			{Kind: "OBJECT_GATEWAY_HTTPS", URI: "https://objects.example"},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URI != "https://objects.example" ||
		got[0].Kind != hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS {
		t.Fatalf("endpoints = %+v", got)
	}
}

// The error for a missing configuration must name the field to fix rather than a generic invalid descriptor.
func TestServiceEndpointsMissingConfigurationErrorNamesFields(t *testing.T) {
	_, err := ServiceEndpoints(config.IdentityConfig{}, "")
	if err == nil {
		t.Fatal("expected a fail-fast error")
	}
	for _, want := range []string{"identity.service_endpoints", "identity.public_endpoint", "NEXUS_GRPC"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// An http public_endpoint is valid on chain (the closed scheme set includes http) and must not be rejected here.
func TestServiceEndpointsAcceptsPlainHTTPPublicEndpoint(t *testing.T) {
	if _, err := ServiceEndpoints(config.IdentityConfig{PublicEndpoint: "http://10.0.0.1:8080"}, ""); err != nil {
		t.Fatalf("plain http public_endpoint rejected: %v", err)
	}
}
