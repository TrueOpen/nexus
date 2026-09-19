package builderreg

import (
	"fmt"
	"net/url"
	"strings"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// defaultEndpointProtocolVersion is the protocol_version written into the descriptor when the
// configuration does not state one. The contract only constrains the character set and the length bound,
// it does not register the values.
const defaultEndpointProtocolVersion = "v1"

// healthEndpointPath matches the health-check path exposed by ingress (/healthz in cmd).
const healthEndpointPath = "/healthz"

// ServiceEndpoints resolves the configuration into the endpoints list submitted on chain.
//
// Two paths:
//
//   - identity.service_endpoints non-empty: each entry is validated against §9.6b and then used as is,
//     exactly as configured.
//   - left empty: three entries are derived from identity.public_endpoint. The single Connect port of
//     nexus serves gRPC, object reads and /healthz at once, so all three kinds point at the same
//     host:port and only HEALTH_HTTPS carries the /healthz path.
//
// [Pending protocol confirmation] The contract does not fix which URI each of the three endpoint_kind
// values should carry (in particular whether OBJECT_GATEWAY_HTTPS needs a path prefix and whether
// HEALTH_HTTPS is simply /healthz). The derivation above is this repository's recommended implementation,
// not a ruling; until that settles it can be overridden explicitly through identity.service_endpoints.
//
// When neither is available it returns a readable error: failing at startup beats submitting an empty or
// half-filled endpoints list.
//
// tlsPubKeyHash is the public key hash of the local certificate when ingress terminates TLS itself
// (ingresstls.Material); when non-empty it is written into every derived endpoint, and into explicitly
// configured https/grpcs endpoints that carry no hash. Clients check the server identity against it, so a
// self-signed certificate is sufficient. Plaintext ingress passes an empty string and the descriptor is unchanged.
func ServiceEndpoints(identity config.IdentityConfig, tlsPubKeyHash string) ([]chaincli.ServiceEndpoint, error) {
	tlsPubKeyHash = strings.TrimSpace(tlsPubKeyHash)
	if len(identity.ServiceEndpoints) > 0 {
		return configuredServiceEndpoints(identity.ServiceEndpoints, tlsPubKeyHash)
	}
	return derivedServiceEndpoints(identity.PublicEndpoint, tlsPubKeyHash)
}

func configuredServiceEndpoints(configured []config.ServiceEndpointConfig, tlsPubKeyHash string) ([]chaincli.ServiceEndpoint, error) {
	endpoints := make([]chaincli.ServiceEndpoint, 0, len(configured))
	for i, entry := range configured {
		kind, err := nodecontract.ParseServiceEndpointKind(entry.Kind)
		if err != nil {
			return nil, fmt.Errorf("identity.service_endpoints[%d]: %w", i, err)
		}
		protocolVersion := strings.TrimSpace(entry.ProtocolVersion)
		if protocolVersion == "" {
			protocolVersion = defaultEndpointProtocolVersion
		}
		uri := strings.TrimSpace(entry.URI)
		hash := strings.TrimSpace(entry.TLSPubKeyHash)
		if hash == "" && tlsPubKeyHash != "" && usesTLSScheme(uri) {
			hash = tlsPubKeyHash
		}
		endpoints = append(endpoints, chaincli.ServiceEndpoint{
			Kind:            kind,
			URI:             uri,
			ProtocolVersion: protocolVersion,
			TLSPubKeyHash:   hash,
		})
	}
	canonical, err := nodecontract.CanonicalServiceEndpoints(endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		return nil, fmt.Errorf("identity.service_endpoints: %w", err)
	}
	return canonical, nil
}

// usesTLSScheme reports whether uri runs over TLS (https / grpcs); only such endpoints get a public key hash.
func usesTLSScheme(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "grpcs":
		return true
	}
	return false
}

func derivedServiceEndpoints(publicEndpoint, tlsPubKeyHash string) ([]chaincli.ServiceEndpoint, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(publicEndpoint), "/")
	if trimmed == "" {
		return nil, fmt.Errorf(
			"builder service descriptor requires endpoints: set identity.service_endpoints " +
				"(kinds NEXUS_GRPC / OBJECT_GATEWAY_HTTPS / HEALTH_HTTPS) or identity.public_endpoint to derive them")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return nil, fmt.Errorf("identity.public_endpoint %q must be an absolute URL to derive service endpoints", publicEndpoint)
	}
	endpoints := []chaincli.ServiceEndpoint{
		{
			Kind:            hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
			URI:             trimmed,
			ProtocolVersion: defaultEndpointProtocolVersion,
			TLSPubKeyHash:   tlsPubKeyHash,
		},
		{
			Kind:            hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
			URI:             trimmed,
			ProtocolVersion: defaultEndpointProtocolVersion,
			TLSPubKeyHash:   tlsPubKeyHash,
		},
		{
			Kind:            hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
			URI:             trimmed + healthEndpointPath,
			ProtocolVersion: defaultEndpointProtocolVersion,
			TLSPubKeyHash:   tlsPubKeyHash,
		},
	}
	canonical, err := nodecontract.CanonicalServiceEndpoints(endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		return nil, fmt.Errorf("identity.public_endpoint %q derives an invalid descriptor: %w", publicEndpoint, err)
	}
	return canonical, nil
}
