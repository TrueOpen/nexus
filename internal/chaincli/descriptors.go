package chaincli

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

const participantTypeBuilder = "BUILDER"

// resolveBuilderEndpoint resolves a peer Builder's public nexus gRPC address.
//
// The frozen contract changed the descriptor from "on-chain descriptor_uri +
// descriptor_hash, JSON document fetched off-chain over HTTPS" to "endpoints stored
// directly on chain" (§9.6b), so no document is fetched here and no hash comparison or
// local cache is needed: the endpoint itself is consensus-protected, and whatever
// QueryServiceDescriptor returns is taken as is.
func (c *client) resolveBuilderEndpoint(ctx context.Context, address string) (string, uint64, error) {
	builder, err := c.QueryBuilder(ctx, address)
	if err != nil {
		return "", 0, err
	}
	if builder.Address != address {
		return "", builder.CurrentDescriptorVersion, fmt.Errorf("builder descriptor: builder owner mismatch")
	}
	version := builder.CurrentDescriptorVersion
	if version == 0 {
		return "", 0, fmt.Errorf("builder descriptor: current version is unavailable")
	}
	descriptor, err := c.QueryServiceDescriptor(ctx, participantTypeBuilder, address, version)
	if err != nil {
		return "", version, err
	}
	if err := validateServiceDescriptor(descriptor, address, version); err != nil {
		return "", version, err
	}
	endpoint, ok := serviceEndpointByKind(descriptor.Endpoints, hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC)
	if !ok {
		return "", version, fmt.Errorf("builder descriptor: no NEXUS_GRPC endpoint published")
	}
	return endpoint.URI, version, nil
}

func serviceEndpointByKind(endpoints []ServiceEndpoint, kind hubv1.ServiceEndpointKind) (ServiceEndpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Kind == kind {
			return endpoint, true
		}
	}
	return ServiceEndpoint{}, false
}

// validateServiceDescriptor only asserts that "this row really is this Builder's current
// descriptor and its content satisfies the §9.6b structural constraints". Validity period
// is not among them: the frozen contract's descriptor has no effective/expires height,
// the current row is the current fact.
func validateServiceDescriptor(descriptor ServiceDescriptorState, address string, version uint64) error {
	if descriptor.ParticipantType != participantTypeBuilder {
		return fmt.Errorf("builder descriptor: participant type mismatch")
	}
	if descriptor.OperatorAddress != address {
		return fmt.Errorf("builder descriptor: on-chain owner mismatch")
	}
	if descriptor.DescriptorVersion != version {
		return fmt.Errorf("builder descriptor: version mismatch")
	}
	if err := validateDescriptorHash(descriptor.DescriptorHash); err != nil {
		return err
	}
	if _, err := nodecontract.CanonicalServiceEndpointFields(descriptor.Endpoints, nodecontract.DefaultServiceEndpointLimits()); err != nil {
		return fmt.Errorf("builder descriptor: %w", err)
	}
	return nil
}

func validateDescriptorHash(hash string) error {
	if strings.TrimSpace(hash) != hash || len(hash) != 64 || strings.ToLower(hash) != hash {
		return fmt.Errorf("builder descriptor: invalid hash")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("builder descriptor: invalid hash")
	}
	return nil
}
