package nodecontract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
)

// The frozen contract replaced the Builder/Cortex service descriptor shape "descriptor_uri + descriptor_hash
// stored on chain, document fetched off-chain over HTTPS" with "repeated ServiceEndpointV1 stored directly
// on chain" (Keeper Interface Contract §9.6b). This file is the single canonicalization entry point for that
// shape on the nexus side: ordering, per-field validation and the H_FIELDS_V1 rule for descriptor_hash must
// all match node x/hub/types/participant_identity.go CanonicalServiceDescriptorEndpointFields /
// CanonicalServiceDescriptorHash byte-for-byte, otherwise the local "is an update needed" decision
// drifts from the on-chain fact.
const (
	// DomainServiceDescriptorV1 is the descriptor hash domain registered in §1.4. §9.6b deliberately keeps
	// chain_id out of this preimage: scope is carried by participant_type + operator_address.
	DomainServiceDescriptorV1 = "TRUEOPEN_SERVICE_DESCRIPTOR_V1"
	// DomainServiceRegistrationV1 is the domain of the service key PoP (§10.0c).
	DomainServiceRegistrationV1 = "TRUEOPEN_SERVICE_REGISTRATION_V1"
)

// ServiceEndpoint is the nexus-side value type of hub.v1.ServiceEndpointV1.
// An empty TLSPubKeyHash means the optional field is absent; when present it must be canonical lowercase
// 64-hex and must not be all zeros (the Keeper checks only length and non-zero, it does not interpret the algorithm).
type ServiceEndpoint struct {
	Kind            hubv1.ServiceEndpointKind `json:"kind"`
	URI             string                    `json:"uri"`
	ProtocolVersion string                    `json:"protocol_version"`
	TLSPubKeyHash   string                    `json:"tls_pubkey_hash,omitempty"`
}

// ServiceEndpointLimits corresponds to ServiceParamsV1 fields 8..11. The truth lives in on-chain params;
// when nexus cannot query them it uses the same numbers as node DefaultParams as a local upper bound: if
// local admits and chain is stricter the Keeper reports the error, and the reverse never builds a message that is certain to be rejected.
type ServiceEndpointLimits struct {
	MaxEndpoints            uint32
	MaxDescriptorBytes      uint64
	MaxURIBytes             uint32
	MaxProtocolVersionBytes uint32
}

// DefaultServiceEndpointLimits is taken from DefaultParams in node x/hub/types/params.go.
func DefaultServiceEndpointLimits() ServiceEndpointLimits {
	return ServiceEndpointLimits{
		MaxEndpoints:            16,
		MaxDescriptorBytes:      16 << 10,
		MaxURIBytes:             512,
		MaxProtocolVersionBytes: 64,
	}
}

// serviceEndpointSchemes is the closed set of URI schemes the Keeper admits. node's
// CanonicalServiceDescriptorEndpointFields explicitly notes "HTTP remains allowed by the
// explicit Node deployment decision": although the OBJECT_GATEWAY_HTTPS / HEALTH_HTTPS kind names
// contain HTTPS, the chain does not force https for them.
var serviceEndpointSchemes = map[string]struct{}{
	"http": {}, "https": {}, "grpc": {}, "grpcs": {},
}

// ParseServiceEndpointKind accepts the §9.6b short names (NEXUS_GRPC / OBJECT_GATEWAY_HTTPS /
// HEALTH_HTTPS) as well as the full names from generated code. UNSPECIFIED is always rejected.
func ParseServiceEndpointKind(name string) (hubv1.ServiceEndpointKind, error) {
	trimmed := strings.TrimSpace(name)
	full := trimmed
	if !strings.HasPrefix(full, "SERVICE_ENDPOINT_KIND_") {
		full = "SERVICE_ENDPOINT_KIND_" + strings.ToUpper(full)
	}
	value, ok := hubv1.ServiceEndpointKind_value[full]
	if !ok || !IsValidServiceEndpointKind(hubv1.ServiceEndpointKind(value)) {
		return hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_UNSPECIFIED,
			fmt.Errorf("service endpoint kind %q is not one of NEXUS_GRPC / OBJECT_GATEWAY_HTTPS / HEALTH_HTTPS", name)
	}
	return hubv1.ServiceEndpointKind(value), nil
}

// ServiceEndpointKindName returns the §9.6b short name, for config echo and logs.
func ServiceEndpointKindName(kind hubv1.ServiceEndpointKind) string {
	return strings.TrimPrefix(kind.String(), "SERVICE_ENDPOINT_KIND_")
}

// IsValidServiceEndpointKind is the predicate for the three-value closed enum; UNSPECIFIED is not valid.
func IsValidServiceEndpointKind(kind hubv1.ServiceEndpointKind) bool {
	switch kind {
	case hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
		hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS:
		return true
	default:
		return false
	}
}

// CanonicalServiceEndpoints normalizes endpoints read from config or chain into the submission shape the
// contract requires: ascending by (endpoint_kind, uri bytes), unique kind, each field within the §9.6b bounds.
// It returns a copy; mutating it does not affect the input.
func CanonicalServiceEndpoints(endpoints []ServiceEndpoint, limits ServiceEndpointLimits) ([]ServiceEndpoint, error) {
	sorted := make([]ServiceEndpoint, len(endpoints))
	copy(sorted, endpoints)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Kind != sorted[j].Kind {
			return sorted[i].Kind < sorted[j].Kind
		}
		return sorted[i].URI < sorted[j].URI
	})
	if _, err := CanonicalServiceEndpointFields(sorted, limits); err != nil {
		return nil, err
	}
	return sorted, nil
}

// CanonicalServiceEndpointFields is the single validator for endpoints and the H_FIELDS_V1 field producer,
// one-to-one with node CanonicalServiceDescriptorEndpointFields: each endpoint is flattened into the four
// top-level fields (enum kind, uri, protocol_version, tls_pubkey_hash), with an absent
// tls_pubkey_hash normalized to the empty byte string.
func CanonicalServiceEndpointFields(endpoints []ServiceEndpoint, limits ServiceEndpointLimits) ([][]byte, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("service descriptor must carry at least one endpoint")
	}
	if uint32(len(endpoints)) > limits.MaxEndpoints {
		return nil, fmt.Errorf("service descriptor carries %d endpoints, above the %d limit", len(endpoints), limits.MaxEndpoints)
	}
	fields := make([][]byte, 0, len(endpoints)*4)
	var previousKind hubv1.ServiceEndpointKind
	for index, endpoint := range endpoints {
		if !IsValidServiceEndpointKind(endpoint.Kind) {
			return nil, fmt.Errorf("service endpoint %d has invalid endpoint_kind %q", index, endpoint.Kind)
		}
		if index > 0 && endpoint.Kind <= previousKind {
			return nil, fmt.Errorf("service endpoints must ascend by unique endpoint_kind; %q repeats or is out of order", ServiceEndpointKindName(endpoint.Kind))
		}
		if err := validateServiceEndpointURI(index, endpoint.URI, limits); err != nil {
			return nil, err
		}
		if err := validateServiceEndpointProtocolVersion(index, endpoint.ProtocolVersion, limits); err != nil {
			return nil, err
		}
		tlsHash, err := serviceEndpointTLSHashBytes(index, endpoint.TLSPubKeyHash)
		if err != nil {
			return nil, err
		}
		fields = append(fields,
			EnumBE(uint32(endpoint.Kind)),
			[]byte(endpoint.URI),
			[]byte(endpoint.ProtocolVersion),
			tlsHash,
		)
		previousKind = endpoint.Kind
	}
	if encoded := uint64(len(CanonicalFrameBytes(fields...))); encoded > limits.MaxDescriptorBytes {
		return nil, fmt.Errorf("service descriptor canonical bytes %d exceed the %d limit", encoded, limits.MaxDescriptorBytes)
	}
	return fields, nil
}

// ServiceDescriptorFields are the top-level fields of the §9.6b descriptor_hash (byte-for-byte with wire v0.4.1
// testdata/v1/hub/hub_domains_v1.json service_descriptor_v1):
//
//	participant_type, operator_address, descriptor_version, endpoint_count,
//	endpoints = FRAME(u32 element count, FRAME(endpoint_kind, uri, protocol_version, tls_pubkey_hash) ...)
//
// endpoints is ONE nested frame, not the four fields of every endpoint flattened to the top level; flattening
// was the old node rule and the chain has long since moved to the nested frame. Once the two sides
// disagree, local recomputation consistently reports "descriptor hash disagrees".
func ServiceDescriptorFields(
	participantType sharedv1.ParticipantType,
	operatorAddress string,
	version uint64,
	endpoints []ServiceEndpoint,
	limits ServiceEndpointLimits,
) ([][]byte, error) {
	if participantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX &&
		participantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
		return nil, fmt.Errorf("service descriptor participant_type %q is invalid", participantType)
	}
	if version == 0 {
		return nil, fmt.Errorf("service descriptor version must be greater than 0")
	}
	operatorBytes, err := CanonicalOperatorAddressBytes("service descriptor operator_address", operatorAddress)
	if err != nil {
		return nil, err
	}
	endpointFields, err := CanonicalServiceEndpointFields(endpoints, limits)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, 0, 1+len(endpoints))
	elements = append(elements, Uint32BE(uint32(len(endpoints))))
	for i := 0; i < len(endpointFields); i += 4 {
		elements = append(elements, CanonicalFrameBytes(endpointFields[i:i+4]...))
	}
	return [][]byte{
		EnumBE(uint32(participantType)),
		operatorBytes,
		Uint64BE(version),
		Uint32BE(uint32(len(endpoints))),
		CanonicalFrameBytes(elements...),
	}, nil
}

// ServiceDescriptorHash recomputes the §9.6b descriptor_hash:
//
//	H_FIELDS_V1("TRUEOPEN_SERVICE_DESCRIPTOR_V1", ServiceDescriptorFields...)
//
// version must be the version number under which this batch of endpoints is actually stored (MsgRegisterBuilder
// is always 1, MsgUpdateServiceDescriptor is expected_descriptor_version + 1), because the version enters the
// preimage: the same endpoints hash differently under different versions.
func ServiceDescriptorHash(
	participantType sharedv1.ParticipantType,
	operatorAddress string,
	version uint64,
	endpoints []ServiceEndpoint,
	limits ServiceEndpointLimits,
) (string, error) {
	fields, err := ServiceDescriptorFields(participantType, operatorAddress, version, endpoints, limits)
	if err != nil {
		return "", err
	}
	digest := CanonicalHashBytes(DomainServiceDescriptorV1, fields...)
	return hex.EncodeToString(digest[:]), nil
}

// ServiceRegistrationBytes is the signing preimage digest of the service key proof-of-possession
// (§10.0c, domain TRUEOPEN_SERVICE_REGISTRATION_V1):
//
//	H_FIELDS_V1(domain, chain_id, participant_type, operator_address,
//	            service_pubkey, initial_service_authorization_nonce)
//
// operator_address enters the preimage as address codec bytes, not bech32 text (ruling 24), and
// service_pubkey as the raw 33-byte compressed public key, not hex text. The return value is a 32-byte
// digest that SignHex signs one more layer over; the Keeper verifies with SDK PubKey.VerifySignature, which
// likewise applies sha256 to these 32 bytes once more, so both sides agree.
func ServiceRegistrationBytes(
	chainID string,
	participantType sharedv1.ParticipantType,
	operatorAddress string,
	servicePubKey []byte,
	nonce uint64,
) ([]byte, error) {
	chainIDField, err := CanonicalUTF8Field("service registration chain_id", chainID)
	if err != nil {
		return nil, err
	}
	if len(chainIDField) == 0 {
		return nil, fmt.Errorf("service registration chain_id is required")
	}
	if participantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX &&
		participantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
		return nil, fmt.Errorf("service registration participant_type %q is invalid", participantType)
	}
	operatorBytes, err := CanonicalOperatorAddressBytes("service registration operator_address", operatorAddress)
	if err != nil {
		return nil, err
	}
	if len(servicePubKey) != 33 {
		return nil, fmt.Errorf("service registration service_pubkey must be 33 compressed bytes, got %d", len(servicePubKey))
	}
	if nonce == 0 {
		return nil, fmt.Errorf("service registration nonce must be greater than 0")
	}
	digest := CanonicalHashBytes(DomainServiceRegistrationV1,
		chainIDField,
		EnumBE(uint32(participantType)),
		operatorBytes,
		servicePubKey,
		Uint64BE(nonce),
	)
	return digest[:], nil
}

// ServiceEndpointsEqual reports whether two endpoint batches are the same descriptor content. Callers should
// first run each through CanonicalServiceEndpoints; this only compares field by field and does not sort.
func ServiceEndpointsEqual(left, right []ServiceEndpoint) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func validateServiceEndpointURI(index int, uri string, limits ServiceEndpointLimits) error {
	if uri == "" || strings.TrimSpace(uri) != uri {
		return fmt.Errorf("service endpoint %d uri must be non-empty and free of surrounding whitespace", index)
	}
	if uint32(len(uri)) > limits.MaxURIBytes {
		return fmt.Errorf("service endpoint %d uri is %d bytes, above the %d limit", index, len(uri), limits.MaxURIBytes)
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("service endpoint %d uri must be absolute, credential-free, and carry no query or fragment", index)
	}
	if _, ok := serviceEndpointSchemes[parsed.Scheme]; !ok {
		return fmt.Errorf("service endpoint %d uri scheme %q is outside the http/https/grpc/grpcs closed set", index, parsed.Scheme)
	}
	return nil
}

func validateServiceEndpointProtocolVersion(index int, version string, limits ServiceEndpointLimits) error {
	if version == "" || strings.TrimSpace(version) != version {
		return fmt.Errorf("service endpoint %d protocol_version must be non-empty and free of surrounding whitespace", index)
	}
	if uint32(len(version)) > limits.MaxProtocolVersionBytes {
		return fmt.Errorf("service endpoint %d protocol_version is %d bytes, above the %d limit", index, len(version), limits.MaxProtocolVersionBytes)
	}
	for _, character := range version {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == '-':
		default:
			return fmt.Errorf("service endpoint %d protocol_version may only use [A-Za-z0-9._-]", index)
		}
	}
	return nil
}

func serviceEndpointTLSHashBytes(index int, value string) ([]byte, error) {
	if value == "" {
		// An absent optional is the empty byte string in node's canonical fields, not a presence byte.
		return []byte{}, nil
	}
	raw, err := Hash32Bytes("service endpoint tls_pubkey_hash", value)
	if err != nil {
		return nil, fmt.Errorf("service endpoint %d %w", index, err)
	}
	if bytes.Equal(raw, make([]byte, 32)) {
		return nil, fmt.Errorf("service endpoint %d tls_pubkey_hash must not be all zero", index)
	}
	return raw, nil
}
