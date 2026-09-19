package nodecontract

import (
	"encoding/hex"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
)

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func hexString(value []byte) string { return hex.EncodeToString(value) }

// testOperator is bech32("trueopen", 0x01..0x14), from the same source as the script that produced the golden below.
const testOperator = "trueopen1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5a0a83w"

const (
	testServicePubKeyHex = "0211223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
	testTLSPubKeyHashHex = "aabb112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

func testEndpoints() []ServiceEndpoint {
	return []ServiceEndpoint{
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: "http://10.0.0.1:8080", ProtocolVersion: "v1"},
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS, URI: "http://10.0.0.1:8080", ProtocolVersion: "v1"},
		{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
			URI:  "http://10.0.0.1:8080/healthz", ProtocolVersion: "v1",
			TLSPubKeyHash: testTLSPubKeyHashHex,
		},
	}
}

// Byte-for-byte with the service_descriptor_v1 vector of wire v0.4.1 testdata/v1/hub/hub_domains_v1.json:
// 5 top-level fields (participant_type, operator_address, descriptor_version,
// endpoint_count, endpoints frame); endpoints is a nested frame of "u32 element count + one sub-frame per
// endpoint", not the four fields of each endpoint flattened to the top level. The old node golden (addbd56)
// used the flattened rule and has been superseded by the contract.
const (
	wireDescriptorOperator = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a" // a1a2…b4
	wireDescriptorTLSHash  = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	wireDescriptorDigest   = "c5ff6099bd3aa6ad1cbf8d4b2359d82b842dc93739a2643228bb61d240ddc166"
	wireDescriptorPreimage = "000000000000001e545255454f50454e5f534552564943455f44455343524950544f525f56310000000000000004000000010000000000000014a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b40000000000000008000000000000000300000000000000040000000200000000000000c80000000000000004000000020000000000000065000000000000000400000001000000000000001d68747470733a2f2f6e657875732e666978747572652e696e76616c6964000000000000000476312e3000000000000000200f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f00000000000000047000000000000000400000002000000000000001f68747470733a2f2f676174657761792e666978747572652e696e76616c6964000000000000000476312e300000000000000000"
)

func wireDescriptorEndpoints() []ServiceEndpoint {
	return []ServiceEndpoint{
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: "https://nexus.fixture.invalid", ProtocolVersion: "v1.0", TLSPubKeyHash: wireDescriptorTLSHash},
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS, URI: "https://gateway.fixture.invalid", ProtocolVersion: "v1.0"},
	}
}

func TestServiceDescriptorHashMatchesWireVector(t *testing.T) {
	fields, err := ServiceDescriptorFields(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, wireDescriptorOperator, 3,
		wireDescriptorEndpoints(), DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := hexString(CanonicalFramePreimage(DomainServiceDescriptorV1, fields...)); got != wireDescriptorPreimage {
		t.Fatalf("preimage mismatch\n got %s\nwant %s", got, wireDescriptorPreimage)
	}
	got, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, wireDescriptorOperator, 3,
		wireDescriptorEndpoints(), DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got != wireDescriptorDigest {
		t.Fatalf("descriptor hash = %s, want wire %s", got, wireDescriptorDigest)
	}
	// version enters the preimage: changing the version must change the digest.
	other, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, wireDescriptorOperator, 4,
		wireDescriptorEndpoints(), DefaultServiceEndpointLimits())
	if err != nil || other == got {
		t.Fatalf("version 4 hash = %s, %v; must differ from version 3", other, err)
	}
}

// The PoP domain/field encoding is likewise reconciled with node: if this digest is wrong, the Keeper rejects
// MsgRegisterBuilder with invalid service key proof-of-possession.
func TestServiceRegistrationBytesMatchesNodeGolden(t *testing.T) {
	pubKey := mustHexBytes(t, testServicePubKeyHex)
	got, err := ServiceRegistrationBytes(
		"trueopen-localnet", sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, pubKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	const want = "de520e6b593a52da8122178d399efbfa7df45cd2aa82ab032228d1dbb9e03ff3"
	if hexString(got) != want {
		t.Fatalf("service registration digest = %s, want the node reference %s", hexString(got), want)
	}
}

// DefaultServiceEndpointLimits must match the four upper bounds of node DefaultHubParams().Service,
// otherwise local admits endpoints the chain is certain to reject (or needlessly rejects valid config).
func TestDefaultServiceEndpointLimitsMatchNodeDefaults(t *testing.T) {
	limits := DefaultServiceEndpointLimits()
	if limits.MaxEndpoints != 16 || limits.MaxDescriptorBytes != 16<<10 ||
		limits.MaxURIBytes != 512 || limits.MaxProtocolVersionBytes != 64 {
		t.Fatalf("limits = %+v", limits)
	}
}

// Canonicalization must actually sort, and input order must not affect the digest.
func TestCanonicalServiceEndpointsSortsByKind(t *testing.T) {
	shuffled := []ServiceEndpoint{testEndpoints()[2], testEndpoints()[0], testEndpoints()[1]}
	canonical, err := CanonicalServiceEndpoints(shuffled, DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !ServiceEndpointsEqual(canonical, testEndpoints()) {
		t.Fatalf("canonical = %+v", canonical)
	}
	sortedHash, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 1, canonical, DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	referenceHash, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 1, testEndpoints(), DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	if sortedHash != referenceHash {
		t.Fatalf("hash after sorting = %s, want %s", sortedHash, referenceHash)
	}
}

// kind must be unique: a duplicate kind is a hard rejection on the Keeper side and must not pass locally.
func TestCanonicalServiceEndpointsRejectsDuplicateKind(t *testing.T) {
	duplicate := []ServiceEndpoint{
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: "http://a:1", ProtocolVersion: "v1"},
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: "http://b:2", ProtocolVersion: "v1"},
	}
	if _, err := CanonicalServiceEndpoints(duplicate, DefaultServiceEndpointLimits()); err == nil {
		t.Fatal("duplicate endpoint_kind must be rejected")
	}
}

// scheme is the closed set http/https/grpc/grpcs; http is VALID (node's explicit deployment decision),
// including for kinds whose name contains HTTPS; file/ftp and the like must be rejected.
func TestServiceEndpointURISchemeClosedSet(t *testing.T) {
	for _, uri := range []string{
		"http://10.0.0.1:8080", "https://10.0.0.1:8080",
		"grpc://10.0.0.1:9090", "grpcs://10.0.0.1:9090",
	} {
		endpoints := []ServiceEndpoint{{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
			URI:  uri, ProtocolVersion: "v1",
		}}
		if _, err := CanonicalServiceEndpoints(endpoints, DefaultServiceEndpointLimits()); err != nil {
			t.Fatalf("uri %q must be accepted: %v", uri, err)
		}
	}
	for _, uri := range []string{
		"file:///etc/passwd", "ftp://10.0.0.1", "10.0.0.1:8080", "",
		"http://user:pw@10.0.0.1:8080", "http://10.0.0.1:8080?token=x", "http://10.0.0.1:8080#frag",
		" http://10.0.0.1:8080",
	} {
		endpoints := []ServiceEndpoint{{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
			URI:  uri, ProtocolVersion: "v1",
		}}
		if _, err := CanonicalServiceEndpoints(endpoints, DefaultServiceEndpointLimits()); err == nil {
			t.Fatalf("uri %q must be rejected", uri)
		}
	}
}

func TestServiceEndpointProtocolVersionCharset(t *testing.T) {
	for _, version := range []string{"", " v1", "v 1", "v1/2", "v1\n"} {
		endpoints := []ServiceEndpoint{{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
			URI:  "http://10.0.0.1:8080", ProtocolVersion: version,
		}}
		if _, err := CanonicalServiceEndpoints(endpoints, DefaultServiceEndpointLimits()); err == nil {
			t.Fatalf("protocol_version %q must be rejected", version)
		}
	}
	endpoints := []ServiceEndpoint{{
		Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		URI:  "http://10.0.0.1:8080", ProtocolVersion: strings.Repeat("v", 65),
	}}
	if _, err := CanonicalServiceEndpoints(endpoints, DefaultServiceEndpointLimits()); err == nil {
		t.Fatal("protocol_version above max_service_endpoint_protocol_version_bytes must be rejected")
	}
}

// An absent tls_pubkey_hash is the empty byte string in the canonical fields; an all-zero fingerprint is a hard rejection.
func TestServiceEndpointTLSPubKeyHash(t *testing.T) {
	base := []ServiceEndpoint{{
		Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		URI:  "http://10.0.0.1:8080", ProtocolVersion: "v1",
	}}
	absent, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 1, base, DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	withHash := []ServiceEndpoint{base[0]}
	withHash[0].TLSPubKeyHash = testTLSPubKeyHashHex
	present, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 1, withHash, DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	if absent == present {
		t.Fatal("tls_pubkey_hash must be bound into descriptor_hash")
	}
	for _, invalid := range []string{
		strings.Repeat("0", 64), "AABB", "aabb", strings.Repeat("A", 64),
	} {
		bad := []ServiceEndpoint{base[0]}
		bad[0].TLSPubKeyHash = invalid
		if _, err := CanonicalServiceEndpoints(bad, DefaultServiceEndpointLimits()); err == nil {
			t.Fatalf("tls_pubkey_hash %q must be rejected", invalid)
		}
	}
}

func TestServiceDescriptorHashRejectsEmptyAndBadScope(t *testing.T) {
	limits := DefaultServiceEndpointLimits()
	if _, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 1, nil, limits); err == nil {
		t.Fatal("an empty endpoints list must be rejected")
	}
	if _, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testOperator, 0, testEndpoints(), limits); err == nil {
		t.Fatal("version 0 must be rejected")
	}
	if _, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED, testOperator, 1, testEndpoints(), limits); err == nil {
		t.Fatal("UNSPECIFIED participant_type must be rejected")
	}
	if _, err := ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, "not-bech32", 1, testEndpoints(), limits); err == nil {
		t.Fatal("a non-canonical operator address must be rejected")
	}
}

func TestServiceRegistrationBytesRejectsBadInput(t *testing.T) {
	pubKey := mustHexBytes(t, testServicePubKeyHex)
	builder := sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER
	if _, err := ServiceRegistrationBytes("", builder, testOperator, pubKey, 1); err == nil {
		t.Fatal("an empty chain_id must be rejected")
	}
	if _, err := ServiceRegistrationBytes("c", builder, testOperator, pubKey[:32], 1); err == nil {
		t.Fatal("a 32-byte pubkey must be rejected")
	}
	if _, err := ServiceRegistrationBytes("c", builder, testOperator, pubKey, 0); err == nil {
		t.Fatal("nonce 0 must be rejected")
	}
}

func TestParseServiceEndpointKind(t *testing.T) {
	for name, want := range map[string]hubv1.ServiceEndpointKind{
		"NEXUS_GRPC":                         hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		"object_gateway_https":               hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
		"SERVICE_ENDPOINT_KIND_HEALTH_HTTPS": hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
	} {
		got, err := ParseServiceEndpointKind(name)
		if err != nil || got != want {
			t.Fatalf("kind %q = %v (%v), want %v", name, got, err, want)
		}
	}
	for _, name := range []string{"", "UNSPECIFIED", "SERVICE_ENDPOINT_KIND_UNSPECIFIED", "NEXUS_HTTP"} {
		if _, err := ParseServiceEndpointKind(name); err == nil {
			t.Fatalf("kind %q must be rejected", name)
		}
	}
}
