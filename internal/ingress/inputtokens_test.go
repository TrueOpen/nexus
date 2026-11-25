package ingress

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

func TestCheckInputTokensAttestation(t *testing.T) {
	digest := bytes.Repeat([]byte{0x11}, 32)
	signed := &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{ChainId: "trueopen-test-1"}, SignatureScheme: "eip712", SignatureChainId: 7}
	good := func() *taskv1.OrderInputTokensAttestationV1 {
		return &taskv1.OrderInputTokensAttestationV1{
			SchemaVersion: 1, ChainId: "trueopen-test-1", OrderDigest: digest, InputTokenCount: 123,
			SignatureScheme: "eip712", UserSignature: bytes.Repeat([]byte{0x02}, 65), SignatureChainId: 7,
		}
	}
	// None supplied: nothing is forwarded and nothing is refused.
	if raw, err := checkInputTokensAttestation(nil, signed, digest); err != nil || raw != nil {
		t.Fatalf("no attestation = %x, %v", raw, err)
	}
	raw, err := checkInputTokensAttestation(good(), signed, digest)
	if err != nil {
		t.Fatal(err)
	}
	var back taskv1.OrderInputTokensAttestationV1
	if err := proto.Unmarshal(raw, &back); err != nil || !proto.Equal(&back, good()) {
		t.Fatalf("forwarded bytes do not decode to the attestation received: %v", err)
	}
	// A zero count is a statement like any other.
	zero := good()
	zero.InputTokenCount = 0
	if _, err := checkInputTokensAttestation(zero, signed, digest); err != nil {
		t.Fatalf("zero count refused: %v", err)
	}
	for name, mutate := range map[string]func(*taskv1.OrderInputTokensAttestationV1){
		"schema_version":     func(a *taskv1.OrderInputTokensAttestationV1) { a.SchemaVersion = 2 },
		"chain_id":           func(a *taskv1.OrderInputTokensAttestationV1) { a.ChainId = "trueopen-test-2" },
		"order_digest":       func(a *taskv1.OrderInputTokensAttestationV1) { a.OrderDigest = bytes.Repeat([]byte{0x12}, 32) },
		"scheme":             func(a *taskv1.OrderInputTokensAttestationV1) { a.SignatureScheme = "other" },
		"signature chain id": func(a *taskv1.OrderInputTokensAttestationV1) { a.SignatureChainId = 8 },
		"user_signature":     func(a *taskv1.OrderInputTokensAttestationV1) { a.UserSignature = nil },
		"oversized":          func(a *taskv1.OrderInputTokensAttestationV1) { a.UserSignature = make([]byte, 257) },
	} {
		att := good()
		mutate(att)
		if _, err := checkInputTokensAttestation(att, signed, digest); err == nil || !strings.Contains(err.Error(), "input_tokens_attestation") {
			t.Errorf("%s: an attestation not bound to the order was accepted (err %v)", name, err)
		}
	}
}
