package ingress

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// maxInputTokensSignatureBytes bounds the attestation's signature: an EIP-712 signature is 65
// bytes; the bound only keeps an oversized field out of the order's stored state.
const maxInputTokensSignatureBytes = 256

// checkInputTokensAttestation checks the form of the user's signed input token count received
// beside an order and that it is bound to that order, and returns it as wire bytes to forward with
// the order's dispatch record. No attestation returns nil: the chain then applies no input token
// rule to the task. The signature itself is verified by the chain, as the order's is.
func checkInputTokensAttestation(att *taskv1.OrderInputTokensAttestationV1, signed *taskv1.SignedOrderV2, orderDigest []byte) ([]byte, error) {
	if att == nil {
		return nil, nil
	}
	switch {
	case att.GetSchemaVersion() != 1:
		return nil, fmt.Errorf("input_tokens_attestation schema_version must be 1")
	case att.GetChainId() == "" || att.GetChainId() != signed.GetOrder().GetChainId():
		return nil, fmt.Errorf("input_tokens_attestation chain_id must equal the signed order's")
	case !bytes.Equal(att.GetOrderDigest(), orderDigest):
		return nil, fmt.Errorf("input_tokens_attestation order_digest must be the digest of the signed order")
	case att.GetSignatureScheme() != signed.GetSignatureScheme() || att.GetSignatureChainId() != signed.GetSignatureChainId():
		return nil, fmt.Errorf("input_tokens_attestation must be signed with the order's scheme and signature chain id")
	case len(att.GetUserSignature()) == 0 || len(att.GetUserSignature()) > maxInputTokensSignatureBytes:
		return nil, fmt.Errorf("input_tokens_attestation user_signature is missing or oversized")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("input_tokens_attestation: %v", err)
	}
	return raw, nil
}
