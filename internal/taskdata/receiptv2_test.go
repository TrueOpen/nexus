package taskdata

import (
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// The two new InferReceiptV2 fields must be carried all the way into the preimage. They
// are uint64 on the wire, so a missed copy at any layer does not fail compilation; it
// only makes nexus compute a digest different from what the Worker signed, surfacing
// on-chain as "signature does not verify against signing digest".
func TestReceiptDigestBindsV2Fields(t *testing.T) {
	base := SignedInferReceipt{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainID: "trueopen-localnet-1",
		TaskID: strings.Repeat("1", 64), TaskHash: strings.Repeat("2", 64),
		WorkerOperatorAddress: "trueopen1e9rxz3ssv5sqf4n23nfnlh4atv3uf3fs9s0pvm", ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: strings.Repeat("3", 64), OutputHash: strings.Repeat("4", 64),
		OutputSizeBytes: 88,
		EvidenceCommitments: []EvidenceCommitment{{
			Kind:             uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING),
			HashOrRoot:       strings.Repeat("5", 64),
			EncodedSizeBytes: 145,
		}},
		ExpiryHeight: 1200, ServiceSignature: strings.Repeat("0", 128),
		GeneratedTokenCount: 128, OutputLeafCount: 5,
	}
	want, err := receiptDigest(base)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*SignedInferReceipt){
		"generated_token_count": func(r *SignedInferReceipt) { r.GeneratedTokenCount = 129 },
		"output_leaf_count":     func(r *SignedInferReceipt) { r.OutputLeafCount = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := base
			mutate(&receipt)
			got, err := receiptDigest(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s changed but the digest did not: it is not in the preimage", name)
			}
		})
	}
}
