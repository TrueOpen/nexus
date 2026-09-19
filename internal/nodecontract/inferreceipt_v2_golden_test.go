package nodecontract

import (
	"encoding/hex"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Byte-for-byte with wire v0.4.1 `testdata/v1/task/infer_receipt_v2.json`. It is the Phase 0 frozen
// contract's (monorepo#142) published vector for TRUEOPEN_INFER_RECEIPT_V2; node, cortex, SDK and
// nexus all check against the same values. The in-repo testdata/task_domains_v1.json is the vector for our
// own pipeline; neither replaces the other: this one proves our preimage matches the external contract,
// that one covers the tamper and replay shapes.
const (
	wireV2ChainID    = "trueopen-golden-1"
	wireV2TaskID     = "1111111111111111111111111111111111111111111111111111111111111111"
	wireV2TaskHash   = "2222222222222222222222222222222222222222222222222222222222222222"
	wireV2Worker     = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	wireV2GenParams  = "3333333333333333333333333333333333333333333333333333333333333333"
	wireV2OutputHash = "1d07690eb524833c073fe74787e52a25e426ed09013500d3dd43f7f363f65ec0"
	wireV2Commitment = "fa05047203b16b229e016fc61d1572cf51ab75c87c4bc01ecd365d0656b1d16d"

	wireV2CommitmentsHash = "84f8c80436e58b32463bbd2da1715a93a131aba9880e6d1c3138f76914f86929"
	wireV2Digest          = "3e3ba35e0267a39132f78d57d0e7ec20adf3d6a10f65936ac81b4036480cd2d0"
)

func wireV2Receipt(t *testing.T) *taskv1.InferReceiptV2 {
	t.Helper()
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &taskv1.InferReceiptV2{
		SchemaVersion:             InferReceiptSchemaVersionV2,
		ChainId:                   wireV2ChainID,
		TaskId:                    mustHex(wireV2TaskID),
		TaskHash:                  mustHex(wireV2TaskHash),
		WorkerOperatorAddress:     wireV2Worker,
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    mustHex(wireV2GenParams),
		OutputHash:                mustHex(wireV2OutputHash),
		OutputSizeBytes:           6,
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind:       sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING,
			EvidenceHashOrRoot: mustHex(wireV2Commitment),
			EncodedSizeBytes:   40,
		}},
		ExpiryHeight:        2000,
		GeneratedTokenCount: 3,
		OutputLeafCount:     3,
	}
}

func TestWireV041InferReceiptV2Vector(t *testing.T) {
	receipt := wireV2Receipt(t)

	commitments, err := EvidenceCommitmentsHash(receipt.GetRequiredEvidenceCommitments())
	if err != nil {
		t.Fatalf("commitments hash: %v", err)
	}
	if got := hex.EncodeToString(commitments[:]); got != wireV2CommitmentsHash {
		t.Fatalf("evidence_commitments_hash = %s, want %s", got, wireV2CommitmentsHash)
	}

	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("receipt digest: %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got != wireV2Digest {
		t.Fatalf("infer_receipt_signing_digest = %s, want %s", got, wireV2Digest)
	}
}

// The two new V2 fields must really enter the preimage: skipping either must break equality with the published vector.
// Without this, an implementation that copied the fields but left them out of the preimage would pass every other test.
func TestWireV041InferReceiptV2BindsNewFields(t *testing.T) {
	for name, mutate := range map[string]func(*taskv1.InferReceiptV2){
		"generated_token_count": func(r *taskv1.InferReceiptV2) { r.GeneratedTokenCount = 0 },
		"output_leaf_count":     func(r *taskv1.InferReceiptV2) { r.OutputLeafCount = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := wireV2Receipt(t)
			mutate(receipt)
			digest, err := InferReceiptSigningDigest(receipt)
			if err != nil {
				t.Fatalf("receipt digest: %v", err)
			}
			if hex.EncodeToString(digest[:]) == wireV2Digest {
				t.Fatalf("%s is not in the preimage: changing it left the digest unchanged", name)
			}
		})
	}
}

// The domain must be V2. Phase 0 has no V1 decoder, and a digest computed under the old domain is never
// accepted by the Keeper, so a wrong domain name must surface here rather than as a signature failure on chain.
func TestInferReceiptDomainIsV2(t *testing.T) {
	if DomainInferReceiptV2 != "TRUEOPEN_INFER_RECEIPT_V2" {
		t.Fatalf("domain = %s", DomainInferReceiptV2)
	}
	receipt := wireV2Receipt(t)
	legacy := CanonicalHashBytes(
		"TRUEOPEN_INFER_RECEIPT_V1",
		Uint32BE(receipt.GetSchemaVersion()),
	)
	if hex.EncodeToString(legacy[:]) == wireV2Digest {
		t.Fatal("the old domain must not produce the same digest")
	}
}
