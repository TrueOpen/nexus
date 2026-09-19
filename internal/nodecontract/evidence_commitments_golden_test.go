package nodecontract

import (
	"encoding/hex"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Values observed on chain: this receipt is the one the Keeper rejected in devlocal, and the two expected
// values are taken directly from node's own EvidenceCommitmentsHash / InferReceiptSigningDigest output
// (x/task/types).
//
// The difference was in how required_evidence_commitments is assembled: node collapses the whole list into
// ONE nested field (each element carrying its own length prefix inside), whereas nexus previously treated
// each element as an independent top-level field, missing the outer wrapper. The element frames match on
// both sides, so the mismatch only appears when the list is non-empty; for an empty list both encodings coincide,
// which is why the unit tests stayed green until a real receipt carried an evidence commitment.
//
// The consequence was chain rejection: nexus verified the Worker signature against its own digest and passed,
// the Keeper reported "signature does not verify against signing digest" against its own; the same signature got opposite verdicts.
//
// Since wire v0.4.1 the receipt is InferReceiptV2 (domain raised to TRUEOPEN_INFER_RECEIPT_V2, with
// generated_token_count and output_leaf_count appended). This on-chain receipt is from the V1 era; its
// receipt digest cannot be reproduced under V2 and must not be "changed to a new value" and passed off as observed.
// Only evidence_commitments_hash is kept here: that domain was not re-versioned, the observed value is still
// valid, and it is exactly the layer where the bug was. The V2 receipt digest is checked against the wire published vector in inferreceipt_v2_golden_test.go.
const goldenCommitmentsHashHex = "fcfc775b30d732bdb69387af47eb6a1893386054fa12799a126f1bc8a7830e09"

func TestEvidenceCommitmentsHashMatchesChain(t *testing.T) {
	receipt := goldenChainReceipt(t)

	commitments, err := EvidenceCommitmentsHash(receipt.GetRequiredEvidenceCommitments())
	if err != nil {
		t.Fatalf("commitments hash: %v", err)
	}
	if got := hex.EncodeToString(commitments[:]); got != goldenCommitmentsHashHex {
		t.Fatalf("evidence_commitments_hash = %s, chain computed %s", got, goldenCommitmentsHashHex)
	}
}

// Both encodings agree on the empty list, so this cannot catch the defect; it is kept to document why the unit tests missed it.
func TestEvidenceCommitmentsHashIsStillDefinedForAnEmptyList(t *testing.T) {
	if _, err := EvidenceCommitmentsHash(nil); err != nil {
		t.Fatalf("empty list must have a defined value: %v", err)
	}
}

func goldenChainReceipt(t *testing.T) *taskv1.InferReceiptV2 {
	t.Helper()
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &taskv1.InferReceiptV2{
		// The observed data is from the V1 era, so schema_version stays 1; this test only uses its commitments list.
		SchemaVersion:             1,
		ChainId:                   "trueopen-localnet-1",
		TaskId:                    mustHex("0696367c45d8ab4de9e18b289fa5df76d86e8a20539e3ddac33551d78f72fed6"),
		TaskHash:                  mustHex("dd149868c68a888924870c031af1d83784580d72c7541c29f68c78c2717cddb0"),
		WorkerOperatorAddress:     "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k",
		ServiceAuthorizationNonce: 1,
		GenerationParamsDigest:    mustHex("2f4fac4607c697feb81161ed776ed2cbabd2a93f42a5cd0b3f984b0db19d423d"),
		OutputHash:                mustHex("3f473a5930a3b347f63a6579f443cd456cdf05f2b4ef607be850179af9a35753"),
		OutputSizeBytes:           88,
		ExpiryHeight:              131708,
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind:       sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING,
			EvidenceHashOrRoot: mustHex("69784b36f25819ef6b2444f0188e947b17faa651ccd52af1a21c142f24e5f028"),
			EncodedSizeBytes:   145,
		}},
	}
}
