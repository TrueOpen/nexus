package nodecontract

import (
	"encoding/hex"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// The verify_commit_v1 vector from the in-repo testdata/task_domains_v1.json.
func TestVerifyCommitSigningDigestGolden(t *testing.T) {
	commit := &taskv1.VerifyCommitV1{
		SchemaVersion:             VerifyCommitSchemaVersionV1,
		ChainId:                   "trueopen-unblock-1",
		TaskId:                    mustHexBytes(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		VerifyRound:               3,
		VerifierOperatorAddress:   "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		ServiceAuthorizationNonce: 7,
		CommitHash:                mustHexBytes(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
		ExpiryHeight:              1200,
		// service_signature does not enter the preimage: fill a non-zero value, the digest must not change.
		ServiceSignature: make([]byte, 64),
	}
	digest, err := VerifyCommitSigningDigest(commit)
	if err != nil {
		t.Fatal(err)
	}
	const want = "3c3c2df8a81d5698ecd9b5de4a40328abc9b5185d8eb0c8dab74cc32e69fdb9f"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("verify_commit_signing_digest = %s, want %s", got, want)
	}
	for i := range commit.ServiceSignature {
		commit.ServiceSignature[i] = 0xff
	}
	again, err := VerifyCommitSigningDigest(commit)
	if err != nil {
		t.Fatal(err)
	}
	if again != digest {
		t.Fatal("service_signature must not enter the preimage")
	}
}

// The result_v2_signing_digest and metric_summary_v1 vectors from wire v0.4.1
// testdata/v1/task/result_receipt_v2.json. The metric summary is a nested frame; pinning it
// separately lets optional-encoding problems be located apart from whole-preimage problems.
func goldenResultReceiptV2(t *testing.T) *taskv1.ResultReceiptV2 {
	t.Helper()
	topk := uint32(900000)
	unionJS := uint32(50000)
	return &taskv1.ResultReceiptV2{
		SchemaVersion:             2,
		ChainId:                   "trueopen-golden-1",
		TaskId:                    mustHexBytes(t, strings.Repeat("11", 32)),
		VerifyRound:               1,
		VerifierOperatorAddress:   "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    mustHexBytes(t, strings.Repeat("55", 32)),
		MetricRoot:                mustHexBytes(t, strings.Repeat("66", 32)),
		MetricSummary: &taskv1.MetricSummaryV1{
			FiniteCount: 3, MissingComparedCount: 0,
			MeanAbsLogprobDiffFp_1E6: 10000, AbsLogprobDiffP95Fp_1E6: 20000,
			AbsLogprobDiffP99Fp_1E6: 30000, RankDeltaNonzeroRateFp_1E6: 40000,
			TopkJaccardMeanFp_1E6: &topk, UnionJsP99Fp_1E6: &unionJS,
			ComparedTopkCount: 3, ComparedRankCount: 3,
		},
		AggregateProofHash:                mustHexBytes(t, "6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2"),
		VerifierEvidenceBundleHash:        mustHexBytes(t, "9b568692f6d7f01cbc7d6d8fa79d37c73c5e24e6e1f533fe7620be6ea2c9d341"),
		VerifierEvidenceManifestSizeBytes: 556,
		Salt:                              mustHexBytes(t, strings.Repeat("aa", 32)),
		ExpiryHeight:                      2000,
		ServiceSignature:                  make([]byte, 64),
	}
}

func TestMetricSummaryHashGolden(t *testing.T) {
	digest, err := MetricSummaryHash(goldenResultReceiptV2(t).GetMetricSummary())
	if err != nil {
		t.Fatal(err)
	}
	const want = "ded3683559777e9ac37623b9d04ab7967c3f4fd0686282d187d9de65381f53bf"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("metric_summary_hash = %s, want %s", got, want)
	}
}

func TestResultReceiptSigningDigestGolden(t *testing.T) {
	receipt := goldenResultReceiptV2(t)
	digest, err := ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	const want = "436017aad2b7e9611063df868aacb8cf1f5e9001a230bcf0b329fa00a00b42a2"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("result_receipt_signing_digest = %s, want %s", got, want)
	}
}

// The three fields V2 adds over V1 must really enter the preimage. Missing any one of them, a
// V1-era signature could pass as a V2 receipt while the Keeper computes a different value.
func TestResultReceiptSigningDigestBindsV2Fields(t *testing.T) {
	base, err := ResultReceiptSigningDigest(goldenResultReceiptV2(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*taskv1.ResultReceiptV2){
		"verifier_evidence_bundle_hash": func(r *taskv1.ResultReceiptV2) {
			r.VerifierEvidenceBundleHash = mustHexBytes(t, strings.Repeat("bb", 32))
		},
		"verifier_evidence_manifest_size_bytes": func(r *taskv1.ResultReceiptV2) {
			r.VerifierEvidenceManifestSizeBytes = 557
		},
		"salt": func(r *taskv1.ResultReceiptV2) {
			r.Salt = mustHexBytes(t, strings.Repeat("bb", 32))
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt := goldenResultReceiptV2(t)
			mutate(receipt)
			got, err := ResultReceiptSigningDigest(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatalf("%s is not in the preimage", name)
			}
		})
	}
}

// The two optionals of the metric summary: presence is decided by the locked profile MetricSpec;
// absent and "filled with 0" are two different commitments, and the implementation must not turn
// the former into the latter.
func TestMetricSummaryOptionalPresenceIsCommitted(t *testing.T) {
	present := goldenResultReceiptV2(t).GetMetricSummary()
	withPresent, err := MetricSummaryHash(present)
	if err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	absent := goldenResultReceiptV2(t).GetMetricSummary()
	absent.TopkJaccardMeanFp_1E6 = nil
	absentHash, err := MetricSummaryHash(absent)
	if err != nil {
		t.Fatal(err)
	}
	filled := goldenResultReceiptV2(t).GetMetricSummary()
	filled.TopkJaccardMeanFp_1E6 = &zero
	filledHash, err := MetricSummaryHash(filled)
	if err != nil {
		t.Fatal(err)
	}
	if absentHash == filledHash || absentHash == withPresent || filledHash == withPresent {
		t.Fatal("absent, filled with 0 and the actual value must be three different digests")
	}
}

// The commit_key_v1 vector from wire testdata/v1/task/task_domains_v1.json.
func TestCommitKeyGolden(t *testing.T) {
	key, err := CommitKey("trueopen-unblock-1",
		mustHexBytes(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		3, "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe")
	if err != nil {
		t.Fatal(err)
	}
	const want = "3663aac9f8f83a460efb8126fe54f0056eea1ec3a76b645bac1e8854f4d3521e"
	if got := hex.EncodeToString(key[:]); got != want {
		t.Fatalf("commit_key = %s, want %s", got, want)
	}
}
