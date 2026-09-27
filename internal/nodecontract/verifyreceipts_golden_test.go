package nodecontract

import (
	"encoding/hex"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// The verify_commit_v1 vector from wire testdata/v1/task/task_domains_v1.json.
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

// wireResultReceipt builds the ResultReceiptV3 of the result_v3_signing_digest vector of wire
// testdata/v1/task/result_receipt_v3.json.
func wireResultReceipt(t *testing.T) (*taskv1.ResultReceiptV3, wirefixture.Vector) {
	t.Helper()
	v := wirefixture.Load(t, "task/result_receipt_v3.json").Vector(t, "result_v3_signing_digest", 0)
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	summary := &taskv1.MetricSummaryV1{}
	for _, m := range f("metric_summary").Fields {
		var value uint32
		if m.Type != "optional" {
			value = uint32(m.Uint64(t))
		} else if m.Present {
			value = uint32(m.Fields[0].Uint64(t))
		}
		opt := func() *uint32 {
			if !m.Present {
				return nil
			}
			return &value
		}
		switch m.Name {
		case "finite_count":
			summary.FiniteCount = value
		case "missing_compared_count":
			summary.MissingComparedCount = value
		case "mean_abs_logprob_diff_fp_1e6":
			summary.MeanAbsLogprobDiffFp_1E6 = value
		case "abs_logprob_diff_p95_fp_1e6":
			summary.AbsLogprobDiffP95Fp_1E6 = value
		case "abs_logprob_diff_p99_fp_1e6":
			summary.AbsLogprobDiffP99Fp_1E6 = value
		case "rank_delta_nonzero_rate_fp_1e6":
			summary.RankDeltaNonzeroRateFp_1E6 = value
		case "topk_jaccard_mean_fp_1e6":
			summary.TopkJaccardMeanFp_1E6 = opt()
		case "union_js_p99_fp_1e6":
			summary.UnionJsP99Fp_1E6 = opt()
		case "compared_topk_count":
			summary.ComparedTopkCount = value
		case "compared_rank_count":
			summary.ComparedRankCount = value
		default:
			t.Fatalf("unknown metric summary field %s", m.Name)
		}
	}
	return &taskv1.ResultReceiptV3{
		SchemaVersion:                     uint32(f("schema_version").Uint64(t)),
		ChainId:                           f("chain_id").UTF8,
		TaskId:                            f("task_id").Bytes(t),
		VerifyRound:                       uint32(f("verify_round").Uint64(t)),
		VerifierOperatorAddress:           accAddress(t, f("verifier_operator_address").Bytes(t)),
		ServiceAuthorizationNonce:         f("service_authorization_nonce").Uint64(t),
		GenerationParamsDigest:            f("generation_params_digest").Bytes(t),
		MetricRoot:                        f("metric_root").Bytes(t),
		MetricSummary:                     summary,
		AggregateProofHash:                f("aggregate_proof_hash").Bytes(t),
		VerifierEvidenceBundleHash:        f("verifier_evidence_bundle_hash").Bytes(t),
		VerifierEvidenceManifestSizeBytes: f("verifier_evidence_manifest_size_bytes").Uint64(t),
		Salt:                              f("salt").Bytes(t),
		ExpiryHeight:                      f("expiry_height").Uint64(t),
		VerifierValueRoot:                 f("verifier_value_root").Bytes(t),
		MetricLeafCount:                   uint32(f("metric_leaf_count").Uint64(t)),
		VerifierEvidenceKeyCommitment:     f("verifier_evidence_key_commitment").Bytes(t),
		ServiceSignature:                  make([]byte, 64),
	}, v
}

func TestMetricSummaryHashGolden(t *testing.T) {
	receipt, _ := wireResultReceipt(t)
	digest, err := MetricSummaryHash(receipt.GetMetricSummary())
	if err != nil {
		t.Fatal(err)
	}
	want := wirefixture.Load(t, "task/result_receipt_v3.json").Vector(t, "metric_summary_v1", 0)
	if digest != want.Digest(t) {
		t.Fatalf("metric_summary_hash = %x, want %s", digest, want.DigestHex)
	}
}

func TestResultReceiptSigningDigestGolden(t *testing.T) {
	receipt, v := wireResultReceipt(t)
	v.CheckPreimage(t)
	if receipt.GetSchemaVersion() != ResultReceiptSchemaVersionV3 {
		t.Fatalf("wire schema_version = %d, want %d", receipt.GetSchemaVersion(), ResultReceiptSchemaVersionV3)
	}
	digest, err := ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("result_receipt_signing_digest = %x, want %s", digest, v.DigestHex)
	}
	if err := ValidatePlaintextResultReceiptV3(receipt); err != nil {
		t.Fatalf("the wire plaintext result must pass admission: %v", err)
	}
}

// The fields V3 adds must really enter the preimage; a plaintext result must carry 32 zero bytes,
// not an empty key commitment.
func TestResultReceiptSigningDigestBindsV3Fields(t *testing.T) {
	base, _ := wireResultReceipt(t)
	digest, err := ResultReceiptSigningDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*taskv1.ResultReceiptV3){
		"verifier_value_root": func(r *taskv1.ResultReceiptV3) { r.VerifierValueRoot = mustHexBytes(t, strings.Repeat("bb", 32)) },
		"metric_leaf_count":   func(r *taskv1.ResultReceiptV3) { r.MetricLeafCount++ },
		"verifier_evidence_key_commitment": func(r *taskv1.ResultReceiptV3) {
			r.VerifierEvidenceKeyCommitment = mustHexBytes(t, strings.Repeat("cc", 32))
		},
		"salt": func(r *taskv1.ResultReceiptV3) { r.Salt = mustHexBytes(t, strings.Repeat("bb", 32)) },
	} {
		t.Run(name, func(t *testing.T) {
			receipt, _ := wireResultReceipt(t)
			mutate(receipt)
			got, err := ResultReceiptSigningDigest(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if got == digest {
				t.Fatalf("%s is not in the preimage", name)
			}
		})
	}
	empty, _ := wireResultReceipt(t)
	empty.VerifierEvidenceKeyCommitment = nil
	if err := ValidatePlaintextResultReceiptV3(empty); err == nil {
		t.Fatal("an empty key commitment must be refused, not treated as zero")
	}
	short, _ := wireResultReceipt(t)
	short.VerifierValueRoot = nil
	if _, err := ResultReceiptSigningDigest(short); err == nil {
		t.Fatal("a missing verifier_value_root must not produce a digest")
	}
}

// The two optionals of the metric summary: presence is decided by the locked profile MetricSpec;
// absent and "filled with 0" are two different commitments, and the implementation must not turn
// the former into the latter.
func TestMetricSummaryOptionalPresenceIsCommitted(t *testing.T) {
	receipt, _ := wireResultReceipt(t)
	present := receipt.GetMetricSummary()
	value := uint32(900000)
	present.TopkJaccardMeanFp_1E6 = &value
	withPresent, err := MetricSummaryHash(present)
	if err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	receipt, _ = wireResultReceipt(t)
	absent := receipt.GetMetricSummary()
	absent.TopkJaccardMeanFp_1E6 = nil
	absentHash, err := MetricSummaryHash(absent)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ = wireResultReceipt(t)
	filled := receipt.GetMetricSummary()
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
