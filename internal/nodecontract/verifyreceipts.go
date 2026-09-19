package nodecontract

import (
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Since wire v0.4.1 the three relay requests carry only the on-chain message body, and the
// authorization is the message's own service_signature. Nexus therefore must be able to compute
// the signing digest of every on-chain message it forwards. Previously commit / result
// authorization went through nexus's own request envelope and the body was relayed as is;
// that no longer works.
const (
	// DomainCommitKeyV1 is the domain of commit_key (Keeper Interface Contract §10.9): the
	// primary key of CommitState / ResultReceiptState and also SubmitVerifyCommitResponse.commit_key.
	DomainCommitKeyV1     = "TRUEOPEN_COMMIT_KEY_V1"
	DomainVerifyCommitV1  = "TRUEOPEN_COMMIT_V1"
	DomainMetricSummaryV1 = "TRUEOPEN_METRIC_SUMMARY_V1"
	DomainResultV2        = "TRUEOPEN_RESULT_V2"
)

// VerifyCommitSchemaVersionV1 is the schema_version of VerifyCommitV1. It does not follow
// InferReceipt up to 2: in the fresh contract only InferReceiptV2 and ResultReceiptV2 use 2.
const VerifyCommitSchemaVersionV1 uint32 = 1

// VerifyCommitSigningDigest is the verify_commit_signing_digest frozen in §5.14:
//
//	H_FIELDS_V1("TRUEOPEN_COMMIT_V1", schema_version, chain_id, task_id, verify_round,
//	  verifier_operator_address, service_authorization_nonce, commit_hash, expiry_height)
//
// 8 fields; service_signature is not among them. commit_key is recomputed by the Keeper and is
// not a caller field.
func VerifyCommitSigningDigest(commit *taskv1.VerifyCommitV1) ([32]byte, error) {
	if commit == nil {
		return [32]byte{}, fmt.Errorf("verify commit is required")
	}
	chainID, err := CanonicalUTF8Field("chain_id", commit.GetChainId())
	if err != nil {
		return [32]byte{}, err
	}
	taskID, err := CanonicalHash32Field("task_id", commit.GetTaskId())
	if err != nil {
		return [32]byte{}, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", commit.GetVerifierOperatorAddress())
	if err != nil {
		return [32]byte{}, err
	}
	commitHash, err := CanonicalHash32Field("commit_hash", commit.GetCommitHash())
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(
		DomainVerifyCommitV1,
		Uint32BE(commit.GetSchemaVersion()),
		chainID,
		taskID,
		Uint32BE(commit.GetVerifyRound()),
		verifier,
		Uint64BE(commit.GetServiceAuthorizationNonce()),
		commitHash,
		Uint64BE(commit.GetExpiryHeight()),
	), nil
}

// CanonicalMetricSummaryFrame is the nested FieldFrameV1 of MetricSummaryV1: ten fields in
// ascending schema field-number order, no domain prefix. Fields 7 and 8 are proto3 optional and
// encoded per §4.4 (absent: single byte 0x00; present: 0x01 || u64be(len) || value). Whether they
// are present is decided by the locked profile MetricSpec; the implementation must not fill in
// defaults on its own.
func CanonicalMetricSummaryFrame(summary *taskv1.MetricSummaryV1) ([]byte, error) {
	if summary == nil {
		return nil, fmt.Errorf("metric summary is required")
	}
	optional := func(value *uint32) []byte {
		if value == nil {
			return []byte{0x00}
		}
		return append([]byte{0x01}, CanonicalFrameBytes(Uint32BE(*value))...)
	}
	return CanonicalFrameBytes(
		Uint32BE(summary.GetFiniteCount()),
		Uint32BE(summary.GetMissingComparedCount()),
		Uint32BE(summary.GetMeanAbsLogprobDiffFp_1E6()),
		Uint32BE(summary.GetAbsLogprobDiffP95Fp_1E6()),
		Uint32BE(summary.GetAbsLogprobDiffP99Fp_1E6()),
		Uint32BE(summary.GetRankDeltaNonzeroRateFp_1E6()),
		optional(summary.TopkJaccardMeanFp_1E6),
		optional(summary.UnionJsP99Fp_1E6),
		Uint32BE(summary.GetComparedTopkCount()),
		Uint32BE(summary.GetComparedRankCount()),
	), nil
}

// MetricSummaryHash is the metric_summary_hash of §9.7. It is recomputed by the Keeper and
// requests must not assert it; nexus uses it only in local decisions and never puts it into
// any upstream message.
func MetricSummaryHash(summary *taskv1.MetricSummaryV1) ([32]byte, error) {
	frame, err := CanonicalMetricSummaryFrame(summary)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainMetricSummaryV1, frame), nil
}

// ResultReceiptSigningDigest is the result_receipt_signing_digest frozen in §5.14:
//
//	H_FIELDS_V1("TRUEOPEN_RESULT_V2", schema_version, chain_id, task_id, verify_round,
//	  verifier_operator_address, service_authorization_nonce, generation_params_digest,
//	  metric_root, canonical metric_summary, aggregate_proof_hash,
//	  verifier_evidence_bundle_hash, verifier_evidence_manifest_size_bytes, salt,
//	  expiry_height)
//
// 14 fields; service_signature is not among them. commit_key, metric_summary_hash and
// result_payload_hash are recomputed by the Keeper and requests must not assert them.
func ResultReceiptSigningDigest(receipt *taskv1.ResultReceiptV2) ([32]byte, error) {
	if receipt == nil {
		return [32]byte{}, fmt.Errorf("result receipt is required")
	}
	chainID, err := CanonicalUTF8Field("chain_id", receipt.GetChainId())
	if err != nil {
		return [32]byte{}, err
	}
	taskID, err := CanonicalHash32Field("task_id", receipt.GetTaskId())
	if err != nil {
		return [32]byte{}, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", receipt.GetVerifierOperatorAddress())
	if err != nil {
		return [32]byte{}, err
	}
	summary, err := CanonicalMetricSummaryFrame(receipt.GetMetricSummary())
	if err != nil {
		return [32]byte{}, err
	}
	hashes := make([][]byte, 0, 5)
	for _, f := range []struct {
		name  string
		value []byte
	}{
		{"generation_params_digest", receipt.GetGenerationParamsDigest()},
		{"metric_root", receipt.GetMetricRoot()},
		{"aggregate_proof_hash", receipt.GetAggregateProofHash()},
		{"verifier_evidence_bundle_hash", receipt.GetVerifierEvidenceBundleHash()},
		{"salt", receipt.GetSalt()},
	} {
		field, err := CanonicalHash32Field(f.name, f.value)
		if err != nil {
			return [32]byte{}, err
		}
		hashes = append(hashes, field)
	}
	return CanonicalHashBytes(
		DomainResultV2,
		Uint32BE(receipt.GetSchemaVersion()),
		chainID,
		taskID,
		Uint32BE(receipt.GetVerifyRound()),
		verifier,
		Uint64BE(receipt.GetServiceAuthorizationNonce()),
		hashes[0], // generation_params_digest
		hashes[1], // metric_root
		summary,
		hashes[2], // aggregate_proof_hash
		hashes[3], // verifier_evidence_bundle_hash
		Uint64BE(receipt.GetVerifierEvidenceManifestSizeBytes()),
		hashes[4], // salt
		Uint64BE(receipt.GetExpiryHeight()),
	), nil
}

// CommitKey recomputes commit_key per Keeper Interface Contract §10.9:
//
//	H_FIELDS_V1("TRUEOPEN_COMMIT_KEY_V1", chain_id, task_id, verify_round, verifier_operator_address)
//
// verify_round is uint32_be and verifier_operator_address is the operator's address codec bytes.
// It is not a caller field: after relaying the commit, nexus returns it to the Verifier, matching
// the Keeper's primary key.
func CommitKey(chainID string, taskID []byte, verifyRound uint32, verifierOperator string) ([32]byte, error) {
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return [32]byte{}, err
	}
	task, err := CanonicalHash32Field("task_id", taskID)
	if err != nil {
		return [32]byte{}, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", verifierOperator)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainCommitKeyV1, chain, task, Uint32BE(verifyRound), verifier), nil
}
