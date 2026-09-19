package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"google.golang.org/protobuf/proto"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// Worker / Verifier side submission methods (Nexus<->Cortex interface contract v0.2 §2.4 / §2.5 / §2.6).
//
// Common conventions:
//   - Cortex does not use the SDK request envelope but Worker/Verifier role signatures; the exact structure of the role
//     signature envelope and SignBytes is not frozen (contract §8.2) and currently lands on TaskDataRequestAuthV1.
//   - RPC success only means the current Builder commits to relaying it, never on-chain accepted (contract §7 mandatory rule).
//   - Nexus must not generate role signatures on behalf of a Cortex Node, nor re-sign or generate verdicts.

// SubmitInferReceipt, contract §2.4: the Builder commits to relaying it after accepting a valid signed InferReceipt,
// without waiting for output/evidence upload to finish; the Worker must still upload large objects to the Task Builders afterwards.
func (s *service) SubmitInferReceipt(
	ctx context.Context,
	req *connect.Request[nexusv1.SubmitInferReceiptRequest],
) (*connect.Response[nexusv1.SubmitInferReceiptResponse], error) {
	m := req.Msg
	receipt, err := inferReceiptFromPB(m, s.auth.ChainID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Since wire v0.4.1 the request carries only the on-chain message body: the authorization is the receipt's own
	// service_signature over the TRUEOPEN_INFER_RECEIPT_V2 digest, with no extra request envelope. The Worker's
	// current service key is registered under the CORTEX domain.
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.verifyParticipantRoleDigest(ctx, servicekey.ParticipantCortex, receipt.WorkerAddress,
		digest[:], receipt.WorkerServiceSignature); err != nil {
		return nil, mapRoleSignatureErr(err)
	}
	// The request carries only the on-chain message body, and the on-chain task_id has no session; the FSM is keyed by
	// (session, task), so like SubmitVerifyCommit / SubmitVerifyResult the session is looked up by task_id first.
	// No match means this Builder is not following the task: NotFound; do not pass an empty session downstream.
	receipt.SessionID, err = s.h.SessionForTask(ctx, receipt.TaskID)
	if err != nil {
		return nil, mapInferReceiptErr(err)
	}
	if err := s.h.OnInferReceipt(ctx, receipt); err != nil {
		return nil, mapInferReceiptErr(err)
	}
	response := &nexusv1.SubmitInferReceiptResponse{
		RelayAccepted: true, InferReceiptHash: hex.EncodeToString(receipt.InferReceiptHash),
	}
	// wire v0.4.1 marked output_storage_confirmation here as reserved: the storage confirmation is now issued once by
	// FinalizeTaskResult after checking the receipt, the STORED output and all required evidence
	// (design §5.5); the transport-level receipt must not prematurely express "the whole Task Result is READY".
	return connect.NewResponse(response), nil
}

// SubmitVerifyCommit, contract §2.5: the initial relay implementation trusts the Builder; the commit signed by the selected Verifier is
// relayed on-chain by this Builder as MsgBatchSubmitVerifyCommit.
//
// Request validation and role signature verification come first: invalid requests are rejected with InvalidArgument / PermissionDenied here;
// the body is relayed as is, Nexus rewrites or fills in nothing. Success only means broadcast, not on-chain accepted;
// a Verifier that does not observe accepted before the deadline still submits the same message directly per the contract.
func (s *service) SubmitVerifyCommit(
	ctx context.Context,
	req *connect.Request[nexusv1.SubmitVerifyCommitRequest],
) (*connect.Response[nexusv1.SubmitVerifyCommitResponse], error) {
	m := req.Msg
	commit, err := verifyCommitFromPB(m, s.auth.ChainID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	digest, err := nodecontract.VerifyCommitSigningDigest(commit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.verifyParticipantRoleDigest(ctx, servicekey.ParticipantCortex,
		commit.GetVerifierOperatorAddress(), digest[:], commit.GetServiceSignature()); err != nil {
		return nil, mapRoleSignatureErr(err)
	}
	sessionID, err := s.h.SessionForTask(ctx, hex.EncodeToString(commit.GetTaskId()))
	if err != nil {
		return nil, mapVerifyRelayErr(err)
	}
	ack, err := s.h.OnVerifyCommit(ctx, sessionID, hex.EncodeToString(commit.GetTaskId()), commit)
	if err != nil {
		return nil, mapVerifyRelayErr(err)
	}
	// commit_key is the primary key of the Keeper-side CommitState (interface contract §10.9), returned to the Verifier
	// so it can match on-chain state; Cortex requires it to be a non-zero Hash32, and an empty value makes the commit look unsuccessful.
	commitKey, err := nodecontract.CommitKey(commit.GetChainId(), commit.GetTaskId(),
		commit.GetVerifyRound(), commit.GetVerifierOperatorAddress())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&nexusv1.SubmitVerifyCommitResponse{
		RelayAccepted: true, Idempotent: ack.Idempotent,
		CommitKey:                 hex.EncodeToString(commitKey[:]),
		VerifyCommitSigningDigest: hex.EncodeToString(digest[:]),
	}), nil
}

// SubmitVerifyResult, contract §2.6: same rules as SubmitVerifyCommit, relayed as
// MsgBatchSubmitVerifyResult. It carries the same ResultReceiptV2 as the VERIFY_RESULT JetStream path,
// and material_digest is identical on both paths.
func (s *service) SubmitVerifyResult(
	ctx context.Context,
	req *connect.Request[nexusv1.SubmitVerifyResultRequest],
) (*connect.Response[nexusv1.SubmitVerifyResultResponse], error) {
	m := req.Msg
	receipt, err := resultReceiptFromPB(m, s.auth.ChainID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	digest, err := nodecontract.ResultReceiptSigningDigest(receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.verifyParticipantRoleDigest(ctx, servicekey.ParticipantCortex,
		receipt.GetVerifierOperatorAddress(), digest[:], receipt.GetServiceSignature()); err != nil {
		return nil, mapRoleSignatureErr(err)
	}
	taskID := hex.EncodeToString(receipt.GetTaskId())
	sessionID, err := s.h.SessionForTask(ctx, taskID)
	if err != nil {
		return nil, mapVerifyRelayErr(err)
	}
	ack, err := s.h.OnVerifyResult(ctx, sessionID, taskID, receipt)
	if err != nil {
		return nil, mapVerifyRelayErr(err)
	}
	// result_payload_hash is recomputed by the Keeper and the receipt does not assert it; only the signing digest is returned
	// so the Verifier can confirm the Builder received the same thing it signed.
	return connect.NewResponse(&nexusv1.SubmitVerifyResultResponse{
		RelayAccepted: true, Idempotent: ack.Idempotent,
		ResultReceiptSigningDigest: hex.EncodeToString(digest[:]),
	}), nil
}

// verifyResultMaterialDigest is the §2.6 material digest: sha256 of the deterministic proto encoding of
// ResultReceiptV2; the API and JetStream paths compute the same value for the same receipt.
func verifyResultMaterialDigest(receipt *taskv1.ResultReceiptV2) (string, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		return "", fmt.Errorf("encode result receipt: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// mapVerifyRelayErr maps relay failures to Connect error codes. Transient failures such as a temporarily unreachable
// chain map to Unavailable: the caller may retry or fall back to direct submission per the contract.
func mapVerifyRelayErr(err error) error {
	switch {
	case errors.Is(err, types.ErrTaskNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("task not found"))
	case errors.Is(err, types.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, types.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, types.ErrFailedPrecondition):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeUnavailable, err)
	}
}

// inferReceiptFromPB validates the minimal semantics of contract §2.4 and converts to the internal submission object.
//
// The receipt no longer carries a self-declared copy of infer_receipt_hash: §5.14 defines infer_receipt_hash and
// infer_receipt_signing_digest as the same value, so it is **derived** here rather than compared --
// the structural checks of InferReceiptSigningDigest (Hash32 length, strict UTF-8, canonical addresses,
// closed evidence kind, strictly ascending list) are the framing-layer admission checks.
func inferReceiptFromPB(m *nexusv1.SubmitInferReceiptRequest, chainID string) (types.InferReceiptSubmission, error) {
	receiptPB := m.GetReceipt()
	if receiptPB == nil {
		return types.InferReceiptSubmission{}, fmt.Errorf("%w: receipt is required", types.ErrInvalidArgument)
	}
	// schema_version equality is an admission check, not part of hash derivation: derivation stays total,
	// and non-1 is explicitly rejected here so Cortex never gets a receipt that "passes locally, never passes on-chain".
	if receiptPB.GetSchemaVersion() != nodecontract.InferReceiptSchemaVersionV2 {
		return types.InferReceiptSubmission{}, fmt.Errorf(
			"%w: schema_version must be %d", types.ErrInvalidArgument, nodecontract.InferReceiptSchemaVersionV2)
	}
	// chain_id must be this chain: it is preimage field 2 and cross-chain isolation depends entirely on it.
	if receiptPB.GetChainId() != chainID {
		return types.InferReceiptSubmission{}, fmt.Errorf("%w: receipt chain_id mismatch", types.ErrInvalidArgument)
	}
	receipt := types.InferReceiptSubmission{
		SchemaVersion:             receiptPB.GetSchemaVersion(),
		ChainID:                   receiptPB.GetChainId(),
		TaskID:                    hex.EncodeToString(receiptPB.GetTaskId()),
		TaskHash:                  hex.EncodeToString(receiptPB.GetTaskHash()),
		WorkerAddress:             receiptPB.GetWorkerOperatorAddress(),
		ServiceAuthorizationNonce: receiptPB.GetServiceAuthorizationNonce(),
		OutputSizeBytes:           receiptPB.GetOutputSizeBytes(),
		ExpiryHeight:              receiptPB.GetExpiryHeight(),
		GeneratedTokenCount:       receiptPB.GetGeneratedTokenCount(),
		OutputLeafCount:           receiptPB.GetOutputLeafCount(),
	}
	// In the on-chain message Hash32 and signatures are already raw bytes with no hex text layer;
	// internally canonical lowercase hex is still used, so only the length is checked before re-encoding.
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", receiptPB.GetTaskId()},
		{"task_hash", receiptPB.GetTaskHash()},
		{"generation_params_digest", receiptPB.GetGenerationParamsDigest()},
		{"output_hash", receiptPB.GetOutputHash()},
	} {
		if len(field.value) != sha256.Size {
			return types.InferReceiptSubmission{}, fmt.Errorf(
				"%w: %s must be 32 bytes", types.ErrInvalidArgument, field.name)
		}
	}
	receipt.GenerationParamsDigest = append([]byte(nil), receiptPB.GetGenerationParamsDigest()...)
	receipt.OutputHash = append([]byte(nil), receiptPB.GetOutputHash()...)
	if len(receiptPB.GetServiceSignature()) != 64 {
		return types.InferReceiptSubmission{}, fmt.Errorf(
			"%w: worker service_signature must be exactly 64 bytes", types.ErrInvalidArgument)
	}
	receipt.WorkerServiceSignature = append([]byte(nil), receiptPB.GetServiceSignature()...)
	if receipt.WorkerAddress == "" || receipt.OutputSizeBytes == 0 ||
		receipt.ServiceAuthorizationNonce == 0 || receipt.ExpiryHeight == 0 {
		return types.InferReceiptSubmission{}, fmt.Errorf(
			"%w: worker_operator_address, output_size_bytes, service_authorization_nonce, and expiry_height are required",
			types.ErrInvalidArgument)
	}
	// required_evidence_commitments[] is co-signed with the receipt (field 10). kind is a closed enum, and the
	// list is strictly ascending by kind and unique -- both are enforced by the derivation function, not silently reordered here.
	// "The kind set must equal the locked profile's requirements" still awaits the Verification Profile freeze (contract §8.5),
	// so set contents are not asserted and no minimum count is set (a known contract gap).
	for _, commitment := range receiptPB.GetRequiredEvidenceCommitments() {
		hashOrRoot := commitment.GetEvidenceHashOrRoot()
		if len(hashOrRoot) != sha256.Size {
			return types.InferReceiptSubmission{}, fmt.Errorf(
				"%w: evidence_hash_or_root must be 32 raw bytes", types.ErrInvalidArgument)
		}
		receipt.EvidenceCommitments = append(receipt.EvidenceCommitments, types.EvidenceCommitment{
			Kind: uint32(commitment.GetEvidenceKind()), HashOrRoot: hashOrRoot,
			EncodedSizeBytes: commitment.GetEncodedSizeBytes(),
		})
	}
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(receipt)
	if err != nil {
		return types.InferReceiptSubmission{}, fmt.Errorf("%w: %v", types.ErrInvalidArgument, err)
	}
	receipt.InferReceiptHash = digest[:]
	return receipt, nil
}

func decodeSHA256Hex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return nil, types.ErrInvalidArgument
	}
	return decoded, nil
}

// inferReceiptSignBytes is the request body covered by the Worker role signature (contract §8.2, not frozen).
// It is the **request envelope** layer binding, not the §5.14 consensus preimage: the latter is
// nodecontract.InferReceiptSigningDigest, covered by receipt.WorkerServiceSignature.
func inferReceiptSignBytes(receipt types.InferReceiptSubmission) []byte {
	fields := [][]byte{
		[]byte("TRUEOPEN_SUBMIT_INFER_RECEIPT_V1"),
		[]byte(receipt.SessionID), u32be(receipt.SchemaVersion), []byte(receipt.ChainID),
		[]byte(receipt.TaskID), []byte(receipt.TaskHash), []byte(receipt.WorkerAddress),
		u64be(receipt.ServiceAuthorizationNonce), receipt.GenerationParamsDigest,
		receipt.OutputHash, u64be(receipt.OutputSizeBytes), u64be(receipt.ExpiryHeight),
		receipt.InferReceiptHash, receipt.WorkerServiceSignature,
	}
	for _, commitment := range receipt.EvidenceCommitments {
		fields = append(fields, u32be(commitment.Kind), commitment.HashOrRoot, u64be(commitment.EncodedSizeBytes))
	}
	return sdkauth.BodyPreimage(fields...)
}

// verifyCommitFromPB does admission checks only: since wire v0.4.1 the request carries the on-chain frozen
// VerifyCommitV1 body itself, there is no second field authority to convert, and Nexus rewrites no fields.
func verifyCommitFromPB(m *nexusv1.SubmitVerifyCommitRequest, chainID string) (*taskv1.VerifyCommitV1, error) {
	pb := m.GetCommit()
	if pb == nil {
		return nil, fmt.Errorf("%w: commit is required", types.ErrInvalidArgument)
	}
	if err := checkVerifyScope(pb.GetSchemaVersion(), nodecontract.VerifyCommitSchemaVersionV1,
		pb.GetChainId(), chainID, pb.GetVerifyRound()); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", pb.GetTaskId()},
		{"commit_hash", pb.GetCommitHash()},
	} {
		if len(field.value) != sha256.Size {
			return nil, fmt.Errorf("%w: %s must be 32 bytes", types.ErrInvalidArgument, field.name)
		}
	}
	if len(pb.GetServiceSignature()) != 64 {
		return nil, fmt.Errorf("%w: service_signature must be exactly 64 bytes", types.ErrInvalidArgument)
	}
	if pb.GetVerifierOperatorAddress() == "" || pb.GetServiceAuthorizationNonce() == 0 || pb.GetExpiryHeight() == 0 {
		return nil, fmt.Errorf("%w: verifier_operator_address, service_authorization_nonce, and expiry_height are required",
			types.ErrInvalidArgument)
	}
	return pb, nil
}

// resultReceiptFromPB likewise does admission checks only. The two optionals of metric_summary pass through as is:
// their presence is decided by the locked profile MetricSpec, and absent versus 0 are two different commitments.
func resultReceiptFromPB(m *nexusv1.SubmitVerifyResultRequest, chainID string) (*taskv1.ResultReceiptV2, error) {
	pb := m.GetReceipt()
	if pb == nil {
		return nil, fmt.Errorf("%w: receipt is required", types.ErrInvalidArgument)
	}
	if err := checkVerifyScope(pb.GetSchemaVersion(), nodecontract.ResultReceiptSchemaVersionV2,
		pb.GetChainId(), chainID, pb.GetVerifyRound()); err != nil {
		return nil, err
	}
	if pb.GetMetricSummary() == nil {
		return nil, fmt.Errorf("%w: metric_summary is required", types.ErrInvalidArgument)
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", pb.GetTaskId()},
		{"generation_params_digest", pb.GetGenerationParamsDigest()},
		{"metric_root", pb.GetMetricRoot()},
		{"aggregate_proof_hash", pb.GetAggregateProofHash()},
		{"verifier_evidence_bundle_hash", pb.GetVerifierEvidenceBundleHash()},
		{"salt", pb.GetSalt()},
	} {
		if len(field.value) != sha256.Size {
			return nil, fmt.Errorf("%w: %s must be 32 bytes", types.ErrInvalidArgument, field.name)
		}
	}
	if len(pb.GetServiceSignature()) != 64 {
		return nil, fmt.Errorf("%w: service_signature must be exactly 64 bytes", types.ErrInvalidArgument)
	}
	if pb.GetVerifierOperatorAddress() == "" || pb.GetServiceAuthorizationNonce() == 0 || pb.GetExpiryHeight() == 0 {
		return nil, fmt.Errorf("%w: verifier_operator_address, service_authorization_nonce, and expiry_height are required",
			types.ErrInvalidArgument)
	}
	return pb, nil
}

// checkVerifyScope is the admission check shared by commit / result: schema_version is the message's
// frozen value, chain_id is this chain, verify_round is a value supported this round. The request no longer has a second
// task_id copy to compare; the whole scope comes from the message body.
func checkVerifyScope(schemaVersion, wantSchemaVersion uint32, bodyChainID, chainID string, verifyRound uint32) error {
	switch {
	case schemaVersion != wantSchemaVersion:
		return fmt.Errorf("%w: schema_version must be %d", types.ErrInvalidArgument, wantSchemaVersion)
	case bodyChainID != chainID:
		return fmt.Errorf("%w: chain_id mismatch", types.ErrInvalidArgument)
	case uint64(verifyRound) != nodecontract.SupportedVerifyRoundV1:
		return fmt.Errorf("%w: verify_round must be %d", types.ErrInvalidArgument, nodecontract.SupportedVerifyRoundV1)
	}
	return nil
}

func decodeSignatureHex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 64 || hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%w: service_signature must be 64-byte lowercase hex", types.ErrInvalidArgument)
	}
	return decoded, nil
}

// verifyCommitSignBytes is the request body covered by the Verifier role signature (request envelope layer binding, not
// the §5.14 consensus preimage -- that is covered by commit.ServiceSignature). The domain carries V2: the field set
// changed to the on-chain body with the initial relay implementation and is incompatible with the old TRUEOPEN_SUBMIT_VERIFY_COMMIT_V1.
func verifyCommitSignBytes(sessionID string, c *taskv1.VerifyCommitV1) []byte {
	return sdkauth.BodyPreimage(
		[]byte("TRUEOPEN_SUBMIT_VERIFY_COMMIT_V2"),
		[]byte(sessionID), u32be(c.GetSchemaVersion()), []byte(c.GetChainId()), c.GetTaskId(),
		u32be(c.GetVerifyRound()), []byte(c.GetVerifierOperatorAddress()),
		u64be(c.GetServiceAuthorizationNonce()), c.GetCommitHash(), u64be(c.GetExpiryHeight()),
		c.GetServiceSignature(),
	)
}

// verifyResultSignBytes mirrors verifyCommitSignBytes and covers every ResultReceiptV2 field;
// the two optional metric_summary fields are encoded as a presence bit plus value.
//
// V2 replaced result_reveal_hash with verifier_evidence_bundle_hash + manifest size +
// salt, changing the covered range -- a breaking change for Cortex; both sides must switch in the same batch.
func verifyResultSignBytes(sessionID string, r *taskv1.ResultReceiptV2) []byte {
	summary := r.GetMetricSummary()
	optional := func(v *uint32) []byte {
		if v == nil {
			return []byte{0}
		}
		return append([]byte{1}, u32be(*v)...)
	}
	return sdkauth.BodyPreimage(
		[]byte("TRUEOPEN_SUBMIT_VERIFY_RESULT_V2"),
		[]byte(sessionID), u32be(r.GetSchemaVersion()), []byte(r.GetChainId()), r.GetTaskId(),
		u32be(r.GetVerifyRound()), []byte(r.GetVerifierOperatorAddress()),
		u64be(r.GetServiceAuthorizationNonce()), r.GetGenerationParamsDigest(), r.GetMetricRoot(),
		u32be(summary.GetFiniteCount()), u32be(summary.GetMissingComparedCount()),
		u32be(summary.GetMeanAbsLogprobDiffFp_1E6()), u32be(summary.GetAbsLogprobDiffP95Fp_1E6()),
		u32be(summary.GetAbsLogprobDiffP99Fp_1E6()), u32be(summary.GetRankDeltaNonzeroRateFp_1E6()),
		optional(summary.TopkJaccardMeanFp_1E6), optional(summary.UnionJsP99Fp_1E6),
		u32be(summary.GetComparedTopkCount()), u32be(summary.GetComparedRankCount()),
		r.GetAggregateProofHash(), r.GetVerifierEvidenceBundleHash(),
		u64be(r.GetVerifierEvidenceManifestSizeBytes()), r.GetSalt(), u64be(r.GetExpiryHeight()),
		r.GetServiceSignature(),
	)
}

func mapInferReceiptErr(err error) error {
	switch {
	case errors.Is(err, types.ErrTaskNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("task not found"))
	case errors.Is(err, types.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, types.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, types.ErrInvalidSignature):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, taskdata.ErrConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
