package ingress

// FinalizeTaskResult / FinalizeVerifierEvidence -- the two atomic commit points of
// Task Data Interface Design §5.5. This file only does boundary work: converts wire messages to
// internal shapes and verifies ResultReceiptV2's own service_signature here (same
// verifyParticipantRoleDigest as the three relay RPCs); every other check lives in taskdata.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// FinalizeTaskResult is initiated by the selected Worker and commits in one shot the receipt, the Worker
// frozen manifest, all its objects and TaskData READY.
func (s *service) FinalizeTaskResult(
	ctx context.Context,
	req *connect.Request[nexusv1.FinalizeTaskResultRequest],
) (*connect.Response[nexusv1.FinalizeTaskResultResponse], error) {
	if s.taskData == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("task data service is not configured"))
	}
	m := req.Msg
	scope, err := finalizeScope(m.GetSessionId(), m.GetTaskId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	receipt, err := signedInferReceiptFromPB(m.GetReceipt(), s.auth.ChainID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	auth, err := requestAuthFromPB(m.GetRequestAuth(), scope)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	outcome, err := s.taskData.FinalizeTaskResult(ctx, taskdata.FinalizeResultRequest{
		Auth: auth, TaskHash: m.GetTaskHash(), Receipt: receipt,
	})
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	bundles := make([]*nexusv1.BuilderStorageConfirmationV1, 0, len(outcome.EvidenceConfirmations))
	for _, confirmation := range outcome.EvidenceConfirmations {
		bundles = append(bundles, confirmationToPB(confirmation))
	}
	return connect.NewResponse(&nexusv1.FinalizeTaskResultResponse{
		Accepted: true, Idempotent: outcome.Idempotent,
		OutputConfirmation:          confirmationToPB(outcome.OutputConfirmation),
		EvidenceBundleConfirmations: bundles,
	}), nil
}

// FinalizeVerifierEvidence is initiated by a round's selected Verifier and commits only that producer/round's
// manifest, objects and VerifierBundle READY.
func (s *service) FinalizeVerifierEvidence(
	ctx context.Context,
	req *connect.Request[nexusv1.FinalizeVerifierEvidenceRequest],
) (*connect.Response[nexusv1.FinalizeVerifierEvidenceResponse], error) {
	if s.taskData == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("task data service is not configured"))
	}
	m := req.Msg
	scope, err := finalizeScope(m.GetSessionId(), m.GetTaskId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	receipt, err := finalizeResultReceiptFromPB(m.GetReceipt(), s.auth.ChainID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// The receipt's own service_signature is the role authentication for this receipt, on the same footing as
	// the three relay RPCs; taskdata receives its result and does not duplicate a second verification implementation.
	signingDigest, err := nodecontract.ResultReceiptSigningDigest(receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.verifyParticipantRoleDigest(ctx, servicekey.ParticipantCortex,
		receipt.GetVerifierOperatorAddress(), signingDigest[:], receipt.GetServiceSignature()); err != nil {
		return nil, mapRoleSignatureErr(err)
	}
	// The round / verifier the receipt claims must match the request: a mismatch means publishing evidence
	// for another round or another party.
	if receipt.GetVerifyRound() != m.GetVerifyRound() ||
		receipt.GetVerifierOperatorAddress() != m.GetVerifierOperator() {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%w: receipt round/verifier does not match the request", types.ErrInvalidArgument))
	}
	if hex.EncodeToString(receipt.GetTaskId()) != m.GetTaskId() {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%w: receipt task_id does not match the request", types.ErrInvalidArgument))
	}
	signatureDigest := sha256.Sum256(receipt.GetServiceSignature())

	auth, err := requestAuthFromPB(m.GetRequestAuth(), scope)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	outcome, err := s.taskData.FinalizeVerifierEvidence(ctx, taskdata.FinalizeVerifierRequest{
		Auth: auth, TaskHash: m.GetTaskHash(), VerifyRound: m.GetVerifyRound(),
		VerifierOperator:  m.GetVerifierOperator(),
		SigningDigest:     hex.EncodeToString(signingDigest[:]),
		SignatureDigest:   hex.EncodeToString(signatureDigest[:]),
		BundleHash:        hex.EncodeToString(receipt.GetVerifierEvidenceBundleHash()),
		ManifestSizeBytes: receipt.GetVerifierEvidenceManifestSizeBytes(),
	})
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	return connect.NewResponse(&nexusv1.FinalizeVerifierEvidenceResponse{
		Accepted: true, Idempotent: outcome.Idempotent,
		EvidenceBundleConfirmation: confirmationToPB(outcome.Confirmation),
	}), nil
}

// finalizeScope locates a Finalize: Finalize does not target a single object, so only
// (session_id, task_id) is present. It never enters the request preimage; it is only used to look up the on-chain task.
func finalizeScope(sessionID, taskID string) (taskdata.ObjectKey, error) {
	if !canonicalHash32Text(sessionID) || !canonicalHash32Text(taskID) {
		return taskdata.ObjectKey{}, fmt.Errorf("%w: session_id and task_id must be lowercase 64-hex", types.ErrInvalidArgument)
	}
	return taskdata.ObjectKey{SessionID: sessionID, TaskID: taskID}, nil
}

func canonicalHash32Text(value string) bool {
	if len(value) != 2*sha256.Size {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

// signedInferReceiptFromPB converts InferReceiptV2 to taskdata's internal shape. Shape validation
// (field lengths, schema_version, chain_id) happens once here; digest and signature verification in taskdata.
func signedInferReceiptFromPB(pb *taskv1.InferReceiptV2, chainID string) (taskdata.SignedInferReceipt, error) {
	if pb == nil {
		return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: receipt is required", types.ErrInvalidArgument)
	}
	if pb.GetSchemaVersion() != nodecontract.InferReceiptSchemaVersionV2 {
		return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: receipt schema_version must be %d",
			types.ErrInvalidArgument, nodecontract.InferReceiptSchemaVersionV2)
	}
	if pb.GetChainId() != chainID {
		return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: receipt chain_id", types.ErrInvalidArgument)
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", pb.GetTaskId()},
		{"task_hash", pb.GetTaskHash()},
		{"generation_params_digest", pb.GetGenerationParamsDigest()},
		{"output_hash", pb.GetOutputHash()},
	} {
		if len(field.value) != sha256.Size {
			return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: %s must be 32 bytes", types.ErrInvalidArgument, field.name)
		}
	}
	if len(pb.GetServiceSignature()) != 64 {
		return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: service_signature must be exactly 64 bytes", types.ErrInvalidArgument)
	}
	commitments := make([]taskdata.EvidenceCommitment, 0, len(pb.GetRequiredEvidenceCommitments()))
	for _, commitment := range pb.GetRequiredEvidenceCommitments() {
		if len(commitment.GetEvidenceHashOrRoot()) != sha256.Size {
			return taskdata.SignedInferReceipt{}, fmt.Errorf("%w: evidence_hash_or_root must be 32 bytes", types.ErrInvalidArgument)
		}
		commitments = append(commitments, taskdata.EvidenceCommitment{
			Kind:             uint32(commitment.GetEvidenceKind()),
			HashOrRoot:       hex.EncodeToString(commitment.GetEvidenceHashOrRoot()),
			EncodedSizeBytes: commitment.GetEncodedSizeBytes(),
		})
	}
	return taskdata.SignedInferReceipt{
		SchemaVersion: pb.GetSchemaVersion(), ChainID: pb.GetChainId(),
		TaskID: hex.EncodeToString(pb.GetTaskId()), TaskHash: hex.EncodeToString(pb.GetTaskHash()),
		WorkerOperatorAddress:     pb.GetWorkerOperatorAddress(),
		ServiceAuthorizationNonce: pb.GetServiceAuthorizationNonce(),
		GenerationParamsDigest:    hex.EncodeToString(pb.GetGenerationParamsDigest()),
		OutputHash:                hex.EncodeToString(pb.GetOutputHash()),
		OutputSizeBytes:           pb.GetOutputSizeBytes(),
		EvidenceCommitments:       commitments,
		ExpiryHeight:              pb.GetExpiryHeight(),
		ServiceSignature:          hex.EncodeToString(pb.GetServiceSignature()),
		GeneratedTokenCount:       pb.GetGeneratedTokenCount(),
		OutputLeafCount:           pb.GetOutputLeafCount(),
	}, nil
}

// finalizeResultReceiptFromPB reuses SubmitVerifyResult's shape validation: that path and this one carry
// the same ResultReceiptV2, and there must not be two sets of validation rules.
func finalizeResultReceiptFromPB(pb *taskv1.ResultReceiptV2, chainID string) (*taskv1.ResultReceiptV2, error) {
	return resultReceiptFromPB(&nexusv1.SubmitVerifyResultRequest{Receipt: pb}, chainID)
}

// confirmationToPB converts the Builder storage confirmation to wire shape.
func confirmationToPB(confirmation taskdata.StorageConfirmation) *nexusv1.BuilderStorageConfirmationV1 {
	if confirmation.SchemaVersion == 0 {
		return nil
	}
	return &nexusv1.BuilderStorageConfirmationV1{
		SchemaVersion:             confirmation.SchemaVersion,
		ChainId:                   confirmation.ChainID,
		BuilderOperatorAddress:    confirmation.BuilderOperator,
		ServiceAuthorizationNonce: confirmation.ServiceAuthorizationNonce,
		ObjectRef:                 objectRefToPB(confirmation.Ref),
		SizeBytes:                 confirmation.SizeBytes,
		ArtifactTotalSizeBytes:    confirmation.ArtifactTotalSizeBytes,
		RetentionUntilHeight:      confirmation.RetentionUntilHeight,
		ServiceSignature:          append([]byte(nil), confirmation.Signature...),
	}
}
