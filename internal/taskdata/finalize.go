package taskdata

// FinalizeTaskResult / FinalizeVerifierEvidence — the two atomic commit points of Task Data
// Interface Design §5.5, and the only source of objects becoming READY and of the Builder issuing
// a storage confirmation.
//
// Division of labour: FinalizeTaskResult commits the receipt, the Worker frozen manifest, all of
// its objects and TaskData READY in one go; FinalizeVerifierEvidence commits only the manifest and
// objects of the given producer/round plus VerifierBundle READY, touches no Worker readiness, and
// does not mean the on-chain Result has been accepted.
//
// Nexus does not parse model evidence semantics and does not recompute model-internal roots. What
// it does is line up what each of the three parties committed to: the receipt says what the OUTPUT
// is, the manifest says which artifacts are in the bundle, and the locked Verification Profile says
// which schema this evidence belongs to. For the Worker bundle that includes recomputing the
// receipt's typed commitment from the manifest and artifact hashes (data plane 02 §2).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

// FinalizeResultRequest is the internal form of FinalizeTaskResultRequest.
type FinalizeResultRequest struct {
	Auth     RequestAuthV1
	TaskHash string
	Receipt  SignedInferReceipt
}

// FinalizeResultOutcome is the internal form of FinalizeTaskResultResponse.
// EvidenceConfirmations is ordered by ascending evidence_kind of the corresponding
// required_evidence_commitments[], and its count is exactly equal to theirs.
type FinalizeResultOutcome struct {
	Idempotent            bool
	OutputConfirmation    StorageConfirmation
	EvidenceConfirmations []StorageConfirmation
}

// FinalizeVerifierRequest is the internal form of FinalizeVerifierEvidenceRequest.
//
// The ResultReceiptV2 body checks (shape, signature, verify_round, verifier identity) are done at
// the ingress boundary — the same verifyParticipantRoleDigest is already built there for the three
// relay RPCs, and a second copy would only add one more implementation that can disagree with it.
// What reaches this point are its products: the verified signing digest, the signature digest, and
// the receipt's two commitments about the bundle.
//
// Note that ResultReceiptV2 carries no task_hash: the task_hash of this Finalize comes from the
// request, and its consistency with the manifest is guaranteed by the object ref the manifest lives
// under (compared at upload time).
type FinalizeVerifierRequest struct {
	Auth             RequestAuthV1
	TaskHash         string
	VerifyRound      uint32
	VerifierOperator string
	// SigningDigest is the TRUEOPEN_RESULT_V2 signing digest (lowercase 64-hex), already verified at
	// ingress.
	SigningDigest string
	// SignatureDigest is SHA256(service_signature raw64), the seventh field of the body digest.
	SignatureDigest string
	// BundleHash / ManifestSizeBytes are the receipt's commitments about this Verifier bundle.
	BundleHash        string
	ManifestSizeBytes uint64
}

// FinalizeVerifierOutcome is the internal form of FinalizeVerifierEvidenceResponse.
type FinalizeVerifierOutcome struct {
	Idempotent   bool
	Confirmation StorageConfirmation
}

// finalizeRecord is the idempotency record: an exact replay returns the bytes and signature
// persisted the first time and does not re-sign — re-signing would change the retention promise and
// would make one Finalize produce two confirmations.
type finalizeRecord struct {
	OutputConfirmation    *StorageConfirmation  `json:"output_confirmation,omitempty"`
	EvidenceConfirmations []StorageConfirmation `json:"evidence_confirmations,omitempty"`
}

// FinalizeTaskResult is the atomic commit point on the Worker side.
func (s *Service) FinalizeTaskResult(ctx context.Context, request FinalizeResultRequest) (FinalizeResultOutcome, error) {
	receipt := request.Receipt
	digest, err := receiptDigest(receipt)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	receiptHash := hex.EncodeToString(digest[:])
	signatureDigest, err := serviceSignatureDigest(receipt.ServiceSignature)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	scope := request.Auth.Key
	body, err := TaskDataFinalizeResultBodyDigest(
		request.TaskHash, scope.SessionID, scope.TaskID, receiptHash, signatureDigest)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	if request.Auth.BodyDigest != hex.EncodeToString(body[:]) {
		return FinalizeResultOutcome{}, fmt.Errorf("%w: finalize result body binding", ErrUnauthorized)
	}

	if cached, found, err := s.finalizeRecord(request.Auth); err != nil {
		return FinalizeResultOutcome{}, err
	} else if found {
		if cached.OutputConfirmation == nil {
			return FinalizeResultOutcome{}, fmt.Errorf("%w: finalize record is not a result finalize", ErrConflict)
		}
		return FinalizeResultOutcome{
			Idempotent: true, OutputConfirmation: *cached.OutputConfirmation,
			EvidenceConfirmations: cached.EvidenceConfirmations,
		}, nil
	}

	task, height, err := s.authorizer.verifyRequest(ctx, request.Auth, MethodFinalizeResult)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	// Only the Worker currently selected for this Task can submit the result.
	worker := task.Assignment.SelectedWorkerOperatorAddress
	if worker == "" || worker != request.Auth.RequesterAddress {
		return FinalizeResultOutcome{}, fmt.Errorf("%w: finalize requester is not the selected worker", ErrUnauthorized)
	}
	if err := s.authorizer.verifyInferReceipt(ctx, task, request.TaskHash, scope, receipt, receiptHash); err != nil {
		return FinalizeResultOutcome{}, err
	}

	// OUTPUT: the receipt says which object it is and how large; locally it must already be STORED
	// and match exactly. The content_hash is exactly receipt.output_hash (after ADR-0017, the MMR
	// root): a streamed object is indexed by the locally computed root when it is finalized, so
	// finding it here is the same as "locally computed root == receipt.output_hash".
	outputRef := ObjectRef{
		TaskHash: request.TaskHash, SessionID: scope.SessionID, TaskID: scope.TaskID,
		Kind: ObjectKindOutput, ContentHash: receipt.OutputHash,
	}
	output, err := s.storedObject(ctx, outputRef)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	if output.SizeBytes != receipt.OutputSizeBytes {
		return FinalizeResultOutcome{}, fmt.Errorf("%w: output size %d, receipt says %d",
			ErrHashMismatch, output.SizeBytes, receipt.OutputSizeBytes)
	}
	// Only a streamed OUTPUT can be finalized: the Worker commitment needs the finish_reason of its
	// Fin (see verifyWorkerValueCommitment), which a whole-object upload does not have. The stream
	// records the leaf count and InferReceiptV2 also carries output_leaf_count: the two must be
	// equal, otherwise the root a Verifier recomputes from chunk_lengths will not match the
	// on-chain commitment.
	if output.OutputMMRRoot == "" {
		return FinalizeResultOutcome{}, fmt.Errorf("%w: output was not streamed, finish_reason unknown", ErrConflict)
	}
	if output.OutputLeafCount != receipt.OutputLeafCount {
		return FinalizeResultOutcome{}, fmt.Errorf("%w: output leaf count %d, receipt says %d",
			ErrHashMismatch, output.OutputLeafCount, receipt.OutputLeafCount)
	}

	schemaHash, err := s.authorizer.lockedEvidenceSchemaHash(ctx, task)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}

	// Each required_evidence_commitments[] entry corresponds to one Worker manifest: the
	// content_hash is exactly the commitment's evidence_hash_or_root (the closed-set semantics of
	// §6.2).
	commitments := append([]EvidenceCommitment(nil), receipt.EvidenceCommitments...)
	sort.Slice(commitments, func(i, j int) bool { return commitments[i].Kind < commitments[j].Kind })
	bundles := make([]Metadata, 0, len(commitments))
	ready := []ObjectRef{outputRef}
	for _, commitment := range commitments {
		manifestRef := ObjectRef{
			TaskHash: request.TaskHash, SessionID: scope.SessionID, TaskID: scope.TaskID,
			Kind: ObjectKindEvidenceManifest, ContentHash: commitment.HashOrRoot,
			// The round of a Worker manifest is always 1.
			EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: worker,
		}
		bundle, artifacts, err := s.storedBundle(ctx, manifestRef, schemaHash)
		if err != nil {
			return FinalizeResultOutcome{}, err
		}
		// wire v0.4.1: EvidenceCommitmentV1.encoded_size_bytes is the checked sum of all artifact
		// sizes in the bundle (per the WorkerValueCommitmentV2 comment), not the manifest byte count.
		if bundle.ArtifactTotalSizeBytes != commitment.EncodedSizeBytes {
			return FinalizeResultOutcome{}, fmt.Errorf("%w: artifact total %d bytes, receipt encoded_size_bytes %d",
				ErrHashMismatch, bundle.ArtifactTotalSizeBytes, commitment.EncodedSizeBytes)
		}
		if err := s.verifyWorkerValueCommitment(ctx, receipt, commitment, schemaHash, outputRef, bundle, artifacts); err != nil {
			return FinalizeResultOutcome{}, err
		}
		bundles = append(bundles, bundle)
		ready = append(ready, manifestRef)
		ready = append(ready, artifacts...)
	}

	confirmations, err := s.commitReady(ctx, ready, output, bundles, &receipt)
	if err != nil {
		return FinalizeResultOutcome{}, err
	}
	record := finalizeRecord{OutputConfirmation: &confirmations[0], EvidenceConfirmations: confirmations[1:]}
	if err := s.putFinalizeRecord(request.Auth, record); err != nil {
		return FinalizeResultOutcome{}, err
	}
	if err := s.authorizer.consumeRequestNonce(request.Auth, height); err != nil {
		return FinalizeResultOutcome{}, err
	}
	return FinalizeResultOutcome{
		OutputConfirmation: confirmations[0], EvidenceConfirmations: confirmations[1:],
	}, nil
}

// FinalizeVerifierEvidence is the atomic commit point on the Verifier side. It switches only the
// bundle of that producer/round and does not change the readiness of the Worker OUTPUT or of Worker
// evidence.
func (s *Service) FinalizeVerifierEvidence(ctx context.Context, request FinalizeVerifierRequest) (FinalizeVerifierOutcome, error) {
	scope := request.Auth.Key
	body, err := TaskDataFinalizeVerifierBodyDigest(
		request.TaskHash, scope.SessionID, scope.TaskID, request.VerifyRound,
		request.VerifierOperator, request.SigningDigest, request.SignatureDigest)
	if err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	if request.Auth.BodyDigest != hex.EncodeToString(body[:]) {
		return FinalizeVerifierOutcome{}, fmt.Errorf("%w: finalize verifier body binding", ErrUnauthorized)
	}

	if cached, found, err := s.finalizeRecord(request.Auth); err != nil {
		return FinalizeVerifierOutcome{}, err
	} else if found {
		if len(cached.EvidenceConfirmations) != 1 || cached.OutputConfirmation != nil {
			return FinalizeVerifierOutcome{}, fmt.Errorf("%w: finalize record is not a verifier finalize", ErrConflict)
		}
		return FinalizeVerifierOutcome{Idempotent: true, Confirmation: cached.EvidenceConfirmations[0]}, nil
	}

	task, height, err := s.authorizer.verifyRequest(ctx, request.Auth, MethodFinalizeVerifier)
	if err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	// The requester and the producer must be the same party, and must be a selected Verifier for
	// that round. Allowing them to differ would let one Verifier publish evidence on behalf of
	// another.
	if request.VerifierOperator != request.Auth.RequesterAddress {
		return FinalizeVerifierOutcome{}, fmt.Errorf("%w: verifier_operator is not the requester", ErrUnauthorized)
	}
	if !isSelectedVerifier(task, request.VerifierOperator, request.VerifyRound) {
		return FinalizeVerifierOutcome{}, fmt.Errorf("%w: requester is not a selected verifier", ErrUnauthorized)
	}
	if request.VerifyRound == 0 {
		return FinalizeVerifierOutcome{}, fmt.Errorf("%w: verify_round must be positive", ErrMalformed)
	}

	schemaHash, err := s.authorizer.lockedEvidenceSchemaHash(ctx, task)
	if err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	manifestRef := ObjectRef{
		TaskHash: request.TaskHash, SessionID: scope.SessionID, TaskID: scope.TaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: request.BundleHash,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: request.VerifyRound,
		ProducerOperator: request.VerifierOperator,
	}
	bundle, artifacts, err := s.storedBundle(ctx, manifestRef, schemaHash)
	if err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	// VerifierResult commits to the size of the exact manifest bytes; the bundle hash is exactly the
	// ref's content_hash, which was verified against the bytes under H_V1 at upload time.
	if bundle.SizeBytes != request.ManifestSizeBytes {
		return FinalizeVerifierOutcome{}, fmt.Errorf("%w: manifest size %d, receipt says %d",
			ErrHashMismatch, bundle.SizeBytes, request.ManifestSizeBytes)
	}

	confirmations, err := s.commitReady(ctx, append([]ObjectRef{manifestRef}, artifacts...), Metadata{}, []Metadata{bundle}, nil)
	if err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	if err := s.putFinalizeRecord(request.Auth, finalizeRecord{EvidenceConfirmations: confirmations}); err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	if err := s.authorizer.consumeRequestNonce(request.Auth, height); err != nil {
		return FinalizeVerifierOutcome{}, err
	}
	return FinalizeVerifierOutcome{Confirmation: confirmations[0]}, nil
}

// storedObject fetches an object that must already be STORED. READY also counts — on a re-entrant
// Finalize the object has already been switched over, which is not an error.
func (s *Service) storedObject(ctx context.Context, ref ObjectRef) (Metadata, error) {
	metadata, err := s.store.Metadata(ctx, ref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Metadata{}, fmt.Errorf("%w: object %s is not stored", ErrNotFound, ref.Kind)
		}
		return Metadata{}, err
	}
	if metadata.State != StateStored && metadata.State != StateReady {
		return Metadata{}, fmt.Errorf("%w: object %s is %s, not STORED", ErrConflict, ref.Kind, metadata.State)
	}
	if metadata.RetentionStatus == RetentionDeleted {
		return Metadata{}, fmt.Errorf("%w: object %s was deleted", ErrNotFound, ref.Kind)
	}
	return metadata, nil
}

// storedBundle checks a complete evidence bundle: the manifest itself and every artifact it
// references. The strict parse of the manifest was already done at upload time (its result is
// persisted with the metadata); what is compared here is the consistency between the manifest, the
// receipt and the locked profile.
func (s *Service) storedBundle(
	ctx context.Context, manifestRef ObjectRef, lockedSchemaHash string,
) (Metadata, []ObjectRef, error) {
	manifest, err := s.storedObject(ctx, manifestRef)
	if err != nil {
		return Metadata{}, nil, err
	}
	// The receipt's size commitment means different things for Worker and Verifier (total artifact
	// size vs manifest byte count) and is compared by each Finalize entry point; here only the
	// bundle's own consistency is checked.
	// Which schema the manifest claims to belong to does not count; what counts is the Verification
	// Profile locked on chain.
	if manifest.EvidenceSchemaHash != lockedSchemaHash {
		return Metadata{}, nil, fmt.Errorf("%w: manifest evidence_schema_hash %s, locked profile %s",
			ErrConflict, manifest.EvidenceSchemaHash, lockedSchemaHash)
	}
	if len(manifest.Artifacts) == 0 {
		return Metadata{}, nil, fmt.Errorf("%w: manifest has no artifacts", ErrMalformed)
	}

	refs := make([]ObjectRef, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		// An artifact's three producer fields are inherited from the manifest it belongs to: the same
		// bytes under two producers are two different objects.
		artifactRef := ObjectRef{
			TaskHash: manifestRef.TaskHash, SessionID: manifestRef.SessionID, TaskID: manifestRef.TaskID,
			Kind: ObjectKindEvidenceArtifact, ContentHash: artifact.ContentHash,
			EvidenceProducerKind: manifestRef.EvidenceProducerKind, VerifyRound: manifestRef.VerifyRound,
			ProducerOperator: manifestRef.ProducerOperator,
		}
		stored, err := s.storedObject(ctx, artifactRef)
		if err != nil {
			return Metadata{}, nil, fmt.Errorf("%w (artifact %s)", err, artifact.ArtifactID)
		}
		if stored.SizeBytes != artifact.SizeBytes {
			return Metadata{}, nil, fmt.Errorf("%w: artifact %s size %d, manifest says %d",
				ErrHashMismatch, artifact.ArtifactID, stored.SizeBytes, artifact.SizeBytes)
		}
		refs = append(refs, artifactRef)
	}
	return manifest, refs, nil
}

// commitReady is the atomic commit of §5.5: first switch every object to READY, then sign a
// confirmation for the OUTPUT and for each complete bundle. Artifacts are not confirmed
// individually — they are covered by the hash of their owning manifest and by that bundle's
// confirmation.
//
// The returned slice starts with the OUTPUT confirmation (omitted when output is the zero value),
// followed by the bundles in order. When receipt is non-nil it is persisted together with the
// OUTPUT so that GetTaskDataMetadata can return a copy of infer_receipt.
func (s *Service) commitReady(
	ctx context.Context, refs []ObjectRef, output Metadata, bundles []Metadata, receipt *SignedInferReceipt,
) ([]StorageConfirmation, error) {
	for _, ref := range refs {
		var err error
		if receipt != nil && ref == output.Key {
			_, err = s.store.MarkOutputReady(ctx, ref, *receipt)
		} else {
			_, err = s.store.MarkReady(ctx, ref)
		}
		if err != nil {
			return nil, err
		}
	}
	confirmations := make([]StorageConfirmation, 0, len(bundles)+1)
	if output.Key.Kind == ObjectKindOutput {
		confirmation, err := s.signReady(ctx, output.Key, 0)
		if err != nil {
			return nil, err
		}
		confirmations = append(confirmations, confirmation)
	}
	for _, bundle := range bundles {
		confirmation, err := s.signReady(ctx, bundle.Key, bundle.ArtifactTotalSizeBytes)
		if err != nil {
			return nil, err
		}
		confirmations = append(confirmations, confirmation)
	}
	return confirmations, nil
}

// signReady reads the metadata back after it has been switched to READY and only then signs: the
// size in the confirmation must be the persisted value, not the one the caller declared. The lease
// height is written back as well so that the returned metadata matches the signed promise.
func (s *Service) signReady(ctx context.Context, ref ObjectRef, artifactTotalSizeBytes uint64) (StorageConfirmation, error) {
	metadata, err := s.store.Metadata(ctx, ref)
	if err != nil {
		return StorageConfirmation{}, err
	}
	confirmation, err := s.authorizer.SignStorageConfirmation(ctx, metadata, artifactTotalSizeBytes)
	if err != nil {
		return StorageConfirmation{}, err
	}
	if metadata.RetainUntilHeight != confirmation.RetentionUntilHeight {
		if _, err := s.store.RecordRetentionLease(ctx, ref, confirmation.RetentionUntilHeight); err != nil {
			return StorageConfirmation{}, err
		}
	}
	return confirmation, nil
}

// finalizeKey is the idempotency key: body digest plus requester. The same requester replaying the
// same body gets back the identical confirmation; a different body is a different Finalize.
func finalizeKey(auth RequestAuthV1) string {
	digest := sha256.Sum256([]byte(auth.BodyDigest + "|" + auth.RequesterAddress + "|" + auth.RPCMethod))
	return hex.EncodeToString(digest[:])
}

func (s *Service) finalizeRecord(auth RequestAuthV1) (finalizeRecord, bool, error) {
	raw, found, err := s.store.backend.GetWithError(kv.NSTaskDataFinalize, finalizeKey(auth))
	if err != nil {
		return finalizeRecord{}, false, fmt.Errorf("%w: read finalize record: %v", ErrStorage, err)
	}
	if !found {
		return finalizeRecord{}, false, nil
	}
	var record finalizeRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return finalizeRecord{}, false, fmt.Errorf("%w: decode finalize record: %v", ErrStorage, err)
	}
	return record, true, nil
}

func (s *Service) putFinalizeRecord(auth RequestAuthV1, record finalizeRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encode finalize record: %v", ErrStorage, err)
	}
	if err := s.store.backend.Set(kv.NSTaskDataFinalize, finalizeKey(auth), raw); err != nil {
		return fmt.Errorf("%w: persist finalize record: %v", ErrStorage, err)
	}
	return nil
}

// serviceSignatureDigest is SHA256(raw64 signature), not the hash of the signature text — both body
// digests put it into their preimage.
func serviceSignatureDigest(hexSignature string) (string, error) {
	raw, err := hex.DecodeString(hexSignature)
	if err != nil || len(raw) != 64 {
		return "", fmt.Errorf("%w: service_signature must be 64 raw bytes in lowercase hex", ErrMalformed)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// lockedEvidenceSchemaHash reads the evidence_schema_hash of the Verification Profile locked on
// chain. Not found means not found: without it there is no way to decide whether the manifest
// belongs to this schema, so it cannot be let through.
func (a *Authorizer) lockedEvidenceSchemaHash(ctx context.Context, task chaincli.OnChainTask) (string, error) {
	modelID, version := task.Assignment.ModelID, task.Assignment.ProfileVersion
	if modelID == "" || version == 0 {
		return "", fmt.Errorf("%w: task carries no locked profile", ErrAuthorityUnavailable)
	}
	profile, err := a.authority.QueryProfile(ctx, modelID, version)
	if err != nil {
		return "", fmt.Errorf("%w: locked profile: %v", ErrAuthorityUnavailable, err)
	}
	if !canonicalSHA256(profile.EvidenceSchemaHash) {
		return "", fmt.Errorf("%w: locked profile evidence_schema_hash", ErrAuthorityUnavailable)
	}
	return profile.EvidenceSchemaHash, nil
}

// verifyInferReceipt checks the receipt body: Task identity, Worker identity, signature, and — when
// the chain already has an accepted receipt — that the local one agrees with it.
func (a *Authorizer) verifyInferReceipt(
	ctx context.Context, task chaincli.OnChainTask, taskHash string, scope ObjectKey,
	receipt SignedInferReceipt, receiptHash string,
) error {
	switch {
	case receipt.ChainID != a.cfg.ChainID:
		return fmt.Errorf("%w: receipt chain_id", ErrUnauthorized)
	case receipt.TaskID != scope.TaskID:
		return fmt.Errorf("%w: receipt task_id", ErrUnauthorized)
	case receipt.TaskHash != taskHash:
		return fmt.Errorf("%w: receipt task_hash", ErrUnauthorized)
	case receipt.WorkerOperatorAddress != task.Assignment.SelectedWorkerOperatorAddress:
		return fmt.Errorf("%w: receipt worker_operator_address", ErrUnauthorized)
	case taskHash != task.Assignment.AcceptedTaskHash:
		return fmt.Errorf("%w: task_hash does not match accepted_task_hash", ErrUnauthorized)
	}
	if err := a.verifyParticipantSignature(
		ctx, receipt.WorkerOperatorAddress, receipt.ServiceAuthorizationNonce,
		receiptHash, receipt.ServiceSignature, "infer receipt"); err != nil {
		return err
	}
	// If the chain has already accepted a receipt, the local one must be that same receipt. Not
	// comparing would let a second receipt replace a result that is already READY.
	if accepted := task.InferReceipt.InferReceiptHash; accepted != "" && accepted != receiptHash {
		return fmt.Errorf("%w: chain accepted infer receipt %s, local %s", ErrConflict, accepted, receiptHash)
	}
	return nil
}

// verifyParticipantSignature verifies the service_signature of an on-chain message with the
// operator's currently ACTIVE CORTEX service key. What is signed is the derived digest itself, with
// no extra hashing layer.
func (a *Authorizer) verifyParticipantSignature(
	ctx context.Context, operator string, nonce uint64, digestHex, signatureHex, label string,
) error {
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%w: %s digest", ErrMalformed, label)
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != 64 {
		return fmt.Errorf("%w: %s service_signature", ErrMalformed, label)
	}
	publicKey, state, err := a.currentParticipantServiceKey(ctx, participantTypeCortex, operator)
	if err != nil {
		return err
	}
	if nonce == 0 || nonce != state.AuthorizationNonce {
		return fmt.Errorf("%w: stale %s service_authorization_nonce", ErrUnauthorized, label)
	}
	if !signer.VerifyDigestSig(publicKey, digest, signature) {
		return fmt.Errorf("%w: %s signature", ErrUnauthorized, label)
	}
	return nil
}

// isSelectedVerifier reads the same per-round sets as task data authorization, so a Verifier
// that may upload a bundle for a round may also finalize it, and no other round's seat counts.
func isSelectedVerifier(task chaincli.OnChainTask, operator string, verifyRound uint32) bool {
	for _, round := range task.VerifierRounds {
		if round.VerifyRound != verifyRound {
			continue
		}
		for _, verifier := range round.Verifiers {
			if verifier == operator {
				return true
			}
		}
	}
	return false
}
