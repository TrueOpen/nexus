package taskdata

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// evidenceKindWorkerValueOpening is shared.v1.EVIDENCE_KIND_WORKER_VALUE_OPENING, the only Worker
// evidence kind of the Phase 0 contract.
const evidenceKindWorkerValueOpening uint32 = 1

// The Phase 0 WORKER_VALUE_OPENING bundle is the one narrowed instance of the generic manifest
// (data plane 02 §2.1): evidence_kind is exactly this value, schema_metadata is absent and the
// artifacts are exactly these four, in UTF-8 order.
const workerValueOpeningManifestKind = "WORKER_VALUE_OPENING"

var workerValueOpeningArtifactIDs = [...]string{"checkpoint", "generated_token_ids", "input_token_ids", "trace"}

// verifyWorkerValueCommitment recomputes the receipt's WORKER_VALUE_OPENING commitment from the
// exact manifest and its four artifacts (data plane 02 §2, validation algorithm §7 and §7.0b) and
// requires it to equal evidence_hash_or_root. Without this the manifest a Worker stored under the
// committed key could be any bundle, and this Builder would sign a storage confirmation for data a
// Verifier then finds does not match the receipt.
//
// Only hashes and sizes are checked: trace and checkpoint enter as the SHA256 of their bytes
// (already verified at upload), the token id vectors only have their count prefix checked. Content
// semantics stay with the Verifier (02 §252).
func (s *Service) verifyWorkerValueCommitment(
	ctx context.Context, receipt SignedInferReceipt, commitment EvidenceCommitment,
	lockedSchemaHash string, outputRef ObjectRef, manifest Metadata, artifactRefs []ObjectRef,
) error {
	if err := s.checkWorkerValueOpeningManifest(ctx, manifest); err != nil {
		return err
	}
	artifacts := make(map[string]struct {
		ref  ObjectRef
		size uint64
	}, len(manifest.Artifacts))
	for i, artifact := range manifest.Artifacts {
		artifacts[artifact.ArtifactID] = struct {
			ref  ObjectRef
			size uint64
		}{artifactRefs[i], artifact.SizeBytes}
	}

	// InferReceiptV2 carries no finish_reason: it is the one the Worker sent in the Fin that sealed
	// this OUTPUT stream. A whole-object OUTPUT has no Fin and so cannot be finalized.
	finishReason, found, err := s.store.SealedOutputFinishReason(ctx, outputRef)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: no sealed output stream for output_hash %s, finish_reason unknown",
			ErrConflict, outputRef.ContentHash)
	}

	inputIDs := artifacts["input_token_ids"]
	inputHash, err := s.storedTokenIDsHash(ctx, nodecontract.DomainInputTokenIDsV1, inputIDs.ref, inputIDs.size)
	if err != nil {
		return err
	}
	generatedIDs := artifacts["generated_token_ids"]
	generatedHash, err := s.storedTokenIDsHash(ctx, nodecontract.DomainGeneratedTokenIDsV1, generatedIDs.ref, generatedIDs.size)
	if err != nil {
		return err
	}

	decoded := make(map[string][]byte, 7)
	for field, value := range map[string]string{
		"task_id": receipt.TaskID, "task_hash": receipt.TaskHash,
		"generation_params_digest": receipt.GenerationParamsDigest, "output_hash": receipt.OutputHash,
		"evidence_schema_hash": lockedSchemaHash,
		"trace_root":           artifacts["trace"].ref.ContentHash,
		"checkpoint_root":      artifacts["checkpoint"].ref.ContentHash,
	} {
		raw, err := nodecontract.Hash32Bytes(field, value)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		decoded[field] = raw
	}
	digest, err := nodecontract.WorkerValueCommitmentV2{
		ChainID:                    receipt.ChainID,
		TaskID:                     decoded["task_id"],
		AcceptedTaskHash:           decoded["task_hash"], // verifyInferReceipt: task_hash == accepted_task_hash
		WorkerOperatorAddress:      receipt.WorkerOperatorAddress,
		GenerationParamsDigest:     decoded["generation_params_digest"],
		EvidenceSchemaHash:         decoded["evidence_schema_hash"],
		OutputHash:                 decoded["output_hash"],
		OutputSizeBytes:            receipt.OutputSizeBytes,
		FinishReason:               finishReason,
		TraceRoot:                  decoded["trace_root"],
		TraceEncodedSizeBytes:      artifacts["trace"].size,
		CheckpointRoot:             decoded["checkpoint_root"],
		CheckpointEncodedSizeBytes: artifacts["checkpoint"].size,
		GeneratedTokenCount:        receipt.GeneratedTokenCount,
		OutputLeafCount:            receipt.OutputLeafCount,
		InputTokenIDsHash:          inputHash[:],
		GeneratedTokenIDsHash:      generatedHash[:],
		InputTokenIDsSizeBytes:     inputIDs.size,
		GeneratedTokenIDsSizeBytes: generatedIDs.size,
	}.Digest()
	if err != nil {
		return fmt.Errorf("%w: worker evidence commitment: %v", ErrMalformed, err)
	}
	if recomputed := hex.EncodeToString(digest[:]); recomputed != commitment.HashOrRoot {
		return fmt.Errorf("%w: worker evidence commitment recomputed %s, receipt evidence_hash_or_root %s",
			ErrHashMismatch, recomputed, commitment.HashOrRoot)
	}
	return nil
}

// checkWorkerValueOpeningManifest reads the exact manifest bytes back and checks the Phase 0 shape.
// evidence_kind and schema_metadata are not kept in the metadata, so the bytes are parsed again; the
// parser also enforces the ascending artifact order.
func (s *Service) checkWorkerValueOpeningManifest(ctx context.Context, manifest Metadata) error {
	reader, err := s.store.OpenStored(ctx, manifest.Key)
	if err != nil {
		return err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, int64(manifest.SizeBytes)+1))
	if err != nil {
		return fmt.Errorf("%w: read manifest: %v", ErrStorage, err)
	}
	if uint64(len(raw)) != manifest.SizeBytes {
		return fmt.Errorf("%w: manifest is %d bytes, metadata says %d", ErrStorage, len(raw), manifest.SizeBytes)
	}
	parsed, err := ParseEvidenceBundleManifest(raw)
	if err != nil {
		return err
	}
	if parsed.EvidenceKind != workerValueOpeningManifestKind {
		return fmt.Errorf("%w: worker manifest evidence_kind %q, want %q",
			ErrMalformed, parsed.EvidenceKind, workerValueOpeningManifestKind)
	}
	if parsed.SchemaMetadata != "" {
		return fmt.Errorf("%w: worker manifest must not carry schema_metadata", ErrMalformed)
	}
	if len(parsed.Artifacts) != len(workerValueOpeningArtifactIDs) {
		return fmt.Errorf("%w: worker manifest has %d artifacts, want %d",
			ErrMalformed, len(parsed.Artifacts), len(workerValueOpeningArtifactIDs))
	}
	for i, id := range workerValueOpeningArtifactIDs {
		if parsed.Artifacts[i].ArtifactID != id || manifest.Artifacts[i].ArtifactID != id {
			return fmt.Errorf("%w: worker manifest artifact %d is %q, want %q",
				ErrMalformed, i, parsed.Artifacts[i].ArtifactID, id)
		}
	}
	return nil
}

// storedTokenIDsHash streams a stored token id artifact through TokenIDsHashReader.
func (s *Service) storedTokenIDsHash(ctx context.Context, domain string, ref ObjectRef, size uint64) ([32]byte, error) {
	reader, err := s.store.OpenStored(ctx, ref)
	if err != nil {
		return [32]byte{}, err
	}
	defer reader.Close()
	digest, err := nodecontract.TokenIDsHashReader(domain, reader, size)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %s artifact: %v", ErrMalformed, domain, err)
	}
	return digest, nil
}
