package taskdata

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// A Worker delivers its evidence in two bundles, each the one narrowed instance of the generic
// manifest: schema_metadata absent and exactly these artifacts, in UTF-8 order.
//   - WORKER_TOKEN_OPENING: the input and generated token ids, which a Verifier needs to reproduce
//     the generation.
//   - WORKER_VALUE_OPENING: worker_values, the Worker's per-position values, which a Verifier may
//     read only after it has committed to its own.
var workerBundleArtifactIDs = map[EvidenceKind][]string{
	EvidenceKindWorkerTokenOpening: {"generated_token_ids", "input_token_ids"},
	EvidenceKindWorkerValueOpening: {"worker_values"},
}

// verifyWorkerCommitment recomputes the receipt's commitment of one Worker bundle from the exact
// manifest and its artifacts and requires it to equal evidence_hash_or_root. Without this the
// manifest a Worker stored under the committed key could be any bundle, and this Builder would sign
// a storage confirmation for data a Verifier then finds does not match the receipt.
//
// For the token bundle the token id vectors are hashed and their counts checked; for the value bundle
// worker_values is strictly decoded and its Merkle root rebuilt. Whether the values are right is the
// Verifier's comparison.
func (s *Service) verifyWorkerCommitment(
	ctx context.Context, receipt SignedInferReceipt, commitment EvidenceCommitment,
	lockedSchemaHash string, outputRef ObjectRef, manifest Metadata, artifactRefs []ObjectRef,
) error {
	kind := manifest.Key.EvidenceKind
	if err := s.checkWorkerManifest(ctx, manifest, kind); err != nil {
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
	decoded := make(map[string][]byte, 5)
	for _, field := range []struct{ name, value string }{
		{"task_id", receipt.TaskID}, {"task_hash", receipt.TaskHash},
		{"generation_params_digest", receipt.GenerationParamsDigest}, {"output_hash", receipt.OutputHash},
		{"evidence_schema_hash", lockedSchemaHash},
	} {
		raw, err := nodecontract.Hash32Bytes(field.name, field.value)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		decoded[field.name] = raw
	}

	var digest [32]byte
	var err error
	switch kind {
	case EvidenceKindWorkerTokenOpening:
		// The receipt carries no finish_reason: it is the one the Worker sent in the Fin that sealed
		// this OUTPUT stream.
		finishReason, found, ferr := s.store.SealedOutputFinishReason(ctx, outputRef)
		if ferr != nil {
			return ferr
		}
		if !found {
			return fmt.Errorf("%w: no sealed output stream for output_hash %s, finish_reason unknown",
				ErrConflict, outputRef.ContentHash)
		}
		inputIDs, generatedIDs := artifacts["input_token_ids"], artifacts["generated_token_ids"]
		inputHash, err := s.storedTokenIDsHash(ctx, nodecontract.DomainInputTokenIDsV1, inputIDs.ref, inputIDs.size)
		if err != nil {
			return err
		}
		generatedHash, err := s.storedTokenIDsHash(ctx, nodecontract.DomainGeneratedTokenIDsV1, generatedIDs.ref, generatedIDs.size)
		if err != nil {
			return err
		}
		// TokenIDsHashReader already checked size == 4 + 4*count.
		if count := (generatedIDs.size - 4) / 4; count != receipt.GeneratedTokenCount {
			return fmt.Errorf("%w: generated_token_ids holds %d ids, receipt generated_token_count %d",
				ErrHashMismatch, count, receipt.GeneratedTokenCount)
		}
		digest, err = nodecontract.WorkerTokenCommitmentV1{
			ChainID:                    receipt.ChainID,
			TaskID:                     decoded["task_id"],
			AcceptedTaskHash:           decoded["task_hash"], // verifyInferReceipt: task_hash == accepted_task_hash
			WorkerOperatorAddress:      receipt.WorkerOperatorAddress,
			GenerationParamsDigest:     decoded["generation_params_digest"],
			EvidenceSchemaHash:         decoded["evidence_schema_hash"],
			OutputHash:                 decoded["output_hash"],
			OutputSizeBytes:            receipt.OutputSizeBytes,
			OutputLeafCount:            receipt.OutputLeafCount,
			FinishReason:               finishReason,
			GeneratedTokenCount:        receipt.GeneratedTokenCount,
			InputTokenIDsHash:          inputHash[:],
			GeneratedTokenIDsHash:      generatedHash[:],
			InputTokenIDsSizeBytes:     inputIDs.size,
			GeneratedTokenIDsSizeBytes: generatedIDs.size,
		}.Digest()
	case EvidenceKindWorkerValueOpening:
		values := artifacts["worker_values"]
		root, rerr := s.storedWorkerValuesRoot(ctx, values.ref, values.size, receipt, decoded)
		if rerr != nil {
			return rerr
		}
		digest, err = nodecontract.WorkerValueCommitmentV3{
			ChainID:                      receipt.ChainID,
			TaskID:                       decoded["task_id"],
			AcceptedTaskHash:             decoded["task_hash"],
			WorkerOperatorAddress:        receipt.WorkerOperatorAddress,
			EvidenceSchemaHash:           decoded["evidence_schema_hash"],
			WorkerValueRoot:              root[:],
			WorkerValuesEncodedSizeBytes: values.size,
		}.Digest()
	default:
		return fmt.Errorf("%w: evidence_kind %d is not a Worker bundle", ErrMalformed, kind)
	}
	if err != nil {
		return fmt.Errorf("%w: worker evidence commitment: %v", ErrMalformed, err)
	}
	if recomputed := hex.EncodeToString(digest[:]); recomputed != commitment.HashOrRoot {
		return fmt.Errorf("%w: worker %s commitment recomputed %s, receipt evidence_hash_or_root %s",
			ErrHashMismatch, kind, recomputed, commitment.HashOrRoot)
	}
	return nil
}

// checkWorkerManifest reads the exact manifest bytes back and checks the shape of the bundle kind.
// schema_metadata is not kept in the metadata, so the bytes are parsed again; the parser also
// enforces the ascending artifact order, and the upload already matched evidence_kind to the ref.
func (s *Service) checkWorkerManifest(ctx context.Context, manifest Metadata, kind EvidenceKind) error {
	want, ok := workerBundleArtifactIDs[kind]
	if !ok {
		return fmt.Errorf("%w: evidence_kind %d is not a Worker bundle", ErrMalformed, kind)
	}
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
	if parsed.EvidenceKind != kind.String() {
		return fmt.Errorf("%w: worker manifest evidence_kind %q, want %q", ErrMalformed, parsed.EvidenceKind, kind)
	}
	if parsed.SchemaMetadata != "" {
		return fmt.Errorf("%w: worker manifest must not carry schema_metadata", ErrMalformed)
	}
	if len(parsed.Artifacts) != len(want) {
		return fmt.Errorf("%w: worker %s manifest has %d artifacts, want %d", ErrMalformed, kind, len(parsed.Artifacts), len(want))
	}
	for i, id := range want {
		if parsed.Artifacts[i].ArtifactID != id || manifest.Artifacts[i].ArtifactID != id {
			return fmt.Errorf("%w: worker manifest artifact %d is %q, want %q", ErrMalformed, i, parsed.Artifacts[i].ArtifactID, id)
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

// storedWorkerValuesRoot streams a stored worker_values artifact through WorkerValuesRootReader;
// every leaf must belong to this task and Worker and there must be one per generated token.
func (s *Service) storedWorkerValuesRoot(
	ctx context.Context, ref ObjectRef, size uint64, receipt SignedInferReceipt, decoded map[string][]byte,
) ([32]byte, error) {
	reader, err := s.store.OpenStored(ctx, ref)
	if err != nil {
		return [32]byte{}, err
	}
	defer reader.Close()
	root, err := nodecontract.WorkerValuesRootReader(reader, size, nodecontract.WorkerValueScope{
		ChainID: receipt.ChainID, TaskID: decoded["task_id"], AcceptedTaskHash: decoded["task_hash"],
		WorkerOperatorAddress: receipt.WorkerOperatorAddress,
	}, receipt.GeneratedTokenCount)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: worker_values artifact: %v", ErrHashMismatch, err)
	}
	return root, nil
}
