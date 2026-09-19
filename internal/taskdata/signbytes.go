package taskdata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	domainSelector = "TRUEOPEN_EVIDENCE_SELECTOR_V1"
	domainRequest  = "TRUEOPEN_TASK_DATA_REQUEST_V1"
	domainRange    = "TRUEOPEN_TASK_DATA_RANGE_V1"
	// DomainStorageConfirmation is the signing domain of BuilderStorageConfirmationV1,
	// H_FIELDS_V1 (wire v0.4.1 registry, Task Data Interface Design §6.3a).
	DomainStorageConfirmation = "TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V1"
)

var zeroDigest = make([]byte, sha256.Size)

// ObjectRefDigest is the object's local identity: the SHA-256 of the canonical object_ref frame.
// It is also the source of the storage key, so the local key and what the caller's signature
// commits to are the same set of fields — the old TRUEOPEN_EVIDENCE_SELECTOR_V1 allowed the two to
// disagree and was removed with wire v0.4.1.
func ObjectRefDigest(ref ObjectRef) ([sha256.Size]byte, error) {
	framed, err := CanonicalObjectRefFrame(ref)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(framed), nil
}

// RangeSignBytes binds every element required by contract §2.2: requester, Task, data_kind
// (including the evidence selector), range, validity and anti-replay nonce, plus chain_id /
// builder to prevent cross-chain and cross-Builder replay.
//
// Difference from the SDK contract v0.1 round: authorization_id is no longer bound — pre-signed
// download credentials were removed by Cortex contract §2.2 ("Nexus verifies the current service
// key and the on-chain role on the spot and does not use pre-signed download credentials").
// The exact wire structure of the range request is still unfrozen (contract §8.4).
func RangeSignBytes(chainID, builderAddress string, key ObjectKey, request SignedRange) ([]byte, error) {
	selector, err := validateObjectKey(key)
	if err != nil {
		return nil, err
	}
	if !canonicalText(chainID) || !canonicalText(builderAddress) || !canonicalText(request.Recipient) ||
		len(request.RequestNonce) < 16 || request.ExpiresAtHeight == 0 {
		return nil, fmt.Errorf("%w: range fields", ErrMalformed)
	}
	return frame4(
		[]byte(domainRange), []byte(chainID), []byte(builderAddress),
		[]byte(key.SessionID), []byte(key.TaskID), []byte(key.Kind.String()), selector[:],
		[]byte(request.Recipient), uint64Bytes(request.Offset), uint64Bytes(request.Length), request.RequestNonce,
		uint64Bytes(request.ExpiresAtHeight),
	)
}

// BuilderStorageConfirmationDigest is the signing digest of BuilderStorageConfirmationV1:
// H_FIELDS_V1 covers the eight fields schema_version, chain_id, builder_operator_address,
// service_authorization_nonce, canonical TaskDataObjectRefV1, size_bytes,
// artifact_total_size_bytes and retention_until_height; service_signature does not enter its own
// digest.
//
// EVIDENCE_ARTIFACT cannot be confirmed on its own: it is covered by the hash of its owning
// manifest and by that bundle's confirmation, and signing a single artifact would create a storage
// promise that no manifest governs.
func BuilderStorageConfirmationDigest(confirmation StorageConfirmation) ([32]byte, error) {
	if confirmation.SchemaVersion != StorageConfirmationSchemaVersionV1 {
		return [32]byte{}, fmt.Errorf("%w: storage confirmation schema_version", ErrMalformed)
	}
	if confirmation.ServiceAuthorizationNonce == 0 {
		return [32]byte{}, fmt.Errorf("%w: storage confirmation service_authorization_nonce", ErrMalformed)
	}
	if confirmation.SizeBytes == 0 || confirmation.RetentionUntilHeight == 0 {
		return [32]byte{}, fmt.Errorf("%w: storage confirmation size/retention", ErrMalformed)
	}
	switch confirmation.Ref.Kind {
	case ObjectKindInput, ObjectKindOutput:
		if confirmation.ArtifactTotalSizeBytes != 0 {
			return [32]byte{}, fmt.Errorf("%w: non-evidence confirmation must not carry artifact_total_size_bytes", ErrMalformed)
		}
	case ObjectKindEvidenceManifest:
	default:
		return [32]byte{}, fmt.Errorf("%w: storage confirmation object_kind", ErrMalformed)
	}
	chainID, err := nodecontract.CanonicalUTF8Field("chain_id", confirmation.ChainID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	builder, err := nodecontract.CanonicalOperatorAddressBytes("builder_operator_address", confirmation.BuilderOperator)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	ref, err := CanonicalObjectRefFrame(confirmation.Ref)
	if err != nil {
		return [32]byte{}, err
	}
	return nodecontract.CanonicalHashBytes(DomainStorageConfirmation,
		nodecontract.Uint32BE(confirmation.SchemaVersion),
		chainID,
		builder,
		nodecontract.Uint64BE(confirmation.ServiceAuthorizationNonce),
		ref,
		nodecontract.Uint64BE(confirmation.SizeBytes),
		nodecontract.Uint64BE(confirmation.ArtifactTotalSizeBytes),
		nodecontract.Uint64BE(confirmation.RetentionUntilHeight),
	), nil
}

// ConfirmationMaterialDigest is the material digest part of the idempotency key
// (the other half is the builder operator, which is already inside the signed range).
func ConfirmationMaterialDigest(confirmation StorageConfirmation) (string, error) {
	digest, err := BuilderStorageConfirmationDigest(confirmation)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func ServiceKeyFingerprint(publicKey []byte) ([sha256.Size]byte, error) {
	if len(publicKey) != 33 {
		return [sha256.Size]byte{}, fmt.Errorf("%w: compressed service public key", ErrMalformed)
	}
	return sha256.Sum256(publicKey), nil
}

// UploadBodyDigest is the body digest of an upload request. Since wire v0.4.1 it is exactly
// TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1 (objectref.go), committing to object_ref, size and media_type;
// the receipt no longer enters the body — it is committed by FinalizeTaskResult.
func UploadBodyDigest(header UploadHeader) ([sha256.Size]byte, error) {
	if header.SizeBytes == 0 || !validMediaType(header.Key.Kind, header.MediaType) {
		return [sha256.Size]byte{}, fmt.Errorf("%w: upload body", ErrMalformed)
	}
	// SemanticHash must equal the content_hash in the ref: object content has only one identity.
	if header.SemanticHash != header.Key.ContentHash {
		return [sha256.Size]byte{}, fmt.Errorf("%w: semantic hash must equal object_ref.content_hash", ErrMalformed)
	}
	return TaskDataUploadBodyDigest(header.Key, header.SizeBytes, header.MediaType)
}

// OutputStreamBodyDigest is the body digest of the streamed upload Header (Interface & Topic
// Catalogue §4.2.1): it reuses the whole-object upload body frame projected onto fixed values —
// at stream open the final root and total length are unknown, so size_bytes = 0,
// content hash = all zeros, media_type = "", and no receipt; it is distinguished from the
// whole-object upload by rpc_method = UploadTaskOutputStream entering the request signature.
// validateStreamKeyScope only checks the Task identity needed to query the chain. task_hash is not
// among them: the subscribe path cannot obtain it, and it is checked at the Header authorization
// step.
func validateStreamKeyScope(key ObjectKey) error {
	for _, f := range []struct{ name, value string }{
		{"session_id", key.SessionID}, {"task_id", key.TaskID},
	} {
		if _, err := canonicalHash32(f.name, f.value); err != nil {
			return err
		}
	}
	return nil
}

// validateStreamKey validates the locating fields of the stream being transferred. It deliberately
// omits content_hash — the object content does not exist yet when the stream starts, and the
// identity is only completed at Fin.
func validateStreamKey(key ObjectKey) error {
	if key.Kind != ObjectKindOutput {
		return fmt.Errorf("%w: output stream kind", ErrMalformed)
	}
	for _, f := range []struct{ name, value string }{
		{"task_hash", key.TaskHash}, {"session_id", key.SessionID}, {"task_id", key.TaskID},
	} {
		if _, err := canonicalHash32(f.name, f.value); err != nil {
			return err
		}
	}
	return nil
}

// OutputStreamBodyDigest is the body digest of the streamed Header.
//
// The content_hash is not known when the stream starts (it can only be computed at Fin), so this
// **must not** use the full object ref — the wire OutputStreamHeaderV1 also carries only
// (session_id, task_id, task_hash). It reuses TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1 projected onto fixed
// values: size 0 and empty media type, committing only to those three identity fields. This domain
// has not yet entered the closed set of five body domains in §4.2.1 and will be registered once
// the document is completed (the wire v0.4.1 comment says the same).
func OutputStreamBodyDigest(key ObjectKey) ([sha256.Size]byte, error) {
	if key.Kind != ObjectKindOutput {
		return [sha256.Size]byte{}, fmt.Errorf("%w: output stream kind", ErrMalformed)
	}
	// Fixed-value projection (Interface & Topic Catalogue §4.2.1): object_kind=OUTPUT,
	// content_hash=0x00*32, evidence_producer_kind=UNSPECIFIED, verify_round=0, producer_operator
	// absent; size_bytes=0, media_type="". At stream open the root and total length are unknown, so
	// the content_hash sent by the caller does not enter the digest.
	projected := ObjectRef{
		TaskHash: key.TaskHash, SessionID: key.SessionID, TaskID: key.TaskID,
		Kind: ObjectKindOutput, ContentHash: hex.EncodeToString(make([]byte, sha256.Size)),
	}
	return TaskDataUploadBodyDigest(projected, 0, "")
}

// receiptFrame is the local 4-byte length-prefixed frame of the Builder storage confirmation
// (contract §8.3, unfrozen); it is not the §5.14 consensus preimage — for that see
// InferReceiptSubmission / receiptDigest.
// The field set follows the frozen wire: commit hash / trace / checkpoint / batch / token_count /
// work_unit were removed and are now carried by typed evidence commitments.
func receiptFrame(receipt SignedInferReceipt) ([]byte, error) {
	if !canonicalText(receipt.TaskID) || !canonicalText(receipt.WorkerOperatorAddress) ||
		!canonicalText(receipt.ChainID) || !canonicalSHA256(receipt.TaskHash) ||
		!canonicalSHA256(receipt.GenerationParamsDigest) || !canonicalSHA256(receipt.OutputHash) ||
		receipt.OutputSizeBytes == 0 || receipt.SchemaVersion == 0 ||
		receipt.ServiceAuthorizationNonce == 0 || receipt.ExpiryHeight == 0 ||
		!canonicalSignatureHex(receipt.ServiceSignature) {
		return nil, fmt.Errorf("%w: infer receipt", ErrMalformed)
	}
	fields := [][]byte{
		uint32Bytes(receipt.SchemaVersion), []byte(receipt.ChainID), []byte(receipt.TaskID),
		[]byte(receipt.TaskHash), []byte(receipt.WorkerOperatorAddress),
		uint64Bytes(receipt.ServiceAuthorizationNonce), []byte(receipt.GenerationParamsDigest),
		[]byte(receipt.OutputHash), uint64Bytes(receipt.OutputSizeBytes),
		uint64Bytes(receipt.ExpiryHeight), []byte(receipt.ServiceSignature),
	}
	for _, commitment := range receipt.EvidenceCommitments {
		if !canonicalSHA256(commitment.HashOrRoot) {
			return nil, fmt.Errorf("%w: infer receipt evidence commitment", ErrMalformed)
		}
		fields = append(fields,
			uint32Bytes(commitment.Kind), []byte(commitment.HashOrRoot), uint64Bytes(commitment.EncodedSizeBytes))
	}
	return frame4(fields...)
}

// receiptSubmission converts the persisted form into the submission object nodecontract needs.
func receiptSubmission(receipt SignedInferReceipt) (types.InferReceiptSubmission, error) {
	generationParamsDigest, err := nodecontract.Hash32Bytes("generation_params_digest", receipt.GenerationParamsDigest)
	if err != nil {
		return types.InferReceiptSubmission{}, err
	}
	outputHash, err := nodecontract.Hash32Bytes("output_hash", receipt.OutputHash)
	if err != nil {
		return types.InferReceiptSubmission{}, err
	}
	commitments := make([]types.EvidenceCommitment, 0, len(receipt.EvidenceCommitments))
	for _, commitment := range receipt.EvidenceCommitments {
		hashOrRoot, err := nodecontract.Hash32Bytes("evidence_hash_or_root", commitment.HashOrRoot)
		if err != nil {
			return types.InferReceiptSubmission{}, err
		}
		commitments = append(commitments, types.EvidenceCommitment{
			Kind: commitment.Kind, HashOrRoot: hashOrRoot, EncodedSizeBytes: commitment.EncodedSizeBytes,
		})
	}
	signature, err := nodecontract.Signature64Bytes("service_signature", receipt.ServiceSignature)
	if err != nil {
		return types.InferReceiptSubmission{}, err
	}
	return types.InferReceiptSubmission{
		SchemaVersion: receipt.SchemaVersion, ChainID: receipt.ChainID, TaskID: receipt.TaskID,
		TaskHash: receipt.TaskHash, WorkerAddress: receipt.WorkerOperatorAddress,
		ServiceAuthorizationNonce: receipt.ServiceAuthorizationNonce,
		GenerationParamsDigest:    generationParamsDigest, OutputHash: outputHash,
		OutputSizeBytes: receipt.OutputSizeBytes, EvidenceCommitments: commitments,
		ExpiryHeight: receipt.ExpiryHeight, WorkerServiceSignature: signature,
		GeneratedTokenCount: receipt.GeneratedTokenCount, OutputLeafCount: receipt.OutputLeafCount,
	}, nil
}

// receiptDigest recomputes the §5.14 infer_receipt_signing_digest (= infer_receipt_hash).
func receiptDigest(receipt SignedInferReceipt) ([32]byte, error) {
	submission, err := receiptSubmission(receipt)
	if err != nil {
		return [32]byte{}, err
	}
	return nodecontract.InferReceiptSigningDigestFromSubmission(submission)
}

// All the rules of validateObjectKey live in CanonicalObjectRefFrame: the shape of the eight
// fields, non-evidence objects not carrying the three producer fields, and evidence objects having
// to carry a producer kind. No second copy is written here.
func validateObjectKey(key ObjectKey) ([sha256.Size]byte, error) {
	return ObjectRefDigest(key)
}

func validMethod(method RequestMethod) bool {
	switch method {
	case MethodOpenTask, MethodGetMetadata, MethodFetch, MethodUpload, MethodUploadStream,
		MethodFinalizeResult, MethodFinalizeVerifier:
		return true
	default:
		return false
	}
}

func canonicalText(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

// validMediaType follows Task Data Interface Design §6.2: media_type is only an optional transport
// hint and may be empty; the codec of EVIDENCE_ARTIFACT is defined solely by the evidence schema,
// so it must be empty.
func validMediaType(kind ObjectKind, mediaType string) bool {
	if kind == ObjectKindEvidenceArtifact {
		return mediaType == ""
	}
	return mediaType == "" || canonicalText(mediaType)
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func canonicalSignatureHex(value string) bool {
	if len(value) != 128 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 64
}

func uint64Bytes(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func uint32Bytes(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, value)
	return encoded
}

func frame4(fields ...[]byte) ([]byte, error) {
	total := uint64(0)
	for _, field := range fields {
		if uint64(len(field)) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: frame field too large", ErrMalformed)
		}
		total += 4 + uint64(len(field))
		if total > uint64(math.MaxInt) {
			return nil, fmt.Errorf("%w: frame too large", ErrMalformed)
		}
	}
	framed := make([]byte, 0, int(total))
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed, nil
}
