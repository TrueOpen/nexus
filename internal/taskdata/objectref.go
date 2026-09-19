// Object addressing and request authentication framing for the Task data plane (Interface &
// Topic Catalogue §4.2.1).
//
// Since wire v0.4.1 an object is uniquely determined by the eight fields of
// TaskDataObjectRefV1, and request authentication is unified as TaskDataRequestAuthV1 plus
// a closed set of five body domains. This file only encodes those two into canonical bytes;
// authorization decisions live in authorizer.go.
package taskdata

import (
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// The five body domains and the outer request domain. body_digest must come from this
// closed set; never build a domain name per RPC.
const (
	DomainTaskDataRequest              = "TRUEOPEN_TASK_DATA_REQUEST_V1"
	DomainTaskDataUploadBody           = "TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1"
	DomainTaskDataMetadataBody         = "TRUEOPEN_TASK_DATA_METADATA_BODY_V1"
	DomainTaskDataFetchBody            = "TRUEOPEN_TASK_DATA_FETCH_BODY_V1"
	DomainTaskDataFinalizeResultBody   = "TRUEOPEN_TASK_DATA_FINALIZE_RESULT_BODY_V1"
	DomainTaskDataFinalizeVerifierBody = "TRUEOPEN_TASK_DATA_FINALIZE_VERIFIER_BODY_V1"
)

// ObjectKind is the internal form of TaskDataObjectKind. On the wire EVIDENCE splits into
// manifest and artifact, whose storage and authorization rules differ, so they must stay
// separate internally too; merging them into one EVIDENCE would mix the manifest's exact
// bytes semantics with the artifact's schema semantics on the same path.
type ObjectKind uint32

const (
	ObjectKindUnspecified      ObjectKind = 0
	ObjectKindInput            ObjectKind = 1
	ObjectKindOutput           ObjectKind = 2
	ObjectKindEvidenceManifest ObjectKind = 3
	ObjectKindEvidenceArtifact ObjectKind = 4
)

func (k ObjectKind) String() string {
	switch k {
	case ObjectKindInput:
		return "INPUT"
	case ObjectKindOutput:
		return "OUTPUT"
	case ObjectKindEvidenceManifest:
		return "EVIDENCE_MANIFEST"
	case ObjectKindEvidenceArtifact:
		return "EVIDENCE_ARTIFACT"
	default:
		return ""
	}
}

// IsEvidence covers the two kinds addressed by (producer_kind, verify_round, producer_operator).
func (k ObjectKind) IsEvidence() bool {
	return k == ObjectKindEvidenceManifest || k == ObjectKindEvidenceArtifact
}

// EvidenceProducerKind identifies the producer of an evidence bundle. Non-evidence objects
// always use Unspecified; it is not arbitrary, since it enters the preimage and a wrong
// value means a different object.
type EvidenceProducerKind uint32

const (
	EvidenceProducerUnspecified EvidenceProducerKind = 0
	EvidenceProducerWorker      EvidenceProducerKind = 1
	EvidenceProducerVerifier    EvidenceProducerKind = 2
)

// ObjectRef is the internal form of TaskDataObjectRefV1. Hash32 stays canonical lowercase
// 64-hex text at this layer (same as Metadata.SemanticHash) and is decoded into raw 32 bytes
// before entering the preimage.
//
// ProducerOperator is optional: non-evidence objects must leave it empty, and evidence
// objects set it to the bundle producer. An empty string means absent, not "an empty
// address was supplied".
type ObjectRef struct {
	TaskHash             string
	SessionID            string
	TaskID               string
	Kind                 ObjectKind
	ContentHash          string
	EvidenceProducerKind EvidenceProducerKind
	VerifyRound          uint32
	ProducerOperator     string
}

// ByteRange is the optional sub-range of FetchTaskData. A whole read must be absent, never
// a present range with zero offset/length: their preimages differ and signatures are not
// interchangeable.
type ByteRange struct {
	Offset uint64
	Length uint64
}

// canonicalOptional applies Base Spec §4.4: absent is the single byte 0x00, present is
// 0x01 || u64be(len(value)) || value.
func canonicalOptional(present bool, value []byte) []byte {
	if !present {
		return []byte{0x00}
	}
	out := make([]byte, 0, 1+8+len(value))
	out = append(out, 0x01)
	out = append(out, nodecontract.CanonicalFrameBytes(value)...)
	return out
}

func canonicalHash32(field, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || value != hex.EncodeToString(raw) {
		return nil, fmt.Errorf("%w: %s must be 32-byte lowercase hex", ErrMalformed, field)
	}
	return raw, nil
}

// CanonicalObjectRefFrame is the nested FieldFrameV1 of object_ref: eight fields in
// ascending schema field number order, with no domain prefix. It is the first field of
// four body domains and the fifth field of the storage confirmation, so it is defined once here.
func CanonicalObjectRefFrame(ref ObjectRef) ([]byte, error) {
	if ref.Kind == ObjectKindUnspecified {
		return nil, fmt.Errorf("%w: object_kind", ErrMalformed)
	}
	taskHash, err := canonicalHash32("task_hash", ref.TaskHash)
	if err != nil {
		return nil, err
	}
	sessionID, err := canonicalHash32("session_id", ref.SessionID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", ref.TaskID)
	if err != nil {
		return nil, err
	}
	contentHash, err := canonicalHash32("content_hash", ref.ContentHash)
	if err != nil {
		return nil, err
	}
	// Non-evidence objects must pin the three producer fields, otherwise one OUTPUT could
	// yield multiple refs from different producer triples and retrieval and attribution
	// would disagree.
	if !ref.Kind.IsEvidence() {
		if ref.EvidenceProducerKind != EvidenceProducerUnspecified || ref.VerifyRound != 0 || ref.ProducerOperator != "" {
			return nil, fmt.Errorf("%w: non-evidence object must not carry producer fields", ErrMalformed)
		}
	} else if ref.EvidenceProducerKind == EvidenceProducerUnspecified {
		return nil, fmt.Errorf("%w: evidence_producer_kind", ErrMalformed)
	}

	producer := []byte(nil)
	if ref.ProducerOperator != "" {
		producer, err = nodecontract.CanonicalOperatorAddressBytes("producer_operator", ref.ProducerOperator)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
	}
	return nodecontract.CanonicalFrameBytes(
		taskHash,
		sessionID,
		taskID,
		nodecontract.EnumBE(uint32(ref.Kind)),
		contentHash,
		nodecontract.EnumBE(uint32(ref.EvidenceProducerKind)),
		nodecontract.Uint32BE(ref.VerifyRound),
		canonicalOptional(ref.ProducerOperator != "", producer),
	), nil
}

// TaskDataUploadBodyDigest is the body digest of UploadTaskResultObject.
func TaskDataUploadBodyDigest(ref ObjectRef, sizeBytes uint64, mediaType string) ([32]byte, error) {
	frame, err := CanonicalObjectRefFrame(ref)
	if err != nil {
		return [32]byte{}, err
	}
	media, err := nodecontract.CanonicalUTF8Field("media_type", mediaType)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nodecontract.CanonicalHashBytes(DomainTaskDataUploadBody,
		frame, nodecontract.Uint64BE(sizeBytes), media), nil
}

// TaskDataMetadataBodyDigest is the body digest of GetTaskDataMetadata: it commits only to object_ref.
func TaskDataMetadataBodyDigest(ref ObjectRef) ([32]byte, error) {
	frame, err := CanonicalObjectRefFrame(ref)
	if err != nil {
		return [32]byte{}, err
	}
	return nodecontract.CanonicalHashBytes(DomainTaskDataMetadataBody, frame), nil
}

// TaskDataFetchBodyDigest is the body digest of FetchTaskData. A nil rng means a whole read.
func TaskDataFetchBodyDigest(ref ObjectRef, rng *ByteRange) ([32]byte, error) {
	frame, err := CanonicalObjectRefFrame(ref)
	if err != nil {
		return [32]byte{}, err
	}
	var inner []byte
	if rng != nil {
		if rng.Length == 0 {
			return [32]byte{}, fmt.Errorf("%w: present range must have a positive length", ErrRangeInvalid)
		}
		inner = nodecontract.CanonicalFrameBytes(
			nodecontract.Uint64BE(rng.Offset), nodecontract.Uint64BE(rng.Length))
	}
	return nodecontract.CanonicalHashBytes(DomainTaskDataFetchBody,
		frame, canonicalOptional(rng != nil, inner)), nil
}

// TaskDataFinalizeResultBodyDigest is the body digest of FinalizeTaskResult.
// infer_receipt_signature_digest is the SHA256 of the raw64 signature, not a hash of its text form.
func TaskDataFinalizeResultBodyDigest(taskHash, sessionID, taskID, inferReceiptHash, receiptSignatureDigest string) ([32]byte, error) {
	fields := make([][]byte, 0, 5)
	for _, f := range []struct{ name, value string }{
		{"task_hash", taskHash}, {"session_id", sessionID}, {"task_id", taskID},
		{"infer_receipt_hash", inferReceiptHash}, {"infer_receipt_signature_digest", receiptSignatureDigest},
	} {
		raw, err := canonicalHash32(f.name, f.value)
		if err != nil {
			return [32]byte{}, err
		}
		fields = append(fields, raw)
	}
	return nodecontract.CanonicalHashBytes(DomainTaskDataFinalizeResultBody, fields...), nil
}

// TaskDataFinalizeVerifierBodyDigest is the body digest of FinalizeVerifierEvidence.
func TaskDataFinalizeVerifierBodyDigest(
	taskHash, sessionID, taskID string,
	verifyRound uint32,
	verifierOperator, resultReceiptSigningDigest, resultReceiptSignatureDigest string,
) ([32]byte, error) {
	scope := make([][]byte, 0, 3)
	for _, f := range []struct{ name, value string }{
		{"task_hash", taskHash}, {"session_id", sessionID}, {"task_id", taskID},
	} {
		raw, err := canonicalHash32(f.name, f.value)
		if err != nil {
			return [32]byte{}, err
		}
		scope = append(scope, raw)
	}
	operator, err := nodecontract.CanonicalOperatorAddressBytes("verifier_operator", verifierOperator)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	signing, err := canonicalHash32("result_receipt_signing_digest", resultReceiptSigningDigest)
	if err != nil {
		return [32]byte{}, err
	}
	signature, err := canonicalHash32("result_receipt_signature_digest", resultReceiptSignatureDigest)
	if err != nil {
		return [32]byte{}, err
	}
	return nodecontract.CanonicalHashBytes(DomainTaskDataFinalizeVerifierBody,
		scope[0], scope[1], scope[2],
		nodecontract.Uint32BE(verifyRound), operator, signing, signature), nil
}

// RequesterKind alone selects the verification path of TaskDataRequestAuthV1: never sniff by
// signature length, and never trust a caller-supplied public key.
type RequesterKind uint32

const (
	RequesterKindUnspecified   RequesterKind = 0
	RequesterKindUser          RequesterKind = 1
	RequesterKindCortexService RequesterKind = 2
)

// RequestAuthV1 is the internal form of TaskDataRequestAuthV1. Signature is not in the
// preimage, nor is Key: it is the object ref used for local addressing, taken by each RPC
// from its own request body and bound indirectly through BodyDigest (the first field of
// every body domain is the canonical object_ref).
type RequestAuthV1 struct {
	SchemaVersion             uint32
	ChainID                   string
	BuilderOperatorAddress    string
	RPCMethod                 string
	BodyDigest                string
	RequesterKind             RequesterKind
	RequesterAddress          string
	ServiceAuthorizationNonce uint64
	RequestNonce              []byte
	ExpiryHeight              uint64
	Signature                 []byte

	// Key is the object this request addresses; it enters no preimage.
	Key ObjectRef
}

// RequestAuth is the old name of RequestAuthV1, kept so one change does not spread to every call site.
type RequestAuth = RequestAuthV1

// CortexTaskDataRequestDigest is the direct digest of the CORTEX_SERVICE path: H_FIELDS_V1
// over fields 1..10, excluding the signature itself. The USER path signs the same ten values
// as EIP-712 typed data producing a keccak digest and does not go through here.
func CortexTaskDataRequestDigest(auth RequestAuthV1) ([32]byte, error) {
	chainID, err := nodecontract.CanonicalUTF8Field("chain_id", auth.ChainID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	builder, err := nodecontract.CanonicalOperatorAddressBytes("builder_operator_address", auth.BuilderOperatorAddress)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	method, err := nodecontract.CanonicalUTF8Field("rpc_method", auth.RPCMethod)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	bodyDigest, err := canonicalHash32("body_digest", auth.BodyDigest)
	if err != nil {
		return [32]byte{}, err
	}
	requester, err := nodecontract.CanonicalOperatorAddressBytes("requester_address", auth.RequesterAddress)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(auth.RequestNonce) != 32 {
		return [32]byte{}, fmt.Errorf("%w: request_nonce must be 32 bytes", ErrMalformed)
	}
	// The USER path has different nonce semantics: it must be 0, asserted by the caller at
	// admission; the derivation function stays total (as with InferReceipt's schema_version).
	return nodecontract.CanonicalHashBytes(DomainTaskDataRequest,
		nodecontract.Uint32BE(auth.SchemaVersion),
		chainID,
		builder,
		method,
		bodyDigest,
		nodecontract.EnumBE(uint32(auth.RequesterKind)),
		requester,
		nodecontract.Uint64BE(auth.ServiceAuthorizationNonce),
		append([]byte(nil), auth.RequestNonce...),
		nodecontract.Uint64BE(auth.ExpiryHeight),
	), nil
}
