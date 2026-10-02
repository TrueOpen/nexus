// Package taskdata owns Nexus V1 INPUT, OUTPUT, and EVIDENCE objects.
package taskdata

import "errors"

var (
	ErrMalformed             = errors.New("NEXUS_DATA_MALFORMED")
	ErrUnauthorized          = errors.New("NEXUS_DATA_UNAUTHORIZED")
	ErrNotFound              = errors.New("NEXUS_DATA_NOT_FOUND")
	ErrConflict              = errors.New("NEXUS_DATA_CONFLICT")
	ErrExpired               = errors.New("NEXUS_DATA_EXPIRED")
	ErrCapacity              = errors.New("NEXUS_DATA_CAPACITY")
	ErrHashMismatch          = errors.New("NEXUS_DATA_HASH_MISMATCH")
	ErrRangeInvalid          = errors.New("NEXUS_DATA_RANGE_INVALID")
	ErrServiceKeyUnavailable = errors.New("NEXUS_DATA_SERVICE_KEY_UNAVAILABLE")
	ErrStorage               = errors.New("NEXUS_DATA_STORAGE")
	ErrAuthorityUnavailable  = errors.New("NEXUS_DATA_AUTHORITY_UNAVAILABLE")
	// USER requests: a signature that does not verify (including a wrong derived grant hash, a wrong
	// domain chainId or a version 1 signature), and a verified requester without the Task duty.
	ErrInvalidSignature = errors.New("DATA_ACCESS_INVALID_SIGNATURE")
	ErrDenied           = errors.New("DATA_ACCESS_DENIED")
	// ErrRequestMalformed is a USER request that fails the format step (step 1 of the user request
	// checks), which shares the code of a malformed SDK request envelope.
	ErrRequestMalformed = errors.New("NEXUS_INGRESS_MALFORMED")
	// ErrReplay is a request nonce already used within its expiry. On the CORTEX_SERVICE path it is
	// reported as NEXUS_DATA_UNAUTHORIZED, as before; OpenTask reports it as SDK_AUTH_REPLAY.
	ErrReplay = errors.New("NEXUS_DATA_REPLAY")
	// ErrRetentionExpired is a stored object deleted when its retention ran out; unlike
	// NEXUS_DATA_EXPIRED (the request expired, sign again) it is final.
	ErrRetentionExpired = errors.New("DATA_EXPIRED")
	// ErrOrderExpired is an OpenTask whose signed order is past its order_expire_height: the chain
	// no longer admits it, so the input is not stored.
	ErrOrderExpired = errors.New("NEXUS_INGRESS_ORDER_EXPIRED")
	// Session grant failures on the USER path.
	ErrSessionMethodNotAllowed = errors.New("DATA_ACCESS_SESSION_METHOD_NOT_ALLOWED")
	ErrSessionGrantInvalid     = errors.New("DATA_ACCESS_SESSION_GRANT_INVALID")
	ErrSessionGrantExpired     = errors.New("DATA_ACCESS_SESSION_GRANT_EXPIRED")
	// ErrNotReady is TASK_DATA_NOT_READY: the object is stored
	// but not READY yet, for example OUTPUT before the Worker's FinalizeTaskResult. It maps to the
	// same transport code as the two *_UNAVAILABLE errors above, so callers tell "ask this Builder
	// again later" from "this Builder cannot serve" by the NEXUS_DATA_NOT_READY message prefix.
	ErrNotReady = errors.New("NEXUS_DATA_NOT_READY")
)

// ObjectKey is an alias for ObjectRef: an object is uniquely determined by
// the nine fields of TaskDataObjectRefV1 (see objectref.go), and the local storage key is
// derived from the same fields, so the two are no longer separate identities.
type ObjectKey = ObjectRef

type RequestMethod string

const (
	MethodOpenTask    RequestMethod = "OpenTask"
	MethodGetMetadata RequestMethod = "GetTaskDataMetadata"
	// MethodFetch follows the method rename (formerly "DownloadTaskData").
	// The fetch path builds no RequestAuth (it uses the range signature under the
	// TRUEOPEN_TASK_DATA_RANGE_V1 domain), so the rename affects no signed bytes.
	MethodFetch RequestMethod = "FetchTaskData"
	// MethodUpload must equal the rpc name UploadTaskResultObject in ingress.proto:
	// auth.rpc_method enters the request signature byte for byte and Cortex signs the real
	// Connect path, so writing the old name "UploadTaskResultData" here would reject every
	// whole-object OUTPUT/EVIDENCE upload as a request binding failure.
	MethodUpload RequestMethod = "UploadTaskResultObject"
	// MethodUploadStream is the Header authorization method name of the streamed
	// upload (`UploadTaskOutputStream`): it is what distinguishes the stream from
	// the whole-object upload once it enters the request signature.
	MethodUploadStream RequestMethod = "UploadTaskOutputStream"
	// MethodFinalizeResult / MethodFinalizeVerifier are the two atomic commit points.
	// The method name enters the request signature, so the two are not interchangeable.
	MethodFinalizeResult   RequestMethod = "FinalizeTaskResult"
	MethodFinalizeVerifier RequestMethod = "FinalizeVerifierEvidence"
)

// The definition of RequestAuth moved to objectref.go (TaskDataRequestAuthV1).

// rpcMethodPath maps the internal method name back to the Connect path that auth.rpc_method must
// equal byte for byte. The method name enters the signature, so no approximation is allowed here —
// one different character is a different authorization.
func rpcMethodPath(method RequestMethod) string {
	return "/nexus.v1.IngressAPI/" + string(method)
}

// StorageConfirmation is BuilderStorageConfirmationV1:
// it only proves that the signing Builder has fully stored and verified the named data and can
// serve it for download within the retention window.
// It carries no local path, CID, endpoint, chunk location or locator.
//
// One confirmation covers INPUT, OUTPUT and a complete evidence bundle: every object difference
// is carried by Ref, so no second, nearly identical message is defined. EVIDENCE_ARTIFACT is not
// confirmed on its own — it is covered by the hash of its owning manifest and by that bundle's
// confirmation.
// The signing domain is TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V2, H_FIELDS_V1 covers the first eight
// fields and Signature does not enter its own digest. The idempotency key is
// material digest + builder operator.
type StorageConfirmation struct {
	SchemaVersion   uint32
	ChainID         string
	BuilderOperator string
	// ServiceAuthorizationNonce must equal the signer's currently ACTIVE service binding and be
	// non-zero; a later rotation neither invalidates an already verified confirmation nor lets an
	// old key sign a new one.
	ServiceAuthorizationNonce uint64
	Ref                       ObjectRef
	// SizeBytes: for INPUT/OUTPUT the object byte count; for EVIDENCE_MANIFEST the size of the
	// exact manifest bytes.
	SizeBytes uint64
	// ArtifactTotalSizeBytes is set only for EVIDENCE_MANIFEST and equals the checked sum of all
	// artifact sizes in the manifest; it is 0 for INPUT/OUTPUT.
	ArtifactTotalSizeBytes uint64
	// RetentionUntilHeight is the lower bound promised at signing time; extending the window does
	// not require re-signing.
	RetentionUntilHeight uint64
	Signature            []byte
}

// StorageConfirmationSchemaVersionV1 is the schema_version of BuilderStorageConfirmationV1.
const StorageConfirmationSchemaVersionV1 uint32 = 1

type SignedRange struct {
	Offset          uint64
	Length          uint64
	RequestNonce    []byte
	ExpiresAtHeight uint64
	Recipient       string
	RecipientPubKey []byte
	Signature       []byte
}

// SignedInferReceipt is the internal form of task.v1.InferReceiptV3; its fields correspond one to
// one. At this layer Hash32 is still canonical lowercase 64-hex text (the same convention as
// Metadata.SemanticHash) and nodecontract decodes it into the raw 32 bytes before it enters the
// receipt preimage.
//
// The receipt carries no infer_receipt_hash field: it is defined as the same value as
// infer_receipt_signing_digest, so it is always recomputed locally (InferReceiptDigestHex) and no
// caller-asserted copy is accepted.
type SignedInferReceipt struct {
	SchemaVersion             uint32
	ChainID                   string
	TaskID                    string
	TaskHash                  string
	WorkerOperatorAddress     string
	ServiceAuthorizationNonce uint64
	GenerationParamsDigest    string
	OutputHash                string
	OutputSizeBytes           uint64
	EvidenceCommitments       []EvidenceCommitment
	ExpiryHeight              uint64
	ServiceSignature          string
	GeneratedTokenCount       uint64
	OutputLeafCount           uint64
	// The four encryption fields, lowercase hex exactly as the Worker signed them (a plaintext task
	// carries 32 zero bytes in each; an empty value stays empty and is refused at admission).
	OutputKeyCommitment      string
	WorkerTokenKeyCommitment string
	WorkerValueKeyCommitment string
	CiphertextOutputRoot     string
}

// EvidenceCommitment is one entry of required_evidence_commitments[].
// Kind is the numeric shared.v1.EvidenceKind; HashOrRoot is canonical lowercase 64-hex.
type EvidenceCommitment struct {
	Kind             uint32
	HashOrRoot       string
	EncodedSizeBytes uint64
}

type RetentionStatus string

const (
	RetentionActive               RetentionStatus = "ACTIVE"
	RetentionRetainedForChallenge RetentionStatus = "RETAINED_FOR_CHALLENGE"
	RetentionEligibleForCleanup   RetentionStatus = "ELIGIBLE_FOR_CLEANUP"
	RetentionDeleted              RetentionStatus = "DELETED"
)

type State string

const (
	// StatePrepared is the staging state: the logical reference exists
	// and the bytes are still being written. Objects in this stage are not externally visible.
	StatePrepared State = "PREPARED"
	// StateStored is STORED: the bytes are fully written and the hash/size checks passed, but the
	// owning bundle has not been finalized yet. Readiness can be queried but the object cannot be
	// fetched.
	StateStored State = "STORED"
	// StateReady is READY: consistently bound to the manifest and the Receipt, and servable.
	// Only OpenTask's INPUT and the two Finalize calls can produce it.
	StateReady       State = "READY"
	StateQuarantined State = "QUARANTINED"
)

type Metadata struct {
	Key                 ObjectKey
	Uploader            string
	SemanticHash        string
	SizeBytes           uint64
	MediaType           string
	State               State
	RetentionStatus     RetentionStatus
	RetainUntilHeight   uint64
	Receipt             *SignedInferReceipt
	AcceptedReceiptHash string
	// Streamed OUTPUT: OutputMMRRoot is the TRUEOPEN_OUTPUT_MMR_V1 root (lowercase hex),
	// i.e. output_hash; ChunkLengths gives the byte count of each chunk in order; OutputLeafCount
	// is the chunk count (>= 1). All three are empty on the old whole-object upload path.
	OutputMMRRoot   string
	ChunkLengths    []uint32
	OutputLeafCount uint64
	// EVIDENCE_MANIFEST only: the values obtained by strictly parsing the manifest at upload time.
	// ArtifactTotalSizeBytes is the checked sum of all artifact sizes in the manifest and enters
	// the storage confirmation; EvidenceSchemaHash is what Finalize compares against the locked
	// Verification Profile; Artifacts is the detail of the artifacts referenced by the manifest,
	// which Finalize checks one by one for being STORED.
	// The parse result is persisted together with the object, so Finalize does not have to read the
	// bytes back and parse them again.
	ArtifactTotalSizeBytes uint64
	EvidenceSchemaHash     string
	Artifacts              []EvidenceArtifact
	// EvidenceBundleHash is H_V1(TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1, manifest bytes), i.e.
	// evidence_manifest_hash in the interface. It is exactly the ref content_hash of a Verifier
	// manifest; the ref content_hash of a Worker manifest is the evidence_hash_or_root of the
	// matching kind in the receipt (the typed token or value commitment, not a byte hash), so the
	// byte hash is recorded only here.
	EvidenceBundleHash string
}
