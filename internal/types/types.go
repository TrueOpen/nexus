// Package types holds shared data types used across nexus modules.
package types

import "errors"

// Error sentinels shared across modules (returned by coordinator, mapped to error codes by ingress; kept here to avoid reverse dependencies).
var (
	// ErrTaskNotFound: query for an unknown task (TASK_NOT_FOUND).
	ErrTaskNotFound = errors.New("task not found")
	// ErrUnauthorized: requester is not entitled to fetch at this access_level (CREDENTIAL_UNAUTHORIZED).
	ErrUnauthorized = errors.New("requester not authorized for access level")
	// ErrInvalidSignature: external role signature is invalid (INVALID_SIGNATURE).
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrInvalidArgument: external input is missing or self-contradictory (MALFORMED).
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrFailedPrecondition: the request itself is valid, but the task's current phase does not accept it (FAILED_PRECONDITION).
	ErrFailedPrecondition = errors.New("failed precondition")
	// ErrChainStateUnavailable: authoritative chain height or task facts are temporarily unavailable.
	ErrChainStateUnavailable = errors.New("authoritative chain state unavailable")
)

// TaskState is the state of the per-order state machine.
type TaskState int

const (
	Pending   TaskState = iota // waiting for hand-raise
	Assigned                   // AssignTx included in a block, winner decided
	Verifying                  // OpenVerify included in a block, commit-reveal in progress
	Settled                    // SettleTx included in a block, challenge window open
	Closed                     // challenge window closed, escrow released
	Failed                     // any stage failed or timed out; terminal
)

func (s TaskState) String() string {
	switch s {
	case Pending:
		return "PENDING"
	case Assigned:
		return "ASSIGNED"
	case Verifying:
		return "VERIFYING"
	case Settled:
		return "SETTLED"
	case Closed:
		return "CLOSED"
	case Failed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// TaskPhase is the fine-grained state, aligned with the Keeper/cortex FSM.
// It expresses intermediate states such as randomness pending / sample ready / full reveal / sweep;
// externally the coarse TaskState is returned by default, while internals and QueryTask may expose TaskPhase.
type TaskPhase int

const (
	PhaseUnspecified             TaskPhase = iota
	PhaseAssignRandomnessPending           // AssignAccepted: AssignTx included in a block, winner not yet decided
	PhaseAssignmentFinalized               // AssignmentFinalized: randomness settled, winner determined
	PhaseOpenVerify                        // OpenVerifyAccepted: formal Verifiers decided, seed not yet decided
	PhaseSampleReady                       // SampleReady: future beacon aggregates sample_seed
	PhaseCommit                            // VerifyCommitAccepted
	PhaseWorkerReveal                      // WorkerRevealReceiptAccepted
	PhaseFullResultReveal                  // FullResultRevealAccepted: Verifier full-result reveal as self-rescue
	PhaseSettle                            // SettleAccepted
	PhaseSweepObserved                     // SweepDeadlineAccepted: timeout sweep advanced
)

func (p TaskPhase) String() string {
	switch p {
	case PhaseAssignRandomnessPending:
		return "ASSIGN_RANDOMNESS_PENDING"
	case PhaseAssignmentFinalized:
		return "ASSIGNMENT_FINALIZED"
	case PhaseOpenVerify:
		return "OPEN_VERIFY"
	case PhaseSampleReady:
		return "SAMPLE_READY"
	case PhaseCommit:
		return "COMMIT"
	case PhaseWorkerReveal:
		return "WORKER_REVEAL"
	case PhaseFullResultReveal:
		return "FULL_RESULT_REVEAL"
	case PhaseSettle:
		return "SETTLE"
	case PhaseSweepObserved:
		return "SWEEP_OBSERVED"
	default:
		return "UNSPECIFIED"
	}
}

// Coarse returns the coarse state a fine-grained phase maps to. Whether SWEEP_OBSERVED
// maps to SETTLED or FAILED depends on the swept stage and is decided by the state machine when it receives the event; SETTLED is the default here.
func (p TaskPhase) Coarse() TaskState {
	switch p {
	case PhaseAssignRandomnessPending:
		return Pending
	case PhaseAssignmentFinalized:
		return Assigned
	case PhaseOpenVerify, PhaseSampleReady, PhaseCommit, PhaseWorkerReveal, PhaseFullResultReveal:
		return Verifying
	case PhaseSettle, PhaseSweepObserved:
		return Settled
	default:
		return Pending
	}
}

// AccessLevel is the fetch authorization tier.
type AccessLevel int

const (
	// AccessPackage fetches the canonical output package + commitments (for candidate Verifiers to check before hand-raise); no sealed key.
	AccessPackage AccessLevel = iota
	// AccessSealedKey fetches the sealed key (order user / formal Verifier chosen by verify-select).
	AccessSealedKey
)

func (a AccessLevel) String() string {
	if a == AccessSealedKey {
		return "SEALED_KEY"
	}
	return "PACKAGE"
}

// types.Stage / types.ParseStage have been removed. Their only consumer was the swept_stage attr of the
// deadline sweep event, and the chain replaced that attr with DeadlineKindV1 +
// DeadlineTransitionCode (see chaincli.SweepDeadlineAccepted). The three-stage coordination vocabulary
// between off-chain Builders still lives in msgbus.BusStage and is unrelated to this type.

// TaskVerdict is computed by the chain (not self-reported by Verifiers).
type TaskVerdict int

const (
	VerdictUnspecified TaskVerdict = iota
	VerdictPass
	VerdictFail
	VerdictNoConsensus
	VerdictFailRevealTimeout
	VerdictWorkerTimeout
	VerdictVerifyUnavailable
	VerdictAssignTimeout
)

// Order is a single order (delivered to the Coordinator after IngressAPI signature verification).
// Composite key: session_id + task_id.
type Order struct {
	SessionID     string
	TaskID        string
	OrderSequence uint64
	// ModelID is the lowercase hex of the order's raw 32-byte model_id; it is decoded back only where
	// it enters a chain or bus message.
	ModelID        string
	ProfileVersion uint32
	TaskType       string
	PayloadCID     string // content-addressed reference to the encrypted input, not the blob itself
	Payload        []byte `json:"-"` // encrypted input body; exists only during the Ingress -> Coordinator hand-off, never enters task snapshots/NATS
	User           string // on-chain address of the ordering user (SDK envelope signer_address; empty = envelope not enabled)
	Deadline       int64
	PriceHint      string

	OrderEnvelope string
	// TaskHash is the canonical identity of this order version:
	// H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V3", canonical TaskOrderV3), lowercase 64-hex.
	// Only the SignedOrder branch can fill it -- it must derive from the TaskOrderV3 the user actually signed.
	// The legacy JSON order_envelope lacks chain_id / session_anchor_* / builder_set_* /
	// generation_params and cannot build the preimage at all, so on that path this is the empty string, and
	// an order with an empty task_hash is never broadcast (taskfsm.onOrder).
	//
	// It replaces the old OrderDigest (= sha256(order_envelope)). Never write any "envelope
	// byte digest" into this field: that is a transport-layer concern; if needed it is called payload_digest
	// and lives in BusEnvelopeV1 field 20.
	TaskHash        string
	SignatureScheme string
	UserSignature   string
	// SignedOrder is the proto-encoded task.v1.SignedOrderV2 submitted directly by the SDK
	// It is the only legitimate carrier for the first-proposal scope branch of
	// MsgSubmitWorkerHandraises: the user signed the TaskOrderV3 inside it, so Nexus may only forward it
	// verbatim and cannot derive it from the legacy JSON order_envelope (the legacy envelope lacks chain_id /
	// session_anchor_* / builder_set_* / generation_params, and its signature coverage differs).
	// Empty = the SDK is still sending the legacy JSON envelope, in which case only the ExistingTaskRefV1
	// branch is available. Stored as wire bytes so it survives JSON snapshotting intact.
	SignedOrder             []byte
	RewardBucket            uint64
	ProfileResourceTier     uint64
	InferInputUnitPriceBid  uint64
	InferOutputUnitPriceBid uint64
	VerifyUnitPriceBid      uint64
	MaxFee                  uint64
	TxFeeReserve            uint64
	InferFeeCap             uint64
	VerifyFeeCap            uint64
	OrderValue              uint64
	ValidAfterHeight        uint64
	DeadlineHeight          uint64
	PayloadHash             string
	InferTimeoutBlocks      uint64
	ReferenceBucketKey      string
	TimeoutBucketKey        string
	Stage1BuilderRank       uint64
	Stage1SelectionProof    string
}

// TaskPayload is the encrypted input that Nexus holds temporarily and returns under per-task authorization.
type TaskPayload struct {
	SessionID      string
	TaskID         string
	Ref            string
	Hash           string
	Payload        []byte
	DeadlineHeight uint64
}

// InferReceiptSubmission is the signed InferReceipt the selected Worker hands to the Builder via
// SubmitInferReceipt; KB-sized end to end.
// Composite key: session_id + task_id.
//
// The protocol removed the OutputRef and SubmitOutputRef objects, so this struct
// no longer carries output_cid, sealed key, canonical_output_package_hash or output_delivery_commitment:
// actual output/evidence content goes through UploadTaskResultData + FetchTaskData, and
// fetch location and decryption key are no longer protocol objects.
//
// The field set corresponds one-to-one with task.v1.InferReceiptV2,
// so the coordinator can assemble MsgSubmitInferReceipt verbatim. The Node baseline once expressed the same
// commitments as trace/checkpoint/batch root + token_count/work_unit; wire replaced them
// with typed EvidenceCommitments (folded into evidence_commitments_hash when entering the preimage), and
// work_unit moved to the SETTLEMENT_BILL leaf.
//
// InferReceiptHash is the signing digest recomputed locally per TRUEOPEN_INFER_RECEIPT_V1, not a self-declared
// value submitted by the caller: wire defines infer_receipt_hash and infer_receipt_signing_digest as the same
// value, and there is no assertable copy on the wire.
type InferReceiptSubmission struct {
	SessionID                 string
	SchemaVersion             uint32
	ChainID                   string
	TaskID                    string
	TaskHash                  string
	WorkerAddress             string
	ServiceAuthorizationNonce uint64
	GenerationParamsDigest    []byte
	OutputHash                []byte
	OutputSizeBytes           uint64
	EvidenceCommitments       []EvidenceCommitment
	ExpiryHeight              uint64
	WorkerServiceSignature    []byte
	InferReceiptHash          []byte
	// GeneratedTokenCount and OutputLeafCount are the 12th and 13th preimage fields added in
	// InferReceiptV2. OutputLeafCount is the leaf count of the MMR behind OutputHash:
	// the root alone does not fix the tree shape; attribution needs it to locate each peak.
	GeneratedTokenCount uint64
	OutputLeafCount     uint64
	// The four InferReceiptV3 encryption fields (15-18). A plaintext task carries 32 zero bytes in each;
	// they are kept as received so the recomputed digest matches what the Worker signed.
	OutputKeyCommitment      []byte
	WorkerTokenKeyCommitment []byte
	WorkerValueKeyCommitment []byte
	CiphertextOutputRoot     []byte
}

// EvidenceCommitment is a single entry of required_evidence_commitments[].
// Kind is the numeric value of shared.v1.EvidenceKind (closed enum, enters the preimage as big-endian
// uint32 in the canonical encoding); the numeric value is stored instead of the enum type so this package does not depend on generated code.
type EvidenceCommitment struct {
	Kind             uint32
	HashOrRoot       []byte
	EncodedSizeBytes uint64
}

// PlaintextOutput is the final plaintext Nexus delivers short-term to the original ordering user.
// Plaintext may only exist in outputdelivery; it must not be embedded in OutputRef, events or task snapshots.
type PlaintextOutput struct {
	OutputID  string
	SessionID string
	TaskID    string
	Text      string
	Hash      []byte
	CreatedAt int64
	ExpiresAt int64
}

// OutputAck is the idempotent result after the user confirms the final output has been safely stored.
type OutputAck struct {
	Acked        bool
	AlreadyAcked bool
	AckedAt      int64
}

// VerifyRelayAck is the result of the Builder relaying a Verifier's commit / result: it only means the tx was
// broadcast, not that it was accepted on chain. Idempotent means the same message was relayed before and was not broadcast again.
type VerifyRelayAck struct {
	Idempotent bool
	TxHash     []byte
}

// BuilderRef is a group member and its endpoint.
type BuilderRef struct {
	Address  string
	Endpoint string
	Rank     int
}

// Coin is an on-chain asset amount.
type Coin struct {
	Denom  string
	Amount string // big integer as string to avoid precision loss
}

// SampledReveal is the Worker's true value at a sampled point + merkle proof (commit-reveal).
// Shape: { index, W_i, merkle_path }.
type SampledReveal struct {
	Index      int      // sample point index (in sample_seed order)
	WI         []byte   // true value W_i at that point
	MerklePath [][]byte // merkle proof up to output_root
}

// Deadlines are the four on-chain deadline heights of commit-reveal.
// Invariant: Commit < WorkerReveal < Reveal < Verify.
type Deadlines struct {
	Commit       int64 // deadline for Verifier commit submission
	WorkerReveal int64 // deadline for Worker reveal receipt on chain
	Reveal       int64 // deadline for Verifier reveal of V_i
	Verify       int64 // deadline for chain-computed verdict
}

// TaskStatus is the task state snapshot returned to external queries (coarse + fine-grained state).
type TaskStatus struct {
	State     string // coarse TaskState
	TaskPhase string // fine-grained TaskPhase
	Stage     string
	SetID     string
	UpdatedAt int64
}

// TaskEvent is a single record of the GetTaskEvents event stream.
// Used only for UX hints and reconnect recovery; on-chain state is authoritative via chain query.
type TaskEvent struct {
	Seq         uint64 // monotonically increasing within a task; its string form is the cursor
	EventCode   string // stable event code (ORDER_RECEIVED / ASSIGNMENT_FINALIZED / ...)
	State       string // coarse TaskState after the event
	TaskPhase   string // fine-grained TaskPhase after the event
	ChainHeight int64  // set when the event comes from chain, otherwise 0
	TS          int64  // record time (Unix milliseconds)
}

// Credential is the fetch credential CredentialV1: bound to task/recipient/usage/
// validity period and issued by the Builder; refresh exchanges the old credential + held credential record for a new one.
type Credential struct {
	ID          string // = hex(sha256(SignBytes)), generated at issue time
	SessionID   string
	TaskID      string
	Recipient   string // target recipient address
	Usage       string // SDK_DELIVERY / VERIFIER_FETCH / CHALLENGE_EVIDENCE / WATCHER_AUDIT
	AccessLevel AccessLevel
	ValidUntil  int64  // Unix milliseconds (switches to chain-height binding once the chain supports it)
	Issuer      string // issuing Builder address
	IssuerSig   []byte // Builder signature (empty when no signer is configured = dev mode)
}

// ChallengePlan is returned by PrepareChallenge: it only helps the SDK organize its challenge inputs and submits no verdict.
type ChallengePlan struct {
	ChallengeOpen        bool
	ChallengeCloseHeight uint64
	RequiredEvidence     []string // suggested evidence categories to collect
	EstimatedBond        Coin
	EstimatedGas         uint64
}
