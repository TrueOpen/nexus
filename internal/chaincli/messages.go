// On-chain message definitions shared with node (Interface & Topic Catalogue §2 / Nexus Detailed Design §5).
// Three groups: Txs that nexus assembles and broadcasts, chain events nexus subscribes to, and query results nexus reads.
// Field names align with the proto / the TrueOpen mainnet mechanism V1 integration plan.
package chaincli

import (
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
)

// TaskKey is the task's chain identity. The protocol requires every task-scoped query,
// transaction and event to carry both session_id and task_id.
type TaskKey struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
}

// Validate checks the target compound identity. Keep this at the boundary so
// calling modules can fail fast before sending ambiguous chain requests.
func (k TaskKey) Validate() error {
	if k.SessionID == "" || k.TaskID == "" {
		return ErrInvalidTaskKey
	}
	return nil
}

// ---- 1. Txs that nexus assembles, signs and broadcasts (§2.2) ----
// These structs are encoded and signed, then submitted via BroadcastTx([]byte); field-level definitions live here.

// AssignTx carries the Worker-duty handraise proposal that nexus relays as
// MsgSubmitWorkerHandraises (Keeper Interface Contract §4.2.1/§10.1).
//
// SignedOrder / ExistingTask / WorkerHandraises are the only fields that reach
// the chain: the contract requires every other assignment fact (Builder
// operator, BuilderSet, Task Builders, pool hash, candidate weights, legal-set
// hash, deadlines, thresholds) to be Keeper-derived, so they must not be sent as
// request copies. The remaining legacy fields below stay as local coordination
// state for builder-selection preparation, order admission and self-checks; they
// are no longer part of the Msg wire.
type AssignTx struct {
	// SignedOrder is the user-signed SignedOrderV2 required for the first
	// proposal of a Task (§4.2.1 scope oneof).
	SignedOrder *taskv1.SignedOrderV2 `json:"-"`
	// ExistingTask addresses an already accepted Task for follow-up proposals.
	ExistingTask *taskv1.ExistingTaskRefV1 `json:"-"`
	// WorkerHandraises are Cortex-authored signed WorkerHandraiseV1 facts,
	// ascending by slot and unique (§4.1/§4.2.2).
	WorkerHandraises []*taskv1.WorkerHandraiseV1 `json:"-"`

	BuilderOperatorAddress string `json:"builder_operator_address"`
	SessionID              string `json:"session_id"`
	TaskID                 string `json:"task_id"`
	UserAddress            string `json:"user_address"`
	OrderSequence          uint64 `json:"order_sequence"`
	OrderEnvelope          string `json:"order_envelope"`
	// TaskHash is the canonical identity of the candidate order (see types.Order.TaskHash).
	// It only feeds local logs and snapshots; the on-chain copy lives in SignedOrder / ExistingTask,
	// and the submitter checks the two agree before submitting.
	TaskHash              string `json:"task_hash"`
	SignatureScheme       string `json:"signature_scheme"`
	UserSignature         string `json:"user_signature"`
	MaxFee                uint64 `json:"max_fee"`
	TxFeeReserve          uint64 `json:"tx_fee_reserve"`
	AssignmentPriorityFee uint64 `json:"assignment_priority_fee"`
	BuilderRank           uint64 `json:"builder_rank"`
	BuilderSelectionProof string `json:"builder_selection_proof"`
	CandidateSnapshotID   string `json:"candidate_snapshot_id"`
	CandidateSetHash      string `json:"candidate_set_hash"`
	WorkerHandraiseSet    string `json:"worker_handraise_set"`
	MinWorkerHandraise    uint64 `json:"min_worker_handraise_required"`
	ReservedFee           uint64 `json:"reserved_fee"`
	InferDeadlineHeight   uint64 `json:"infer_deadline_height"`
	ServiceSignature      string `json:"service_signature"`
	Submitter             string `json:"submitter"`
}

// OpenVerifyTx carries the two contract messages that replace the old single
// MsgOpenVerify: MsgSubmitInferReceipt (§10.3) and, once the Verifier window is
// READY, MsgSubmitVerifierHandraises (§4.2.1/§10.4). The Verifier window, legal
// set, selected Verifier set and every deadline are Keeper-derived, so the
// legacy selected_verifiers / window proof fields no longer reach the chain.
// VerifyResultTx relays the Verifier-signed ResultReceiptV2 verbatim (Keeper Interface Contract
// §10.9). Nexus rewrites or fills in no field: the receipt's signature preimage is locked by the
// Verifier's current service key, and changing a single byte fails on-chain signature verification.
type VerifyResultTx struct {
	Receipt   *taskv1.ResultReceiptV2 `json:"-"`
	Submitter string                  `json:"submitter"`
}

// VerifyCommitTx relays the Verifier-signed VerifyCommitV1 verbatim (Keeper Interface Contract §10.6).
// Same rule as VerifyResultTx: Nexus rewrites or fills in no field.
type VerifyCommitTx struct {
	Commit    *taskv1.VerifyCommitV1 `json:"-"`
	Submitter string                 `json:"submitter"`
}

type OpenVerifyTx struct {
	// InferReceipt is the Worker-signed InferReceiptV2 (§5.14).
	InferReceipt *taskv1.InferReceiptV2 `json:"-"`
	// VerifierHandraises are Cortex-authored signed VerifierHandraiseV1 facts
	// belonging to the frozen window (§4.1/§4.4).
	VerifierHandraises []*taskv1.VerifierHandraiseV1 `json:"-"`

	// The pre-freeze MsgOpenVerify string copies of receipt fields (infer_receipt_commit_hash /
	// infer_receipt_hash / output_hash / output_size_bytes / trace_commit_root /
	// checkpoint_commit_root / batch_log_root / token_count / work_unit /
	// service_signature) were removed: these facts are now carried only by the InferReceipt itself;
	// keeping a parallel copy invites the silent inconsistency of "copy filled, original not".
	BuilderOperatorAddress       string `json:"builder_operator_address"`
	SessionID                    string `json:"session_id"`
	TaskID                       string `json:"task_id"`
	WorkerOperatorAddress        string `json:"worker_operator_address"`
	BuilderRank                  uint64 `json:"builder_rank"`
	BuilderSelectionProof        string `json:"builder_selection_proof"`
	VerifierHandraiseList        string `json:"verifier_handraise_list"`
	SelectedVerifiers            string `json:"selected_verifiers"`
	Submitter                    string `json:"submitter"`
	VerifierCandidateWindowProof string `json:"verifier_candidate_window_proof"`
}

// MsgWorkerReveal does not exist in the Keeper contract: §9.4 registers no
// Worker reveal Msg, and §10.11 keeps Worker metric evidence off chain unless a
// Verifier registers MsgSubmitFullResultReveal. WorkerRevealTx is therefore
// removed rather than renamed.

// SettleTx prepares MsgSettleTask. Only TaskID and Submitter reach the chain:
// §10.10a fixes the public request at `1=task_id:Hash32,2=submitter_address`
// and forbids callers from submitting verdict, cluster, receipt refs, payout,
// refund, fault, evidence root, plan hash, completion height or a Builder
// identity copy. The remaining fields stay as local settlement-readiness state
// that the FSM checks before it triggers the Msg.
type SettleTx struct {
	Submitter                      string   `json:"submitter"`
	SessionID                      string   `json:"session_id"`
	TaskID                         string   `json:"task_id"`
	WorkerOperatorAddress          string   `json:"worker_operator_address"`
	FormalVerifierOperatorAddress1 string   `json:"formal_verifier_operator_address_1"`
	FormalVerifierOperatorAddress2 string   `json:"formal_verifier_operator_address_2"`
	FormalVerifierOperatorAddress3 string   `json:"formal_verifier_operator_address_3"`
	CommitHeightRefs               string   `json:"commit_height_refs"`
	MissingOrTimeoutVerifiers      string   `json:"missing_or_timeout_verifiers"`
	TaskVerdict                    string   `json:"task_verdict"`
	AssignmentTxHash               string   `json:"assignment_tx_hash"`
	AssignmentHeight               uint64   `json:"assignment_height"`
	OpenVerifyTxHash               string   `json:"open_verify_tx_hash"`
	OpenVerifyHeight               uint64   `json:"open_verify_height"`
	InferReceiptHash               string   `json:"infer_receipt_hash"`
	OutputHash                     string   `json:"output_hash"`
	TraceCommitRoot                string   `json:"trace_commit_root"`
	CheckpointCommitRoot           string   `json:"checkpoint_commit_root"`
	BatchLogRoot                   string   `json:"batch_log_root"`
	InputWorkUnit                  uint64   `json:"input_work_unit"`
	ActualOutputTokens             uint64   `json:"actual_output_tokens"`
	ActualOutputDuration           uint64   `json:"actual_output_duration"`
	ActualOutputWorkUnit           uint64   `json:"actual_output_work_unit"`
	MaxOutputTokens                uint64   `json:"max_output_tokens"`
	MaxOutputDuration              uint64   `json:"max_output_duration"`
	InferInputUnitPriceBid         uint64   `json:"infer_input_unit_price_bid"`
	InferOutputUnitPriceBid        uint64   `json:"infer_output_unit_price_bid"`
	VerifyUnitPriceBid             uint64   `json:"verify_unit_price_bid"`
	InferFeeCap                    uint64   `json:"infer_fee_cap"`
	VerifyFeeCap                   uint64   `json:"verify_fee_cap"`
	MaxFee                         uint64   `json:"max_fee"`
	InferActualFee                 uint64   `json:"infer_actual_fee"`
	VerifyActualFee                uint64   `json:"verify_actual_fee"`
	AssignmentPriorityFeeUsed      uint64   `json:"assignment_priority_fee_used"`
	TxFeeReserveUsed               uint64   `json:"tx_fee_reserve_used"`
	TxFeeReserveRefund             uint64   `json:"tx_fee_reserve_refund"`
	RefundAmount                   uint64   `json:"refund_amount"`
	WorkerPayout                   uint64   `json:"worker_payout"`
	VerifierPayouts                string   `json:"verifier_payouts"`
	OutlierVerifier                string   `json:"outlier_verifier"`
	FaultEvents                    string   `json:"fault_events"`
	ValidTaskFlags                 string   `json:"valid_task_flags"`
	VerifyWorkUnit                 uint64   `json:"verify_work_unit"`
	FullResultRevealRefs           []string `json:"full_result_reveal_refs"`
	BuilderOperatorAddress         string   `json:"builder_operator_address"`
	BuilderRank                    uint64   `json:"builder_rank"`
	BuilderSelectionProof          string   `json:"builder_selection_proof"`
	SettlementStatus               string   `json:"settlement_status"`
	MaintenanceFee                 uint64   `json:"maintenance_fee"`
	GasReimbursements              string   `json:"gas_reimbursements"`
	SettlementID                   string   `json:"settlement_id"`
	TaskEvidenceRoot               string   `json:"task_evidence_root"`
	LeafOrderingVersion            uint64   `json:"leaf_ordering_version"`
	EvidenceSchemaHash             string   `json:"evidence_schema_hash"`
	JudgmentFunctionVersion        string   `json:"judgment_function_version"`
	RootManifestHash               string   `json:"root_manifest_hash"`
	LeafCountByType                string   `json:"leaf_count_by_type"`
	WorkerRevealReceiptRef         string   `json:"worker_reveal_receipt_ref"`
	ResultReceiptRefsHash          string   `json:"result_receipt_refs_hash"`
	RegisteredFullResultRefsHash   string   `json:"registered_full_result_refs_hash"`
	PayoutHash                     string   `json:"payout_hash"`
	FaultSummaryHash               string   `json:"fault_summary_hash"`
	ChallengeCloseHeight           uint64   `json:"challenge_close_height"`
	ServiceSignature               string   `json:"service_signature"`
}

// SweepDeadlineTx triggers MsgSweepDeadline (Keeper Interface Contract §9.6a BOUNDED_RUNNER).
//
// MsgSweepDeadline is the only public deadline runner in V1: any account may submit it, the public
// runner pays its own gas, and EndBlock goes through the same internal executor. It is therefore not
// "relaying someone else's signature": Nexus is entitled to act as this runner itself, with no detached
// signature from the Cortex/Verifier side.
//
// This struct expresses only the task branch of §5.9 DeadlineLocatorV1: the challenge / evidence_request
// branches are not active yet (no ACTIVE writer can create the object, the executor must reject),
// and the session_lifecycle branch is not single-task orchestration; neither is exposed here.
type SweepDeadlineTx struct {
	Submitter string `json:"submitter"`
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	// DeadlineKind must be a TaskDeadlineLocator kind from the §5.9 table.
	DeadlineKind taskv1.DeadlineKindV1 `json:"deadline_kind"`
}

// ServiceEndpoint is a value-type alias of hub.v1.ServiceEndpointV1. Canonicalization
// (ordering, unique kind, URI/protocol_version bounds) and the descriptor_hash rule belong to
// nodecontract; chaincli only moves it onto the wire.
type ServiceEndpoint = nodecontract.ServiceEndpoint

// RegisterBuilderTx establishes the Builder identity in the global Node Registry.
//
// The frozen contract's MsgRegisterBuilder is
// (service_pubkey, service_key_proof, descriptor, builder_operator_address):
// descriptor is the endpoints list, descriptor_version is always the 1 assigned by the Keeper, and
// descriptor_uri / descriptor_hash / schema / expires_height are not on the wire.
// AuthorizationNonce likewise never reaches the chain; it is only the preimage scope of ServiceKeyProof
// (always 1 on first registration) and is kept here so the submit point can assert the proof is not made up.
type RegisterBuilderTx struct {
	Builder            string            `json:"builder"`
	ServicePubKey      string            `json:"service_pubkey"`
	ServiceKeyProof    string            `json:"service_key_proof"`
	AuthorizationNonce uint64            `json:"authorization_nonce"`
	Endpoints          []ServiceEndpoint `json:"endpoints"`
}

// UpdateServiceDescriptorTx publishes a new version of the endpoints list.
//
// The frozen contract's MsgUpdateServiceDescriptor is
// (participant_type, expected_descriptor_version, descriptor, operator_address).
// ExpectedDescriptorVersion is the **current** on-chain version (the Keeper asserts equality, then writes
// current+1), not the target version; authorization is the Cosmos account signature, with no
// controller_signature and no effective/expires height: on-chain descriptors no longer have a validity period.
type UpdateServiceDescriptorTx struct {
	OperatorAddress           string            `json:"operator_address"`
	ParticipantType           string            `json:"participant_type"`
	ExpectedDescriptorVersion uint64            `json:"expected_descriptor_version"`
	Endpoints                 []ServiceEndpoint `json:"endpoints"`
}

// ---- 2. Chain events nexus subscribes to (§2.3) ----
// ChainEvent.Type takes one of the constants below; Attrs carries each event's fields, decodable into the matching struct.

const (
	EventResyncRequired           = "ResyncRequired"              // local signal: re-check authoritative chain state after a new subscription is established
	EventTaskStateChanged         = "TaskStateChanged"            // new-style Node task notification: must QueryTask before advancing
	EventAssignAccepted           = "AssignAccepted"              // AssignTx included in a block, winner undecided → RANDOMNESS_PENDING
	EventAssignmentFinalized      = "AssignmentFinalized"         // randomness settled, winner decided → triggers trueopen.assign to start work
	EventOpenVerifyAccepted       = "OpenVerifyAccepted"          // formal Verifier set decided (no seed) → VERIFYING
	EventSampleReady              = "SampleReady"                 // future beacon aggregates sample_seed → triggers trueopen.sample-ready
	EventVerifyCommitAccepted     = "VerifyCommitAccepted"        // commit collection progress
	EventWorkerRevealAccepted     = "WorkerRevealReceiptAccepted" // Worker reveal receipt is on-chain
	EventFullResultRevealAccepted = "FullResultRevealAccepted"    // Verifier full-result reveal self-rescue included on-chain
	EventSettleAccepted           = "SettleAccepted"              // VERIFYING → SETTLED
	EventSweepDeadlineAccepted    = "SweepDeadlineAccepted"       // timeout sweep advanced
	EventBuilderSetUpdated        = "BuilderSetUpdated"           // set rotation: update the local active set
	EventNewBlock                 = "NewBlock"                    // independent height polling signal, used for gap detection
)

// AssignAccepted: AssignTx included in a block (v1.5 two-phase step one): enters randomness pending,
// winner not yet decided, so no start-work notification is sent.
type AssignAccepted struct {
	SessionID   string             `json:"session_id"`
	TaskID      string             `json:"task_id"`
	AssignedSet []types.BuilderRef `json:"assigned_set"`
	Height      int64              `json:"height"`
}

// AssignmentFinalized: randomness settled and winner decided (v1.5 two-phase step two):
// only after receiving it is the winner told to start work via trueopen.assign.
type AssignmentFinalized struct {
	SessionID  string `json:"session_id"`
	TaskID     string `json:"task_id"`
	Winner     string `json:"winner"`      // selected Worker address
	AssignSeed []byte `json:"assign_seed"` // assignment randomness (lets the winner derivation be checked locally)
	Height     int64  `json:"height"`
	// InferDeadlineHeight is the chain-height deadline for the winner to deliver output (infer_deadline of
	// the WorkerAssignmentFinalized event; the recovery path reads the same-named task snapshot field).
	InferDeadlineHeight uint64 `json:"infer_deadline_height"`
}

// OpenVerifyAccepted: open-verify included in a block (no sample_seed; the seed arrives with the later SampleReady).
type OpenVerifyAccepted struct {
	SessionID string          `json:"session_id"`
	TaskID    string          `json:"task_id"`
	Verifiers []string        `json:"verifiers"` // formal Verifier set addresses
	Deadlines types.Deadlines `json:"deadlines"` // commit/worker_reveal/reveal/verify
	Height    int64           `json:"height"`
}

// SampleReady: the future proposer-VRF beacon aggregated the sample seed (SampleReadyIndex).
type SampleReady struct {
	SessionID   string `json:"session_id"`
	TaskID      string `json:"task_id"`
	SampleSeed  []byte `json:"sample_seed"`
	ReadyHeight int64  `json:"ready_height"` // seed-ready height (beacon aggregation completion point)
	Height      int64  `json:"height"`
}

// VerifyCommitAccepted: a single Verifier's commit is on-chain.
type VerifyCommitAccepted struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Verifier  string `json:"verifier"` // address
	Height    int64  `json:"height"`
}

// WorkerRevealAccepted: the Worker reveal receipt is on-chain; on timeout it carries FAIL_REVEAL_TIMEOUT.
type WorkerRevealAccepted struct {
	SessionID string            `json:"session_id"`
	TaskID    string            `json:"task_id"`
	Verdict   types.TaskVerdict `json:"verdict,omitempty"` // set to FAIL_REVEAL_TIMEOUT only on the timeout branch
	Height    int64             `json:"height"`
}

// FullResultRevealAccepted: Verifier full-result reveal self-rescue included on-chain (v1.5 §2.3):
// V_i+salt is written to FullResultRevealState and SettleTx can reference it via full_result_reveal.
type FullResultRevealAccepted struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Verifier  string `json:"verifier"` // address
	Height    int64  `json:"height"`
}

// SweepDeadlineAccepted: any party triggered a deadline sweep that advanced a timed-out state
// (EventDeadlineSwept, ProtocolEventCodeV1 = 20).
//
// The frozen contract replaced the old swept_stage with DeadlineKindV1 + DeadlineTransitionCode:
// "which deadline was swept" and "how the state actually transitioned" are two different things, and only
// the latter tells whether the task converged to a terminal state. COMMIT_CLOSED is the classic
// counterexample: a closed commit window usually means the reveal phase starts and the task is still
// alive; treating it as failure would kill in-flight tasks.
type SweepDeadlineAccepted struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	// DeadlineKind is the deadline that was swept (§5.9).
	DeadlineKind taskv1.DeadlineKindV1 `json:"deadline_kind"`
	// TransitionCode is the state transition this sweep actually performed (§9.6b closed enum).
	TransitionCode taskv1.DeadlineTransitionCode `json:"transition_code"`
	Height         int64                         `json:"height"`
}

// ConvergesTask reports whether this sweep converged the task to a terminal state.
//
// Only transition codes that clearly say "this leg cannot proceed any further" are terminal: assignment
// failed, Worker timed out, Open Verify window closed without a usable Verifier set, session closed.
// SESSION_ACTIVE_TO_IDLE (session goes idle), COMMIT_CLOSED (commit window closed / reveal starts) and
// REVEAL_CLOSED (reveal window closed, chain still has to compute the final verdict) are only window
// advances, not terminal; in those cases always go back to Query to reconcile and let the on-chain
// snapshot decide the state instead of deciding locally.
func (e SweepDeadlineAccepted) ConvergesTask() bool {
	switch e.TransitionCode {
	case taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_ASSIGNMENT_FAILED,
		taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_WORKER_TIMEOUT,
		taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT,
		taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_SESSION_IDLE_TO_CLOSED:
		return true
	default:
		return false
	}
}

// Payout is one settlement distribution entry.
type Payout struct {
	Recipient string     `json:"recipient"` // address
	Amount    types.Coin `json:"amount"`
	Reason    string     `json:"reason,omitempty"` // e.g. worker/verifier/builder reward
}

// SettleAccepted: settlement included in a block; task_verdict is computed by the chain.
type SettleAccepted struct {
	SessionID   string              `json:"session_id"`
	TaskID      string              `json:"task_id"`
	TaskVerdict types.TaskVerdict   `json:"task_verdict"` // PASS/FAIL/NO_CONSENSUS/FAIL_REVEAL_TIMEOUT
	Settlement  TaskSettlementState `json:"settlement"`
	Payouts     []Payout            `json:"payouts"`
	Height      int64               `json:"height"`
}

// BuilderSetUpdated: set rotation, the active BuilderSet changed.
type BuilderSetUpdated struct {
	Epoch   uint64             `json:"epoch"`
	Members []types.BuilderRef `json:"members"`
	Height  int64              `json:"height"`
}

// ---- 3. Query results nexus reads (§2.1 / §2.4) ----

// BuilderSet is the BuilderSetViewV1 returned by QueryBuilderSet (Keeper Interface Contract §16.5).
//
// The old term_start_height / term_end_height were removed from the wire: term boundaries now have only
// epoch semantics (start_epoch / end_epoch), and at the height level only snapshot_height remains as the
// "height at which the set-selection fact was frozen". SetHash is the lowercase 64-hex encoding of the
// raw 32-byte on-chain Hash32; Nexus does not recompute it: the view does not deliver
// builder_set_members_hash, and any recomputation would necessarily use a different formula, so the
// comparison would fail consistently.
type BuilderSet struct {
	// Epoch is builder_set_version: since wire v0.4.1 the BuilderSet has only a version number, no
	// term / epoch range (Phase 0 is a governance-fixed set with no rotation). It is returned by the Hub in a
	// single fixed-height query; Nexus neither derives nor hardcodes it.
	Epoch        uint64 `json:"epoch"`
	BuilderSetID string `json:"builder_set_id"`
	// Members get rank (starting at 1) in the on-chain order of active_builders.
	Members []types.BuilderRef `json:"members"`
	SetHash string             `json:"set_hash"`
	// ActiveBuilderCount is unchanged by trimming and is the evidence for deciding whether empty members
	// means an empty set or a trimmed body; BodyStatus is that decision itself.
	ActiveBuilderCount uint32 `json:"active_builder_count"`
	BodyStatus         string `json:"body_status"`
	// UpdatedHeight takes effective_height: the height at which this BuilderSet version took effect.
	UpdatedHeight int64 `json:"updated_height"`
}

// TaskBuilderSelectionState is the on-chain frozen Task Builder selection (task.v1.Query/TaskBuilders,
// wire v0.1.2). SelectedBuilders is in committed order; settlement submission rights rotate in that order (§10.10a).
type TaskBuilderSelectionState struct {
	TaskID           string   `json:"task_id"`
	SelectedBuilders []string `json:"selected_builders"`
	SelectedCount    uint32   `json:"selected_count"`
	CreatedHeight    uint64   `json:"created_height"`
	BodyStatus       string   `json:"body_status"`
}

// StageBuilderSelectionState is the locally stored settlement ordering (snapshot field settle_selection).
// Its source is TaskBuilders: SelectedBuilders is the frozen order of selected_task_builders and
// SelectedHeight is created_height. BuilderSetID / StageRef / SeedHash / SelectionProofHash are fields of
// the old hub StageBuilderSelection; the chain no longer has that query and they are kept
// only so old snapshots still decode.
type StageBuilderSelectionState struct {
	SessionID          string   `json:"session_id"`
	TaskID             string   `json:"task_id"`
	Stage              string   `json:"stage"`
	BuilderSetID       uint64   `json:"builder_set_id"`
	StageRef           string   `json:"stage_ref"`
	SeedHash           string   `json:"seed_hash"`
	SelectedBuilders   []string `json:"selected_builders"`
	SelectionProofHash string   `json:"selection_proof_hash"`
	SelectedHeight     uint64   `json:"selected_height"`
}

// BuilderState is the Builder main row returned by QueryBuilder.
//
// There is no ActiveTerm here: the current Node BuilderState dropped `active_term`, and keeping a field
// that always deserializes to zero is a trap: code reading it would classify an on-chain ACTIVE Builder as
// "no active term". The current term can only be read from the QueryBuilderSetAtHeight result.
// BuilderState is the local projection of wire v0.4.1 hub.v1.BuilderState: Builder identity +
// current service key + descriptor version. Admission status (ADMITTED / REVOKED) is not here; it lives
// in BuilderAdmissionState, is governance-fixed in Phase 0 and is not delivered by a separate public
// Query; "admitted or not" is decided by whether active_builders of the BuilderSet at that height
// contains this address.
type BuilderState struct {
	Address               string `json:"address"`
	CurrentServiceAddress string `json:"current_service_address"`
	// ServiceKeyStatus is the short name of the ServiceKeyStatus enum with the prefix stripped (ACTIVE / REVOKED).
	ServiceKeyStatus          string `json:"service_key_status"`
	ServiceAuthorizationNonce uint64 `json:"service_authorization_nonce"`
	RegisteredHeight          uint64 `json:"registered_height"`
	CurrentDescriptorVersion  uint64 `json:"current_descriptor_version"`
}

type ServiceKeyState struct {
	ParticipantType    string `json:"participant_type"`
	OperatorAddress    string `json:"operator_address"`
	ServiceAddress     string `json:"service_address"`
	ServicePubKey      string `json:"service_pubkey"`
	AuthorizationNonce uint64 `json:"authorization_nonce"`
	UpdatedHeight      uint64 `json:"updated_height"`
	Status             string `json:"status"`
}

// CortexNodeState is the stable Cortex identity row returned by QueryCortexNode (CortexNodeState, §6.4).
// The auth callback service reads it only to confirm "this operator is registered as a Cortex"; pubkey and
// nonce are authoritative in QueryCurrentServiceKey, and here they are just a copy of the same row.
// It does not carry schema_version or current_descriptor_version: the callback service only decides the
// fact "registered or not", not version/schema compatibility, so keeping those two fields would be a trap
// nobody reads.
type CortexNodeState struct {
	OperatorAddress           string `json:"operator_address"`
	CurrentServiceAddress     string `json:"current_service_address"`
	CurrentServicePubKey      string `json:"current_service_pubkey"` // 33-byte compressed secp256k1, lowercase hex
	ServiceAuthorizationNonce uint64 `json:"service_authorization_nonce"`
	ServiceKeyStatus          string `json:"service_key_status"` // ACTIVE / REVOKED
	RegisteredHeight          uint64 `json:"registered_height"`
	UpdatedHeight             uint64 `json:"updated_height"`
}

// ServiceDescriptorState is the current descriptor row returned by QueryServiceDescriptor.
// The frozen contract's ServiceDescriptorState stores endpoints + descriptor_hash directly,
// with no URI / schema_version / effective_height / expires_height.
type ServiceDescriptorState struct {
	ParticipantType   string            `json:"participant_type"`
	OperatorAddress   string            `json:"operator_address"`
	DescriptorVersion uint64            `json:"descriptor_version"`
	Endpoints         []ServiceEndpoint `json:"endpoints"`
	DescriptorHash    string            `json:"descriptor_hash"`
	UpdatedHeight     uint64            `json:"updated_height"`
}

type TimeoutBucketState struct {
	BucketKey              string `json:"bucket_key"`
	Version                uint64 `json:"version"`
	EffectiveHeight        uint64 `json:"effective_height"`
	InferTimeoutBlocks     uint64 `json:"infer_timeout_blocks"`
	VerifyTimeoutBlocks    uint64 `json:"verify_timeout_blocks"`
	RevealTimeoutBlocks    uint64 `json:"reveal_timeout_blocks"`
	ChallengeTimeoutBlocks uint64 `json:"challenge_timeout_blocks"`
	Source                 string `json:"source"`
	CreatedHeight          uint64 `json:"created_height"`
	SupersededByVersion    uint64 `json:"superseded_by_version"`
}

type ProfileState struct {
	ModelID                   string `json:"model_id"`
	ProfileVersion            uint32 `json:"profile_version"`
	Status                    string `json:"status"`
	ChallengeOpenWindowBlocks uint64 `json:"challenge_open_window_blocks"`
	// EvidenceSchemaHash comes from the locked VerificationProfile (lowercase 64-hex).
	// FinalizeTaskResult compares it against manifest.evidence_schema_hash: which schema the manifest
	// claims to belong to does not count; the one locked on-chain does.
	EvidenceSchemaHash string `json:"evidence_schema_hash"`
}

type TaskAssignmentState struct {
	UserAddress                   string `json:"user_address"`
	OrderSequence                 uint64 `json:"order_sequence"`
	OrderEnvelope                 string `json:"order_envelope"`
	SignatureScheme               string `json:"signature_scheme"`
	UserSignature                 string `json:"user_signature"`
	MaxFee                        uint64 `json:"max_fee"`
	TxFeeReserve                  uint64 `json:"tx_fee_reserve"`
	AssignmentPriorityFee         uint64 `json:"assignment_priority_fee"`
	BuilderRank                   uint64 `json:"builder_rank"`
	BuilderSelectionProof         string `json:"builder_selection_proof"`
	CandidateSnapshotID           string `json:"candidate_snapshot_id"`
	CandidateSetHash              string `json:"candidate_set_hash"`
	WorkerHandraiseSet            string `json:"worker_handraise_set"`
	MinWorkerHandraiseRequired    uint64 `json:"min_worker_handraise_required"`
	SelectedWorkerOperatorAddress string `json:"selected_worker_operator_address"`
	ReservedFee                   uint64 `json:"reserved_fee"`
	InferDeadlineHeight           uint64 `json:"infer_deadline_height"`
	AssignAcceptHeight            uint64 `json:"assign_accept_height"`
	AssignmentRandomnessHeight    uint64 `json:"assignment_randomness_height"`
	WinnerConfirmHeight           uint64 `json:"winner_confirm_height"`
	OrderValue                    uint64 `json:"order_value"`
	InferFeeCap                   uint64 `json:"infer_fee_cap"`
	VerifyFeeCap                  uint64 `json:"verify_fee_cap"`
	ModelID                       string `json:"model_id"`
	ProfileVersion                uint32 `json:"profile_version"`
	TimeoutBucketKey              string `json:"timeout_bucket_key"`
	TimeoutBucketVersion          uint64 `json:"timeout_bucket_version"`
	ServiceSignature              string `json:"service_signature"`
	BuilderOperatorAddress        string `json:"builder_operator_address"`
	// AcceptedTaskHash is the projection of TaskCoreState.accepted_task_hash (assignment.proto
	// field 5): the authoritative task_hash locked once the Keeper accepts, lowercase 64-hex.
	// It can only come from on-chain query/event; Nexus does not create consensus facts.
	// The former name accepted_item_hash was a generic alias that hid that it is accepted_task_hash,
	// conflicting with the "one identity, one name" rule, so it was renamed.
	AcceptedTaskHash string `json:"accepted_task_hash"`
}

type InferReceiptState struct {
	WorkerOperatorAddress  string `json:"worker_operator_address"`
	InferReceiptCommitHash string `json:"infer_receipt_commit_hash"`
	InferReceiptHash       string `json:"infer_receipt_hash"`
	OutputHash             string `json:"output_hash"`
	OutputSizeBytes        uint64 `json:"output_size_bytes"`
	TraceCommitRoot        string `json:"trace_commit_root"`
	CheckpointCommitRoot   string `json:"checkpoint_commit_root"`
	BatchLogRoot           string `json:"batch_log_root"`
	TokenCount             uint64 `json:"token_count"`
	WorkUnit               uint64 `json:"work_unit"`
	ServiceSignature       string `json:"service_signature"`
	OpenVerifyHeight       uint64 `json:"open_verify_height"`
	AcceptedItemHash       string `json:"accepted_item_hash"`
}

type VerifierAssignmentState struct {
	FormalVerifierSet          string `json:"formal_verifier_set"`
	VerifierHandraiseList      string `json:"verifier_handraise_list"`
	VerificationSampleSeed     string `json:"verification_sample_seed"`
	CommitDeadlineHeight       uint64 `json:"commit_deadline_height"`
	WorkerRevealDeadlineHeight uint64 `json:"worker_reveal_deadline_height"`
	RevealDeadlineHeight       uint64 `json:"reveal_deadline_height"`
	VerifyDeadlineHeight       uint64 `json:"verify_deadline_height"`
	OpenVerifyHeight           uint64 `json:"open_verify_height"`
	SampleSeedReadyHeight      uint64 `json:"sample_seed_ready_height"`
	Stage3BuilderGraceBlocks   uint64 `json:"stage3_builder_grace_blocks"`
	BuilderOperatorAddress     string `json:"builder_operator_address"`
}

type TaskSettlementState struct {
	SettlementID                      string `json:"settlement_id,omitempty"`
	SettlementMode                    string `json:"settlement_mode,omitempty"`
	SettlementStatus                  string `json:"settlement_status,omitempty"`
	SettlementHeight                  uint64 `json:"settlement_height,omitempty"`
	ChallengeCloseHeight              uint64 `json:"challenge_close_height,omitempty"`
	EvidenceCleanupHeight             uint64 `json:"evidence_cleanup_height,omitempty"`
	OptimisticFinalityStatus          string `json:"optimistic_finality_status,omitempty"`
	MaxChallengeResolveDeadlineHeight uint64 `json:"max_challenge_resolve_deadline_height,omitempty"`
	TaskFinalityHeight                uint64 `json:"task_finality_height,omitempty"`
	ClaimableAfterHeight              uint64 `json:"claimable_after_height,omitempty"`
	// FinalityStatus is TaskCoreState.finality_status by short name (PENDING / FINAL). Settlement
	// and finality are one step, taken after every verification round has closed (Challenge
	// and Evidence spec §9), so FINAL means the task has nothing left to drive.
	FinalityStatus          string `json:"finality_status,omitempty"`
	SubmitterServiceAddress string `json:"submitter_service_address,omitempty"`
	ServiceSignatureHash    string `json:"service_signature_hash,omitempty"`
	BuilderOperatorAddress  string `json:"builder_operator_address,omitempty"`
}

// AcceptedInferReceipt is the part of the on-chain InferReceiptState that a Builder which did not
// receive the signed receipt needs: the hashes every Verifier handraise binds.
type AcceptedInferReceipt struct {
	OutputHash       []byte
	InferReceiptHash []byte
}

// TaskStage is task.v1.Query/TaskStage: the task's statuses and its next deadline. While round 1
// has closed and no challenge round is open, the next deadline is the challenge window close
// (06 §9); QueryTask does not carry the round summary that holds it.
type TaskStage struct {
	FinalityStatus     string `json:"finality_status,omitempty"`
	NextDeadlineKind   string `json:"next_deadline_kind,omitempty"` // DeadlineKindV1 short name; empty when none
	NextDeadlineHeight uint64 `json:"next_deadline_height,omitempty"`
}

// ChallengeCloseHeight returns challenge_close_height while the challenge window is the task's
// next deadline, and 0 otherwise.
func (s TaskStage) ChallengeCloseHeight() uint64 {
	if s.NextDeadlineKind != "CHALLENGE_WINDOW_CLOSE" {
		return 0
	}
	return s.NextDeadlineHeight
}

type FullResultRevealFact struct {
	Verifier       string `json:"verifier"`
	AcceptedHeight uint64 `json:"accepted_height"`
}

type SettlementBuildFacts struct {
	SnapshotHeight             uint64                 `json:"snapshot_height"`
	HasWorkerRevealReceipt     bool                   `json:"has_worker_reveal_receipt"`
	Worker                     string                 `json:"worker,omitempty"`
	WorkerRevealAcceptedHeight uint64                 `json:"worker_reveal_accepted_height,omitempty"`
	FullResultReveals          []FullResultRevealFact `json:"full_result_reveals,omitempty"`
}

// EvidenceCleanupStatus is the chain's cleanup progress for one task (TaskCleanupStatus).
type EvidenceCleanupStatus string

const (
	// EvidenceCleanupNotScheduled: the task has not met the cleanup preconditions yet (06 §10:
	// task finality reached, no open round, max_evidence_retention_blocks passed).
	EvidenceCleanupNotScheduled EvidenceCleanupStatus = "NOT_SCHEDULED"
	EvidenceCleanupRunning      EvidenceCleanupStatus = "RUNNING"
	EvidenceCleanupCompacted    EvidenceCleanupStatus = "COMPACTED"
)

// Started reports whether the chain has begun compacting the task's evidence.
func (s EvidenceCleanupStatus) Started() bool {
	return s == EvidenceCleanupRunning || s == EvidenceCleanupCompacted
}

// OnChainTask QueryTask returns both compatibility views and the authoritative
// nested state required to prepare current Node transactions.
type OnChainTask struct {
	SessionID          string                  `json:"session_id"`
	TaskID             string                  `json:"task_id"`
	Status             string                  `json:"status"`
	State              types.TaskState         `json:"state"`
	Winner             string                  `json:"winner,omitempty"`
	AssignedSet        []types.BuilderRef      `json:"assigned_set,omitempty"`
	Verifiers          []string                `json:"verifiers,omitempty"`
	SampleSeed         []byte                  `json:"sample_seed,omitempty"`
	InferDeadline      int64                   `json:"infer_deadline,omitempty"`
	Deadlines          types.Deadlines         `json:"deadlines"`
	TaskVerdict        types.TaskVerdict       `json:"task_verdict,omitempty"` // after SETTLED
	FailureClass       string                  `json:"failure_class,omitempty"`
	Assignment         TaskAssignmentState     `json:"assignment"`
	InferReceipt       InferReceiptState       `json:"infer_receipt"`
	VerifierAssignment VerifierAssignmentState `json:"verifier_assignment"`
	Settlement         TaskSettlementState     `json:"settlement"`
	// ReceiptAccepted comes from TaskCoreState.receipt_status: the chain has accepted the InferReceipt.
	// The InferReceipt itself is carried by the separate QueryInferReceipt, not by QueryTask; the
	// OPEN_VERIFY submit point needs only this one bit.
	ReceiptAccepted bool `json:"receipt_accepted,omitempty"`
	// VerifierRounds carries one entry per verification round whose assignment QueryTask returned
	// (round 1, and round 2 once a challenge round is selected), in ascending round order.
	// Verifiers above stays the round-1 set that the coordinator uses; task data authorization
	// reads this field, because which evidence a Verifier may read depends on its round and on
	// whether that round's commits are locked.
	VerifierRounds []VerifierRound `json:"verifier_rounds,omitempty"`
	// Compacted is set when the chain has already run evidence cleanup on the task and
	// QueryTask returns only its fixed-size terminal summary. The task is final; only the
	// summary facts (identity, phase, verdict, winner, settlement and finality heights) are
	// filled, and every per-round or per-participant view stays empty.
	Compacted bool `json:"compacted,omitempty"`
}

// VerifierRound is the part of one round's VerifierAssignmentState that task data authorization
// needs: who was selected, and the two heights that tell whether the round's commit set is locked.
type VerifierRound struct {
	VerifyRound uint32   `json:"verify_round"`
	Verifiers   []string `json:"verifiers"`
	// CommitDeadlineHeight is the last height at which a commit of this round can be accepted.
	CommitDeadlineHeight uint64 `json:"commit_deadline_height"`
	// RevealDeadlineHeight is written only when the round enters reveal, which on the fast path
	// happens once every selected Verifier has committed; zero means reveal has not started.
	RevealDeadlineHeight uint64 `json:"reveal_deadline_height,omitempty"`
}

// CommitsLocked reports whether no further commit of this round can be accepted at height:
// either the round has entered reveal (every selected Verifier committed, or the deadline
// passed with enough commits), or the commit deadline has passed. Task Execution spec §8: a
// commit is accepted only while current_height <= commit_deadline_height and the task is still
// in the commit stage.
//
// The commit deadline is frozen when the round's assignment is written and is never zero; a zero
// here means the chain view is incomplete, and since this gates evidence reads it fails closed.
func (r VerifierRound) CommitsLocked(height uint64) bool {
	if r.CommitDeadlineHeight == 0 {
		return false
	}
	return r.RevealDeadlineHeight != 0 || height > r.CommitDeadlineHeight
}

// SimResult is the Simulate result.
type SimResult struct {
	GasEstimate uint64 `json:"gas_estimate"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
}
