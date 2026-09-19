package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	OrderEnvelopeSchemaV1     = "trueopen-order-envelope-v1"
	WorkerHandraiseSchemaV1   = "trueopen-worker-handraise-v1"
	VerifierHandraiseSchemaV1 = "trueopen-verifier-handraise-v1"
)

type AssignmentOrderEnvelopeV1 struct {
	SchemaVersion           string `json:"schema_version"`
	ModelID                 string `json:"model_id"`
	ProfileVersion          uint32 `json:"profile_version"`
	TaskType                string `json:"task_type"`
	RewardBucket            uint64 `json:"reward_bucket"`
	ProfileResourceTier     uint64 `json:"profile_resource_tier"`
	InferInputUnitPriceBid  uint64 `json:"infer_input_unit_price_bid"`
	InferOutputUnitPriceBid uint64 `json:"infer_output_unit_price_bid"`
	VerifyUnitPriceBid      uint64 `json:"verify_unit_price_bid"`
	MaxFee                  uint64 `json:"max_fee"`
	TxFeeReserve            uint64 `json:"tx_fee_reserve"`
	InferFeeCap             uint64 `json:"infer_fee_cap"`
	VerifyFeeCap            uint64 `json:"verify_fee_cap"`
	OrderValue              uint64 `json:"order_value"`
	ValidAfterHeight        uint64 `json:"valid_after_height"`
	DeadlineHeight          uint64 `json:"deadline_height"`
	PayloadHash             string `json:"payload_hash"`
	InferTimeoutBlocks      uint64 `json:"infer_timeout_blocks"`
	ReferenceBucketKey      string `json:"reference_bucket_key,omitempty"`
	TimeoutBucketKey        string `json:"timeout_bucket_key,omitempty"`
}

func ParseAssignmentOrderEnvelope(raw string) (AssignmentOrderEnvelopeV1, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope must be canonical json")
	}
	var envelope AssignmentOrderEnvelopeV1
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope must be canonical json: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope must contain exactly one json value")
	}
	canonical, err := CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		return AssignmentOrderEnvelopeV1{}, err
	}
	if canonical != raw {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope must be canonical json")
	}
	if envelope.SchemaVersion != OrderEnvelopeSchemaV1 {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("unsupported order_envelope schema_version %q", envelope.SchemaVersion)
	}
	if !canonicalStrings(envelope.ModelID, envelope.TaskType, envelope.PayloadHash) || envelope.ProfileVersion == 0 {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope model, profile, task type, and payload hash are required and canonical")
	}
	decodedPayloadHash, err := hex.DecodeString(envelope.PayloadHash)
	if err != nil || len(decodedPayloadHash) != 32 || hex.EncodeToString(decodedPayloadHash) != envelope.PayloadHash {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope payload_hash must be canonical lowercase sha256 hex")
	}
	if !canonicalOptionalStrings(envelope.ReferenceBucketKey, envelope.TimeoutBucketKey) {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope bucket keys must be canonical")
	}
	if envelope.InferInputUnitPriceBid == 0 || envelope.InferOutputUnitPriceBid == 0 || envelope.VerifyUnitPriceBid == 0 {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope unit price bids are required")
	}
	if envelope.MaxFee == 0 || envelope.InferFeeCap == 0 || envelope.VerifyFeeCap == 0 || envelope.OrderValue == 0 {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope fee caps and order_value are required")
	}
	expectedOrderValue, ok := assignmentOrderValue(envelope.MaxFee, envelope.InferFeeCap, envelope.VerifyFeeCap)
	if !ok {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope fee cap overflow")
	}
	if envelope.OrderValue != expectedOrderValue {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_value does not match fee caps")
	}
	if envelope.DeadlineHeight == 0 || envelope.InferTimeoutBlocks == 0 {
		return AssignmentOrderEnvelopeV1{}, fmt.Errorf("order_envelope deadlines are required")
	}
	return envelope, nil
}

func CanonicalAssignmentOrderEnvelope(envelope AssignmentOrderEnvelopeV1) (string, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("canonical order_envelope json: %w", err)
	}
	return string(encoded), nil
}

func assignmentOrderValue(maxFee, inferFeeCap, verifyFeeCap uint64) (uint64, bool) {
	if ^uint64(0)-inferFeeCap < verifyFeeCap {
		return 0, false
	}
	value := inferFeeCap + verifyFeeCap
	if value > maxFee {
		value = maxFee
	}
	return value, true
}

// WorkerHandraiseV1 is the OLD string canonical-set form, feeding only the historical string field
// AssignTx.worker_handraise_set (long since off chain); it is kept because it still does the fact
// consistency cross-check between hand-raises. The on-chain one is
// task.v1.WorkerHandraiseV1 (proto, field number = signing order).
//
// order_digest was renamed to task_hash. This field enters the canonicalStrings validation sequence and
// the canonical set string produced by json.Marshal, so renaming it changes that string's bytes.
// Those bytes currently enter NO consensus preimage and do NOT go on chain (SubmitAssign takes only scope /
// handraises / submitter_address), so this rename is not a signing-rule change; should anyone wire it
// back into the signing path later, the field order here becomes a frozen surface and must then be aligned with Node.
// candidate_set_hash and membership_proof were removed from here: Interface & Topic Catalogue §5.5 dropped
// them from the WORKER_HANDRAISE wire (membership is now looked up directly on chain by the Keeper from the
// member 4-tuple in the snapshot bitmap and slot binding), so the source has no value to fill; the on-chain
// assignment wire also no longer echoes worker_handraise_set (see the note in chaincli/client.go).
// Keeping them as required fields would only make the canonical set impossible to build.
type WorkerHandraiseV1 struct {
	SchemaVersion         string `json:"schema_version"`
	WorkerOperatorAddress string `json:"worker_operator_address"`
	TaskID                string `json:"task_id"`
	TaskHash              string `json:"task_hash"`
	CandidateSnapshotID   string `json:"candidate_snapshot_id"`
	ExpiryHeight          uint64 `json:"expiry_height"`
	ServiceSignature      string `json:"service_signature"`
}

type VerifierHandraiseV1 struct {
	SchemaVersion           string `json:"schema_version"`
	VerifierOperatorAddress string `json:"verifier_operator_address"`
	TaskID                  string `json:"task_id"`
	InferReceiptHash        string `json:"infer_receipt_hash"`
	OutputHash              string `json:"output_hash"`
	CandidateSnapshotID     string `json:"candidate_snapshot_id"`
	MembershipProof         string `json:"membership_proof"`
	ExpiryHeight            uint64 `json:"expiry_height"`
	ServiceSignature        string `json:"service_signature"`
}

func CanonicalWorkerHandraiseSet(input []WorkerHandraiseV1) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("worker handraise set must not be empty")
	}
	handraises := append([]WorkerHandraiseV1(nil), input...)
	sort.Slice(handraises, func(i, j int) bool { return handraises[i].WorkerOperatorAddress < handraises[j].WorkerOperatorAddress })
	seen := make(map[string]struct{}, len(handraises))
	for _, handraise := range handraises {
		if handraise.SchemaVersion != WorkerHandraiseSchemaV1 || handraise.ExpiryHeight == 0 ||
			!canonicalStrings(handraise.WorkerOperatorAddress, handraise.TaskID, handraise.TaskHash,
				handraise.CandidateSnapshotID, handraise.ServiceSignature) {
			return "", fmt.Errorf("worker handraise is incomplete or non-canonical")
		}
		if _, exists := seen[handraise.WorkerOperatorAddress]; exists {
			return "", fmt.Errorf("duplicate worker handraise %q", handraise.WorkerOperatorAddress)
		}
		seen[handraise.WorkerOperatorAddress] = struct{}{}
	}
	encoded, err := json.Marshal(handraises)
	if err != nil {
		return "", fmt.Errorf("canonical worker handraise set: %w", err)
	}
	return string(encoded), nil
}

func CanonicalVerifierHandraiseList(input []VerifierHandraiseV1) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("verifier handraise list must not be empty")
	}
	handraises := rankVerifierHandraises(input)
	seen := make(map[string]struct{}, len(handraises))
	for _, handraise := range handraises {
		if handraise.SchemaVersion != VerifierHandraiseSchemaV1 || handraise.ExpiryHeight == 0 ||
			!canonicalStrings(handraise.VerifierOperatorAddress, handraise.TaskID, handraise.InferReceiptHash, handraise.OutputHash,
				handraise.CandidateSnapshotID, handraise.MembershipProof, handraise.ServiceSignature) {
			return "", fmt.Errorf("verifier handraise is incomplete or non-canonical")
		}
		if _, exists := seen[handraise.VerifierOperatorAddress]; exists {
			return "", fmt.Errorf("duplicate verifier handraise %q", handraise.VerifierOperatorAddress)
		}
		seen[handraise.VerifierOperatorAddress] = struct{}{}
	}
	encoded, err := json.Marshal(handraises)
	if err != nil {
		return "", fmt.Errorf("canonical verifier handraise list: %w", err)
	}
	return string(encoded), nil
}

func SelectedVerifierCSV(input []VerifierHandraiseV1, count int) (string, error) {
	if count <= 0 {
		return "", fmt.Errorf("selected verifier count must be positive")
	}
	if _, err := CanonicalVerifierHandraiseList(input); err != nil {
		return "", err
	}
	if len(input) < count {
		return "", fmt.Errorf("need at least %d verifier handraises", count)
	}
	ranked := rankVerifierHandraises(input)
	selected := make([]string, count)
	for i := range selected {
		selected[i] = ranked[i].VerifierOperatorAddress
	}
	return strings.Join(selected, ","), nil
}

func VerifierCandidateWindowProof(candidateSnapshotID, candidateWindowHash string) string {
	return canonicalHashHex(
		"TRUEOPEN_VERIFIER_CANDIDATE_WINDOW_PROOF_V1",
		strings.TrimSpace(candidateSnapshotID), strings.TrimSpace(candidateWindowHash),
	)
}

func rankVerifierHandraises(input []VerifierHandraiseV1) []VerifierHandraiseV1 {
	handraises := append([]VerifierHandraiseV1(nil), input...)
	sort.SliceStable(handraises, func(i, j int) bool {
		left := canonicalHash(
			"TRUEOPEN_VERIFIER_HANDRAISE_SORT_V1",
			handraises[i].TaskID, handraises[i].InferReceiptHash, handraises[i].OutputHash,
			handraises[i].VerifierOperatorAddress,
		)
		right := canonicalHash(
			"TRUEOPEN_VERIFIER_HANDRAISE_SORT_V1",
			handraises[j].TaskID, handraises[j].InferReceiptHash, handraises[j].OutputHash,
			handraises[j].VerifierOperatorAddress,
		)
		if string(left) != string(right) {
			return string(left) < string(right)
		}
		return handraises[i].VerifierOperatorAddress < handraises[j].VerifierOperatorAddress
	})
	return handraises
}

func canonicalStrings(values ...string) bool {
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
			return false
		}
	}
	return true
}

func canonicalOptionalStrings(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
			return false
		}
	}
	return true
}
