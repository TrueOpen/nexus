// Canonical task_hash of TaskOrderV2 (10-protocol-spec/04-task/08-TaskOrder Hashing and Signing.md
// §4, Keeper Interface Contract §5.13, implementation design §4.2).
//
// task_hash = H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V2", canonical TaskOrderV2)
//
// It is the Task's CONTENT identity: flip one bit in any TaskOrder field and task_hash changes; swapping
// only the user signature does not. Its counterpart is task_id (taskid.go), the stable RBF slot identity:
// multiple quote versions of the same (session_id, order_sequence) share one task_id and each has its own
// task_hash. These two are the whole of Phase 0 Task identity; "envelope SHA-256" aliases such as
// order_hash / order_digest / signed_order_hash do not exist (gh #42).
//
// This file encodes field by field per the 25-field table in 08 §4.1; field order is ascending TaskOrderV2
// proto field number, encoding rules per the §1.2 table in hfields.go. V2 is the only order schema of the
// fresh genesis: no V1, no field aliases, no compatibility decoder (08 §9). If either side changes the framing,
// the same TaskOrder yields different task_hash values and the Keeper rejects Nexus's submission at admission using
// the user signature, so field order or encoding here must NOT be "optimized"; changes must move with the contract.
// The regression gate is the three contract-published digests in taskorder_test.go.
//
// Nexus only DERIVES this digest and does not verify the user signature: the user signature is a recoverable
// signature over the order-domain EIP-712 digest (08 §7.4), verified against the on-chain account public key,
// which is the Keeper's job. Nexus does not create consensus facts.
package nodecontract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// DomainTaskOrderV2 is the TaskOrder row of the Task domain registry (08 §2).
const DomainTaskOrderV2 = "TRUEOPEN_TASK_ORDER_V2"

// TaskOrderSchemaVersionV2 is the only accepted value of TaskOrderV2.schema_version.
const TaskOrderSchemaVersionV2 uint32 = 2

// GenerationParamsSchemaVersionV1 is the only currently accepted value of
// GenerationParamsV1.generation_params_schema_version (08 §4.3).
const GenerationParamsSchemaVersionV1 uint32 = 1

// TaskOrderHashV2 returns the canonical task_hash of TaskOrderV2 (raw 32 bytes).
// An incomplete order or a non-canonical field is an error rather than a zero digest: an order whose
// task_hash cannot be computed is certain to be rejected on chain, and failing early beats proceeding with a fake identity.
func TaskOrderHashV2(order *taskv1.TaskOrderV2) ([32]byte, error) {
	fields, err := canonicalTaskOrderFieldsV2(order)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainTaskOrderV2, fields...), nil
}

// TaskOrderHashHexV2 is the canonical lowercase 64-hex form of TaskOrderHashV2.
// Inside Nexus (types.Order, NATS payload, logs) hex text is used throughout; it is decoded back to 32 bytes
// only before entering an H_FIELDS_V1 preimage or an on-chain bytes field (§1.1 rule 3).
func TaskOrderHashHexV2(order *taskv1.TaskOrderV2) (string, error) {
	digest, err := TaskOrderHashV2(order)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// canonicalTaskOrderFieldsV2 flattens TaskOrderV2 in ascending proto field number 1..25.
func canonicalTaskOrderFieldsV2(order *taskv1.TaskOrderV2) ([][]byte, error) {
	if err := validateTaskOrderScalarScopeV2(order); err != nil {
		return nil, err
	}
	user, err := CanonicalOperatorAddressBytes("user_address", order.GetUserAddress())
	if err != nil {
		return nil, err
	}
	// The 4 Amounts of fields 14-17 are in ascending proto field number; the order must not change.
	amounts := []*sharedv1.Amount{
		order.GetPriceBid(), order.GetMaxFee(), order.GetAssignmentPriorityFee(), order.GetTxFeeReserve(),
	}
	encodedAmounts := make([][]byte, 0, len(amounts))
	for index, amount := range amounts {
		units, err := canonicalAmountUnitsV1(amount)
		if err != nil {
			return nil, fmt.Errorf("order amount field %d is not canonical: %w", index+14, err)
		}
		// Amount is a nested message whose framing is its own single-field FieldFrameV1
		// (08 §4.4: FRAME_V1(ascii(canonical u64 decimal))), not a bare u64_be.
		encodedAmounts = append(encodedAmounts, CanonicalFrameBytes(units))
	}
	generation, err := canonicalGenerationParamsFrameV1(order.GetGenerationParams())
	if err != nil {
		return nil, err
	}
	// deadline_policy is likewise a nested single-field frame (08 §4.5), not a bare EnumBE.
	deadline := CanonicalFrameBytes(EnumBE(uint32(order.GetDeadlinePolicy().GetLatencyClass())))

	fields := [][]byte{
		Uint32BE(order.GetSchemaVersion()), []byte(order.GetChainId()), user, order.GetSessionId(),
		Uint64BE(order.GetOrderSequence()), []byte(order.GetModelId()), Uint32BE(order.GetProfileVersion()),
		EnumBE(uint32(order.GetTaskType())), order.GetInputHash(), Uint64BE(order.GetInputSizeBytes()),
		Uint32BE(order.GetInputBucket()), Uint32BE(order.GetOutputBudgetBucket()), generation,
	}
	fields = append(fields, encodedAmounts...)
	fields = append(fields,
		Uint64BE(order.GetEarliestSubmitHeight()), Uint64BE(order.GetOrderExpireHeight()), deadline,
		Uint64BE(order.GetTimeoutBucketVersion()),
		Uint64BE(order.GetSessionAnchorHeight()), order.GetSessionAnchorBlockHash(),
		[]byte(order.GetBuilderSetId()), order.GetBuilderSetHash(),
	)
	return fields, nil
}

// canonicalGenerationParamsFrameV1 encodes field 13 (GenerationParamsV1, 08 §4.3).
// Two levels of nesting: the GenerationParams frame wraps a DecodingParams frame, whose two repeated
// fields each wrap another "u32 element count + elements" frame; the count frame is encoded even when empty.
func canonicalGenerationParamsFrameV1(params *taskv1.GenerationParamsV1) ([]byte, error) {
	if params.GetGenerationParamsSchemaVersion() != GenerationParamsSchemaVersionV1 {
		return nil, fmt.Errorf("unsupported generation params schema version")
	}
	decoding := params.GetDecodingParams()
	stopSequences := decoding.GetStopSequences()
	stops := make([][]byte, 0, 1+len(stopSequences))
	stops = append(stops, Uint32BE(uint32(len(stopSequences))))
	for _, value := range stopSequences {
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("stop sequence is not valid UTF-8")
		}
		stops = append(stops, []byte(value))
	}
	stopTokens := decoding.GetStopTokenIds()
	tokens := make([][]byte, 0, 1+len(stopTokens))
	tokens = append(tokens, Uint32BE(uint32(len(stopTokens))))
	for _, value := range stopTokens {
		tokens = append(tokens, Uint32BE(value))
	}
	decodingFrame := CanonicalFrameBytes(
		BoolByte(decoding.GetSamplingEnabled()), Uint32BE(decoding.GetTemperatureMilli()),
		Uint32BE(decoding.GetTopPPpm()), Uint32BE(decoding.GetTopK()), Uint64BE(decoding.GetSeed()),
		Int32BE(decoding.GetPresencePenaltyMilli()), Int32BE(decoding.GetFrequencyPenaltyMilli()),
		Uint32BE(decoding.GetRepetitionPenaltyPpm()),
		CanonicalFrameBytes(stops...), CanonicalFrameBytes(tokens...),
	)
	return CanonicalFrameBytes(
		Uint32BE(params.GetGenerationParamsSchemaVersion()), Uint64BE(params.GetMaxOutputTokens()),
		Uint64BE(params.GetMaxOutputDuration()), decodingFrame,
	), nil
}

// canonicalAmountUnitsV1 validates and extracts the canonical bytes of Amount.atomic_units
// (08 §4.4 / §8.4): non-negative decimal, no `+`, no leading zeros, within uint64. What enters the preimage
// is this DECIMAL TEXT, not the numeric value.
func canonicalAmountUnitsV1(amount *sharedv1.Amount) ([]byte, error) {
	units := amount.GetAtomicUnits()
	if units == "" {
		return nil, fmt.Errorf("amount atomic_units is required")
	}
	if units != "0" && units[0] == '0' {
		return nil, fmt.Errorf("amount atomic_units must not contain leading zeroes")
	}
	for i := range units {
		if units[i] < '0' || units[i] > '9' {
			return nil, fmt.Errorf("amount atomic_units must be canonical unsigned decimal")
		}
	}
	if _, err := strconv.ParseUint(units, 10, 64); err != nil {
		return nil, fmt.Errorf("amount atomic_units exceeds uint64: %w", err)
	}
	return []byte(units), nil
}

// validateTaskOrderScalarScopeV2 is the precondition of the "Typed encoding" column in the 08 §4.1 table,
// not "application-level validation": a Hash32 must really be 32 bytes, text must be strict UTF-8, schema_version
// must be 2, otherwise the computed digest silently disagrees with the Keeper.
// "assignment_priority_fee must be 0 in Phase 0" is a Keeper admission rule and is not checked here;
// the contract §8.3 u64-max vector has all four Amounts at maximum and must still compute.
func validateTaskOrderScalarScopeV2(order *taskv1.TaskOrderV2) error {
	if order == nil {
		return fmt.Errorf("task order is required")
	}
	// schema_version gets its own check and dedicated error: during integration the protocol is upgraded in lockstep
	// on both sides, and an SDK request still sending V1 is the most likely mistake, worth a clearer hint than "scope validation failed".
	if order.GetSchemaVersion() != TaskOrderSchemaVersionV2 {
		return fmt.Errorf("task order schema_version must be %d (V1 orders are not accepted), got %d",
			TaskOrderSchemaVersionV2, order.GetSchemaVersion())
	}
	if order.GetChainId() == "" || !utf8.ValidString(order.GetChainId()) ||
		order.GetModelId() == "" || !utf8.ValidString(order.GetModelId()) ||
		len(order.GetSessionId()) != sha256.Size || order.GetProfileVersion() == 0 ||
		order.GetTaskType() == sharedv1.TaskType_TASK_TYPE_UNSPECIFIED ||
		len(order.GetInputHash()) != sha256.Size || order.GetInputSizeBytes() == 0 ||
		order.GetOutputBudgetBucket() == 0 ||
		order.GetEarliestSubmitHeight() == 0 || order.GetOrderExpireHeight() == 0 ||
		order.GetEarliestSubmitHeight() >= order.GetOrderExpireHeight() ||
		order.GetDeadlinePolicy().GetLatencyClass() == taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_UNSPECIFIED ||
		order.GetTimeoutBucketVersion() == 0 ||
		order.GetSessionAnchorHeight() == 0 || len(order.GetSessionAnchorBlockHash()) != sha256.Size ||
		order.GetBuilderSetId() == "" || !utf8.ValidString(order.GetBuilderSetId()) ||
		len(order.GetBuilderSetHash()) != sha256.Size {
		return fmt.Errorf("task order scalar scope is invalid")
	}
	return nil
}
