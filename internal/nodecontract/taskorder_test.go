package nodecontract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// The three digests below are PUBLISHED BY THE CONTRACT ITSELF: monorepo
// TaskOrder Hashing and Signing §8.3 "TaskOrder and opening"
// gives the full 25-field core input and expected values. wire v0.4.1 has not yet turned them into a
// fixture, but the published values are authoritative on their own; node, cortex, SDK and nexus all check against the same values.
//
// This is the only hard evidence about task_hash between this repository and the contract: if our
// understanding of the field order or encoding of H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V2", canonical TaskOrderV2)
// differs anywhere, the same order yields a different digest and these tests go red immediately.
// Do not "update the expected value in place"; first confirm what changed on the contract side.
const (
	contractTaskHashCore      = "87ac39ab4c5616522a55d5303b76f121731dd6dc072a4cb197d04d817c16ce40"
	contractPreimageLenCore   = 776
	contractTaskHashLower     = "38011c54053ab42e3ba0163f2186c091c647b1833053bef93f40bd045c182040"
	contractPreimageLenLower  = 728
	contractTaskHashMaxAmt    = "3b78f4ba9d854367ca948e1243d3ffe84421778af10392ff6a0ce7ee453ba94c"
	contractPreimageLenMaxAmt = 839

	// Key intermediate frames listed in §8.3.
	contractStopSequencesFrame  = "00000000000000040000000200000000000000043c2f733e000000000000000453544f50"
	contractStopTokenIDsFrame   = "00000000000000040000000200000000000000040000000b0000000000000004000000dc"
	contractDeadlinePolicyFrame = "000000000000000400000002"
	contractMaxFeeFrame         = "0000000000000006313530303030"
	contractPriorityFeeFrame    = "000000000000000130"

	// §8.3: user_address = bech32("trueopen", a0a1…b3).
	contractUserAddress = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
)

func repeatByte(value byte, size int) []byte { return bytes.Repeat([]byte{value}, size) }

// accAddress encodes a 20-byte address codec into bech32. The hrp does not enter the preimage (§1.2
// frames the codec bytes); "trueopen" is used only to match node's AccountAddressPrefix.
func accAddress(t *testing.T, raw []byte) string {
	t.Helper()
	encoded, err := bech32.ConvertAndEncode("trueopen", raw)
	if err != nil {
		t.Fatalf("bech32 encode: %v", err)
	}
	return encoded
}

func amountOf(units string) *sharedv1.Amount { return &sharedv1.Amount{AtomicUnits: units} }

// contractTaskOrderFixture reproduces the TaskOrder Hashing and Signing §8.3 core input field by field.
func contractTaskOrderFixture(t *testing.T) *taskv1.TaskOrderV2 {
	t.Helper()
	raw := make([]byte, 20)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	if got := accAddress(t, raw); got != contractUserAddress {
		t.Fatalf("fixture user_address = %s, want contract %s", got, contractUserAddress)
	}
	return &taskv1.TaskOrderV2{
		SchemaVersion: 2, ChainId: "trueopen-golden-1", UserAddress: contractUserAddress,
		SessionId: repeatByte(0x11, 32), OrderSequence: 42, ModelId: "qwen3-8b-test", ProfileVersion: 1,
		TaskType: sharedv1.TaskType_TASK_TYPE_CHAT, InputHash: repeatByte(0x22, 32), InputSizeBytes: 4096,
		InputBucket: 3, OutputBudgetBucket: 4,
		GenerationParams: &taskv1.GenerationParamsV1{
			GenerationParamsSchemaVersion: GenerationParamsSchemaVersionV1, MaxOutputTokens: 256, MaxOutputDuration: 30_000,
			DecodingParams: &taskv1.DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 700, TopPPpm: 950_000, TopK: 40, Seed: 8_675_309,
				PresencePenaltyMilli: -250, FrequencyPenaltyMilli: 125, RepetitionPenaltyPpm: 1_050_000,
				StopSequences: []string{"</s>", "STOP"}, StopTokenIds: []uint32{11, 220},
			},
		},
		PriceBid: amountOf("4000000"), MaxFee: amountOf("150000"),
		AssignmentPriorityFee: amountOf("0"), TxFeeReserve: amountOf("250"),
		EarliestSubmitHeight: 1000, OrderExpireHeight: 2000,
		DeadlinePolicy:       &taskv1.DeadlinePolicyV1{LatencyClass: taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD},
		TimeoutBucketVersion: 9, SessionAnchorHeight: 990,
		SessionAnchorBlockHash: repeatByte(0x33, 32), BuilderSetId: "12", BuilderSetHash: repeatByte(0x44, 32),
	}
}

func mustTaskOrderFields(t *testing.T, order *taskv1.TaskOrderV2) [][]byte {
	t.Helper()
	fields, err := canonicalTaskOrderFieldsV2(order)
	if err != nil {
		t.Fatalf("canonical fields: %v", err)
	}
	if len(fields) != 25 {
		t.Fatalf("TaskOrderV2 must flatten to exactly 25 top-level fields, got %d", len(fields))
	}
	return fields
}

// TestTaskOrderHashMatchesContractVectors is the regression gate for cross-repo task_hash consistency:
// the preimage byte counts and digests of the three contract-published vectors must match byte-for-byte.
func TestTaskOrderHashMatchesContractVectors(t *testing.T) {
	lower := contractTaskOrderFixture(t)
	lower.GenerationParams.MaxOutputTokens = 1
	lower.GenerationParams.MaxOutputDuration = 1
	lower.GenerationParams.DecodingParams = &taskv1.DecodingParamsV1{
		SamplingEnabled: false, TemperatureMilli: 0, TopPPpm: 1, TopK: 0, Seed: 0,
		PresencePenaltyMilli: -2000, FrequencyPenaltyMilli: -2000, RepetitionPenaltyPpm: 100_000,
	}
	maxAmount := contractTaskOrderFixture(t)
	for _, set := range []func(*sharedv1.Amount){
		func(a *sharedv1.Amount) { maxAmount.PriceBid = a }, func(a *sharedv1.Amount) { maxAmount.MaxFee = a },
		func(a *sharedv1.Amount) { maxAmount.AssignmentPriorityFee = a }, func(a *sharedv1.Amount) { maxAmount.TxFeeReserve = a },
	} {
		set(amountOf("18446744073709551615"))
	}

	cases := []struct {
		name        string
		order       *taskv1.TaskOrderV2
		preimageLen int
		digest      string
	}{
		{"core", contractTaskOrderFixture(t), contractPreimageLenCore, contractTaskHashCore},
		{"decoding lower bound, empty lists", lower, contractPreimageLenLower, contractTaskHashLower},
		{"four amounts at u64 max", maxAmount, contractPreimageLenMaxAmt, contractTaskHashMaxAmt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fields := mustTaskOrderFields(t, c.order)
			if got := len(CanonicalFramePreimage(DomainTaskOrderV2, fields...)); got != c.preimageLen {
				t.Fatalf("preimage = %d bytes, want %d", got, c.preimageLen)
			}
			digest, err := TaskOrderHashV2(c.order)
			if err != nil {
				t.Fatalf("task order hash: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != c.digest {
				t.Fatalf("task_hash = %s, want contract %s", got, c.digest)
			}
			hexDigest, err := TaskOrderHashHexV2(c.order)
			if err != nil {
				t.Fatalf("hex form: %v", err)
			}
			if hexDigest != c.digest {
				t.Fatalf("hex form = %s, want %s", hexDigest, c.digest)
			}
		})
	}
}

// TestTaskOrderIntermediateFramesMatchContract checks the intermediate frames listed in §8.3:
// a single byte difference pinpoints which framing layer is wrong, without guessing from the final digest.
func TestTaskOrderIntermediateFramesMatchContract(t *testing.T) {
	order := contractTaskOrderFixture(t)
	fields := mustTaskOrderFields(t, order)

	generation := fields[12] // field 13
	for name, want := range map[string]string{
		"stop_sequences_frame": contractStopSequencesFrame,
		"stop_token_ids_frame": contractStopTokenIDsFrame,
	} {
		wantBytes, _ := hex.DecodeString(want)
		if !bytes.Contains(generation, wantBytes) {
			t.Fatalf("%s %s not found inside generation_params frame %x", name, want, generation)
		}
	}
	wants := map[string]string{
		"max_fee_frame":                 contractMaxFeeFrame,
		"assignment_priority_fee_frame": contractPriorityFeeFrame,
		"deadline_policy_frame":         contractDeadlinePolicyFrame,
	}
	for name, got := range map[string][]byte{
		"max_fee_frame":                 fields[14], // field 15
		"assignment_priority_fee_frame": fields[15], // field 16
		"deadline_policy_frame":         fields[19], // field 20
	} {
		if hex.EncodeToString(got) != wants[name] {
			t.Fatalf("%s = %x, want %s", name, got, wants[name])
		}
	}
}

// TestTaskOrderHashChangesOnEveryField: changing any single TaskOrderV2 field must change
// task_hash (TaskOrder Hashing and Signing §8.4 "each of the following changes must change task_hash").
func TestTaskOrderHashChangesOnEveryField(t *testing.T) {
	base := contractTaskOrderFixture(t)
	digest, err := TaskOrderHashV2(base)
	if err != nil {
		t.Fatalf("base hash: %v", err)
	}

	mutations := []struct {
		name string
		// wantError marks mutations rejected outright by the scalar scope: failing to compute a digest at all
		// is the strongest form of "different identity", but it is distinguished explicitly so an error is not mistaken for "unchanged".
		wantError bool
		edit      func(*testing.T, *taskv1.TaskOrderV2)
	}{
		// V1's schema_version=1 is a rejection in V2, not another digest (TaskOrder Hashing and Signing §4.1).
		{name: "schema_version", wantError: true, edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.SchemaVersion = 1 }},
		{name: "chain_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.ChainId += "-x" }},
		{name: "user_address", edit: func(t *testing.T, v *taskv1.TaskOrderV2) { v.UserAddress = accAddress(t, repeatByte(0x22, 20)) }},
		{name: "session_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.SessionId = repeatByte(0x23, 32) }},
		{name: "order_sequence", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.OrderSequence++ }},
		{name: "model_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.ModelId += "-x" }},
		{name: "profile_version", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.ProfileVersion++ }},
		{name: "task_type", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.TaskType = sharedv1.TaskType_TASK_TYPE_IMAGE_GENERATION
		}},
		{name: "input_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.InputHash = repeatByte(0x24, 32) }},
		{name: "input_size_bytes", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.InputSizeBytes++ }},
		{name: "input_bucket", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.InputBucket++ }},
		{name: "output_budget_bucket", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.OutputBudgetBucket++ }},
		{name: "generation_params.max_output_tokens", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.MaxOutputTokens++
		}},
		{name: "generation_params.max_output_duration", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.MaxOutputDuration++
		}},
		{name: "decoding_params.sampling_enabled", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.SamplingEnabled = false
		}},
		{name: "decoding_params.temperature_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.TemperatureMilli++
		}},
		{name: "decoding_params.top_p_ppm", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.TopPPpm++
		}},
		{name: "decoding_params.top_k", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.TopK++
		}},
		{name: "decoding_params.seed", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.Seed++
		}},
		// The negative penalty term goes through Int32BE (two's complement big-endian); writing it as decimal text
		// would fork this mutation from the contract digest, so it must be covered separately.
		{name: "decoding_params.presence_penalty_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.PresencePenaltyMilli = -251
		}},
		{name: "decoding_params.frequency_penalty_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.FrequencyPenaltyMilli = -125
		}},
		{name: "decoding_params.repetition_penalty_ppm", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.RepetitionPenaltyPpm++
		}},
		{name: "decoding_params.stop_sequences", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.StopSequences = []string{"</s>", "STOP", "HALT"}
		}},
		// Order enters the preimage too: reordering stop_sequences must change the digest, otherwise the
		// "ascending unique" constraint is an empty promise on our side.
		{name: "decoding_params.stop_sequences order", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.StopSequences = []string{"STOP", "</s>"}
		}},
		{name: "decoding_params.stop_token_ids", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.StopTokenIds = []uint32{11, 220, 221}
		}},
		{name: "decoding_params.stop_token_ids order", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.GenerationParams.DecodingParams.StopTokenIds = []uint32{220, 11}
		}},
		{name: "price_bid", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.PriceBid = amountOf("4000001") }},
		{name: "max_fee", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.MaxFee = amountOf("150001") }},
		{name: "assignment_priority_fee", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.AssignmentPriorityFee = amountOf("1") }},
		{name: "tx_fee_reserve", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.TxFeeReserve = amountOf("251") }},
		{name: "earliest_submit_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.EarliestSubmitHeight++ }},
		{name: "order_expire_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.OrderExpireHeight++ }},
		{name: "deadline_policy", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.DeadlinePolicy.LatencyClass = taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_FAST
		}},
		{name: "timeout_bucket_version", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.TimeoutBucketVersion++ }},
		{name: "session_anchor_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.SessionAnchorHeight++ }},
		{name: "session_anchor_block_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) {
			v.SessionAnchorBlockHash = repeatByte(0x25, 32)
		}},
		{name: "builder_set_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.BuilderSetId = "13" }},
		{name: "builder_set_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV2) { v.BuilderSetHash = repeatByte(0x26, 32) }},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := proto.Clone(base).(*taskv1.TaskOrderV2)
			mutation.edit(t, changed)
			got, err := TaskOrderHashV2(changed)
			if mutation.wantError {
				if err == nil {
					t.Fatalf("mutating %s must be refused, got %x", mutation.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("hash after mutating %s: %v", mutation.name, err)
			}
			if got == digest {
				t.Fatalf("mutating %s did not move task_hash", mutation.name)
			}
		})
	}
}

// TestTaskOrderHashIgnoresUserSignature: swapping only the user signature (SignedOrderV2 envelope
// fields) leaves task_hash unchanged (TaskOrder Hashing and Signing §7.3: scheme and signature are transport metadata and
// do not enter task_hash).
func TestTaskOrderHashIgnoresUserSignature(t *testing.T) {
	order := contractTaskOrderFixture(t)
	signed := &taskv1.SignedOrderV2{
		Order: order, SignatureScheme: SignedOrderSchemeV2, UserSignature: append(repeatByte(0x55, 64), 27),
	}
	before, err := TaskOrderHashV2(signed.GetOrder())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	resigned := proto.Clone(signed).(*taskv1.SignedOrderV2)
	resigned.UserSignature = append(repeatByte(0x66, 64), 28)
	after, err := TaskOrderHashV2(resigned.GetOrder())
	if err != nil {
		t.Fatalf("hash after re-signing: %v", err)
	}
	if before != after {
		t.Fatalf("task_hash moved when only user_signature changed: %x -> %x", before, after)
	}
}

// TestTaskOrderHashRefusesNonCanonicalOrders covers the framing preconditions: an order whose canonical
// task_hash cannot be computed must error rather than return a zero digest and carry on (TaskOrder Hashing and Signing §8.4).
func TestTaskOrderHashRefusesNonCanonicalOrders(t *testing.T) {
	cases := map[string]func(*taskv1.TaskOrderV2){
		"schema_version 1 (V1)": func(v *taskv1.TaskOrderV2) { v.SchemaVersion = 1 },
		"nil generation params": func(v *taskv1.TaskOrderV2) { v.GenerationParams = nil },
		"generation params schema": func(v *taskv1.TaskOrderV2) {
			v.GenerationParams.GenerationParamsSchemaVersion = 2
		},
		"short session_id":            func(v *taskv1.TaskOrderV2) { v.SessionId = repeatByte(0x11, 31) },
		"short input_hash":            func(v *taskv1.TaskOrderV2) { v.InputHash = repeatByte(0x22, 16) },
		"hex session_id":              func(v *taskv1.TaskOrderV2) { v.SessionId = []byte(hex.EncodeToString(repeatByte(0x11, 32))) },
		"unspecified task_type":       func(v *taskv1.TaskOrderV2) { v.TaskType = sharedv1.TaskType_TASK_TYPE_UNSPECIFIED },
		"unspecified deadline":        func(v *taskv1.TaskOrderV2) { v.DeadlinePolicy = nil },
		"expire before earliest":      func(v *taskv1.TaskOrderV2) { v.OrderExpireHeight = v.EarliestSubmitHeight },
		"empty amount":                func(v *taskv1.TaskOrderV2) { v.MaxFee = nil },
		"leading zero amount":         func(v *taskv1.TaskOrderV2) { v.PriceBid = amountOf("04000000") },
		"plus sign amount":            func(v *taskv1.TaskOrderV2) { v.PriceBid = amountOf("+4000000") },
		"non decimal amount":          func(v *taskv1.TaskOrderV2) { v.MaxFee = amountOf("0x249f0") },
		"amount exceeds u64":          func(v *taskv1.TaskOrderV2) { v.TxFeeReserve = amountOf("18446744073709551616") },
		"bad user_address":            func(v *taskv1.TaskOrderV2) { v.UserAddress = "not-bech32" },
		"empty builder_set_id":        func(v *taskv1.TaskOrderV2) { v.BuilderSetId = "" },
		"zero timeout_bucket_version": func(v *taskv1.TaskOrderV2) { v.TimeoutBucketVersion = 0 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			order := contractTaskOrderFixture(t)
			edit(order)
			_, err := TaskOrderHashV2(order)
			if err == nil {
				t.Fatalf("%s must be refused", name)
			}
			// schema_version takes the dedicated error branch; assert that the error text points at it rather than
			// blending into the generic "scalar scope is invalid" hint.
			if name == "schema_version 1 (V1)" && !strings.Contains(err.Error(), "schema_version") {
				t.Fatalf("%s: error should mention schema_version, got %q", name, err)
			}
		})
	}
	if _, err := TaskOrderHashV2(nil); err == nil {
		t.Fatal("nil order must be refused")
	}
}
