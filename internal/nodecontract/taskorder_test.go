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
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func repeatByte(value byte, size int) []byte { return bytes.Repeat([]byte{value}, size) }

// accAddress encodes a 20-byte address codec into bech32. The hrp does not enter the preimage (H_FIELDS_V1
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

// wireTaskOrder builds the TaskOrderV3 that a wire task_order_v3 vector describes.
func wireTaskOrder(t *testing.T, v wirefixture.Vector) *taskv1.TaskOrderV3 {
	t.Helper()
	return wirefixture.TaskOrderV3(t, v)
}

// contractTaskOrderFixture is the core vector's order.
func contractTaskOrderFixture(t *testing.T) *taskv1.TaskOrderV3 {
	t.Helper()
	file := wirefixture.Load(t, "task/task_order_v3.json")
	return wireTaskOrder(t, file.Vector(t, "task_order_v3_core", 0))
}

func mustTaskOrderFields(t *testing.T, order *taskv1.TaskOrderV3) [][]byte {
	t.Helper()
	fields, err := canonicalTaskOrderFieldsV3(order)
	if err != nil {
		t.Fatalf("canonical fields: %v", err)
	}
	if len(fields) != 28 {
		t.Fatalf("TaskOrderV3 must flatten to exactly 28 top-level fields, got %d", len(fields))
	}
	return fields
}

// TestTaskOrderHashMatchesWireVectors is the regression gate for cross-repo task_hash consistency:
// every TRUEOPEN_TASK_ORDER_V3 vector of the pinned wire release must match byte for byte, preimage
// and digest.
func TestTaskOrderHashMatchesWireVectors(t *testing.T) {
	file := wirefixture.Load(t, "task/task_order_v3.json")
	seen := 0
	for _, v := range file.Vectors {
		if v.Domain != DomainTaskOrderV3 {
			continue
		}
		seen++
		t.Run(v.Name, func(t *testing.T) {
			v.CheckPreimage(t)
			order := wireTaskOrder(t, v)
			fields := mustTaskOrderFields(t, order)
			if got := hex.EncodeToString(CanonicalFramePreimage(DomainTaskOrderV3, fields...)); got != v.PreimageHex {
				t.Fatalf("preimage differs from the wire vector")
			}
			digest, err := TaskOrderHashV3(order)
			if err != nil {
				t.Fatalf("task order hash: %v", err)
			}
			if digest != v.Digest(t) {
				t.Fatalf("task_hash = %x, want %s", digest, v.DigestHex)
			}
			hexDigest, err := TaskOrderHashHexV3(order)
			if err != nil || hexDigest != v.DigestHex {
				t.Fatalf("hex form = %s (%v), want %s", hexDigest, err, v.DigestHex)
			}
			if err := ValidatePlaintextOrderV3(order); err != nil {
				t.Fatalf("a wire plaintext order must pass admission: %v", err)
			}
		})
	}
	if seen != 3 {
		t.Fatalf("expected 3 TaskOrderV3 vectors, found %d", seen)
	}
}

// TestPlaintextOrderAdmission: while encryption is inactive only PLAINTEXT with a zero32 key
// commitment and an empty recipient key is admitted; an empty commitment is not padded.
func TestPlaintextOrderAdmission(t *testing.T) {
	cases := map[string]func(*taskv1.TaskOrderV3){
		"encrypted mode":           func(v *taskv1.TaskOrderV3) { v.PayloadMode = taskv1.PayloadModeV1_PAYLOAD_MODE_V1_ENCRYPTED },
		"nonzero key commitment":   func(v *taskv1.TaskOrderV3) { v.InputKeyCommitment = repeatByte(0x01, 32) },
		"empty key commitment":     func(v *taskv1.TaskOrderV3) { v.InputKeyCommitment = nil },
		"recipient pubkey present": func(v *taskv1.TaskOrderV3) { v.UserRecipientPubkey = repeatByte(0x02, 65) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			order := contractTaskOrderFixture(t)
			edit(order)
			if err := ValidatePlaintextOrderV3(order); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// TestTaskOrderHashChangesOnEveryField: changing any single TaskOrderV3 field must change task_hash.
func TestTaskOrderHashChangesOnEveryField(t *testing.T) {
	base := contractTaskOrderFixture(t)
	digest, err := TaskOrderHashV3(base)
	if err != nil {
		t.Fatalf("base hash: %v", err)
	}

	mutations := []struct {
		name string
		// wantError marks mutations rejected outright by the scalar scope: failing to compute a digest at all
		// is the strongest form of "different identity", but it is distinguished explicitly so an error is not mistaken for "unchanged".
		wantError bool
		edit      func(*testing.T, *taskv1.TaskOrderV3)
	}{
		// An older schema_version is a rejection, not another digest.
		{name: "schema_version", wantError: true, edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.SchemaVersion = 2 }},
		{name: "chain_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.ChainId += "-x" }},
		{name: "user_address", edit: func(t *testing.T, v *taskv1.TaskOrderV3) { v.UserAddress = accAddress(t, repeatByte(0x22, 20)) }},
		{name: "session_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.SessionId = repeatByte(0x23, 32) }},
		{name: "order_sequence", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.OrderSequence++ }},
		{name: "model_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.ModelId = repeatByte(0x56, 32) }},
		{name: "profile_version", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.ProfileVersion++ }},
		{name: "task_type", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.TaskType = sharedv1.TaskType_TASK_TYPE_IMAGE_GENERATION
		}},
		{name: "input_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.InputHash = repeatByte(0x24, 32) }},
		{name: "input_size_bytes", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.InputSizeBytes++ }},
		{name: "input_bucket", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.InputBucket++ }},
		{name: "output_budget_bucket", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.OutputBudgetBucket++ }},
		{name: "generation_params.max_output_tokens", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.MaxOutputTokens++
		}},
		{name: "generation_params.max_output_duration", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.MaxOutputDuration++
		}},
		{name: "decoding_params.sampling_enabled", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.SamplingEnabled = false
		}},
		{name: "decoding_params.temperature_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.TemperatureMilli++
		}},
		{name: "decoding_params.top_p_ppm", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.TopPPpm++
		}},
		{name: "decoding_params.top_k", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.TopK++
		}},
		{name: "decoding_params.seed", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.Seed++
		}},
		// The negative penalty term goes through Int32BE (two's complement big-endian); writing it as decimal text
		// would fork this mutation from the canonical digest, so it must be covered separately.
		{name: "decoding_params.presence_penalty_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.PresencePenaltyMilli = -251
		}},
		{name: "decoding_params.frequency_penalty_milli", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.FrequencyPenaltyMilli = -125
		}},
		{name: "decoding_params.repetition_penalty_ppm", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.RepetitionPenaltyPpm++
		}},
		{name: "decoding_params.stop_sequences", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.StopSequences = []string{"</s>", "STOP", "HALT"}
		}},
		// Order enters the preimage too: reordering stop_sequences must change the digest, otherwise the
		// "ascending unique" constraint is an empty promise on our side.
		{name: "decoding_params.stop_sequences order", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.StopSequences = []string{"STOP", "</s>"}
		}},
		{name: "decoding_params.stop_token_ids", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.StopTokenIds = []uint32{11, 220, 221}
		}},
		{name: "decoding_params.stop_token_ids order", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.GenerationParams.DecodingParams.StopTokenIds = []uint32{220, 11}
		}},
		{name: "price_bid", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.PriceBid = amountOf("4000001") }},
		{name: "max_fee", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.MaxFee = amountOf("150001") }},
		{name: "assignment_priority_fee", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.AssignmentPriorityFee = amountOf("1") }},
		{name: "tx_fee_reserve", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.TxFeeReserve = amountOf("251") }},
		{name: "earliest_submit_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.EarliestSubmitHeight++ }},
		{name: "order_expire_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.OrderExpireHeight++ }},
		{name: "deadline_policy", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.DeadlinePolicy.LatencyClass = taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_FAST
		}},
		{name: "timeout_bucket_version", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.TimeoutBucketVersion++ }},
		{name: "session_anchor_height", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.SessionAnchorHeight++ }},
		{name: "session_anchor_block_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.SessionAnchorBlockHash = repeatByte(0x25, 32)
		}},
		{name: "builder_set_id", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.BuilderSetId = "13" }},
		{name: "builder_set_hash", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.BuilderSetHash = repeatByte(0x26, 32) }},
		{name: "payload_mode", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) {
			v.PayloadMode = taskv1.PayloadModeV1_PAYLOAD_MODE_V1_ENCRYPTED
		}},
		{name: "input_key_commitment", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.InputKeyCommitment = repeatByte(0x27, 32) }},
		{name: "user_recipient_pubkey", edit: func(_ *testing.T, v *taskv1.TaskOrderV3) { v.UserRecipientPubkey = repeatByte(0x04, 65) }},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := proto.Clone(base).(*taskv1.TaskOrderV3)
			mutation.edit(t, changed)
			got, err := TaskOrderHashV3(changed)
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
// fields) leaves task_hash unchanged: scheme, signature and signature_chain_id are signature metadata,
// so the same order signed under another signature_chain_id is the same order.
func TestTaskOrderHashIgnoresUserSignature(t *testing.T) {
	order := contractTaskOrderFixture(t)
	signed := &taskv1.SignedOrderV2{
		Order: order, SignatureScheme: SignedOrderSchemeV2, UserSignature: append(repeatByte(0x55, 64), 27),
		SignatureChainId: 424242,
	}
	before, err := TaskOrderHashV3(signed.GetOrder())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	resigned := proto.Clone(signed).(*taskv1.SignedOrderV2)
	resigned.UserSignature = append(repeatByte(0x66, 64), 28)
	resigned.SignatureChainId = 1
	after, err := TaskOrderHashV3(resigned.GetOrder())
	if err != nil {
		t.Fatalf("hash after re-signing: %v", err)
	}
	if before != after {
		t.Fatalf("task_hash moved when only user_signature changed: %x -> %x", before, after)
	}
}

// TestTaskOrderHashRefusesNonCanonicalOrders covers the framing preconditions: an order whose canonical
// task_hash cannot be computed must error rather than return a zero digest and carry on.
func TestTaskOrderHashRefusesNonCanonicalOrders(t *testing.T) {
	cases := map[string]func(*taskv1.TaskOrderV3){
		"schema_version 2": func(v *taskv1.TaskOrderV3) { v.SchemaVersion = 2 },
		"text model_id":    func(v *taskv1.TaskOrderV3) { v.ModelId = []byte("qwen3-8b-test") },
		"unspecified payload_mode": func(v *taskv1.TaskOrderV3) {
			v.PayloadMode = taskv1.PayloadModeV1_PAYLOAD_MODE_V1_UNSPECIFIED
		},
		"short input_key_commitment": func(v *taskv1.TaskOrderV3) { v.InputKeyCommitment = nil },
		"nil generation params":      func(v *taskv1.TaskOrderV3) { v.GenerationParams = nil },
		"generation params schema": func(v *taskv1.TaskOrderV3) {
			v.GenerationParams.GenerationParamsSchemaVersion = 2
		},
		"short session_id":            func(v *taskv1.TaskOrderV3) { v.SessionId = repeatByte(0x11, 31) },
		"short input_hash":            func(v *taskv1.TaskOrderV3) { v.InputHash = repeatByte(0x22, 16) },
		"hex session_id":              func(v *taskv1.TaskOrderV3) { v.SessionId = []byte(hex.EncodeToString(repeatByte(0x11, 32))) },
		"unspecified task_type":       func(v *taskv1.TaskOrderV3) { v.TaskType = sharedv1.TaskType_TASK_TYPE_UNSPECIFIED },
		"unspecified deadline":        func(v *taskv1.TaskOrderV3) { v.DeadlinePolicy = nil },
		"expire before earliest":      func(v *taskv1.TaskOrderV3) { v.OrderExpireHeight = v.EarliestSubmitHeight },
		"empty amount":                func(v *taskv1.TaskOrderV3) { v.MaxFee = nil },
		"leading zero amount":         func(v *taskv1.TaskOrderV3) { v.PriceBid = amountOf("04000000") },
		"plus sign amount":            func(v *taskv1.TaskOrderV3) { v.PriceBid = amountOf("+4000000") },
		"non decimal amount":          func(v *taskv1.TaskOrderV3) { v.MaxFee = amountOf("0x249f0") },
		"amount exceeds u64":          func(v *taskv1.TaskOrderV3) { v.TxFeeReserve = amountOf("18446744073709551616") },
		"bad user_address":            func(v *taskv1.TaskOrderV3) { v.UserAddress = "not-bech32" },
		"empty builder_set_id":        func(v *taskv1.TaskOrderV3) { v.BuilderSetId = "" },
		"zero timeout_bucket_version": func(v *taskv1.TaskOrderV3) { v.TimeoutBucketVersion = 0 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			order := contractTaskOrderFixture(t)
			edit(order)
			_, err := TaskOrderHashV3(order)
			if err == nil {
				t.Fatalf("%s must be refused", name)
			}
			// schema_version takes the dedicated error branch; assert that the error text points at it rather than
			// blending into the generic "scalar scope is invalid" hint.
			if name == "schema_version 2" && !strings.Contains(err.Error(), "schema_version") {
				t.Fatalf("%s: error should mention schema_version, got %q", name, err)
			}
		})
	}
	if _, err := TaskOrderHashV3(nil); err == nil {
		t.Fatal("nil order must be refused")
	}
}
