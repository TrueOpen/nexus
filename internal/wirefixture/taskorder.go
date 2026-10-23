package wirefixture

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// TaskOrderV3 builds the TaskOrderV3 that a wire task_order_v3 vector describes, field by field
// from the vector rather than from constants copied into this file.
func TaskOrderV3(t testing.TB, v Vector) *taskv1.TaskOrderV3 {
	t.Helper()
	f := func(name string) Field { return v.Field(t, name) }
	sub := func(parent Field, name string) Field {
		for _, x := range parent.Fields {
			if x.Name == name {
				return x
			}
		}
		t.Fatalf("vector %s: %s has no field %s", v.Name, parent.Name, name)
		return Field{}
	}
	amount := func(name string) *sharedv1.Amount {
		return &sharedv1.Amount{AtomicUnits: sub(f(name), "atomic_units").UTF8}
	}
	gen := f("generation_params")
	dec := sub(gen, "decoding_params")
	var stops []string
	for _, x := range sub(dec, "stop_sequences").Fields[1:] {
		stops = append(stops, x.UTF8)
	}
	var stopTokens []uint32
	for _, x := range sub(dec, "stop_token_ids").Fields[1:] {
		stopTokens = append(stopTokens, uint32(x.Uint64(t)))
	}
	user, err := bech32.ConvertAndEncode("trueopen", f("user_address").Bytes(t))
	if err != nil {
		t.Fatalf("vector %s: user_address: %v", v.Name, err)
	}
	return &taskv1.TaskOrderV3{
		SchemaVersion: uint32(f("schema_version").Uint64(t)), ChainId: f("chain_id").UTF8, UserAddress: user,
		SessionId: f("session_id").Bytes(t), OrderSequence: f("order_sequence").Uint64(t),
		ModelId: f("model_id").Bytes(t), ProfileVersion: uint32(f("profile_version").Uint64(t)),
		TaskType: sharedv1.TaskType(f("task_type").Uint64(t)), InputHash: f("input_hash").Bytes(t),
		InputSizeBytes: f("input_size_bytes").Uint64(t), InputBucket: uint32(f("input_bucket").Uint64(t)),
		OutputBudgetBucket: uint32(f("output_budget_bucket").Uint64(t)),
		GenerationParams: &taskv1.GenerationParamsV1{
			GenerationParamsSchemaVersion: uint32(sub(gen, "generation_params_schema_version").Uint64(t)),
			MaxOutputTokens:               sub(gen, "max_output_tokens").Uint64(t),
			MaxOutputDuration:             sub(gen, "max_output_duration").Uint64(t),
			DecodingParams: &taskv1.DecodingParamsV1{
				SamplingEnabled:       sub(dec, "sampling_enabled").BoolValue(t),
				TemperatureMilli:      uint32(sub(dec, "temperature_milli").Uint64(t)),
				TopPPpm:               uint32(sub(dec, "top_p_ppm").Uint64(t)),
				TopK:                  uint32(sub(dec, "top_k").Uint64(t)),
				Seed:                  sub(dec, "seed").Uint64(t),
				PresencePenaltyMilli:  int32(sub(dec, "presence_penalty_milli").Int64(t)),
				FrequencyPenaltyMilli: int32(sub(dec, "frequency_penalty_milli").Int64(t)),
				RepetitionPenaltyPpm:  uint32(sub(dec, "repetition_penalty_ppm").Uint64(t)),
				StopSequences:         stops,
				StopTokenIds:          stopTokens,
			},
		},
		PriceBid: amount("price_bid"), MaxFee: amount("max_fee"),
		AssignmentPriorityFee: amount("assignment_priority_fee"), TxFeeReserve: amount("tx_fee_reserve"),
		EarliestSubmitHeight: f("earliest_submit_height").Uint64(t), OrderExpireHeight: f("order_expire_height").Uint64(t),
		DeadlinePolicy: &taskv1.DeadlinePolicyV1{
			LatencyClass: taskv1.DeadlineLatencyClass(sub(f("deadline_policy"), "latency_class").Uint64(t)),
		},
		TimeoutBucketVersion: f("timeout_bucket_version").Uint64(t),
		SessionAnchorHeight:  f("session_anchor_height").Uint64(t), SessionAnchorBlockHash: f("session_anchor_block_hash").Bytes(t),
		BuilderSetId: f("builder_set_id").UTF8, BuilderSetHash: f("builder_set_hash").Bytes(t),
		PayloadMode:         taskv1.PayloadModeV1(f("payload_mode").Uint64(t)),
		InputKeyCommitment:  f("input_key_commitment").Bytes(t),
		UserRecipientPubkey: f("user_recipient_pubkey").Bytes(t),
	}
}
