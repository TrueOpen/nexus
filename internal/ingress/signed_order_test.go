package ingress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// testFrozenUserAddress must be canonical bech32: since gh #42 ingress derives task_hash from this
// TaskOrderV2, and the preimage frames the address codec bytes of user_address
// (§1.2 / ruling 24), so a value that cannot be decoded yields no digest.
// Value = bech32("trueopen", 20 x 0x11).
const testFrozenUserAddress = "trueopen1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rsxm9a"

// testUserSignatureV2 is a shape-valid 65-byte R||S||V (V=27, S < N/2). nexus only checks the shape
// and passes it through; signature verification happens in the keeper.
func testUserSignatureV2(fill byte) []byte { return append(bytes.Repeat([]byte{fill}, 64), 27) }

// testFrozenSignedOrder is a §5.13 task order **complete enough to derive task_hash**.
// Before gh #42 amounts / output_budget_bucket / the bucket version could be missing here, because
// the order identity was then sha256(envelope), which ignores the content; now a single missing item makes the canonical
// task_hash uncomputable and the order is rejected at ingress -- which is exactly the fail-closed behaviour wanted.
func testFrozenSignedOrder() *taskv1.SignedOrderV2 {
	amount := func(units string) *sharedv1.Amount { return &sharedv1.Amount{AtomicUnits: units} }
	return &taskv1.SignedOrderV2{
		Order: &taskv1.TaskOrderV2{
			SchemaVersion: 2, ChainId: "trueopen-localnet", UserAddress: testFrozenUserAddress,
			SessionId: bytes.Repeat([]byte{0x11}, 32), OrderSequence: 7,
			ModelId: "model-1", ProfileVersion: 2,
			TaskType:  sharedv1.TaskType_TASK_TYPE_TEXT_GENERATION,
			InputHash: bytes.Repeat([]byte{0x22}, 32), InputSizeBytes: 512,
			InputBucket: 1, OutputBudgetBucket: 2,
			GenerationParams: &taskv1.GenerationParamsV1{
				GenerationParamsSchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
				DecodingParams: &taskv1.DecodingParamsV1{},
			},
			PriceBid:              amount("4"),
			MaxFee:                amount("100"),
			AssignmentPriorityFee: amount("0"),
			TxFeeReserve:          amount("5"),
			EarliestSubmitHeight:  100, OrderExpireHeight: 1000,
			DeadlinePolicy: &taskv1.DeadlinePolicyV1{
				LatencyClass: taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD,
			},
			TimeoutBucketVersion:   4,
			SessionAnchorHeight:    90,
			SessionAnchorBlockHash: bytes.Repeat([]byte{0x33}, 32),
			BuilderSetId:           "term-1",
			BuilderSetHash:         bytes.Repeat([]byte{0x44}, 32),
		},
		SignatureScheme: "eip712",
		UserSignature:   testUserSignatureV2(0x55),
	}
}

// TestParseOrderEnvelopeAcceptsFrozenSignedOrder pins the two carriers of order_envelope:
// a leading '{' means the old canonical JSON, otherwise it is decoded as a proto-encoded task.v1.SignedOrderV2.
// The first-proposal scope of the frozen contract accepts only the latter, and order_envelope is bytes anyway, so this
// path needs no change to the fields of SubmitOrderRequest and the body digest of the SDK request envelope stays the same.
func TestParseOrderEnvelopeAcceptsFrozenSignedOrder(t *testing.T) {
	signed := testFrozenSignedOrder()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if isLegacyOrderEnvelope(raw) {
		t.Fatal("proto SignedOrderV2 misdetected as the legacy json envelope")
	}

	// The third argument is the top-level secp256k1 request-layer signature of SubmitOrderRequest, which is a different thing
	// from the eip712 user signature embedded in SignedOrderV2; a separate 64-byte placeholder is used here.
	order, err := parseOrderEnvelope(raw, "secp256k1", hex.EncodeToString(bytes.Repeat([]byte{0x99}, 64)))
	if err != nil {
		t.Fatalf("parseOrderEnvelope: %v", err)
	}
	if !bytes.Equal(order.SignedOrder, raw) {
		t.Fatal("SignedOrder must be preserved verbatim: the user signature covers the frozen TaskOrderV2 and nexus must not rebuild it")
	}
	if order.ModelID != "model-1" || order.ProfileVersion != 2 || order.TaskType != "text_generation" {
		t.Fatalf("order model binding: %+v", order)
	}
	if order.DeadlineHeight != 1000 || order.ValidAfterHeight != 100 {
		t.Fatalf("order height window: %+v", order)
	}
	if order.PayloadHash != strings.Repeat("22", 32) {
		t.Fatalf("payload hash = %q", order.PayloadHash)
	}
	// gh #42: the order identity is the canonical task_hash derived from the user-signed TaskOrderV2,
	// not sha256(order_envelope).
	wantTaskHash, hashErr := nodecontract.TaskOrderHashHexV2(signed.GetOrder())
	if hashErr != nil {
		t.Fatalf("task order hash: %v", hashErr)
	}
	if order.TaskHash != wantTaskHash {
		t.Fatalf("task_hash = %q, want %q", order.TaskHash, wantTaskHash)
	}
	envelopeDigest := sha256.Sum256(raw)
	if order.TaskHash == hex.EncodeToString(envelopeDigest[:]) {
		t.Fatal("task_hash equals the SHA-256 of the envelope: the order_digest alias is back")
	}
}

// TestParseOrderEnvelopeTaskHashIgnoresUserSignature is how gh #42 acceptance criterion 3 shows up at the ingress
// layer: the same TaskOrder with a different user signature keeps the same task_hash. The old
// order_digest = sha256(order_envelope) could not do this -- the signature is inside the envelope, so changing it changed the identity.
func TestParseOrderEnvelopeTaskHashIgnoresUserSignature(t *testing.T) {
	// The request-layer secp256k1 signature is unrelated to the embedded eip712 user signature; a fixed 64-byte placeholder is used.
	requestSignature := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 64))
	parse := func(t *testing.T, signature []byte) string {
		t.Helper()
		signed := testFrozenSignedOrder()
		signed.UserSignature = signature
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		order, err := parseOrderEnvelope(raw, "secp256k1", requestSignature)
		if err != nil {
			t.Fatalf("parseOrderEnvelope: %v", err)
		}
		return order.TaskHash
	}
	first := parse(t, testUserSignatureV2(0x55))
	second := parse(t, testUserSignatureV2(0x66))
	if first == "" || first != second {
		t.Fatalf("task_hash moved when only user_signature changed: %q -> %q", first, second)
	}
}

// TestParseOrderEnvelopeRejectsOrdersWithoutCanonicalTaskHash covers fail-closed behaviour:
// an order whose canonical task_hash cannot be computed must not enter the flow -- the keeper would certainly reject it on chain,
// and rather than broadcasting it with an empty identity and collecting a pile of hand-raises that match nothing, it is rejected at the entrance.
func TestParseOrderEnvelopeRejectsOrdersWithoutCanonicalTaskHash(t *testing.T) {
	cases := map[string]func(*taskv1.TaskOrderV2){
		"non-bech32 user_address": func(o *taskv1.TaskOrderV2) { o.UserAddress = "trueopen1user" },
		"missing max_fee":         func(o *taskv1.TaskOrderV2) { o.MaxFee = nil },
		"leading zero amount":     func(o *taskv1.TaskOrderV2) { o.PriceBid = &sharedv1.Amount{AtomicUnits: "04"} },
		"no output budget bucket": func(o *taskv1.TaskOrderV2) { o.OutputBudgetBucket = 0 },
		"no timeout bucket":       func(o *taskv1.TaskOrderV2) { o.TimeoutBucketVersion = 0 },
		"short session_id":        func(o *taskv1.TaskOrderV2) { o.SessionId = bytes.Repeat([]byte{0x11}, 16) },
	}
	// Request-layer secp256k1 signature placeholder: 64 bytes, unrelated to the embedded eip712 user signature.
	signature := bytes.Repeat([]byte{0x55}, 64)
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			signed := testFrozenSignedOrder()
			corrupt(signed.Order)
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseOrderEnvelope(raw, "secp256k1", hex.EncodeToString(signature)); err == nil {
				t.Fatalf("%s: order was accepted although no canonical task_hash can be computed", name)
			}
		})
	}
}

// TestParseLegacyOrderEnvelopeCarriesNoTaskHash records the position of the old JSON envelope: it lacks
// chain_id / session_anchor_* / builder_set_* / generation_params, so the TRUEOPEN_TASK_ORDER_V2 preimage cannot be
// built and there is **no** task_hash to fill in. This used to be filled with
// sha256(envelope) posing as the identity, which gh #42 removed; the consequence is that such orders cannot be broadcast
// (taskfsm.onOrder rejects them), and they never passed the first-proposal scope branch anyway.
func TestParseLegacyOrderEnvelopeCarriesNoTaskHash(t *testing.T) {
	legacy := []byte(`{"schema_version":"trueopen-order-envelope-v1","model_id":"model-1","profile_version":1,` +
		`"task_type":"inference","reward_bucket":1,"profile_resource_tier":2,"infer_input_unit_price_bid":2,` +
		`"infer_output_unit_price_bid":3,"verify_unit_price_bid":4,"max_fee":1000,"tx_fee_reserve":100,` +
		`"infer_fee_cap":600,"verify_fee_cap":300,"order_value":900,"valid_after_height":10,` +
		`"deadline_height":100,"payload_hash":"` + strings.Repeat("a", 64) + `","infer_timeout_blocks":20,` +
		`"reference_bucket_key":"reference-v1","timeout_bucket_key":"timeout-v1"}`)
	if !isLegacyOrderEnvelope(legacy) {
		t.Fatal("legacy json envelope was not detected")
	}
	order, err := parseOrderEnvelope(legacy, "secp256k1", hex.EncodeToString(bytes.Repeat([]byte{0x55}, 64)))
	if err != nil {
		t.Fatalf("parseOrderEnvelope: %v", err)
	}
	if order.TaskHash != "" {
		t.Fatalf("legacy envelope produced a task_hash %q; the old envelope has no canonical identity to derive", order.TaskHash)
	}
}

// TestParseOrderEnvelopeRejectsUnknownFieldsInSignedOrder: before going on chain nexus re-encodes this message with its own
// mirror, which silently drops unknown fields, so what gets forwarded would no longer be the order the user
// signed. It must error at the entrance rather than quietly rewrite.
func TestParseOrderEnvelopeRejectsUnknownFieldsInSignedOrder(t *testing.T) {
	signed := testFrozenSignedOrder()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	// Append an unknown field (field 99, varint).
	tampered := append(append([]byte(nil), raw...), 0xd8, 0x06, 0x01)

	if _, err := parseOrderEnvelope(tampered, "secp256k1", hex.EncodeToString(bytes.Repeat([]byte{0x99}, 64))); err == nil {
		t.Fatal("a SignedOrderV2 with unknown fields was accepted")
	}
}

// TestParseOrderEnvelopeRejectsIncompleteSignedOrder covers structural validation: a missing order,
// the wrong signature scheme and the wrong signature length must all be blocked at ingress.
func TestParseOrderEnvelopeRejectsIncompleteSignedOrder(t *testing.T) {
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x55}, 64))
	cases := map[string]*taskv1.SignedOrderV2{
		"no order":          {SignatureScheme: "eip712", UserSignature: testUserSignatureV2(0x55)},
		"wrong scheme":      {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "ed25519", UserSignature: testUserSignatureV2(0x55)},
		"legacy secp256k1":  {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "secp256k1", UserSignature: bytes.Repeat([]byte{0x55}, 64)},
		"64-byte signature": {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "eip712", UserSignature: bytes.Repeat([]byte{0x55}, 64)},
		"short signature":   {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "eip712", UserSignature: bytes.Repeat([]byte{0x55}, 32)},
		"bad V":             {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "eip712", UserSignature: append(bytes.Repeat([]byte{0x55}, 64), 1)},
		"high-S":            {Order: testFrozenSignedOrder().GetOrder(), SignatureScheme: "eip712", UserSignature: append(append(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0xff}, 32)...), 27)},
		"no profile":        {Order: &taskv1.TaskOrderV2{ModelId: "model-1"}, SignatureScheme: "eip712", UserSignature: testUserSignatureV2(0x55)},
		"no model": {Order: &taskv1.TaskOrderV2{ProfileVersion: 1}, SignatureScheme: "eip712",
			UserSignature: testUserSignatureV2(0x55)},
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) == 0 {
				t.Skip("empty encoding cannot reach the signed-order branch")
			}
			if _, err := parseOrderEnvelope(raw, "secp256k1", signature); err == nil {
				t.Fatalf("%s: incomplete SignedOrderV2 was accepted", name)
			}
		})
	}
}

// TestParseOrderEnvelopeStillAcceptsLegacyJSON confirms old SDKs are not broken by this change:
// the old canonical JSON envelope still parses, only without a SignedOrder, so the first proposal errors at the
// coordinator layer instead of being forged.
func TestParseOrderEnvelopeStillAcceptsLegacyJSON(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	req := canonicalOrderRequest(t, sg, "session-legacy", 1, "model-1")
	order, err := parseOrderEnvelope(req.GetOrderEnvelope(), "secp256k1", hex.EncodeToString(req.GetSignature()))
	if err != nil {
		t.Fatalf("legacy json envelope: %v", err)
	}
	if len(order.SignedOrder) != 0 {
		t.Fatal("legacy json envelope must not synthesise a SignedOrderV2")
	}
	if order.ModelID != "model-1" {
		t.Fatalf("order=%+v", order)
	}
}
