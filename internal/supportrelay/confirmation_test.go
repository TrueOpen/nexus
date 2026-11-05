package supportrelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/hash32text"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// relayVector is wire testdata/v1/hub/model_support_relay_v1.json.
type relayVector struct {
	ChainID      string `json:"chain_id"`
	EpochIndex   string `json:"epoch_index"`
	Confirmation struct {
		OperatorAddress           string   `json:"operator_address"`
		SupportedModelsHex        []string `json:"supported_models_hex"`
		ServiceAuthorizationNonce string   `json:"service_authorization_nonce"`
		ExpiryHeight              string   `json:"expiry_height"`
		ServiceSignatureHex       string   `json:"service_signature_hex"`
	} `json:"confirmation"`
	ServicePublicKeyHex       string `json:"service_public_key_hex"`
	ConfirmationSigningDigest string `json:"confirmation_signing_digest"`
	SignatureDigestHex        string `json:"signature_digest_hex"`
	ConfirmationProtobufHex   string `json:"confirmation_protobuf_hex"`
	EquivalentConfirmationHex string `json:"equivalent_confirmation_protobuf_hex"`
	RequestProtobufHex        string `json:"request_protobuf_hex"`
	EquivalentRequestHex      string `json:"equivalent_request_protobuf_hex"`
	ResponseProtobufHex       string `json:"response_protobuf_hex"`
}

func loadRelayVector(t *testing.T) relayVector {
	t.Helper()
	var v relayVector
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/hub/model_support_relay_v1.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustUint(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Both published encodings decode to the vector's fields and to one signing digest, which the
// fixture service key signed; the replay fingerprint is SHA-256 of the raw signature.
func TestDecodeMatchesTheWireRelayVector(t *testing.T) {
	v := loadRelayVector(t)
	epoch := mustUint(t, v.EpochIndex)
	for _, encoding := range []string{v.ConfirmationProtobufHex, v.EquivalentConfirmationHex} {
		c, err := Decode(mustHex(t, encoding), "trueopen")
		if err != nil {
			t.Fatal(err)
		}
		if c.Operator != v.Confirmation.OperatorAddress || c.Nonce != mustUint(t, v.Confirmation.ServiceAuthorizationNonce) ||
			c.ExpiryHeight != mustUint(t, v.Confirmation.ExpiryHeight) ||
			!bytes.Equal(c.Signature, mustHex(t, v.Confirmation.ServiceSignatureHex)) ||
			len(c.Models) != len(v.Confirmation.SupportedModelsHex) {
			t.Fatalf("decoded %+v", c)
		}
		for i, model := range v.Confirmation.SupportedModelsHex {
			if !bytes.Equal(c.Models[i], mustHex(t, model)) {
				t.Fatalf("model %d = %x", i, c.Models[i])
			}
		}
		digest, err := c.Digest(v.ChainID, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if got := hash32text.Encode(digest[:]); got != v.ConfirmationSigningDigest {
			t.Fatalf("digest = %s, want %s", got, v.ConfirmationSigningDigest)
		}
		if !signer.VerifyDigestSig(mustHex(t, v.ServicePublicKeyHex), digest[:], c.Signature) {
			t.Fatal("fixture signature does not verify")
		}
		fingerprint := sha256.Sum256(c.Signature)
		if hex.EncodeToString(fingerprint[:]) != v.SignatureDigestHex {
			t.Fatalf("signature fingerprint = %x", fingerprint)
		}
		raw, err := proto.Marshal(c.Proto())
		if err != nil || hex.EncodeToString(raw) != v.ConfirmationProtobufHex {
			t.Fatalf("canonical re-encoding = %x, %v", raw, err)
		}
	}
}

// The request and response bytes are the generated nexus.v1 messages.
func TestRelayVectorRequestAndResponseBytes(t *testing.T) {
	v := loadRelayVector(t)
	for _, encoding := range []string{v.RequestProtobufHex, v.EquivalentRequestHex} {
		var req nexusv1.SubmitModelSupportConfirmationRequest
		if err := proto.Unmarshal(mustHex(t, encoding), &req); err != nil {
			t.Fatal(err)
		}
		if req.GetEpochIndex() != mustUint(t, v.EpochIndex) {
			t.Fatalf("epoch_index = %d", req.GetEpochIndex())
		}
		if _, err := Decode(req.GetConfirmation(), "trueopen"); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := proto.Marshal(&nexusv1.SubmitModelSupportConfirmationResponse{
		RelayAccepted: true, ConfirmationSigningDigest: v.ConfirmationSigningDigest,
	})
	if err != nil || hex.EncodeToString(resp) != v.ResponseProtobufHex {
		t.Fatalf("response = %x, %v", resp, err)
	}
}

func appendBytesField(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func appendVarintField(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

// An ambiguous or malformed payload is refused rather than read the way one decoder would: unknown
// and duplicate singular fields, wrong wire types and non-canonical field values.
func TestDecodeRefusesMalformedPayloads(t *testing.T) {
	v := loadRelayVector(t)
	valid := mustHex(t, v.ConfirmationProtobufHex)
	model := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	base := func() *hubv1.ModelSupportConfirmationV1 {
		return &hubv1.ModelSupportConfirmationV1{
			OperatorAddress: v.Confirmation.OperatorAddress, SupportedModels: [][]byte{model(1), model(2)},
			ServiceAuthorizationNonce: 7, ExpiryHeight: 2000, ServiceSignature: make([]byte, 64),
		}
	}
	encode := func(edit func(*hubv1.ModelSupportConfirmationV1)) []byte {
		m := base()
		edit(m)
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	operatorRaw := mustHex(t, "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4")
	otherPrefix, err := bech32.ConvertAndEncode("cosmos", operatorRaw)
	if err != nil {
		t.Fatal(err)
	}
	shortOperator, err := bech32.ConvertAndEncode("trueopen", operatorRaw[:19])
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":               nil,
		"truncated":           valid[:len(valid)-1],
		"unknown field":       appendVarintField(append([]byte(nil), valid...), 6, 1),
		"duplicate operator":  appendBytesField(append([]byte(nil), valid...), 1, []byte(v.Confirmation.OperatorAddress)),
		"duplicate nonce":     appendVarintField(append([]byte(nil), valid...), 3, 7),
		"duplicate expiry":    appendVarintField(append([]byte(nil), valid...), 4, 2000),
		"duplicate signature": appendBytesField(append([]byte(nil), valid...), 5, make([]byte, 64)),
		"nonce as bytes":      appendBytesField(encode(func(m *hubv1.ModelSupportConfirmationV1) { m.ServiceAuthorizationNonce = 0 }), 3, []byte{7}),
		"operator as varint":  appendVarintField(encode(func(m *hubv1.ModelSupportConfirmationV1) { m.OperatorAddress = "" }), 1, 1),
		"model as varint":     appendVarintField(append([]byte(nil), valid...), 2, 1),
		"group wire type":     append(append([]byte(nil), valid...), protowire.AppendTag(nil, 7, protowire.StartGroupType)...),
		"no operator":         encode(func(m *hubv1.ModelSupportConfirmationV1) { m.OperatorAddress = "" }),
		"uppercase operator": encode(func(m *hubv1.ModelSupportConfirmationV1) {
			m.OperatorAddress = "TRUEOPEN15X328F9956N632D24WK2MT40KZCM9VA5VW5E0A"
		}),
		"other prefix":         encode(func(m *hubv1.ModelSupportConfirmationV1) { m.OperatorAddress = otherPrefix }),
		"19-byte operator":     encode(func(m *hubv1.ModelSupportConfirmationV1) { m.OperatorAddress = shortOperator }),
		"no models":            encode(func(m *hubv1.ModelSupportConfirmationV1) { m.SupportedModels = nil }),
		"short model":          encode(func(m *hubv1.ModelSupportConfirmationV1) { m.SupportedModels = [][]byte{model(1)[:31]} }),
		"descending models":    encode(func(m *hubv1.ModelSupportConfirmationV1) { m.SupportedModels = [][]byte{model(2), model(1)} }),
		"duplicate models":     encode(func(m *hubv1.ModelSupportConfirmationV1) { m.SupportedModels = [][]byte{model(1), model(1)} }),
		"zero nonce":           encode(func(m *hubv1.ModelSupportConfirmationV1) { m.ServiceAuthorizationNonce = 0 }),
		"zero expiry":          encode(func(m *hubv1.ModelSupportConfirmationV1) { m.ExpiryHeight = 0 }),
		"short signature":      encode(func(m *hubv1.ModelSupportConfirmationV1) { m.ServiceSignature = make([]byte, 63) }),
		"invalid utf8 address": appendBytesField(encode(func(m *hubv1.ModelSupportConfirmationV1) { m.OperatorAddress = "" }), 1, []byte{0xff}),
	}
	for name, raw := range cases {
		if _, err := Decode(raw, "trueopen"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := Decode(encode(func(*hubv1.ModelSupportConfirmationV1) {}), "trueopen"); err != nil {
		t.Fatalf("the valid base was refused: %v", err)
	}
}
