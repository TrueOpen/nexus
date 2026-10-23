package ingress

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// These tests open no listener: they call validateOpenTaskHeader directly with the wire vectors of
// testdata/v1/task/session_key_authorization_v1.json (an OpenTask of order sequence 7 at chain
// "trueopen-golden-1", signed by the account and by its registered session key).

type registeredKeyFile struct {
	Account struct {
		Bech32        string `json:"account_bech32"`
		PrivateKey    string `json:"private_key"`
		PubCompressed string `json:"pub_compressed"`
	} `json:"account"`
	SessionKey struct {
		AddressBytes string `json:"address_bytes"`
	} `json:"session_key"`
	WrongKey struct {
		PrivateKey string `json:"private_key"`
	} `json:"wrong_key"`
	OrderPayload   wirefixture.Vector `json:"order_payload"`
	WalletOrder    registeredKeySig   `json:"wallet_order"`
	DelegatedOrder registeredKeySig   `json:"delegated_order"`
	SDKRequest     struct {
		Message   map[string]string `json:"message"`
		Signature string            `json:"signature_65"`
	} `json:"registered_sdk_request"`
	Body struct {
		Fields []wirefixture.Field `json:"fields"`
	} `json:"registered_open_task_body"`
}

type registeredKeySig struct {
	Message struct {
		FeeDenom string `json:"feeDenom"`
	} `json:"message"`
	Signature        string `json:"signature_65"`
	SignatureChainID uint64 `json:"signature_chain_id,string"`
	SigningDigest    string `json:"signing_digest"`
}

// countingUserChain answers the account key of the vector account at a fixed height and counts
// height reads.
type countingUserChain struct {
	height      uint64
	heightReads int
	account     string
	pubKey      []byte
}

func (c *countingUserChain) CurrentHeight(context.Context) (uint64, error) {
	c.heightReads++
	return c.height, nil
}

func (c *countingUserChain) AccountPubKey(_ context.Context, address string) ([]byte, error) {
	if address != c.account {
		return nil, sdkauth.ErrNoAccountKey
	}
	return c.pubKey, nil
}

type recordingSessionKeys struct {
	state   registeredkey.State
	heights []uint64
}

func (k *recordingSessionKeys) Lookup(_ context.Context, _ string, height uint64) (registeredkey.State, error) {
	k.heights = append(k.heights, height)
	return k.state, nil
}

type registeredKeyHeader struct {
	file   registeredKeyFile
	header *nexusv1.OpenTaskHeader
	body   [32]byte
	chain  *countingUserChain
	keys   *recordingSessionKeys
	svc    *service
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signDigest65(t *testing.T, keyHex string, digest []byte) []byte {
	t.Helper()
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(mustHexBytes(t, keyHex)), digest, false) // [V R S]
	return append(append([]byte{}, compact[1:]...), compact[0])
}

// newRegisteredKeyHeader builds the vector OpenTask: the order and the request envelope both signed
// by the registered key, judged at height 1000 against a key registered at 980 until 1100 with
// 1000000 of a 1150000 cap spent.
func newRegisteredKeyHeader(t *testing.T) *registeredKeyHeader {
	t.Helper()
	var file registeredKeyFile
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/session_key_authorization_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	field := func(name string) wirefixture.Field {
		for _, f := range file.Body.Fields {
			if f.Name == name {
				return f
			}
		}
		t.Fatalf("body has no field %s", name)
		return wirefixture.Field{}
	}
	m := file.SDKRequest.Message
	var body [32]byte
	copy(body[:], mustHexBytes(t, m["bodyDigest"]))
	h := &registeredKeyHeader{file: file, body: body}
	h.header = &nexusv1.OpenTaskHeader{
		PayloadRef: "nexus://sha256/" + field("input_hash").Hex,
		RequestEnvelope: &nexusv1.SDKRequestEnvelopeV2{
			RequestDomain: sdkauth.RequestDomain, ChainId: m["chainId"], Method: m["method"], Endpoint: m["endpoint"],
			SessionId: "0x" + m["sessionId"], TaskId: "0x" + m["taskId"], RequestNonce: mustHexBytes(t, m["requestNonce"]),
			ExpiryHeightOrTime: 1010, BodyDigest: body[:], SignerAddress: file.Account.Bech32,
			Signature: mustHexBytes(t, file.SDKRequest.Signature), SignatureChainId: file.DelegatedOrder.SignatureChainID,
		},
		SessionId: "0x" + m["sessionId"], OrderSequence: field("order_sequence").Uint64(t),
		UserAddress: file.Account.Bech32, InputSizeBytes: field("input_size_bytes").Uint64(t),
		InputHash: "0x" + field("input_hash").Hex, InputMediaType: field("input_media_type").UTF8,
		IdempotencyKey: field("idempotency_key").UTF8,
	}
	h.setOrderSignature(t, mustHexBytes(t, file.DelegatedOrder.Signature))
	var key [20]byte
	copy(key[:], mustHexBytes(t, file.SessionKey.AddressBytes))
	h.keys = &recordingSessionKeys{state: registeredkey.State{
		Found: true, Owner: file.Account.Bech32, Key: &key, ExpiryHeight: 1100, SetHeight: 980,
		SpendCap: "1150000", Spent: "1000000",
	}}
	h.chain = &countingUserChain{height: 1000, account: file.Account.Bech32, pubKey: mustHexBytes(t, file.Account.PubCompressed)}
	h.svc = &service{auth: AuthParams{
		ChainID: m["chainId"], Bech32Prefix: "trueopen", Chain: h.chain, MaxSessionGrantBlocks: 100,
		SessionKeys: h.keys, FeeDenom: file.DelegatedOrder.Message.FeeDenom,
	}}
	return h
}

func (h *registeredKeyHeader) setOrderSignature(t *testing.T, signature []byte) {
	t.Helper()
	raw, err := proto.Marshal(&taskv1.SignedOrderV2{
		Order: wirefixture.TaskOrderV3(t, h.file.OrderPayload), SignatureScheme: "eip712",
		UserSignature: signature, SignatureChainId: h.file.DelegatedOrder.SignatureChainID,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.header.OrderEnvelope = raw
}

// signEnvelopeWithWallet re-signs the request envelope with the account's wallet key.
func (h *registeredKeyHeader) signEnvelopeWithWallet(t *testing.T) {
	t.Helper()
	digest, err := sdkauth.RequestDigest(envelopeFromPB(h.header.GetRequestEnvelope()), h.body, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	h.header.RequestEnvelope.Signature = signDigest65(t, h.file.Account.PrivateKey, digest[:])
}

func (h *registeredKeyHeader) validate() error {
	_, _, err := h.svc.validateOpenTaskHeader(context.Background(), h.header)
	return err
}

func wantConnectErr(t *testing.T, err error, code connect.Code, text string) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != code || !strings.Contains(err.Error(), text) {
		t.Fatalf("err = %v, want %v %s", err, code, text)
	}
}

// Both signed by the registered key: accepted, with one height read shared by the envelope and the
// order precheck.
func TestOpenTaskHeaderRegisteredKeyAccepted(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	if err := h.validate(); err != nil {
		t.Fatalf("validateOpenTaskHeader: %v", err)
	}
	if h.chain.heightReads != 1 {
		t.Fatalf("height reads = %d, want 1", h.chain.heightReads)
	}
	if len(h.keys.heights) != 2 || h.keys.heights[0] != 1000 || h.keys.heights[1] != 1000 {
		t.Fatalf("lookups at %v, want the envelope and the order both at 1000", h.keys.heights)
	}
}

// A wallet order with a wallet envelope reads neither the height nor the session.
func TestOpenTaskHeaderWalletOrderUnchanged(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.setOrderSignature(t, mustHexBytes(t, h.file.WalletOrder.Signature))
	h.signEnvelopeWithWallet(t)
	if err := h.validate(); err != nil {
		t.Fatalf("validateOpenTaskHeader: %v", err)
	}
	if h.chain.heightReads != 0 || len(h.keys.heights) != 0 {
		t.Fatalf("wallet order read %d heights and %d sessions", h.chain.heightReads, len(h.keys.heights))
	}
}

func TestOpenTaskHeaderRegisteredKeyOrderRejections(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, *registeredKeyHeader)
		code connect.Code
		text string
	}{
		{"order signed by a key that is not the session's", func(t *testing.T, h *registeredKeyHeader) {
			h.setOrderSignature(t, signDigest65(t, h.file.WrongKey.PrivateKey, mustHexBytes(t, h.file.DelegatedOrder.SigningDigest)))
		}, connect.CodeUnauthenticated, "SDK_AUTH_INVALID_SIGNATURE"},
		// The wallet signed another digest (another fee denom): it no longer recovers to the user and
		// is refused at the entry instead of on chain.
		{"wallet signature over another digest", func(t *testing.T, h *registeredKeyHeader) {
			h.setOrderSignature(t, mustHexBytes(t, h.file.WalletOrder.Signature))
			h.svc.auth.FeeDenom = "uother"
		}, connect.CodeUnauthenticated, "SDK_AUTH_INVALID_SIGNATURE"},
		{"key rotated", func(_ *testing.T, h *registeredKeyHeader) {
			other := [20]byte{9}
			h.keys.state.Key = &other
		}, connect.CodeUnauthenticated, "SDK_AUTH_INVALID_SIGNATURE"},
		{"key re-registered after the order's anchor", func(_ *testing.T, h *registeredKeyHeader) {
			h.keys.state.SetHeight = 991
		}, connect.CodeUnauthenticated, "SDK_AUTH_INVALID_SIGNATURE"},
		{"key expired", func(_ *testing.T, h *registeredKeyHeader) {
			h.keys.state.ExpiryHeight = 999
		}, connect.CodeDeadlineExceeded, "SDK_AUTH_SESSION_GRANT_EXPIRED"},
		{"spend cap one unit short", func(_ *testing.T, h *registeredKeyHeader) {
			h.keys.state.SpendCap = "1149999"
		}, connect.CodeFailedPrecondition, "SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newRegisteredKeyHeader(t)
			// A wallet envelope isolates the order precheck from the envelope's own key check.
			h.signEnvelopeWithWallet(t)
			c.edit(t, h)
			wantConnectErr(t, h.validate(), c.code, c.text)
		})
	}
}
