package sdkauth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// accountSigning is the part of wire testdata/v1/shared/account_signing_v1.json these tests use.
type accountSigning struct {
	Account struct {
		Bech32        string `json:"account_bech32"`
		PubCompressed string `json:"pub_compressed"`
	} `json:"account"`
	SDKRequest        signedTypedData `json:"sdk_request"`
	SDKRequestSession signedTypedData `json:"sdk_request_session"`
	SessionGrant      struct {
		signedTypedData
		Transport struct {
			ChainID      string `json:"chain_id"`
			ExpiryHeight string `json:"expiry_height"`
			GrantNonce   string `json:"grant_nonce_hex"`
			SessionKey   string `json:"session_key_hex"`
			User         string `json:"user"`
		} `json:"transport"`
		Context struct {
			CurrentHeight string `json:"current_height"`
			MaxBlocks     string `json:"max_session_grant_blocks"`
		} `json:"verification_context"`
	} `json:"session_grant"`
}

type signedTypedData struct {
	Domain struct {
		ChainID   string `json:"chain_id"`
		Separator string `json:"domain_separator"`
	} `json:"domain"`
	Envelope struct {
		SignerAddress string `json:"signer_address"`
		ReplayKey     string `json:"replay_key"`
	} `json:"envelope"`
	HashStruct string            `json:"hash_struct"`
	Message    map[string]string `json:"message"`
	Recovered  string            `json:"recovered_address"`
	Signature  string            `json:"signature_65"`
	Digest     string            `json:"signing_digest"`
}

func loadAccountSigning(t *testing.T) accountSigning {
	t.Helper()
	var out accountSigning
	if err := json.Unmarshal(wirefixture.ReadFile(t, filepath.Join("testdata", "v1", "shared", "account_signing_v1.json")), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustUint(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func hash32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], mustHex(t, s))
	return out
}

// fakeChain answers the chain reads verification needs.
type fakeChain struct {
	height  uint64
	keys    map[string][]byte
	keyErr  error
	heightE error
}

func (c *fakeChain) CurrentHeight(context.Context) (uint64, error) { return c.height, c.heightE }
func (c *fakeChain) AccountPubKey(_ context.Context, address string) ([]byte, error) {
	if c.keyErr != nil {
		return nil, c.keyErr
	}
	key, ok := c.keys[address]
	if !ok {
		return nil, ErrNoAccountKey
	}
	return key, nil
}

func envelopeFrom(t *testing.T, v signedTypedData) *Envelope {
	t.Helper()
	expiry, err := strconv.ParseInt(v.Message["expiryHeightOrTime"], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return &Envelope{
		RequestDomain: RequestDomain, ChainID: v.Message["chainId"], Method: v.Message["method"],
		Endpoint: v.Message["endpoint"], SessionID: v.Message["sessionId"], TaskID: v.Message["taskId"],
		RequestNonce: mustHex(t, v.Message["requestNonce"]), ExpiryHeightOrTime: expiry,
		BodyDigest: mustHex(t, v.Message["bodyDigest"]), SignerAddress: v.Envelope.SignerAddress,
		Signature: mustHex(t, v.Signature),
	}
}

func grantFrom(t *testing.T, f accountSigning) *SessionGrant {
	t.Helper()
	g := f.SessionGrant
	return &SessionGrant{
		ChainID: g.Transport.ChainID, User: g.Transport.User, SessionKey: mustHex(t, g.Transport.SessionKey),
		ExpiryHeight: mustUint(t, g.Transport.ExpiryHeight), GrantNonce: mustHex(t, g.Transport.GrantNonce),
		UserSignature: mustHex(t, g.Signature),
	}
}

func optsFor(t *testing.T, f accountSigning, v signedTypedData, chain *fakeChain) VerifyOpts {
	t.Helper()
	return VerifyOpts{
		ChainID: v.Message["chainId"], EVMChainID: mustUint(t, v.Domain.ChainID), Method: v.Message["method"],
		NowMS: 1_700_000_000_000, Body: hash32(t, v.Message["bodyDigest"]), Bech32Prefix: "trueopen",
		Chain: chain, MaxSessionGrantBlocks: mustUint(t, f.SessionGrant.Context.MaxBlocks),
	}
}

func chainFor(t *testing.T, f accountSigning) *fakeChain {
	t.Helper()
	return &fakeChain{
		height: mustUint(t, f.SessionGrant.Context.CurrentHeight),
		keys:   map[string][]byte{f.Account.Bech32: mustHex(t, f.Account.PubCompressed)},
	}
}

// The five User Ingress body digests match wire's sdk_request_body_v1.json byte for byte.
func TestBodyDigestsMatchWire(t *testing.T) {
	file := wirefixture.Load(t, filepath.Join("task", "sdk_request_body_v1.json"))
	check := func(name string, got [32]byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v := file.Vector(t, name, 0)
		if want := v.Digest(t); got != want {
			t.Fatalf("%s = %x, want %x", name, got, want)
		}
	}
	open := file.Vector(t, "sdk_body_open_task_v1", 0)
	var taskHash [32]byte
	copy(taskHash[:], open.Field(t, "task_hash").Bytes(t))
	got, err := OpenTaskBody(taskHash, hex.EncodeToString(open.Field(t, "session_id").Bytes(t)),
		open.Field(t, "order_sequence").Uint64(t), open.Field(t, "user_address").Bech32,
		open.Field(t, "input_size_bytes").Uint64(t), hex.EncodeToString(open.Field(t, "input_hash").Bytes(t)),
		open.Field(t, "input_media_type").UTF8, open.Field(t, "idempotency_key").UTF8)
	check("sdk_body_open_task_v1", got, err)

	sub := file.Vector(t, "sdk_body_subscribe_output_v1", 0)
	session := hex.EncodeToString(sub.Field(t, "session_id").Bytes(t))
	task := hex.EncodeToString(sub.Field(t, "task_id").Bytes(t))
	got, err = SubscribeOutputBody(session, task, nil)
	check("sdk_body_subscribe_output_v1", got, err)

	ack := file.Vector(t, "sdk_body_ack_output_v1", 0)
	got, err = AckOutputBody(session, task, ack.Field(t, "last_seq").Uint64(t))
	check("sdk_body_ack_output_v1", got, err)

	got, err = GetTaskEventsBody(session, task, "")
	check("sdk_body_get_task_events_v1", got, err)

	challenge := file.Vector(t, "sdk_body_prepare_challenge_v1", 0)
	evidence := challenge.Field(t, "local_evidence_digest").Fields[0].Bytes(t)
	got, err = PrepareChallengeBody(session, task, challenge.Field(t, "challenge_kind").UTF8, evidence)
	check("sdk_body_prepare_challenge_v1", got, err)
}

// The wallet-signed OpenTask request: domain, hash_struct, digest and recovered signer match wire, and
// Verify accepts it with the account's stored key.
func TestWalletSignedRequestMatchesWire(t *testing.T) {
	f := loadAccountSigning(t)
	v := f.SDKRequest
	if got := domainSeparator(mustUint(t, v.Domain.ChainID)); hex.EncodeToString(got[:]) != v.Domain.Separator {
		t.Fatalf("domain separator %x, want %s", got, v.Domain.Separator)
	}
	e := envelopeFrom(t, v)
	digest, err := RequestDigest(e, hash32(t, v.Message["bodyDigest"]), [32]byte{}, mustUint(t, v.Domain.ChainID))
	if err != nil || hex.EncodeToString(digest[:]) != v.Digest {
		t.Fatalf("digest %x (%v), want %s", digest, err, v.Digest)
	}
	recovered, err := eip712.Recover(digest, e.Signature)
	if err != nil || hex.EncodeToString(recovered.Address[:]) != v.Recovered {
		t.Fatalf("recovered %x (%v), want %s", recovered.Address, err, v.Recovered)
	}
	if ReplayKey(e) != unescape(v.Envelope.ReplayKey) {
		t.Fatalf("replay key %q, want %q", ReplayKey(e), v.Envelope.ReplayKey)
	}
	opts := optsFor(t, f, v, chainFor(t, f))
	opts.HeightExpiry = true // the OpenTask vector carries a chain-height expiry
	if err := Verify(context.Background(), e, opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// The session grant and the session-key-signed SubscribeOutput request match wire, and Verify accepts
// them inside the grant window.
func TestSessionSignedRequestMatchesWire(t *testing.T) {
	f := loadAccountSigning(t)
	grant := grantFrom(t, f)
	hash, err := SessionGrantHash(grant)
	if err != nil || hex.EncodeToString(hash[:]) != f.SessionGrant.HashStruct {
		t.Fatalf("grant hash %x (%v), want %s", hash, err, f.SessionGrant.HashStruct)
	}
	grantDigest, err := SessionGrantDigest(grant, mustUint(t, f.SessionGrant.Domain.ChainID))
	if err != nil || hex.EncodeToString(grantDigest[:]) != f.SessionGrant.Digest {
		t.Fatalf("grant digest %x (%v), want %s", grantDigest, err, f.SessionGrant.Digest)
	}
	v := f.SDKRequestSession
	e := envelopeFrom(t, v)
	e.SessionGrant = grant
	digest, err := RequestDigest(e, hash32(t, v.Message["bodyDigest"]), hash, mustUint(t, v.Domain.ChainID))
	if err != nil || hex.EncodeToString(digest[:]) != v.Digest {
		t.Fatalf("digest %x (%v), want %s", digest, err, v.Digest)
	}
	opts := optsFor(t, f, v, chainFor(t, f))
	opts.SessionAllowed = true
	opts.ReplayCache = NewMemoryReplayCache()
	if err := Verify(context.Background(), e, opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := Verify(context.Background(), e, opts); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Verify = %v, want replay", err)
	}
}

func unescape(s string) string {
	out, err := strconv.Unquote(`"` + s + `"`)
	if err != nil {
		return s
	}
	return out
}
