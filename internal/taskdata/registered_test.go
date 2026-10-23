package taskdata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// The OUTPUT object of wire session_key_authorization_v1.json registered_output_metadata_body.
func registeredOutputRef() ObjectRef {
	return ObjectRef{
		TaskHash:    "a7d5076b0d1348f0e68939c430f1a06229e406e2a4ca66efa666edf09f211977",
		SessionID:   "77625100ba4faa1306ae6eaf5a872a661443aa94f87c5530c4b178614e3d62f7",
		TaskID:      "bce966ae829f212a35982bcd85aaea77d8893539afa04f32ea540c46ff8323b0",
		Kind:        ObjectKindOutput,
		ContentHash: "4444444444444444444444444444444444444444444444444444444444444444",
	}
}

type registeredFixture struct {
	Account struct {
		Bech32        string `json:"account_bech32"`
		PubCompressed string `json:"pub_compressed"`
	} `json:"account"`
	SessionKey struct {
		AddressBytes string `json:"address_bytes"`
	} `json:"session_key"`
	Request goldenTypedData `json:"registered_data_request"`
}

type fakeRegisteredKeys struct {
	state registeredkey.State
	err   error
	calls int
}

func (f *fakeRegisteredKeys) Lookup(context.Context, string, uint64) (registeredkey.State, error) {
	f.calls++
	return f.state, f.err
}

// registeredDataRequest is the wire GetTaskDataMetadata request signed by the registered key with
// no grant, at height 1000 with the key registered until 1100 and the Task on record locally.
func registeredDataRequest(t *testing.T) (RequestAuthV1, SessionGrantEnv, *fakeRegisteredKeys, *bool) {
	t.Helper()
	var file registeredFixture
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/session_key_authorization_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	v := file.Request
	body, err := TaskDataMetadataBodyDigest(registeredOutputRef())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(body[:]) != v.Message["bodyDigest"] {
		t.Fatalf("metadata body %x is not the vector's %s", body, v.Message["bodyDigest"])
	}
	if v.Recovered != file.SessionKey.AddressBytes {
		t.Fatalf("vector recovers %s, not the session key", v.Recovered)
	}
	auth := RequestAuthV1{
		SchemaVersion: 1, ChainID: v.Message["chainId"],
		BuilderOperatorAddress: v.Message["builderOperatorAddress"],
		RPCMethod:              v.Message["rpcMethod"],
		BodyDigest:             hex.EncodeToString(body[:]),
		RequesterKind:          RequesterKindUser,
		RequesterAddress:       v.Message["requesterAddress"],
		RequestNonce:           mustHexT(t, v.Message["requestNonce"]),
		ExpiryHeight:           mustUintT(t, v.Message["expiryHeight"]),
		Signature:              mustHexT(t, v.Signature),
		SignatureChainID:       mustUintT(t, v.SignatureChainID),
		Key:                    registeredOutputRef(),
	}
	var key [20]byte
	copy(key[:], mustHexT(t, file.SessionKey.AddressBytes))
	keys := &fakeRegisteredKeys{state: registeredkey.State{
		Found: true, Owner: file.Account.Bech32, Key: &key, ExpiryHeight: 1100, SetHeight: 980, SpendCap: "0", Spent: "0",
	}}
	local := true
	env := SessionGrantEnv{
		Chain: goldenGrantChain{height: 1000, keys: map[string][]byte{
			file.Account.Bech32: mustHexT(t, file.Account.PubCompressed),
		}},
		MaxBlocks: 100, ChainID: v.Message["chainId"], SessionKeys: keys,
		LocalTask: func(_ context.Context, sessionID, taskID string) (bool, error) {
			ref := registeredOutputRef()
			return local && sessionID == ref.SessionID && taskID == ref.TaskID, nil
		},
	}
	return auth, env, keys, &local
}

func TestRegisteredKeyTaskDataRequestMatchesWire(t *testing.T) {
	auth, env, keys, _ := registeredDataRequest(t)
	if err := VerifyUserTaskDataRequest(context.Background(), auth, env); err != nil {
		t.Fatalf("VerifyUserTaskDataRequest: %v", err)
	}
	if keys.calls != 1 {
		t.Fatalf("lookups = %d, want 1", keys.calls)
	}
}

func TestRegisteredKeyTaskDataRequestErrors(t *testing.T) {
	other := [20]byte{9}
	cases := []struct {
		name string
		edit func(*RequestAuthV1, *SessionGrantEnv, *fakeRegisteredKeys, *bool)
		want error
	}{
		{"not configured", func(_ *RequestAuthV1, e *SessionGrantEnv, _ *fakeRegisteredKeys, _ *bool) { e.SessionKeys = nil }, ErrInvalidSignature},
		{"no local task", func(_ *RequestAuthV1, _ *SessionGrantEnv, _ *fakeRegisteredKeys, local *bool) { *local = false }, ErrInvalidSignature},
		{"local read fails", func(_ *RequestAuthV1, e *SessionGrantEnv, _ *fakeRegisteredKeys, _ *bool) {
			e.LocalTask = func(context.Context, string, string) (bool, error) { return false, errors.New("disk") }
		}, ErrAuthorityUnavailable},
		{"closed", func(_ *RequestAuthV1, _ *SessionGrantEnv, k *fakeRegisteredKeys, _ *bool) { k.state.Closed = true }, ErrInvalidSignature},
		{"another key", func(_ *RequestAuthV1, _ *SessionGrantEnv, k *fakeRegisteredKeys, _ *bool) { k.state.Key = &other }, ErrInvalidSignature},
		{"expired", func(_ *RequestAuthV1, _ *SessionGrantEnv, k *fakeRegisteredKeys, _ *bool) { k.state.ExpiryHeight = 999 }, ErrSessionGrantExpired},
		{"state unavailable", func(_ *RequestAuthV1, _ *SessionGrantEnv, k *fakeRegisteredKeys, _ *bool) {
			k.err = registeredkey.ErrUnavailable
		}, ErrAuthorityUnavailable},
		// A request field for another chain fails as a signature before any session read.
		{"other chain", func(a *RequestAuthV1, _ *SessionGrantEnv, _ *fakeRegisteredKeys, _ *bool) { a.ChainID = "other-chain" }, ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auth, env, keys, local := registeredDataRequest(t)
			c.edit(&auth, &env, keys, local)
			if err := VerifyUserTaskDataRequest(context.Background(), auth, env); !errors.Is(err, c.want) {
				t.Fatalf("VerifyUserTaskDataRequest = %v, want %v", err, c.want)
			}
		})
	}
}

// The registered key may sign only metadata and fetch of an OUTPUT object; anything else is
// refused after the key and expiry checks pass.
func TestRegisteredKeyTaskDataMethodSet(t *testing.T) {
	auth, env, _, _ := registeredDataRequest(t)
	if err := verifyRegisteredTaskDataKey(context.Background(), auth, env, sessionKeyOf(t, env)); err != nil {
		t.Fatalf("OUTPUT metadata: %v", err)
	}
	auth.Key.Kind = ObjectKindInput
	if err := verifyRegisteredTaskDataKey(context.Background(), auth, env, sessionKeyOf(t, env)); !errors.Is(err, ErrSessionMethodNotAllowed) {
		t.Fatalf("INPUT metadata = %v, want method not allowed", err)
	}
	auth.Key.Kind = ObjectKindOutput
	auth.RPCMethod = rpcMethodPath(MethodUpload)
	if err := verifyRegisteredTaskDataKey(context.Background(), auth, env, sessionKeyOf(t, env)); !errors.Is(err, ErrSessionMethodNotAllowed) {
		t.Fatalf("upload = %v, want method not allowed", err)
	}
}

func sessionKeyOf(t *testing.T, env SessionGrantEnv) [20]byte {
	t.Helper()
	return *env.SessionKeys.(*fakeRegisteredKeys).state.Key
}
