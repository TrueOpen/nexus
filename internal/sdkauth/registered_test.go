package sdkauth

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// registeredVectors is the part of wire testdata/v1/task/session_key_authorization_v1.json these
// tests use.
type registeredVectors struct {
	Account struct {
		Bech32        string `json:"account_bech32"`
		PubCompressed string `json:"pub_compressed"`
	} `json:"account"`
	SessionKey struct {
		AddressBytes string `json:"address_bytes"`
	} `json:"session_key"`
	RegisteredSDKRequest signedTypedData         `json:"registered_sdk_request"`
	RequestCases         []registeredRequestCase `json:"registered_request_cases"`
}

// registeredRequestCase is one row of registered_request_cases: the session state a request
// signed by the registered key is judged against, and the expected outcome.
type registeredRequestCase struct {
	Name     string `json:"name"`
	Base     string `json:"base"`
	Expected string `json:"expected"`
	State    struct {
		ChainAvailable bool   `json:"chain_available"`
		SessionExists  bool   `json:"session_exists"`
		Status         string `json:"status"`
		OwnerMatches   bool   `json:"owner_matches"`
		KeyMatches     bool   `json:"key_matches"`
		CurrentHeight  uint64 `json:"current_height"`
		ExpiryHeight   uint64 `json:"expiry_height"`
		MethodAllowed  bool   `json:"method_allowed"`
	} `json:"state"`
}

type fakeSessionKeys struct {
	state   registeredkey.State
	err     error
	calls   int
	heights []uint64
}

func (f *fakeSessionKeys) Lookup(_ context.Context, _ string, height uint64) (registeredkey.State, error) {
	f.calls++
	f.heights = append(f.heights, height)
	return f.state, f.err
}

func loadRegistered(t *testing.T) registeredVectors {
	t.Helper()
	var out registeredVectors
	raw := wirefixture.ReadFile(t, filepath.Join("testdata", "v1", "task", "session_key_authorization_v1.json"))
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// registeredSetup is the wire OpenTask request signed by the registered key, at height 1000 with
// the key registered until 1100.
func registeredSetup(t *testing.T) (registeredVectors, *Envelope, VerifyOpts, *fakeSessionKeys) {
	t.Helper()
	f := loadRegistered(t)
	v := f.RegisteredSDKRequest
	e := envelopeFrom(t, v)
	var key [20]byte
	copy(key[:], mustHex(t, f.SessionKey.AddressBytes))
	keys := &fakeSessionKeys{state: registeredkey.State{
		Found: true, Owner: f.Account.Bech32, Key: &key, ExpiryHeight: 1100, SetHeight: 980, SpendCap: "0", Spent: "0",
	}}
	opts := VerifyOpts{
		ChainID: v.Message["chainId"], Method: v.Message["method"], NowMS: 1_700_000_000_000,
		Body: hash32(t, v.Message["bodyDigest"]), Bech32Prefix: "trueopen",
		HeightExpiry: true, SessionAllowed: true, OrderUser: f.Account.Bech32,
		Chain:                 &fakeChain{height: 1000, keys: map[string][]byte{f.Account.Bech32: mustHex(t, f.Account.PubCompressed)}},
		MaxSessionGrantBlocks: 100, SessionKeys: keys,
	}
	return f, e, opts, keys
}

func TestRegisteredKeyRequestMatchesWire(t *testing.T) {
	f, e, opts, keys := registeredSetup(t)
	if f.RegisteredSDKRequest.Recovered != f.SessionKey.AddressBytes {
		t.Fatalf("vector recovers %s, not the session key", f.RegisteredSDKRequest.Recovered)
	}
	if err := Verify(context.Background(), e, opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if keys.calls != 1 || keys.heights[0] != 1000 {
		t.Fatalf("lookups %d at %v, want one at the current height 1000", keys.calls, keys.heights)
	}
	// A height the caller already read is used instead of reading one.
	opts.Height = 1100
	opts.Chain.(*fakeChain).heightE = errors.New("CurrentHeight must not be called")
	if err := Verify(context.Background(), e, opts); err != nil {
		t.Fatalf("Verify at the inclusive expiry: %v", err)
	}
	if keys.heights[1] != 1100 {
		t.Fatalf("lookup height %d, want the caller's 1100", keys.heights[1])
	}
}

// The registered-key branch checks state and key, then expiry, then the method set, each with its
// own SDK error code.
func TestRegisteredKeyRequestErrors(t *testing.T) {
	other := [20]byte{9}
	cases := []struct {
		name string
		edit func(*VerifyOpts, *fakeSessionKeys)
		want error
	}{
		{"not configured", func(o *VerifyOpts, _ *fakeSessionKeys) { o.SessionKeys = nil }, ErrInvalidSignature},
		{"no such session", func(_ *VerifyOpts, k *fakeSessionKeys) { k.state = registeredkey.State{} }, ErrInvalidSignature},
		{"closed", func(_ *VerifyOpts, k *fakeSessionKeys) { k.state.Closed = true }, ErrInvalidSignature},
		{"no key", func(_ *VerifyOpts, k *fakeSessionKeys) { k.state.Key = nil }, ErrInvalidSignature},
		{"another key", func(_ *VerifyOpts, k *fakeSessionKeys) { k.state.Key = &other }, ErrInvalidSignature},
		{"another owner", func(_ *VerifyOpts, k *fakeSessionKeys) {
			k.state.Owner = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
		}, ErrInvalidSignature},
		{"expired", func(o *VerifyOpts, _ *fakeSessionKeys) { o.Height = 1101 }, ErrSessionGrantExpired},
		{"method outside the session set", func(o *VerifyOpts, _ *fakeSessionKeys) { o.SessionAllowed = false }, ErrSessionMethodNotAllowed},
		{"state before expiry", func(o *VerifyOpts, k *fakeSessionKeys) { o.Height = 1101; k.state.Closed = true }, ErrInvalidSignature},
		{"expiry before method", func(o *VerifyOpts, _ *fakeSessionKeys) { o.Height = 1101; o.SessionAllowed = false }, ErrSessionGrantExpired},
		{"state unreadable", func(_ *VerifyOpts, k *fakeSessionKeys) { k.err = registeredkey.ErrChainUnreadable }, ErrInvalidSignature},
		// The read budget is Nexus's own limit, not a verdict on the key: retryable.
		{"lookups over budget", func(_ *VerifyOpts, k *fakeSessionKeys) { k.err = registeredkey.ErrUnavailable }, ErrUnavailable},
		{"height unavailable", func(o *VerifyOpts, _ *fakeSessionKeys) { o.Chain.(*fakeChain).heightE = errors.New("down") }, ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e, opts, keys := registeredSetup(t)
			c.edit(&opts, keys)
			if err := Verify(context.Background(), e, opts); !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, want %v", err, c.want)
			}
		})
	}
}

// A wallet-signed request never looks at the registered key.
func TestWalletRequestDoesNotReadSessionKeys(t *testing.T) {
	f := loadAccountSigning(t)
	v := f.SDKRequest
	keys := &fakeSessionKeys{err: errors.New("must not be called")}
	opts := optsFor(t, f, v, chainFor(t, f))
	opts.SessionKeys = keys
	opts.HeightExpiry = true // the OpenTask vector carries a chain-height expiry
	if err := Verify(context.Background(), envelopeFrom(t, v), opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if keys.calls != 0 {
		t.Fatalf("wallet request read the registered key %d times", keys.calls)
	}
}

// The wire registered_request_cases for SDK requests: state and key before expiry before the
// method set, an absent session and an unreadable chain both as invalid signatures.
func TestRegisteredKeyRequestCasesMatchWire(t *testing.T) {
	f := loadRegistered(t)
	want := map[string]error{
		"ACCEPT": nil, "SDK_AUTH_INVALID_SIGNATURE": ErrInvalidSignature,
		"SDK_AUTH_SESSION_GRANT_EXPIRED": ErrSessionGrantExpired, "SDK_AUTH_SESSION_METHOD_NOT_ALLOWED": ErrSessionMethodNotAllowed,
	}
	rows := 0
	for _, c := range f.RequestCases {
		if c.Base != "registered_sdk_request" {
			continue
		}
		rows++
		t.Run(c.Name, func(t *testing.T) {
			expected, ok := want[c.Expected]
			if !ok {
				t.Fatalf("unknown expected outcome %s", c.Expected)
			}
			_, e, opts, keys := registeredSetup(t)
			recovered := *keys.state.Key
			st := c.State
			opts.Height = st.CurrentHeight
			opts.SessionAllowed = st.MethodAllowed
			keys.state.ExpiryHeight = st.ExpiryHeight
			keys.state.Closed = st.Status == "CLOSED"
			if !st.OwnerMatches {
				keys.state.Owner = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
			}
			if !st.KeyMatches {
				recovered = [20]byte{9}
			}
			if !st.SessionExists {
				keys.state = registeredkey.State{}
			}
			if !st.ChainAvailable {
				keys.err = registeredkey.ErrChainUnreadable
			}
			err := verifyRegisteredKey(context.Background(), e, opts, recovered)
			if (expected == nil) != (err == nil) || expected != nil && !errors.Is(err, expected) {
				t.Fatalf("verifyRegisteredKey = %v, want %s", err, c.Expected)
			}
		})
	}
	if rows != 8 {
		t.Fatalf("%d SDK request cases, want 8", rows)
	}
}
