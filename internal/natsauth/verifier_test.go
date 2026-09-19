package natsauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type vectorFile struct {
	PublicKeyCompressed string `json:"public_key_compressed"`
	PrivateKey          string `json:"private_key"`
	NATSUserSeed        string `json:"nats_user_seed"`
	NATSUserPubkey      string `json:"nats_user_pubkey"`
	Cases               []struct {
		Fields struct {
			ChainID                   string `json:"chain_id"`
			OperatorAddress           string `json:"operator_address"`
			ServiceAuthorizationNonce string `json:"service_authorization_nonce"`
			IssuedAtUnixMS            string `json:"issued_at_unix_ms"`
		} `json:"fields"`
		Expected struct {
			Token string `json:"token"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/nats_user_binding_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

// counts reads fakeChain's call counters; fakeChain guards them with a mutex, and this takes the same lock.
func (f *fakeChain) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keyCalls, f.nodeCalls
}

// goodRequest builds a request from wire vector case 0 that should pass all nine steps:
// chain "c", operator trueopen1wltmkp…, nonce 1, issued_at 1; the nonce signature is computed on the fly from the vector's nkey seed.
func goodRequest(t *testing.T) (Request, *fakeChain, vectorFile) {
	t.Helper()
	file := loadVector(t)
	kp, err := nkeys.FromSeed([]byte(file.NATSUserSeed))
	if err != nil {
		t.Fatal(err)
	}
	serverNonce := "server-nonce-1234"
	sig, err := kp.Sign([]byte(serverNonce))
	if err != nil {
		t.Fatal(err)
	}
	c := file.Cases[0]
	chain := &fakeChain{
		keys:  map[string]chaincli.ServiceKeyState{c.Fields.OperatorAddress: vectorServiceKey(file)},
		nodes: map[string]chaincli.CortexNodeState{c.Fields.OperatorAddress: {OperatorAddress: c.Fields.OperatorAddress}},
	}
	return Request{
		UserNkey:    "UXYZ",
		ServerID:    "NSERVER",
		ClientNonce: serverNonce,
		ConnectNkey: file.NATSUserPubkey,
		ConnectSig:  base64.RawURLEncoding.EncodeToString(sig),
		AuthToken:   c.Expected.Token,
	}, chain, file
}

// vectorServiceKey is the on-chain current service key row matching vector case 0: CORTEX, ACTIVE, nonce 1.
func vectorServiceKey(file vectorFile) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: "CORTEX", OperatorAddress: file.Cases[0].Fields.OperatorAddress,
		ServicePubKey: file.PublicKeyCompressed, AuthorizationNonce: 1, Status: "ACTIVE",
	}
}

// newVerifierWith is the verifier construction shared by all cases: chain "c", fixed clock at 1000ms, 5 minute skew.
func newVerifierWith(chain ChainReader) *Verifier {
	return NewVerifier(VerifierConfig{
		ChainID: "c", Chain: chain, MaxClockSkew: 5 * time.Minute,
		Now: func() time.Time { return time.UnixMilli(1000) },
	})
}

func newVerifier(chain ChainQueries) *Verifier {
	return newVerifierWith(NewCachedChain(chain, 0, time.Now))
}

func TestVerifierAcceptsWireVector(t *testing.T) {
	req, chain, file := goodRequest(t)
	decision, err := newVerifier(chain).Verify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.OperatorAddress != file.Cases[0].Fields.OperatorAddress || decision.NATSUserPubkey != file.NATSUserPubkey {
		t.Fatalf("decision = %+v", decision)
	}
}

// Some NATS client libraries send sig as padded standard base64, so both encodings must be accepted.
func TestVerifierAcceptsStdEncodingSignature(t *testing.T) {
	req, chain, _ := goodRequest(t)
	raw, err := base64.RawURLEncoding.DecodeString(req.ConnectSig)
	if err != nil {
		t.Fatal(err)
	}
	req.ConnectSig = base64.StdEncoding.EncodeToString(raw)
	if _, err := newVerifier(chain).Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func assertRejected(t *testing.T, err error, want Code) {
	t.Helper()
	var rej *RejectError
	if !errors.As(err, &rej) {
		t.Fatalf("want RejectError %s, got %v", want, err)
	}
	if rej.Code != want {
		t.Fatalf("want %s, got %s (%s)", want, rej.Code, rej.Detail)
	}
}

func TestVerifierStepOrderAndCodes(t *testing.T) {
	t.Run("1 malformed token", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		req.AuthToken = "trueopen-nub1.!!!"
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeBindingMalformed)
	})
	t.Run("2 chain id", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		v := NewVerifier(VerifierConfig{ChainID: "other", Chain: NewCachedChain(chain, 0, time.Now), MaxClockSkew: time.Minute, Now: func() time.Time { return time.UnixMilli(1000) }})
		_, err := v.Verify(context.Background(), req)
		assertRejected(t, err, CodeChainIDMismatch)
	})
	t.Run("4 nkey differs from binding", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		// Use a second genuine user nkey: both public keys are valid but unequal, which is what NKEY_MISMATCH is for.
		other, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		if req.ConnectNkey, err = other.PublicKey(); err != nil {
			t.Fatal(err)
		}
		_, err = newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeNkeyMismatch)
	})
	t.Run("4 empty nkey is accepted (sentinel connect)", func(t *testing.T) {
		// operator mode: Cortex presents sentinel JWT + sig + auth_token with no nkey.
		// Identity is carried by nats_user_pubkey in the binding declaration, and the nonce signature must still verify.
		req, chain, file := goodRequest(t)
		req.ConnectNkey = ""
		req.ConnectJWT = "eyJ0eXAiOiJKV1QifQ.sentinel.sig"
		decision, err := newVerifier(chain).Verify(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if decision.NATSUserPubkey != file.NATSUserPubkey {
			t.Fatalf("decision = %+v", decision)
		}
	})
	t.Run("5 empty nkey with signature by another key", func(t *testing.T) {
		// A missing nkey must not turn into "anyone may connect": sig must be signed by the private key in the binding.
		req, chain, _ := goodRequest(t)
		other, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := other.Sign([]byte(req.ClientNonce))
		if err != nil {
			t.Fatal(err)
		}
		req.ConnectNkey = ""
		req.ConnectSig = base64.RawURLEncoding.EncodeToString(sig)
		_, err = newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeNonceSignatureInvalid)
	})
	t.Run("5 nonce signature", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		req.ClientNonce = "different-nonce"
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeNonceSignatureInvalid)
	})
	t.Run("5 nonce signature not base64", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		req.ConnectSig = "***"
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeNonceSignatureInvalid)
	})
	t.Run("6 issued in the future", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		v := NewVerifier(VerifierConfig{ChainID: "c", Chain: NewCachedChain(chain, 0, time.Now), MaxClockSkew: 0, Now: func() time.Time { return time.UnixMilli(0) }})
		_, err := v.Verify(context.Background(), req)
		assertRejected(t, err, CodeBindingMalformed)
	})
	t.Run("7 key not found", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		chain.keys = nil
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeServiceKeyNotActive)
	})
	t.Run("7 key revoked", func(t *testing.T) {
		req, chain, file := goodRequest(t)
		op := file.Cases[0].Fields.OperatorAddress
		state := chain.keys[op]
		state.Status = "REVOKED"
		chain.keys[op] = state
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeServiceKeyNotActive)
	})
	t.Run("7 nonce rotated", func(t *testing.T) {
		req, chain, file := goodRequest(t)
		op := file.Cases[0].Fields.OperatorAddress
		state := chain.keys[op]
		state.AuthorizationNonce = 2
		chain.keys[op] = state
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeServiceKeyNonceMismatch)
	})
	t.Run("7 chain down", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		chain.err = errors.New("connection refused")
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeChainUnavailable)
	})
	t.Run("8 wrong service key on chain", func(t *testing.T) {
		req, chain, file := goodRequest(t)
		op := file.Cases[0].Fields.OperatorAddress
		state := chain.keys[op]
		state.ServicePubKey = "02" + hex.EncodeToString(make([]byte, 32))
		chain.keys[op] = state
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeBindingSignatureInvalid)
	})
	t.Run("8 valid but different service key", func(t *testing.T) {
		req, chain, file := goodRequest(t)
		op := file.Cases[0].Fields.OperatorAddress
		var priv [32]byte
		priv[31] = 2
		other := secp256k1.PrivKeyFromBytes(priv[:]).PubKey().SerializeCompressed()
		state := chain.keys[op]
		state.ServicePubKey = hex.EncodeToString(other)
		chain.keys[op] = state
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeBindingSignatureInvalid)
	})
	t.Run("9 cortex row missing", func(t *testing.T) {
		req, chain, _ := goodRequest(t)
		chain.nodes = nil
		_, err := newVerifier(chain).Verify(context.Background(), req)
		assertRejected(t, err, CodeCortexNotRegistered)
	})
}

// Steps 1-6 are purely local checks; a failure there must not issue a single chain query.
func TestVerifierMakesNoChainCallBeforeStepSeven(t *testing.T) {
	req, chain, _ := goodRequest(t)
	req.ClientNonce = "different-nonce"
	_, err := newVerifier(chain).Verify(context.Background(), req)
	assertRejected(t, err, CodeNonceSignatureInvalid)
	if keyCalls, nodeCalls := chain.counts(); keyCalls != 0 || nodeCalls != 0 {
		t.Fatalf("local rejection must not query the chain: keyCalls=%d nodeCalls=%d", keyCalls, nodeCalls)
	}
}

func TestVerifierRefusesBuilderParticipantBeforeChainLookup(t *testing.T) {
	// A binding declaration whose participant_type is not CORTEX is rejected by bus.DecodeBinding as BINDING_MALFORMED,
	// and must not trigger any chain query.
	req, chain, _ := goodRequest(t)
	raw, err := bus.DecodeBindingToken(req.AuthToken)
	if err != nil {
		t.Fatal(err)
	}
	// field 3 varint 1 -> 2: bytes 0x18 0x01 -> 0x18 0x02
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == 0x18 && raw[i+1] == 0x01 {
			raw[i+1] = 0x02
			break
		}
	}
	req.AuthToken = bus.EncodeBindingToken(raw)
	_, err = newVerifier(chain).Verify(context.Background(), req)
	assertRejected(t, err, CodeBindingMalformed)
	if keyCalls, nodeCalls := chain.counts(); keyCalls != 0 || nodeCalls != 0 {
		t.Fatal("malformed binding must be refused before any chain query")
	}
}

// signedToken re-signs the modified projection with the vector's private key, producing a token that passes steps 1-5 cleanly,
// so that the step 6 boundary is the step actually under test.
func signedToken(t *testing.T, file vectorFile, fields bus.BindingFields) string {
	t.Helper()
	privBytes, err := hex.DecodeString(file.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bus.BindingSigningDigest(fields)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := bus.EncodeBinding(fields, bus.SignDigest(secp256k1.PrivKeyFromBytes(privBytes), digest))
	if err != nil {
		t.Fatal(err)
	}
	return bus.EncodeBindingToken(encoded)
}

// issued_at_unix_ms is a uint64: values >= 2^63 wrap to negative when converted to int64, which must not let them bypass step 6.
func TestVerifierRejectsIssuedAtOverflow(t *testing.T) {
	cases := []struct {
		name     string
		issuedAt uint64
	}{
		{name: "just past int64 max", issuedAt: 1<<63 + 5},
		{name: "uint64 max", issuedAt: ^uint64(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, chain, file := goodRequest(t)
			fields := bus.BindingFields{
				SchemaVersion:             1,
				ChainID:                   "c",
				ParticipantType:           bus.ParticipantCortex,
				OperatorAddress:           file.Cases[0].Fields.OperatorAddress,
				ServiceAuthorizationNonce: 1,
				NATSUserPubkey:            file.NATSUserPubkey,
				IssuedAtUnixMS:            tc.issuedAt,
			}
			req.AuthToken = signedToken(t, file, fields)
			_, err := newVerifier(chain).Verify(context.Background(), req)
			assertRejected(t, err, CodeBindingMalformed)
			if keyCalls, nodeCalls := chain.counts(); keyCalls != 0 || nodeCalls != 0 {
				t.Fatalf("step 6 rejection must not query the chain: keyCalls=%d nodeCalls=%d", keyCalls, nodeCalls)
			}
		})
	}
}

// rawErrorChain is a ChainReader that bypasses CachedChain: it returns bare errors directly,
// and the verifier must wrap them into CHAIN_UNAVAILABLE itself rather than letting a bare error escape.
type rawErrorChain struct {
	key     chaincli.ServiceKeyState
	keyErr  error
	nodeErr error
}

func (r rawErrorChain) CurrentServiceKey(context.Context, string) (chaincli.ServiceKeyState, error) {
	return r.key, r.keyErr
}

func (r rawErrorChain) CortexNode(context.Context, string) (chaincli.CortexNodeState, error) {
	return chaincli.CortexNodeState{}, r.nodeErr
}

func TestVerifierWrapsRawChainErrors(t *testing.T) {
	base, _, file := goodRequest(t)

	t.Run("step 7", func(t *testing.T) {
		v := newVerifierWith(rawErrorChain{keyErr: errors.New("dial tcp: connection refused")})
		_, err := v.Verify(context.Background(), base)
		assertRejected(t, err, CodeChainUnavailable)
	})
	t.Run("step 9", func(t *testing.T) {
		v := newVerifierWith(rawErrorChain{key: vectorServiceKey(file), nodeErr: errors.New("dial tcp: connection refused")})
		_, err := v.Verify(context.Background(), base)
		assertRejected(t, err, CodeChainUnavailable)
	})
}
