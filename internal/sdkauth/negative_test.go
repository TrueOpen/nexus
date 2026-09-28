package sdkauth

import (
	"context"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Private keys from wire account_signing_v1.json: the account, the session key and wrong_key.
const (
	accountKeyHex = "0101010101010101010101010101010101010101010101010101010101010101"
	sessionKeyHex = "0303030303030303030303030303030303030303030303030303030303030303"
)

// sign65 signs digest as a wallet does: 65 bytes R||S||V with V in {27, 28}.
func sign65(t *testing.T, keyHex string, digest [32]byte) []byte {
	t.Helper()
	key := secp256k1.PrivKeyFromBytes(mustHex(t, keyHex))
	compact := ecdsa.SignCompact(key, digest[:], false) // [V R S], V = 27 + recovery id
	return append(append([]byte{}, compact[1:]...), compact[0])
}

func wrongKeyHex(t *testing.T) string {
	t.Helper()
	return "0202020202020202020202020202020202020202020202020202020202020202"
}

// resign signs e (with this grant hash and body) by keyHex under the vector's EVM chain ID.
func resign(t *testing.T, e *Envelope, body, grantHash [32]byte, evm uint64, keyHex string) {
	t.Helper()
	digest, err := RequestDigest(e, body, grantHash, evm)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = sign65(t, keyHex, digest)
}

// Each row changes one thing about a valid request and must fail with the wire error code, in the
// wire verification order.
func TestVerifyRejectsWithWireErrorCodes(t *testing.T) {
	f := loadAccountSigning(t)
	evm := mustUint(t, f.SDKRequest.Domain.ChainID)
	wallet := func() (*Envelope, VerifyOpts) {
		e := envelopeFrom(t, f.SDKRequest)
		opts := optsFor(t, f, f.SDKRequest, chainFor(t, f))
		opts.AllowHeightExpiry = true
		return e, opts
	}
	session := func() (*Envelope, VerifyOpts) {
		e := envelopeFrom(t, f.SDKRequestSession)
		e.SessionGrant = grantFrom(t, f)
		opts := optsFor(t, f, f.SDKRequestSession, chainFor(t, f))
		opts.SessionAllowed = true
		return e, opts
	}
	grantHash := func(e *Envelope) [32]byte {
		h, err := SessionGrantHash(e.SessionGrant)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	tests := []struct {
		name  string
		build func() (*Envelope, VerifyOpts)
		want  error
	}{
		{"verifier on another chain", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			o.ChainID = "trueopen-golden-2"
			return e, o
		}, ErrInvalidSignature},
		{"verifier with another EVM chain ID", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			o.EVMChainID = 424243
			return e, o
		}, ErrInvalidSignature},
		{"signed by wrong key", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			resign(t, e, o.Body, [32]byte{}, evm, wrongKeyHex(t))
			return e, o
		}, ErrInvalidSignature},
		{"session request signed by wrong key", func() (*Envelope, VerifyOpts) {
			e, o := session()
			resign(t, e, o.Body, grantHash(e), evm, wrongKeyHex(t))
			return e, o
		}, ErrInvalidSignature},
		{"grant signed by wrong key", func() (*Envelope, VerifyOpts) {
			e, o := session()
			d, _ := SessionGrantDigest(e.SessionGrant, evm)
			e.SessionGrant.UserSignature = sign65(t, wrongKeyHex(t), d)
			return e, o
		}, ErrSessionGrantInvalid},
		{"session key signs a zero grant hash", func() (*Envelope, VerifyOpts) {
			e, o := session()
			resign(t, e, o.Body, [32]byte{}, evm, sessionKeyHex)
			return e, o
		}, ErrInvalidSignature},
		{"wallet signs a grant hash without a grant", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			resign(t, e, o.Body, grantHash(&Envelope{SessionGrant: grantFrom(t, f)}), evm, accountKeyHex)
			return e, o
		}, ErrInvalidSignature},
		{"body changed in transit", func() (*Envelope, VerifyOpts) {
			e, o := session()
			o.Body[31] ^= 1
			return e, o
		}, ErrInvalidSignature},
		{"grant expired", func() (*Envelope, VerifyOpts) {
			e, o := session()
			o.Chain.(*fakeChain).height = 1501
			return e, o
		}, ErrSessionGrantExpired},
		{"grant beyond window", func() (*Envelope, VerifyOpts) {
			e, o := session()
			o.Chain.(*fakeChain).height = 1099
			return e, o
		}, ErrSessionGrantExpired},
		{"grant for another chain", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.SessionGrant.ChainID = "trueopen-golden-2"
			d, _ := SessionGrantDigest(e.SessionGrant, evm)
			e.SessionGrant.UserSignature = sign65(t, accountKeyHex, d)
			return e, o
		}, ErrSessionGrantInvalid},
		{"OpenTask with a session grant", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			e.SessionGrant = grantFrom(t, f)
			resign(t, e, o.Body, grantHash(e), evm, sessionKeyHex)
			return e, o
		}, ErrSessionMethodNotAllowed},
		{"expiry zero", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			e.ExpiryHeightOrTime = 0
			return e, o
		}, ErrMalformed},
		{"expiry negative", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			e.ExpiryHeightOrTime = -1
			return e, o
		}, ErrMalformed},
		{"method and endpoint disagree", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.Endpoint = EndpointPrefix + "AckOutput"
			return e, o
		}, ErrMalformed},
		{"uppercase session_id", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.SessionID = "77625100BA4FAA1306AE6EAF5A872A661443AA94F87C5530C4B178614E3D62F7"
			return e, o
		}, ErrMalformed},
		{"0x task_id", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.TaskID = "0x" + e.TaskID[2:]
			return e, o
		}, ErrMalformed},
		{"16-byte nonce", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.RequestNonce = e.RequestNonce[:16]
			return e, o
		}, ErrMalformed},
		{"height expiry outside OpenTask", func() (*Envelope, VerifyOpts) {
			e, o := session()
			e.ExpiryHeightOrTime = 1010
			return e, o
		}, ErrMalformed},
		{"account holds another key", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			o.Chain.(*fakeChain).keys[e.SignerAddress] = mustHex(t, "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337")
			return e, o
		}, ErrInvalidSignature},
		{"account without a key", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			delete(o.Chain.(*fakeChain).keys, e.SignerAddress)
			return e, o
		}, ErrInvalidSignature},
		{"account key unreadable", func() (*Envelope, VerifyOpts) {
			e, o := wallet()
			o.Chain.(*fakeChain).keyErr = errors.New("node down")
			return e, o
		}, ErrUnavailable},
		{"grant user without a key", func() (*Envelope, VerifyOpts) {
			e, o := session()
			delete(o.Chain.(*fakeChain).keys, e.SignerAddress)
			return e, o
		}, ErrSessionGrantInvalid},
		{"request expired", func() (*Envelope, VerifyOpts) {
			e, o := session()
			o.NowMS = e.ExpiryHeightOrTime + 1
			return e, o
		}, ErrExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, opts := tt.build()
			if err := Verify(context.Background(), e, opts); !errors.Is(err, tt.want) {
				t.Fatalf("Verify = %v, want %v", err, tt.want)
			}
		})
	}
}

// Both grant window bounds are inclusive.
func TestSessionGrantWindowEdgesAccept(t *testing.T) {
	f := loadAccountSigning(t)
	for _, height := range []uint64{1100, 1500} {
		e := envelopeFrom(t, f.SDKRequestSession)
		e.SessionGrant = grantFrom(t, f)
		opts := optsFor(t, f, f.SDKRequestSession, chainFor(t, f))
		opts.SessionAllowed = true
		opts.Chain.(*fakeChain).height = height
		if err := Verify(context.Background(), e, opts); err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
	}
}
