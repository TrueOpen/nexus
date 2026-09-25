package sdkauth

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/signer"
)

// Test-only private key (same as signer_test; for tests only).
const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func signedEnvelope(t *testing.T, mutate func(*Envelope)) (*Envelope, VerifyOpts) {
	t.Helper()
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	body := BodyDigest([]byte("order-envelope-bytes"))
	env := &Envelope{
		RequestDomain:      RequestDomain,
		ChainID:            "trueopen-localnet",
		Method:             "SubmitOrder",
		Endpoint:           "/nexus.v1.IngressAPI/SubmitOrder",
		SessionID:          "sess-1",
		TaskID:             "task-1",
		RequestNonce:       []byte{1, 2, 3},
		ExpiryHeightOrTime: 4_000_000_000_000, // far-future timestamp
		BodyDigest:         body,
		SignerAddress:      sg.Address(),
		SignerPubKey:       sg.PubKeyCompressed(),
	}
	if mutate != nil {
		mutate(env)
	}
	sig, err := sg.Sign(SignBytes(env))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	return env, VerifyOpts{
		ChainID: "trueopen-localnet", Method: "SubmitOrder",
		NowMS: 1_800_000_000_000, WantBody: body, Bech32Prefix: "trueopen",
	}
}

func TestVerifyOK(t *testing.T) {
	env, opts := signedEnvelope(t, nil)
	if err := Verify(env, opts); err != nil {
		t.Fatalf("expected valid envelope, got %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(env *Envelope, opts *VerifyOpts)
		want   error
	}{
		{"tampered body_digest", func(e *Envelope, o *VerifyOpts) { o.WantBody = BodyDigest([]byte("tampered")) }, ErrMalformed},
		{"expired", func(e *Envelope, o *VerifyOpts) { o.NowMS = 5_000_000_000_000 }, ErrExpired},
		{"cross-chain replay", func(e *Envelope, o *VerifyOpts) { o.ChainID = "other-chain" }, ErrMalformed},
		{"cross-method replay", func(e *Envelope, o *VerifyOpts) { o.Method = "FetchOutputRef" }, ErrMalformed},
		{"missing pubkey", func(e *Envelope, o *VerifyOpts) { e.SignerPubKey = nil }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, opts := signedEnvelope(t, nil)
			tc.mutate(env, &opts)
			if err := Verify(env, opts); err != tc.want {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyRejectsMissingNonce(t *testing.T) {
	env, opts := signedEnvelope(t, func(e *Envelope) { e.RequestNonce = nil })
	if err := Verify(env, opts); err != ErrMalformed {
		t.Fatalf("want ErrMalformed for empty nonce, got %v", err)
	}
}

func TestVerifyRejectsReplayNonce(t *testing.T) {
	cache := NewMemoryReplayCache()
	env, opts := signedEnvelope(t, nil)
	opts.ReplayCache = cache
	if err := Verify(env, opts); err != nil {
		t.Fatalf("first verify should pass: %v", err)
	}
	if err := Verify(env, opts); err != ErrReplay {
		t.Fatalf("want ErrReplay on second verify, got %v", err)
	}

	otherNonce, otherOpts := signedEnvelope(t, func(e *Envelope) { e.RequestNonce = []byte{9, 9, 9} })
	otherOpts.ReplayCache = cache
	if err := Verify(otherNonce, otherOpts); err != nil {
		t.Fatalf("different nonce should pass: %v", err)
	}
}

// Changing a field after signing -> signature invalid.
func TestVerifyRejectsTamperedField(t *testing.T) {
	env, opts := signedEnvelope(t, nil)
	env.TaskID = "task-2" // the signature covers task_id; a post-hoc change must be rejected
	if err := Verify(env, opts); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

// Impersonation: sign with another key but claim the original address -> address check rejects.
func TestVerifyRejectsImpersonation(t *testing.T) {
	other, err := signer.NewFromHex("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d", "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	env, opts := signedEnvelope(t, nil)
	// Re-sign with another key + include its pubkey, but signer_address stays the original.
	env.SignerPubKey = other.PubKeyCompressed()
	sig, _ := other.Sign(SignBytes(env))
	env.Signature = sig
	if err := Verify(env, opts); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

// The generic envelope accepts only a Unix-millisecond expiry; a chain height is rejected unless
// the caller says another check owns it (OpenTask), and then no replay cache may be passed.
func TestVerifyHeightExpiry(t *testing.T) {
	height := func(e *Envelope) { e.ExpiryHeightOrTime = 110 }

	env, opts := signedEnvelope(t, height)
	if err := Verify(env, opts); err != ErrMalformed {
		t.Fatalf("generic path: want ErrMalformed for a height expiry, got %v", err)
	}

	env, opts = signedEnvelope(t, height)
	opts.AllowHeightExpiry = true
	if err := Verify(env, opts); err != nil {
		t.Fatalf("OpenTask path: height expiry should pass, got %v", err)
	}

	env, opts = signedEnvelope(t, height)
	opts.AllowHeightExpiry = true
	opts.ReplayCache = NewMemoryReplayCache()
	if err := Verify(env, opts); err != ErrMisconfigured {
		t.Fatalf("height expiry with a replay cache: want ErrMisconfigured, got %v", err)
	}
}
