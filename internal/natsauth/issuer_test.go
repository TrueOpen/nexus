package natsauth

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// assertTTL asserts that exp - iat equals the configured ttl. iat is written by jwt/v2 inside Encode from the real clock,
// while exp is computed by this package; the two clock reads can straddle a whole second, so ±1s is tolerated.
func assertTTL(t *testing.T, claims *jwt.UserClaims, ttl time.Duration) {
	t.Helper()
	want := int64(ttl / time.Second)
	if got := claims.Expires - claims.IssuedAt; got < want-1 || got > want+1 {
		t.Fatalf("exp - iat = %d, want %d (±1)", got, want)
	}
}

func mustPublicKey(t *testing.T, kp nkeys.KeyPair) string {
	t.Helper()
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// testIssuer builds a CORTEX issuer that signs with a signing key distinct from the account identity key.
func testIssuer(t *testing.T) (*Issuer, nkeys.KeyPair, nkeys.KeyPair) {
	t.Helper()
	cortexAccount, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cortexSigning, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	authAccount, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(IssuerConfig{
		CortexAccountPublicKey: mustPublicKey(t, cortexAccount),
		CortexSigningKey:       cortexSigning,
		AuthSigningKey:         authAccount,
		JetStreamStream:        "TRUEOPEN_TASK",
		UserJWTTTL:             time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss, cortexSigning, authAccount
}

func TestIssuerSignsUserJWTForCortexAccount(t *testing.T) {
	iss, cortexSigning, _ := testIssuer(t)
	userNkey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub := mustPublicKey(t, userNkey)
	const operator = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	token, err := iss.UserJWT(userPub, Decision{OperatorAddress: operator})
	if err != nil {
		t.Fatal(err)
	}
	// DecodeUserClaims verifies the signature itself: decoding successfully proves it was signed by this signing key.
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	signingPub := mustPublicKey(t, cortexSigning)
	if claims.Subject != userPub || claims.Issuer != signingPub || claims.IssuerAccount != iss.cfg.CortexAccountPublicKey {
		t.Fatalf("subject/issuer wrong: sub=%s iss=%s issuer_account=%s", claims.Subject, claims.Issuer, claims.IssuerAccount)
	}
	if !nkeys.IsValidPublicAccountKey(claims.Issuer) {
		t.Fatalf("issuer %q is not an account nkey", claims.Issuer)
	}
	if claims.Name != "cortex:"+operator {
		t.Fatalf("name = %q", claims.Name)
	}
	if claims.Audience != iss.cfg.CortexAccountPublicKey {
		t.Fatalf("aud = %q", claims.Audience)
	}
	assertTTL(t, claims, time.Hour)
	want := CortexPermissions("TRUEOPEN_TASK")
	if !slices.Equal(claims.Pub.Allow, want.Pub.Allow) || !slices.Equal(claims.Sub.Allow, want.Sub.Allow) {
		t.Fatalf("permissions differ: %+v", claims.Permissions)
	}
	if len(claims.Pub.Deny) != 0 || len(claims.Sub.Deny) != 0 {
		t.Fatalf("permission set must be allow-only: %+v", claims.Permissions)
	}
}

// When the account identity key signs for itself, issuer_account is omitted: setting it would claim to be a signing key, which the verifier rejects.
func TestIssuerOmitsIssuerAccountWhenAccountKeySigns(t *testing.T) {
	cortexAccount, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	authAccount, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cortexPub := mustPublicKey(t, cortexAccount)
	iss, err := NewIssuer(IssuerConfig{
		CortexAccountPublicKey: cortexPub,
		CortexSigningKey:       cortexAccount,
		AuthSigningKey:         authAccount,
		JetStreamStream:        "TRUEOPEN_TASK",
		UserJWTTTL:             time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	userNkey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	token, err := iss.UserJWT(mustPublicKey(t, userNkey), Decision{OperatorAddress: "trueopen1abc"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.IssuerAccount != "" {
		t.Fatalf("issuer_account must stay empty when the account key itself signs, got %q", claims.IssuerAccount)
	}
	if claims.Issuer != cortexPub {
		t.Fatalf("iss = %q, want %q", claims.Issuer, cortexPub)
	}
}

func TestIssuerResponseCarriesJWTOrError(t *testing.T) {
	iss, _, authAccount := testIssuer(t)
	userNkey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal(err)
	}
	userPub, serverPub := mustPublicKey(t, userNkey), mustPublicKey(t, serverKey)

	ok, err := iss.Response(userPub, serverPub, "user.jwt", nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeAuthorizationResponseClaims(ok)
	if err != nil {
		t.Fatal(err)
	}
	authPub := mustPublicKey(t, authAccount)
	if claims.Subject != userPub || claims.Audience != serverPub || claims.Issuer != authPub || claims.Jwt != "user.jwt" || claims.Error != "" {
		t.Fatalf("response = %+v", claims)
	}

	bad, err := iss.Response(userPub, serverPub, "", Reject(CodeChainIDMismatch, "x"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err = jwt.DecodeAuthorizationResponseClaims(bad)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Jwt != "" || claims.Error != "CHAIN_ID_MISMATCH: x" {
		t.Fatalf("error response = %+v", claims)
	}
}

// Any non-RejectError falls back to BINDING_MALFORMED: the closed set of error codes must not be bypassed, and the original text must not leak to the caller.
func TestIssuerResponseFallsBackToClosedSet(t *testing.T) {
	iss, _, _ := testIssuer(t)
	userNkey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal(err)
	}
	token, err := iss.Response(mustPublicKey(t, userNkey), mustPublicKey(t, serverKey), "",
		errors.New("dial tcp 10.0.0.1:26657: connection refused"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeAuthorizationResponseClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Error != string(CodeBindingMalformed)+": "+genericFailureDetail {
		t.Fatalf("error = %q", claims.Error)
	}
	if claims.Jwt != "" {
		t.Fatalf("failed response must not carry a jwt: %+v", claims)
	}
}

// An empty user_nkey cannot be signed on either path: the jwt/v2 constructor returns nil, which must surface as an error rather than a nil-pointer dereference.
func TestIssuerRejectsEmptyUserNkey(t *testing.T) {
	iss, _, _ := testIssuer(t)
	serverKey, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal(err)
	}
	serverPub := mustPublicKey(t, serverKey)
	cases := []struct {
		name string
		call func() (string, error)
	}{
		{"UserJWT", func() (string, error) { return iss.UserJWT("", Decision{OperatorAddress: "trueopen1abc"}) }},
		{"Response success path", func() (string, error) { return iss.Response("", serverPub, "user.jwt", nil) }},
		{"Response failure path", func() (string, error) {
			return iss.Response("", serverPub, "", Reject(CodeChainIDMismatch, "x"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.call()
			if err == nil {
				t.Fatalf("empty user nkey must be refused, got token %q", token)
			}
			if token != "" {
				t.Fatalf("no token may be returned alongside the error, got %q", token)
			}
		})
	}
}

func TestIssuerRejectsMisconfiguration(t *testing.T) {
	acct, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub := mustPublicKey(t, acct)
	userPub := mustPublicKey(t, user)
	cases := []struct {
		name string
		cfg  IssuerConfig
	}{
		{"user key cannot act as the account signing key", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: user, AuthSigningKey: acct, JetStreamStream: "S", UserJWTTTL: time.Hour}},
		{"auth key must likewise be an account nkey", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, AuthSigningKey: user, JetStreamStream: "S", UserJWTTTL: time.Hour}},
		{"account public key must be an account nkey", IssuerConfig{CortexAccountPublicKey: userPub, CortexSigningKey: acct, AuthSigningKey: acct, JetStreamStream: "S", UserJWTTTL: time.Hour}},
		{"stream name must not be empty", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, AuthSigningKey: acct, JetStreamStream: "", UserJWTTTL: time.Hour}},
		{"stream name must not be only whitespace", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, AuthSigningKey: acct, JetStreamStream: "  ", UserJWTTTL: time.Hour}},
		{"ttl must not exceed one hour", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, AuthSigningKey: acct, JetStreamStream: "S", UserJWTTTL: 2 * time.Hour}},
		{"ttl must not be zero", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, AuthSigningKey: acct, JetStreamStream: "S"}},
		{"signing key must not be missing", IssuerConfig{CortexAccountPublicKey: pub, AuthSigningKey: acct, JetStreamStream: "S", UserJWTTTL: time.Hour}},
		{"auth key must not be missing", IssuerConfig{CortexAccountPublicKey: pub, CortexSigningKey: acct, JetStreamStream: "S", UserJWTTTL: time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewIssuer(tc.cfg); err == nil {
				t.Fatal("misconfiguration must be refused at construction")
			}
		})
	}
}

// A public-key-only pair cannot sign and must be refused at construction rather than blowing up at issue time.
func TestIssuerRejectsKeyWithoutSeed(t *testing.T) {
	acct, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	pub := mustPublicKey(t, acct)
	pubOnly, err := nkeys.FromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewIssuer(IssuerConfig{
		CortexAccountPublicKey: pub, CortexSigningKey: pubOnly, AuthSigningKey: acct,
		JetStreamStream: "S", UserJWTTTL: time.Hour,
	}); err == nil {
		t.Fatal("a public-key-only pair cannot sign and must be refused")
	}
}
