package ingress

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/nexus/internal/config"
)

// writeSentinel mints a user JWT signed by the AUTH account and writes it to disk, returning the file path and account public key.
// Whether it is bearer is up to the caller: non-bearer ones must be rejected by Start.
func writeSentinel(t *testing.T, bearer bool) (string, string) {
	t.Helper()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accountPub, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.NewUserClaims(userPub)
	claims.BearerToken = bearer
	claims.Permissions.Pub.Deny.Add(">")
	claims.Permissions.Sub.Deny.Add(">")
	token, err := claims.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nats-sentinel.jwt")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, accountPub
}

func newSentinelServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{}, AuthParams{}, &fakeHandler{}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNATSSentinelNotConfiguredReturns404(t *testing.T) {
	s := newSentinelServer(t)
	if err := s.loadNATSSentinel(); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, NATSSentinelPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"error":"nats sentinel is not configured"}` {
		t.Fatalf("body = %q", got)
	}
	// 404 means "not configured yet"; once configured, Cortex retries must get the new result and must not be pinned by intermediate caches.
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", cc)
	}
}

func TestNATSSentinelServesBearerJWT(t *testing.T) {
	path, accountPub := writeSentinel(t, true)
	s := newSentinelServer(t, WithNATSSentinelFile(path))
	if err := s.loadNATSSentinel(); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, NATSSentinelPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var doc natsSentinelDocument
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || doc.AuthAccountPublicKey != accountPub {
		t.Fatalf("doc = %+v, want account %s", doc, accountPub)
	}
	// The returned value must be the very JWT from the file (trailing newline stripped); Cortex uses it directly as CONNECT.jwt.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SentinelJWT != strings.TrimSpace(string(raw)) {
		t.Fatalf("sentinel_jwt = %q", doc.SentinelJWT)
	}
	// The returned JWT must still decode and really be bearer.
	claims, err := jwt.DecodeUserClaims(doc.SentinelJWT)
	if err != nil || !claims.BearerToken {
		t.Fatalf("served jwt is not a bearer user jwt: %v", err)
	}
}

// Both non-bearer and not-a-JWT-at-all files must make Start fail: fail-closed, no silently skipping the route.
func TestStartRefusesInvalidSentinel(t *testing.T) {
	nonBearer, _ := writeSentinel(t, false)
	badPath := filepath.Join(t.TempDir(), "not-a-jwt.txt")
	if err := os.WriteFile(badPath, []byte("hello sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"non bearer": {nonBearer, "must be a bearer user jwt"},
		"not a jwt":  {badPath, "is not a user jwt"},
		"missing":    {filepath.Join(t.TempDir(), "absent.jwt"), "read nats sentinel"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSentinelServer(t, WithNATSSentinelFile(tc.path))
			err := s.Start(t.Context())
			if err == nil {
				t.Fatal("Start accepted an invalid sentinel")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// writeSentinelSignedBy signs a bearer user JWT with signer and writes it to disk; issuer_account is chosen by the caller.
// Covers the "issued by account signing key" path: issuer is the signing key, the account is in issuer_account.
func writeSentinelSignedBy(t *testing.T, signer nkeys.KeyPair, issuerAccount string) string {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.NewUserClaims(userPub)
	claims.BearerToken = true
	claims.IssuerAccount = issuerAccount
	token, err := claims.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nats-sentinel.jwt")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// nsc by default signs users with the account signing key: issuer is the signing key, not the account; what goes back to Cortex must be issuer_account.
func TestNATSSentinelSignedBySigningKeyReportsIssuerAccount(t *testing.T) {
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accountPub, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signingPub, err := signingKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	path := writeSentinelSignedBy(t, signingKey, accountPub)

	s := newSentinelServer(t, WithNATSSentinelFile(path))
	if err := s.loadNATSSentinel(); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, NATSSentinelPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d body=%q", rr.Code, rr.Body.String())
	}
	var doc natsSentinelDocument
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.AuthAccountPublicKey != accountPub {
		t.Fatalf("auth_account_public_key = %q, want account %q (not signing key %q)", doc.AuthAccountPublicKey, accountPub, signingPub)
	}
}

// issuer_account is not an account public key: the jwt library's Decode will not catch it; this service must catch it itself and refuse to start.
func TestStartRefusesSentinelWithInvalidIssuerAccount(t *testing.T) {
	signingKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	path := writeSentinelSignedBy(t, signingKey, "not-an-account-key")

	s := newSentinelServer(t, WithNATSSentinelFile(path))
	err = s.Start(t.Context())
	if err == nil {
		t.Fatal("Start accepted a sentinel with an invalid issuer_account")
	}
	if !strings.Contains(err.Error(), "is not a NATS account public key") {
		t.Fatalf("err = %v", err)
	}
}
