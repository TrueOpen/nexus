package ingress

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

// writeNATSCert writes a self-signed certificate PEM, optionally followed by its private key, and
// returns the path and the certificate's DER.
func writeNATSCert(t *testing.T, withKey bool) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-nats"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("203.0.113.10")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if withKey {
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		body = append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), body...)
	}
	path := filepath.Join(t.TempDir(), "nats-cert.pem")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, der
}

func sentinelBody(t *testing.T, s *Server) []byte {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, NATSSentinelPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d body=%q", rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

// With advertise_servers the response carries the NATS address and only the certificate blocks of
// ca_file: a private key in the same file is never served.
func TestNATSSentinelServesAdvertisedServersAndCertificate(t *testing.T) {
	sentinel, _ := writeSentinel(t, true)
	caFile, der := writeNATSCert(t, true)
	s := newSentinelServer(t, WithNATSSentinelFile(sentinel),
		WithNATSAdvertise([]string{" tls://203.0.113.10:4222 ", ""}, caFile))
	if err := s.loadNATSSentinel(); err != nil {
		t.Fatal(err)
	}
	body := sentinelBody(t, s)
	var doc natsSentinelDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || len(doc.NATSServers) != 1 || doc.NATSServers[0] != "tls://203.0.113.10:4222" {
		t.Fatalf("doc = %+v", doc)
	}
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("a private key from ca_file was served")
	}
	block, rest := pem.Decode([]byte(doc.NATSCAPEM))
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, der) || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("nats_ca_pem = %q, want exactly the certificate", doc.NATSCAPEM)
	}
}

// Without advertise_servers the response is exactly what it was before: three fields, even when
// ca_file is set. Without ca_file (dev) nats_ca_pem is omitted.
func TestNATSSentinelAdvertiseIsOptIn(t *testing.T) {
	sentinel, _ := writeSentinel(t, true)
	caFile, _ := writeNATSCert(t, false)
	for name, c := range map[string]struct {
		opts []Option
		want []string
	}{
		"not configured":      {[]Option{WithNATSAdvertise(nil, caFile)}, []string{"auth_account_public_key", "schema_version", "sentinel_jwt"}},
		"no ca_file (dev)":    {[]Option{WithNATSAdvertise([]string{"nats://127.0.0.1:4222"}, "")}, []string{"auth_account_public_key", "nats_servers", "schema_version", "sentinel_jwt"}},
		"servers and ca_file": {[]Option{WithNATSAdvertise([]string{"tls://203.0.113.10:4222"}, caFile)}, []string{"auth_account_public_key", "nats_ca_pem", "nats_servers", "schema_version", "sentinel_jwt"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSentinelServer(t, append([]Option{WithNATSSentinelFile(sentinel)}, c.opts...)...)
			if err := s.loadNATSSentinel(); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(sentinelBody(t, s), &fields); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(fields))
			for key := range fields {
				got = append(got, key)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("fields = %v, want %v", got, c.want)
			}
		})
	}
}

// Misconfiguration fails closed at Start rather than serving something Cortex cannot use.
func TestStartRefusesInvalidNATSAdvertise(t *testing.T) {
	sentinel, _ := writeSentinel(t, true)
	caFile, _ := writeNATSCert(t, false)
	noCert := filepath.Join(t.TempDir(), "key-only.pem")
	keyOnly, _ := writeNATSCert(t, true)
	raw, _ := os.ReadFile(keyOnly)
	keyBlock, _ := pem.Decode(raw)
	if err := os.WriteFile(noCert, pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	badCert := filepath.Join(t.TempDir(), "bad-cert.pem")
	if err := os.WriteFile(badCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		opts []Option
		want string
	}{
		"servers without sentinel": {[]Option{WithNATSAdvertise([]string{"tls://203.0.113.10:4222"}, caFile)}, "nats.sentinel_file is not"},
		"no port":                  {[]Option{WithNATSSentinelFile(sentinel), WithNATSAdvertise([]string{"tls://203.0.113.10"}, caFile)}, "must be tls://host:port"},
		"other scheme":             {[]Option{WithNATSSentinelFile(sentinel), WithNATSAdvertise([]string{"https://203.0.113.10:4222"}, caFile)}, "must be tls://host:port"},
		"ca_file without cert":     {[]Option{WithNATSSentinelFile(sentinel), WithNATSAdvertise([]string{"tls://203.0.113.10:4222"}, noCert)}, "holds no certificate"},
		"ca_file bad cert":         {[]Option{WithNATSSentinelFile(sentinel), WithNATSAdvertise([]string{"tls://203.0.113.10:4222"}, badCert)}, "does not parse"},
		"ca_file missing":          {[]Option{WithNATSSentinelFile(sentinel), WithNATSAdvertise([]string{"tls://203.0.113.10:4222"}, filepath.Join(t.TempDir(), "absent.pem"))}, "read nats.ca_file"},
	} {
		t.Run(name, func(t *testing.T) {
			err := newSentinelServer(t, c.opts...).loadNATSSentinel()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
