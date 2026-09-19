package ingress

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// NATSSentinelPath is the sentinel distribution route: plain HTTP on the same port, callable directly with curl,
// and it does **not** pass through the api-key / IP allowlist / SDK envelope interceptors -- those hang only on the Connect handler.
// This is deliberate: the sentinel is public, non-secret data (a bearer user JWT of the AUTH account with no permissions);
// whoever holds it cannot connect to anything useful, and the real identity is carried by the binding claim in CONNECT.auth_token.
const NATSSentinelPath = "/v1/nats/sentinel"

// natsSentinelSchemaVersion is the response body schema version; like other external JSON it starts at 1.
const natsSentinelSchemaVersion = 1

// natsSentinelDocument is the response body of GET /v1/nats/sentinel.
// auth_account_public_key lets Cortex verify that this JWT really comes from the AUTH account it expects.
type natsSentinelDocument struct {
	SchemaVersion        int    `json:"schema_version"`
	AuthAccountPublicKey string `json:"auth_account_public_key"`
	SentinelJWT          string `json:"sentinel_jwt"`
}

// WithNATSSentinelFile sets the AUTH account sentinel user JWT file; empty string = route not served.
func WithNATSSentinelFile(path string) Option {
	return func(s *Server) {
		s.natsSentinelFile = strings.TrimSpace(path)
	}
}

// loadNATSSentinel reads and validates the sentinel file at Start and pre-encodes the JSON returned to Cortex.
// fail-closed: if a file is configured but does not yield a valid bearer user JWT, refuse to start -- a broken sentinel is a
// configuration error, and silently degrading to "route absent" only lets Cortex discover it when connecting to NATS, at far higher troubleshooting cost.
func (s *Server) loadNATSSentinel() error {
	if s.natsSentinelFile == "" {
		return nil
	}
	raw, err := os.ReadFile(s.natsSentinelFile)
	if err != nil {
		return fmt.Errorf("read nats sentinel %q: %w", s.natsSentinelFile, err)
	}
	token := strings.TrimSpace(string(raw))
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return fmt.Errorf("nats sentinel %q is not a user jwt: %w", s.natsSentinelFile, err)
	}
	// Must be bearer: a CONNECT via sentinel carries no nkey, and for a non-bearer JWT the server demands a nonce signature and fails.
	if !claims.BearerToken {
		return fmt.Errorf("nats sentinel %q must be a bearer user jwt (nsc add user --bearer)", s.natsSentinelFile)
	}
	// With a signing key the issuer is the signing key and issuer_account is the account; without one the account signs itself
	// and the issuer is the account public key. The account must be obtainable in both cases.
	account := claims.IssuerAccount
	if account == "" {
		account = claims.Issuer
	}
	if !nkeys.IsValidPublicAccountKey(account) {
		return fmt.Errorf("nats sentinel %q: issuer account %q is not a NATS account public key", s.natsSentinelFile, account)
	}
	body, err := json.Marshal(natsSentinelDocument{
		SchemaVersion:        natsSentinelSchemaVersion,
		AuthAccountPublicKey: account,
		SentinelJWT:          token,
	})
	if err != nil {
		return fmt.Errorf("encode nats sentinel document: %w", err)
	}
	s.natsSentinel = body
	return nil
}

// natsSentinelHandler returns 404 when unconfigured (rather than not registering the route): Cortex can thus distinguish
// "Builder provides no sentinel" from "wrong address / hit a different service".
func (s *Server) natsSentinelHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(s.natsSentinel) == 0 {
			// "not configured yet" must not be pinned by intermediate caches: after configuring and restarting, Cortex retries must get the new result.
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"nats sentinel is not configured"}`))
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(s.natsSentinel)
	})
}
