package ingress

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
// nats_servers and nats_ca_pem are optional (interface list §4.12, ADR-0016 decision one item 1):
// the NATS address and the PEM that verifies the NATS server, so a Cortex needs neither handed to
// it by hand. The response travels over the ingress TLS pinned by the on-chain tls_pubkey_hash,
// which is what makes the certificate trustworthy. Adding optional fields keeps schema_version 1;
// callers ignore unknown fields.
type natsSentinelDocument struct {
	SchemaVersion        int      `json:"schema_version"`
	AuthAccountPublicKey string   `json:"auth_account_public_key"`
	SentinelJWT          string   `json:"sentinel_jwt"`
	NATSServers          []string `json:"nats_servers,omitempty"`
	NATSCAPEM            string   `json:"nats_ca_pem,omitempty"`
}

// WithNATSSentinelFile sets the AUTH account sentinel user JWT file; empty string = route not served.
func WithNATSSentinelFile(path string) Option {
	return func(s *Server) {
		s.natsSentinelFile = strings.TrimSpace(path)
	}
}

// WithNATSAdvertise sets the NATS addresses handed to Cortex with the sentinel (nats.advertise_servers)
// and the certificate file whose certificates go with them (nats.ca_file, the same file nexus
// verifies NATS against). Both are served only when servers is non-empty; an empty caFile omits
// nats_ca_pem (dev only: production requires nats.ca_file).
func WithNATSAdvertise(servers []string, caFile string) Option {
	return func(s *Server) {
		s.natsAdvertiseServers = nil
		for _, server := range servers {
			if trimmed := strings.TrimSpace(server); trimmed != "" {
				s.natsAdvertiseServers = append(s.natsAdvertiseServers, trimmed)
			}
		}
		s.natsAdvertiseCAFile = strings.TrimSpace(caFile)
	}
}

// loadNATSSentinel reads and validates the sentinel file at Start and pre-encodes the JSON returned to Cortex.
// fail-closed: if a file is configured but does not yield a valid bearer user JWT, refuse to start -- a broken sentinel is a
// configuration error, and silently degrading to "route absent" only lets Cortex discover it when connecting to NATS, at far higher troubleshooting cost.
func (s *Server) loadNATSSentinel() error {
	if s.natsSentinelFile == "" {
		if len(s.natsAdvertiseServers) > 0 {
			return fmt.Errorf("nats.advertise_servers is set but nats.sentinel_file is not: the addresses are served only with the sentinel")
		}
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
	document := natsSentinelDocument{
		SchemaVersion:        natsSentinelSchemaVersion,
		AuthAccountPublicKey: account,
		SentinelJWT:          token,
	}
	if len(s.natsAdvertiseServers) > 0 {
		for _, server := range s.natsAdvertiseServers {
			if err := validateNATSAdvertiseServer(server); err != nil {
				return err
			}
		}
		document.NATSServers = s.natsAdvertiseServers
		if s.natsAdvertiseCAFile != "" {
			if document.NATSCAPEM, err = certificatesOnlyPEM(s.natsAdvertiseCAFile); err != nil {
				return err
			}
		}
	}
	body, err := json.Marshal(document)
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

// validateNATSAdvertiseServer accepts tls://host:port or nats://host:port; whether nats:// is
// allowed is the security mode's decision (config.ValidateSecurity).
func validateNATSAdvertiseServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "tls" && u.Scheme != "nats") || u.Host == "" || u.Path != "" || u.User != nil {
		return fmt.Errorf("nats.advertise_servers %q must be tls://host:port", server)
	}
	if host, port, err := net.SplitHostPort(u.Host); err != nil || host == "" || port == "" {
		return fmt.Errorf("nats.advertise_servers %q must be tls://host:port", server)
	}
	return nil
}

// certificatesOnlyPEM reads the file and re-encodes only its CERTIFICATE blocks, each of which must
// parse. Anything else in the file (a private key put there by mistake, for one) is never served.
func certificatesOnlyPEM(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read nats.ca_file %q: %w", path, err)
	}
	var out []byte
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", fmt.Errorf("nats.ca_file %q: certificate does not parse: %w", path, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("nats.ca_file %q holds no certificate", path)
	}
	return string(out), nil
}
