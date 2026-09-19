// Package ingresstls prepares TLS material for ingress (implementation design §4.1 transport security).
//
// The Builder does not need a certificate from a CA: on first start a self-signed certificate is
// generated, and the sha256 of its public key is written on-chain as tls_pubkey_hash in the service
// descriptor when the Builder registers (Keeper Interface Contract §9.6b). The SDK and cortex verify
// certificate changes the public key and requires resubmitting the descriptor.
package ingresstls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
)

const (
	dirName  = "tls"
	certName = "cert.pem"
	keyName  = "key.pem"
	// Validity of the self-signed certificate. Clients only check the public key hash, not the validity
	// period; it is long so that tools that validate via the CA chain (curl, browsers) do not suddenly report expiry years later.
	selfSignedValidity = 10 * 365 * 24 * time.Hour
)

// Material is the TLS material shared by the ingress listener and descriptor registration.
type Material struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	// PubKeyHash = hex(sha256(Leaf.RawSubjectPublicKeyInfo)), i.e. the on-chain tls_pubkey_hash.
	PubKeyHash string
}

// Enabled reports whether a usable certificate is held; zero value when TLS is disabled.
func (m Material) Enabled() bool { return m.Leaf != nil }

// LoadOrCreate obtains TLS material per config:
//   - disabled: returns the zero value without touching the filesystem;
//   - cert_file/key_file configured: loads them;
//   - otherwise: reuses <dataDir>/tls/ if present, else generates a self-signed certificate (SAN from hosts).
func LoadOrCreate(cfg config.IngressTLSConfig, dataDir string, hosts []string) (Material, error) {
	if err := cfg.Validate(); err != nil {
		return Material{}, err
	}
	if !cfg.Enabled {
		return Material{}, nil
	}
	certFile, keyFile := strings.TrimSpace(cfg.CertFile), strings.TrimSpace(cfg.KeyFile)
	if certFile != "" {
		return load(certFile, keyFile)
	}
	dir := filepath.Join(dataDir, dirName)
	certFile, keyFile = filepath.Join(dir, certName), filepath.Join(dir, keyName)
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	switch {
	case certErr == nil && keyErr == nil:
		return load(certFile, keyFile)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		if err := generateSelfSigned(dir, certFile, keyFile, hosts); err != nil {
			return Material{}, err
		}
		return load(certFile, keyFile)
	default:
		return Material{}, fmt.Errorf("ingress tls: %s and %s must both exist or both be absent (cert: %v, key: %v)", certFile, keyFile, certErr, keyErr)
	}
}

// Load only loads, never generates: used by `nexus start`. If the certificate is missing it errors and points to
// `nexus tls init` -- a certificate freshly generated at startup has a fingerprint not on-chain, so nobody could connect even with TLS on (ADR-0015 decision 2).
func Load(cfg config.IngressTLSConfig, dataDir string) (Material, error) {
	if err := cfg.Validate(); err != nil {
		return Material{}, err
	}
	if !cfg.Enabled {
		return Material{}, nil
	}
	certFile, keyFile := Paths(cfg, dataDir)
	if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
		return Material{}, fmt.Errorf("ingress tls: certificate %s not found; run `nexus tls init`, register its fingerprint with `nexus builder register`, then start", certFile)
	}
	return load(certFile, keyFile)
}

// Paths returns the certificate and key paths: the configured cert_file/key_file if set, else the default names under <dataDir>/tls/.
func Paths(cfg config.IngressTLSConfig, dataDir string) (certFile, keyFile string) {
	certFile, keyFile = strings.TrimSpace(cfg.CertFile), strings.TrimSpace(cfg.KeyFile)
	if certFile != "" {
		return certFile, keyFile
	}
	dir := filepath.Join(dataDir, dirName)
	return filepath.Join(dir, certName), filepath.Join(dir, keyName)
}

// PubKeyHash computes the sha256 of the certificate public key (over the SubjectPublicKeyInfo DER), lowercase hex.
// Clients use the same algorithm when verifying; see the SDK / cortex implementations.
func PubKeyHash(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// HostsFromEndpoint extracts the hostname from the public endpoint for use as the self-signed certificate SAN.
// Returns nil if unparseable: SAN only affects tools that validate via the CA chain, not public key verification.
func HostsFromEndpoint(endpoint string) []string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return nil
	}
	return []string{host}
}

func load(certFile, keyFile string) (Material, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return Material{}, fmt.Errorf("ingress tls: load %s / %s: %w", certFile, keyFile, err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return Material{}, fmt.Errorf("ingress tls: parse %s: %w", certFile, err)
	}
	certificate.Leaf = leaf
	return Material{Certificate: certificate, Leaf: leaf, PubKeyHash: PubKeyHash(leaf)}, nil
}

func generateSelfSigned(dir, certFile, keyFile string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ingress tls: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("ingress tls: serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "trueopen-nexus"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("ingress tls: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("ingress tls: marshal key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ingress tls: create %s: %w", dir, err)
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return err
	}
	if err := writePEM(certFile, "CERTIFICATE", der); err != nil {
		_ = os.Remove(keyFile)
		return err
	}
	return nil
}

func writePEM(path, blockType string, der []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("ingress tls: write %s: %w", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = file.Close()
		return fmt.Errorf("ingress tls: write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("ingress tls: write %s: %w", path, err)
	}
	return nil
}
