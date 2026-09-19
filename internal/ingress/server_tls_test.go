package ingress

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/ingresstls"
)

// With a certificate configured, ingress listens with TLS: a client verifying the certificate public key sha256 can reach
// /healthz over HTTPS and negotiates HTTP/2; plaintext requests on the same port are rejected.
func TestStartServesTLSWhenCertificateConfigured(t *testing.T) {
	material, err := ingresstls.LoadOrCreate(config.IngressTLSConfig{Enabled: true}, t.TempDir(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("self-signed material: %v", err)
	}
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{ListenAddr: "127.0.0.1:0"},
		AuthParams{},
		&fakeHandler{},
		WithTLS(material.Certificate),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	addr := s.Addr()

	wantHash := material.PubKeyHash
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				// Self-signed certificate does not use a CA chain; only the on-chain registered public key hash is checked.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("no peer certificate")
					}
					leaf, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
					if got := hex.EncodeToString(sum[:]); got != wantHash {
						return errors.New("pubkey hash mismatch: " + got)
					}
					return nil
				},
			},
		},
	}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("https GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2 over TLS", resp.Proto)
	}

	// Go's TLS listener answers a plaintext request with 400 "client sent an HTTP request to an HTTPS server",
	// rather than returning 200 as h2c would.
	plain := &http.Client{Timeout: 5 * time.Second}
	plainResp, err := plain.Get("http://" + addr + "/healthz")
	if err == nil {
		defer plainResp.Body.Close()
		if plainResp.StatusCode == http.StatusOK {
			t.Fatal("plaintext request must not succeed on a TLS listener")
		}
	}
}

// On a public key hash mismatch the client must reject -- this is the check the SDK / cortex side performs.
func TestTLSClientRejectsUnexpectedPubKeyHash(t *testing.T) {
	material, err := ingresstls.LoadOrCreate(config.IngressTLSConfig{Enabled: true}, t.TempDir(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("self-signed material: %v", err)
	}
	s, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{ListenAddr: "127.0.0.1:0"},
		AuthParams{}, &fakeHandler{}, WithTLS(material.Certificate))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			return errors.New("pubkey hash mismatch")
		},
	}}}
	_, err = client.Get("https://" + s.Addr() + "/healthz")
	if err == nil || !strings.Contains(err.Error(), "pubkey hash mismatch") {
		t.Fatalf("expected pubkey mismatch to abort the connection, got %v", err)
	}
}
