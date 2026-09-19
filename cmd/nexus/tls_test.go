package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var fingerprintLine = regexp.MustCompile(`(?m)^tls_pubkey_hash: ([0-9a-f]{64})$`)

func configureTLSCommand(t *testing.T, dataDir string) {
	t.Helper()
	t.Setenv("NEXUS_DATA_DIR", dataDir)
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_PUBLIC_ENDPOINT", "https://builder.example:8080")
	t.Setenv("NEXUS_INGRESS_TLS_ENABLED", "")
	t.Setenv("NEXUS_INGRESS_TLS_CERT_FILE", "")
	t.Setenv("NEXUS_INGRESS_TLS_KEY_FILE", "")
}

// The first step of the ADR-0015 registration order: `nexus tls init` creates the self-signed certificate and prints the
// public-key fingerprint, which the operator writes into the descriptor. Running it again reuses the same certificate and the fingerprint stays the same.
func TestTLSInitGeneratesCertificateAndPrintsFingerprint(t *testing.T) {
	dataDir := t.TempDir()
	configureTLSCommand(t, dataDir)

	out, err := executeBuilderCommand("tls", "init")
	if err != nil {
		t.Fatalf("tls init: %v\n%s", err, out)
	}
	match := fingerprintLine.FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("tls init output lacks a tls_pubkey_hash line:\n%s", out)
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		path := filepath.Join(dataDir, "tls", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
		if !strings.Contains(out, path) {
			t.Fatalf("tls init output should name %s:\n%s", path, out)
		}
	}

	again, err := executeBuilderCommand("tls", "init")
	if err != nil {
		t.Fatalf("second tls init: %v", err)
	}
	if got := fingerprintLine.FindStringSubmatch(again); got == nil || got[1] != match[1] {
		t.Fatalf("second tls init changed the fingerprint:\n%s", again)
	}
}

// `nexus tls fingerprint` is read-only: with no certificate it errors and points at init, and with one it prints the same fingerprint.
func TestTLSFingerprintReadsTheExistingCertificate(t *testing.T) {
	dataDir := t.TempDir()
	configureTLSCommand(t, dataDir)

	if out, err := executeBuilderCommand("tls", "fingerprint"); err == nil || !strings.Contains(err.Error(), "nexus tls init") {
		t.Fatalf("tls fingerprint without a certificate = %v, want an error naming `nexus tls init`\n%s", err, out)
	}
	initOut, err := executeBuilderCommand("tls", "init")
	if err != nil {
		t.Fatalf("tls init: %v", err)
	}
	out, err := executeBuilderCommand("tls", "fingerprint")
	if err != nil {
		t.Fatalf("tls fingerprint: %v", err)
	}
	want, got := fingerprintLine.FindStringSubmatch(initOut), fingerprintLine.FindStringSubmatch(out)
	if want == nil || got == nil || want[1] != got[1] {
		t.Fatalf("fingerprint = %v, want the one printed by init %v", got, want)
	}
}
