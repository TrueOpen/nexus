package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/ingresstls"
)

// The full ADR-0015 registration order: tls init -> builder register (the descriptor carries the fingerprint) -> start with TLS enabled.
// start only checks: it comes up only when the on-chain fingerprint matches the local certificate, and the ingress really presents that certificate over TLS.
func TestTLSInitRegisterThenStartServesThePinnedCertificate(t *testing.T) {
	taskNode, hubNode, taskGRPC, hubGRPC, stop := startBuilderCommandNodes(t)
	defer stop()
	dataDir := t.TempDir()
	configureBuilderCommand(t, dataDir, taskGRPC, hubGRPC)
	addr := freeLoopbackAddr(t)
	t.Setenv("NEXUS_INGRESS_ADDR", addr)
	t.Setenv("NEXUS_INGRESS_TLS_ENABLED", "true")

	// start without init: the certificate does not exist, so it refuses, points at tls init and broadcasts nothing.
	if err := runStartUntilExit(t, 2*time.Second); err == nil || !strings.Contains(err.Error(), "nexus tls init") {
		t.Fatalf("start without a certificate = %v, want a refusal naming `nexus tls init`", err)
	}
	if hubNode.broadcasts.Load() != 0 {
		t.Fatalf("broadcasts = %d, want 0", hubNode.broadcasts.Load())
	}

	initOut, err := executeBuilderCommand("tls", "init")
	if err != nil {
		t.Fatalf("tls init: %v", err)
	}
	pin := fingerprintLine.FindStringSubmatch(initOut)
	if pin == nil {
		t.Fatalf("tls init printed no fingerprint:\n%s", initOut)
	}

	// Initialized but the fingerprint is not on chain yet: start still refuses, and says clearly that tls_pubkey_hash does not match.
	if err := runStartUntilExit(t, 2*time.Second); err == nil || !strings.Contains(err.Error(), "nexus builder register") {
		t.Fatalf("start before registering the fingerprint = %v, want a refusal naming `nexus builder register`", err)
	}

	registerOut, err := executeBuilderCommand("builder", "register")
	if err != nil {
		t.Fatalf("builder register: %v", err)
	}
	if !strings.Contains(registerOut, "tls_pubkey_hash: "+pin[1]) {
		t.Fatalf("builder register should print the fingerprint it registered:\n%s", registerOut)
	}
	hubNode.mu.Lock()
	descriptor := hubNode.descriptor
	hubNode.mu.Unlock()
	if descriptor == nil {
		t.Fatal("Hub received no descriptor")
	}
	for _, endpoint := range descriptor.GetEndpoints() {
		if got := endpoint.GetTlsPubkeyHash(); len(got) != 32 {
			t.Fatalf("endpoint %s registered without tls_pubkey_hash", endpoint.GetUri())
		}
	}
	if taskNode.broadcasts.Load() != 0 {
		t.Fatalf("Task Chain broadcasts = %d, want 0", taskNode.broadcasts.Load())
	}

	// With the fingerprint on chain: start passes the check and the ingress presents that same certificate over TLS.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newRootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"start"})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	material, err := ingresstls.Load(config.IngressTLSConfig{Enabled: true}, dataDir)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	conn := dialTLSUntilUp(t, done, addr, 3*time.Second)
	served := ingresstls.PubKeyHash(conn.ConnectionState().PeerCertificates[0])
	_ = conn.Close()
	if served != material.PubKeyHash || served != pin[1] {
		t.Fatalf("ingress served fingerprint %s, want the registered %s", served, pin[1])
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz over TLS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	if got := hubNode.broadcastTypeURLs(); len(got) != 1 || got[0] != chaincli.TypeURLMsgRegisterBuilder {
		t.Fatalf("Hub broadcasts after start = %v, want only the one MsgRegisterBuilder from register", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("start did not stop after command context cancellation")
	}
}

// freeLoopbackAddr borrows a free loopback port: start needs something to listen on for TLS and the test needs to know where to connect.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// dialTLSUntilUp keeps dialing TLS until the ingress is up; it fails if start exits early.
func dialTLSUntilUp(t *testing.T, done <-chan error, addr string, timeout time.Duration) *tls.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("start exited before serving TLS: %v", err)
		default:
		}
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate, the check goes through the fingerprint
		if err == nil {
			return conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ingress did not serve TLS on %s within %s", addr, timeout)
	return nil
}

// runStartUntilExit runs `nexus start` and waits for it to exit on its own; a timeout is taken to mean it successfully became resident.
func runStartUntilExit(t *testing.T, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newRootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"start"})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		cancel()
		<-done
		t.Fatal("start kept running, want it to refuse")
		return nil
	}
}
