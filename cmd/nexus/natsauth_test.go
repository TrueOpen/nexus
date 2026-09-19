package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/nexus/internal/config"
)

func writeSeed(t *testing.T, path string, kp nkeys.KeyPair) {
	t.Helper()
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
}

func configureNATSAuthCommand(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cortexAcct, _ := nkeys.CreateAccount()
	cortexSk, _ := nkeys.CreateAccount()
	authSk, _ := nkeys.CreateAccount()
	cortexPub, _ := cortexAcct.PublicKey()
	writeSeed(t, filepath.Join(dir, "cortex.nk"), cortexSk)
	writeSeed(t, filepath.Join(dir, "auth.nk"), authSk)
	if err := os.WriteFile(filepath.Join(dir, "auth.creds"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_DATA_DIR", dir)
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_CHAIN_ID", "c")
	t.Setenv("NEXUS_CHAIN_GRPC", "https://127.0.0.1:1")
	t.Setenv("NEXUS_NATSAUTH_NATS_SERVERS", "tls://127.0.0.1:1")
	t.Setenv("NEXUS_NATSAUTH_NATS_CREDS_FILE", filepath.Join(dir, "auth.creds"))
	t.Setenv("NEXUS_NATSAUTH_NATS_CA_FILE", filepath.Join(dir, "ca.pem"))
	t.Setenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_PUBLIC_KEY", cortexPub)
	t.Setenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_SIGNING_KEY_FILE", filepath.Join(dir, "cortex.nk"))
	t.Setenv("NEXUS_NATSAUTH_AUTH_ACCOUNT_SIGNING_KEY_FILE", filepath.Join(dir, "auth.nk"))
	// The following are left at their defaults: clear any same-named variables from the outer environment so the test assertions are not polluted by the host.
	for _, key := range []string{
		"NEXUS_NATSAUTH_USER_JWT_TTL_MS",
		"NEXUS_NATSAUTH_CHAIN_QUERY_CACHE_TTL_MS",
		"NEXUS_NATSAUTH_MAX_CLOCK_SKEW_MS",
		"NEXUS_NATSAUTH_XKEY_FILE",
		"NEXUS_NATSAUTH_NATS_USER",
		"NEXUS_NATSAUTH_NATS_PASSWORD",
	} {
		t.Setenv(key, "")
	}
	return dir
}

// seedPublicKey reads back the seed file the fixture wrote and computes its public key, used to assert that check printed this very key.
func seedPublicKey(t *testing.T, path string) string {
	t.Helper()
	seed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// `natsauth check` only loads the keys and config; it does not connect to NATS or query the chain, and is used to verify the keys and config are complete before deployment.
func TestNATSAuthCheckReportsLoadedMaterial(t *testing.T) {
	dir := configureNATSAuthCommand(t)
	out, err := executeBuilderCommand("natsauth", "check")
	if err != nil {
		t.Fatalf("natsauth check: %v\n%s", err, out)
	}
	// Full assertion: every line is what operators check their deployment config against, so a missing or wrong line must be caught.
	want := strings.Join([]string{
		"chain_id: c",
		"chain_grpc: https://127.0.0.1:1",
		"nats_servers: tls://127.0.0.1:1",
		"cortex_account_public_key: " + os.Getenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_PUBLIC_KEY"),
		"cortex_signing_key: " + seedPublicKey(t, filepath.Join(dir, "cortex.nk")),
		"auth_signing_key: " + seedPublicKey(t, filepath.Join(dir, "auth.nk")),
		"user_jwt_ttl_ms: 3600000",
		"chain_query_cache_ttl_ms: 60000",
		"max_clock_skew_ms: 300000",
		"xkey_file: (unset)",
		"auth_subject: $SYS.REQ.USER.AUTH",
		"",
	}, "\n")
	if out != want {
		t.Fatalf("natsauth check output\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// The config layer only validates the length and prefix of cortex_account_public_key; check must validate the checksum too,
// otherwise a public key mistyped by one character is only exposed when start connects to NATS.
func TestNATSAuthCheckRejectsAccountKeyWithBadChecksum(t *testing.T) {
	configureNATSAuthCommand(t)
	// 56 characters starting with A: it passes the config's coarse shape check but is not a valid nkey (it is exactly the placeholder in the example config).
	shapeOnly := "A" + strings.Repeat("B", 55)
	t.Setenv("NEXUS_NATSAUTH_CORTEX_ACCOUNT_PUBLIC_KEY", shapeOnly)
	out, err := executeBuilderCommand("natsauth", "check")
	if err == nil || !strings.Contains(err.Error()+out, "natsauth.cortex_account_public_key") {
		t.Fatalf("expected a refusal naming natsauth.cortex_account_public_key, got err=%v out=%s", err, out)
	}
}

// xkey_file configured while nobody uses it to encrypt responses makes operators believe responses are encrypted: refuse to start, fail-closed.
func TestNATSAuthRejectsUnimplementedXKeyFile(t *testing.T) {
	dir := configureNATSAuthCommand(t)
	t.Setenv("NEXUS_NATSAUTH_XKEY_FILE", filepath.Join(dir, "ca.pem"))
	out, err := executeBuilderCommand("natsauth", "check")
	if err == nil || !strings.Contains(err.Error()+out, "natsauth.xkey_file") {
		t.Fatalf("expected a fail-closed refusal naming natsauth.xkey_file, got err=%v out=%s", err, out)
	}
	if _, buildErr := buildNATSAuthService(config.Load(), slog.New(slog.DiscardHandler), "TRUEOPEN_TASK", func(context.Context) (*nats.Conn, error) {
		t.Fatal("must not connect")
		return nil, nil
	}); buildErr == nil || !strings.Contains(buildErr.Error(), "not implemented yet") {
		t.Fatalf("buildNATSAuthService error = %v, want one saying response encryption is not implemented", buildErr)
	}
}

func TestNATSAuthCheckFailsClosedOnMissingKey(t *testing.T) {
	dir := configureNATSAuthCommand(t)
	if err := os.Remove(filepath.Join(dir, "cortex.nk")); err != nil {
		t.Fatal(err)
	}
	out, err := executeBuilderCommand("natsauth", "check")
	if err == nil || !strings.Contains(err.Error()+out, "cortex_account_signing_key_file") {
		t.Fatalf("expected failure naming the missing key, got err=%v out=%s", err, out)
	}
}

func TestNATSAuthCheckRejectsUserSeedAsSigningKey(t *testing.T) {
	dir := configureNATSAuthCommand(t)
	user, _ := nkeys.CreateUser()
	writeSeed(t, filepath.Join(dir, "cortex.nk"), user)
	out, err := executeBuilderCommand("natsauth", "check")
	if err == nil || !strings.Contains(err.Error()+out, "account nkey") {
		t.Fatalf("expected account-key refusal, got err=%v out=%s", err, out)
	}
}

// The chain identity is a prerequisite of the nine-step verification: missing either chain_id or grpc_addr means the service cannot start and check cannot pass.
func TestNATSAuthRefusesEmptyChainIdentity(t *testing.T) {
	configureNATSAuthCommand(t)
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"empty chain_id", func(c *config.Config) { c.Chain.ChainID = " " }},
		{"empty grpc_addr", func(c *config.Config) { c.Chain.GRPCAddr = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Load()
			tc.mutate(&cfg)
			_, err := loadNATSAuthMaterial(cfg)
			if err == nil || !strings.Contains(err.Error(), "chain.chain_id") {
				t.Fatalf("loadNATSAuthMaterial error = %v, want one naming chain.chain_id", err)
			}
		})
	}
}

// An empty --jetstream-stream must be rejected by the issuer before connecting to NATS: a permission set without a stream name is a permission set without a boundary.
func TestNATSAuthStartRejectsEmptyJetStreamStream(t *testing.T) {
	configureNATSAuthCommand(t)
	out, err := executeBuilderCommand("natsauth", "start", "--jetstream-stream", "")
	if err == nil || !strings.Contains(err.Error()+out, "jetstream stream") {
		t.Fatalf("expected an issuer refusal before connecting, got err=%v out=%s", err, out)
	}
}

// Wiring-layer unit test: start needs a real NATS to run, so the wiring is verified separately and the injected Connect is never called.
func TestBuildNATSAuthServiceWiresMaterialWithoutConnecting(t *testing.T) {
	configureNATSAuthCommand(t)
	cfg := config.Load()
	connected := false
	connect := func(context.Context) (*nats.Conn, error) {
		connected = true
		return nil, nil
	}
	svc, err := buildNATSAuthService(cfg, slog.New(slog.DiscardHandler), "TRUEOPEN_TASK", connect)
	if err != nil {
		t.Fatalf("buildNATSAuthService: %v", err)
	}
	if svc == nil {
		t.Fatal("buildNATSAuthService returned a nil service")
	}
	if connected {
		t.Fatal("buildNATSAuthService must not connect to NATS")
	}
}

func TestBuildNATSAuthServiceFailsOnBadMaterial(t *testing.T) {
	dir := configureNATSAuthCommand(t)
	cfg := config.Load()
	if err := os.WriteFile(filepath.Join(dir, "auth.nk"), []byte("not-a-seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildNATSAuthService(cfg, slog.New(slog.DiscardHandler), "TRUEOPEN_TASK", func(context.Context) (*nats.Conn, error) {
		t.Fatal("must not connect")
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "auth_account_signing_key_file") {
		t.Fatalf("buildNATSAuthService error = %v, want one naming the bad auth key file", err)
	}
}
