package main

import (
	"context"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/drain"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/ops"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

func configureOpsCommand(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("NEXUS_DATA_DIR", dataDir)
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	return dataDir
}

// runDaemonTicks stands in for the running daemon: its monitor ticks until the test ends.
func runDaemonTicks(t *testing.T, dataDir string) *drain.Controller {
	t.Helper()
	d, err := drain.New(drain.Config{
		Store: kv.NewMemStore(), LocalPubKey: "02aa",
		Key: func(context.Context) (chaincli.ServiceKeyState, error) {
			return chaincli.ServiceKeyState{ServicePubKey: "02aa", AuthorizationNonce: 3}, nil
		},
		Sources: drain.Sources{
			InFlight:  func() (int, *big.Int) { return 1, big.NewInt(25) },
			Records:   func() int { return 0 },
			Takeovers: func() int { return 0 },
			Sync:      func() []drain.SyncPending { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := ops.New(ops.Config{DataDir: dataDir, Drain: d, Metrics: opsmetrics.New(), Interval: 20 * time.Millisecond})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return d
}

// Without a running daemon the request stays in the data directory for its next start.
func TestDrainBeginWithoutADaemonLeavesTheRequest(t *testing.T) {
	dataDir := configureOpsCommand(t)
	out, err := executeBuilderCommand("drain", "begin", "--wait", "0s")
	if err != nil {
		t.Fatalf("drain begin: %v\n%s", err, out)
	}
	if !strings.Contains(out, "has not taken it yet") {
		t.Fatalf("output = %s", out)
	}
	raw, err := os.ReadFile(ops.DrainRequestPath(dataDir))
	if err != nil || strings.TrimSpace(string(raw)) != ops.DrainBegin {
		t.Fatalf("request file = %q, %v", raw, err)
	}
	if out, err := executeBuilderCommand("drain", "status"); err == nil || !strings.Contains(err.Error(), "no status file yet") {
		t.Fatalf("drain status without a daemon = %v\n%s", err, out)
	}
}

// With the daemon running, drain begin waits for it and prints where the drain stands; drain
// status and status read the daemon's status file; drain end ends the drain.
func TestDrainCommandsDriveTheRunningDaemon(t *testing.T) {
	dataDir := configureOpsCommand(t)
	d := runDaemonTicks(t, dataDir)
	out, err := executeBuilderCommand("drain", "begin", "--wait", "5s")
	if err != nil {
		t.Fatalf("drain begin: %v\n%s", err, out)
	}
	if !d.Draining() || !strings.Contains(out, `"phase": "DRAINING"`) || !strings.Contains(out, `"in_flight_orders": 1`) {
		t.Fatalf("drain begin output = %s", out)
	}
	if out, err := executeBuilderCommand("drain", "status"); err != nil || !strings.Contains(out, `"in_flight_max_fee": "25"`) {
		t.Fatalf("drain status = %v\n%s", err, out)
	}
	if out, err := executeBuilderCommand("status"); err != nil || !strings.Contains(out, `"readiness"`) || !strings.Contains(out, `"metrics"`) {
		t.Fatalf("status = %v\n%s", err, out)
	}
	out, err = executeBuilderCommand("drain", "end", "--wait", "5s")
	if err != nil || d.Draining() || !strings.Contains(out, `"phase": "SERVING"`) {
		t.Fatalf("drain end = %v (draining %t)\n%s", err, d.Draining(), out)
	}
}
