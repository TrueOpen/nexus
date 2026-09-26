package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/kv"
)

type identitySource struct {
	hash    []byte
	hashErr error
	latest  uint64
}

func (s identitySource) BlockHash(context.Context, int64) ([]byte, error) { return s.hash, s.hashErr }
func (s identitySource) Syncing(context.Context) (bool, error)            { return false, nil }
func (s identitySource) LatestHeight(context.Context) (uint64, error)     { return s.latest, nil }

func openState(t *testing.T, dataDir string, src chainreset.Source) (kv.Store, *chainreset.Monitor) {
	t.Helper()
	store, monitor, err := openLocalState(slog.New(slog.NewTextHandler(io.Discard, nil)), dataDir, "trueopen-dev", src)
	if err != nil {
		t.Fatal(err)
	}
	return store, monitor
}

// State of a chain that was since reset is moved aside, and the next start opens an empty kv;
// the TLS directory, whose fingerprint is on chain, stays.
func TestOpenLocalStateMovesAsideStateOfResetChain(t *testing.T) {
	dataDir := t.TempDir()
	tlsDir := filepath.Join(dataDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(taskDataRoot(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}

	store, monitor := openState(t, dataDir, identitySource{hash: []byte{0x0a}})
	if monitor == nil {
		t.Fatal("no monitor after the identity was recorded")
	}
	if err := store.Set(kv.NSTask, "session|task", []byte("old chain task")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Same chain: the task is still there.
	store, _ = openState(t, dataDir, identitySource{hash: []byte{0x0a}})
	if _, ok := store.Get(kv.NSTask, "session|task"); !ok {
		t.Fatal("state of the same chain was dropped")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Reset chain: empty kv, old directories kept beside it, TLS untouched.
	store, monitor = openState(t, dataDir, identitySource{hash: []byte{0x0b}})
	defer store.Close()
	if monitor == nil {
		t.Fatal("no monitor after a reset")
	}
	if _, ok := store.Get(kv.NSTask, "session|task"); ok {
		t.Fatal("a task of the previous chain survived the reset")
	}
	if identity, ok, err := chainreset.Load(store); err != nil || !ok || identity.FirstBlockHash != "0b" {
		t.Fatalf("recorded identity = %+v, %v, %v", identity, ok, err)
	}
	for pattern, want := range map[string]int{"kv.stale-*": 1, "task-data.stale-*": 1, "tls*": 1} {
		matches, err := filepath.Glob(filepath.Join(dataDir, pattern))
		if err != nil || len(matches) != want {
			t.Fatalf("%s: %v, %v", pattern, matches, err)
		}
	}
}

// A start that cannot read the chain's identity keeps watching against the recorded one.
func TestOpenLocalStateUncheckedKeepsRecordedIdentity(t *testing.T) {
	dataDir := t.TempDir()
	store, _ := openState(t, dataDir, identitySource{hash: []byte{0x0a}})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, monitor := openState(t, dataDir, identitySource{hashErr: errors.New("node unreachable")})
	defer store.Close()
	if monitor == nil {
		t.Fatal("no monitor although an identity is recorded")
	}
}

// A chain that cannot tell its identity leaves the state alone and turns the runtime check off.
func TestOpenLocalStateWithoutIdentity(t *testing.T) {
	dataDir := t.TempDir()
	store, monitor := openState(t, dataDir, identitySource{hashErr: errors.New("height 1 is not available")})
	defer store.Close()
	if monitor != nil {
		t.Fatal("monitor without a recorded identity")
	}
	if _, ok, _ := chainreset.Load(store); ok {
		t.Fatal("an identity was recorded without a chain answer")
	}
}
