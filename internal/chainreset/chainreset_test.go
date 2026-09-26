package chainreset

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

type fakeSource struct {
	mu        sync.Mutex
	hash      []byte
	hashErr   error
	syncing   bool
	syncErr   error
	latest    uint64
	hashCalls int
}

func (f *fakeSource) BlockHash(_ context.Context, height int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashCalls++
	if height != identityHeight {
		return nil, errors.New("unexpected height")
	}
	return f.hash, f.hashErr
}

func (f *fakeSource) Syncing(context.Context) (bool, error) { return f.syncing, f.syncErr }

func (f *fakeSource) LatestHeight(context.Context) (uint64, error) { return f.latest, nil }

func (f *fakeSource) set(hash []byte) {
	f.mu.Lock()
	f.hash = hash
	f.mu.Unlock()
}

func (f *fakeSource) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hashCalls
}

func observed(t *testing.T, store kv.Store, height uint64) {
	t.Helper()
	if err := store.Set(kv.NSChainState, coordinatorStateKey, []byte(`{"version":1,"last_observed_height":`+
		strconv.FormatUint(height, 10)+`,"last_reconciled_height":1}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	oldChain := Identity{ChainID: "trueopen-dev", FirstBlockHash: "0a0a"}
	tests := []struct {
		name     string
		recorded *Identity
		observed uint64
		src      *fakeSource
		want     Verdict
	}{
		{name: "first start", src: &fakeSource{hash: []byte{0xb}, latest: 50}, want: Recorded},
		{name: "same chain", recorded: &Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"},
			src: &fakeSource{hash: []byte{0xb}}, want: Same},
		{name: "recorded identity differs", recorded: &oldChain, src: &fakeSource{hash: []byte{0xb}}, want: Reset},
		{name: "recorded identity decides even when the height looks fine", recorded: &oldChain, observed: 10,
			src: &fakeSource{hash: []byte{0xb}, latest: 5000}, want: Reset},
		{name: "unrecorded, old state far above the chain", observed: 90000,
			src: &fakeSource{hash: []byte{0xb}, latest: 2000}, want: Reset},
		{name: "unrecorded, within tolerance", observed: 2100,
			src: &fakeSource{hash: []byte{0xb}, latest: 2000}, want: Recorded},
		{name: "unrecorded, node catching up", observed: 90000,
			src: &fakeSource{hash: []byte{0xb}, latest: 2000, syncing: true}, want: Unchecked},
		{name: "unrecorded, syncing unknown", observed: 90000,
			src: &fakeSource{hash: []byte{0xb}, latest: 2000, syncErr: errors.New("down")}, want: Unchecked},
		{name: "first block pruned", recorded: &oldChain, src: &fakeSource{hashErr: errors.New("height 1 is not available")}, want: Unchecked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := kv.NewMemStore()
			if tt.recorded != nil {
				if err := Record(store, *tt.recorded); err != nil {
					t.Fatal(err)
				}
			}
			if tt.observed != 0 {
				observed(t, store, tt.observed)
			}
			got, err := Check(context.Background(), store, tt.src, "trueopen-dev")
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tt.want {
				t.Fatalf("verdict = %v (%s), want %v", got.Verdict, got.Reason, tt.want)
			}
			if got.Verdict != Unchecked && got.Current != (Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"}) {
				t.Fatalf("current = %+v", got.Current)
			}
			// Recording is the caller's move.
			if _, recorded, _ := Load(store); recorded != (tt.recorded != nil) {
				t.Fatalf("Check changed the recorded identity")
			}
			if tt.recorded != nil && got.Previous != *tt.recorded {
				t.Fatalf("previous = %+v, want the recorded identity", got.Previous)
			}
		})
	}
}

// A start that cannot check the chain must not lose the old state's height: the coordinator then
// overwrites its record with the new chain's height, and the next start still sees the reset.
// Recording an identity drops the kept height.
func TestLegacyHeightSurvivesAnUncheckedStart(t *testing.T) {
	store := kv.NewMemStore()
	observed(t, store, 90000)
	down := &fakeSource{hashErr: errors.New("node unreachable")}
	if got, err := Check(context.Background(), store, down, "trueopen-dev"); err != nil || got.Verdict != Unchecked {
		t.Fatalf("verdict = %v, %v", got.Verdict, err)
	}
	observed(t, store, 2000) // the coordinator ran against the new chain
	up := &fakeSource{hash: []byte{0xb}, latest: 2000}
	got, err := Check(context.Background(), store, up, "trueopen-dev")
	if err != nil || got.Verdict != Reset {
		t.Fatalf("verdict = %v (%s), %v; want Reset", got.Verdict, got.Reason, err)
	}
	if err := Record(store, got.Current); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.GetWithError(kv.NSChainState, legacyHeightKey); ok {
		t.Fatal("legacy height kept after the identity was recorded")
	}
}

func TestSameChain(t *testing.T) {
	recorded := Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"}
	src := &fakeSource{hash: []byte{0xb}}
	m := newTestMonitor(src, recorded)
	if same, err := m.SameChain(context.Background()); err != nil || !same {
		t.Fatalf("same = %v, %v", same, err)
	}
	src.set([]byte{0xc})
	if same, err := m.SameChain(context.Background()); err != nil || same {
		t.Fatalf("same = %v, %v after the chain changed", same, err)
	}
	var off *Monitor
	if _, err := off.SameChain(context.Background()); !errors.Is(err, ErrCheckOff) {
		t.Fatalf("nil monitor err = %v", err)
	}
}

func TestArchiveMovesOnlyExistingDirectories(t *testing.T) {
	root := t.TempDir()
	kvDir, dataDir, tlsDir := filepath.Join(root, "kv"), filepath.Join(root, "task-data"), filepath.Join(root, "tls")
	for _, dir := range []string{kvDir, tlsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	moved, err := Archive([]string{kvDir, dataDir}, "T1")
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 1 || moved[0] != kvDir+".stale-T1" {
		t.Fatalf("moved = %v", moved)
	}
	for dir, exists := range map[string]bool{kvDir: false, kvDir + ".stale-T1": true, tlsDir: true} {
		if _, err := os.Stat(dir); (err == nil) != exists {
			t.Fatalf("%s exists = %v, want %v", dir, err == nil, exists)
		}
	}
}

func newTestMonitor(src Source, recorded Identity) *Monitor {
	m := NewMonitor(slog.New(slog.NewTextHandler(io.Discard, nil)), src, recorded)
	m.interval = time.Millisecond
	return m
}

func TestMonitorFiresAfterRepeatedMismatch(t *testing.T) {
	src := &fakeSource{hash: []byte{0xc}}
	m := newTestMonitor(src, Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"})
	m.Suspect("height fell")
	select {
	case err := <-m.Fatal():
		if !errors.Is(err, ErrChainReset) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no fatal after a confirmed reset")
	}
	if got := src.calls(); got != 3 {
		t.Fatalf("identity read %d times, want 3", got)
	}
	m.Suspect("again")
	time.Sleep(20 * time.Millisecond)
	if got := src.calls(); got != 3 {
		t.Fatalf("a fired monitor checked again: %d reads", got)
	}
}

func TestMonitorDoesNotFireWithoutConfirmation(t *testing.T) {
	recorded := Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"}
	tests := map[string]*fakeSource{
		"identity unchanged": {hash: []byte{0xb}},
		"query fails":        {hashErr: errors.New("down")},
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			m := newTestMonitor(src, recorded)
			m.Suspect("task not found")
			waitIdle(t, m)
			select {
			case err := <-m.Fatal():
				t.Fatalf("fatal = %v", err)
			default:
			}
		})
	}
}

// One read that disagrees and a later one that agrees again is a node hiccup, not a reset.
func TestMonitorNeedsEveryReadToDisagree(t *testing.T) {
	src := &fakeSource{hash: []byte{0xc}}
	m := newTestMonitor(src, Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"})
	m.interval = 50 * time.Millisecond
	m.Suspect("height fell")
	time.Sleep(10 * time.Millisecond)
	src.set([]byte{0xb})
	waitIdle(t, m)
	select {
	case err := <-m.Fatal():
		t.Fatalf("fatal = %v", err)
	default:
	}
}

func TestMonitorCooldown(t *testing.T) {
	src := &fakeSource{hash: []byte{0xb}}
	m := newTestMonitor(src, Identity{ChainID: "trueopen-dev", FirstBlockHash: "0b"})
	m.Suspect("first")
	waitIdle(t, m)
	m.Suspect("second, within the cooldown")
	waitIdle(t, m)
	if got := src.calls(); got != 1 {
		t.Fatalf("identity read %d times, want 1", got)
	}
}

func TestNilMonitor(t *testing.T) {
	var m *Monitor
	m.Suspect("ignored")
	if m.Fatal() != nil {
		t.Fatal("nil monitor has a fatal channel")
	}
}

func waitIdle(t *testing.T, m *Monitor) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		checking := m.checking
		m.mu.Unlock()
		if !checking {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("monitor still checking")
}
