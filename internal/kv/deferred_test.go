package kv

import (
	"io"
	"log/slog"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// crashablePebble opens a pebble store on a filesystem that keeps only what was synced when crash
// is called, and reopens it after the crash.
type crashablePebble struct {
	t  *testing.T
	fs *vfs.MemFS
}

func (c crashablePebble) open() Store {
	c.t.Helper()
	s, err := openPebble("db", &pebble.Options{FS: c.fs, Logger: pebbleQuietLogger{}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		c.t.Fatalf("open pebble: %v", err)
	}
	return s
}

// newCrashablePebble prepares the store's directory, synced, as a disk that already holds it.
func newCrashablePebble(t *testing.T) crashablePebble {
	t.Helper()
	fs := vfs.NewStrictMem()
	if err := fs.MkdirAll("db", 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := fs.OpenDir("")
	if err == nil {
		err = root.Sync()
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	return crashablePebble{t: t, fs: fs}
}

// crash drops everything the store did not sync, as a power loss would, and reopens it.
func (c crashablePebble) crash(s Store) Store {
	c.t.Helper()
	c.fs.SetIgnoreSyncs(true)
	_ = s.Close()
	c.fs.ResetToSyncedState()
	c.fs.SetIgnoreSyncs(false)
	return c.open()
}

func mustDefer(t *testing.T, s Store, key string) {
	t.Helper()
	if err := WriteDeferred(s, WriteOp{NS: NSTask, Key: key, Val: []byte(key)}); err != nil {
		t.Fatal(err)
	}
}

// TestPebbleDeferredWriteDurableAfterLaterSync pins what WriteDeferred relies on: a deferred
// write is visible at once, is lost by a crash while no synced write followed it, and is durable
// once any later synced write returned.
func TestPebbleDeferredWriteDurableAfterLaterSync(t *testing.T) {
	c := newCrashablePebble(t)
	s := c.open()
	mustDefer(t, s, "alone")
	if _, ok := s.Get(NSTask, "alone"); !ok {
		t.Fatal("a deferred write must be visible at once")
	}
	s = c.crash(s)
	if _, ok := s.Get(NSTask, "alone"); ok {
		t.Fatal("a deferred write with no synced write after it survived the crash; the test does not exercise deferral")
	}

	mustDefer(t, s, "before")
	if err := s.Set(NSCustody, "synced", []byte("x")); err != nil {
		t.Fatal(err)
	}
	mustDefer(t, s, "after")
	s = c.crash(s)
	defer func() { _ = s.Close() }()
	if _, ok := s.Get(NSTask, "before"); !ok {
		t.Fatal("a deferred write followed by a synced write was lost")
	}
	if _, ok := s.Get(NSCustody, "synced"); !ok {
		t.Fatal("a synced write was lost")
	}
	if _, ok := s.Get(NSTask, "after"); ok {
		t.Fatal("a deferred write after the last synced write survived the crash")
	}
}

// TestWriteDeferredFallsBackToSyncedBatch: a store that cannot defer writes the batch synced.
func TestWriteDeferredFallsBackToSyncedBatch(t *testing.T) {
	inner := NewMemStore()
	s := syncOnly{Store: inner}
	if err := WriteDeferred(s, WriteOp{NS: NSTask, Key: "k", Val: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if v, ok := inner.Get(NSTask, "k"); !ok || string(v) != "v" {
		t.Fatalf("fallback write = %q %v", v, ok)
	}
}

// syncOnly hides the store's WriteBatchDeferred.
type syncOnly struct{ Store }
