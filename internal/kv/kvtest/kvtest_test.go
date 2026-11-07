package kvtest

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func TestCrashKeepsWritesUpToTheLastSyncedOne(t *testing.T) {
	s := New()
	if err := kv.WriteDeferred(s, kv.WriteOp{NS: kv.NSTask, Key: "a", Val: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if got := s.Crash(); func() bool { _, ok := got.Get(kv.NSTask, "a"); return ok }() {
		t.Fatal("a deferred write alone survived a crash")
	}
	if err := s.Set(kv.NSTask, "b", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteBatchDeferred(kv.WriteOp{NS: kv.NSTask, Key: "c", Val: []byte("3")}, kv.WriteOp{NS: kv.NSTask, Key: "a", Delete: true}); err != nil {
		t.Fatal(err)
	}
	if s.Synced() != 1 || s.Deferred() != 2 {
		t.Fatalf("counts synced %d deferred %d, want 1 and 2", s.Synced(), s.Deferred())
	}
	if _, ok := s.Get(kv.NSTask, "a"); ok {
		t.Fatal("the live view misses the deferred delete")
	}
	after := s.Crash()
	for key, want := range map[string]bool{"a": true, "b": true, "c": false} {
		if _, ok := after.Get(kv.NSTask, key); ok != want {
			t.Fatalf("after the crash %q present %v, want %v", key, ok, want)
		}
	}
	if after.Synced() != 0 || after.Deferred() != 0 {
		t.Fatal("a crashed store starts counting from zero")
	}
}
