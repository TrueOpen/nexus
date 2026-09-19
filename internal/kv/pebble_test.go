package kv

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func newTestPebble(t *testing.T, dir string) Store {
	t.Helper()
	s, err := NewPebble(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	return s
}

// TestPebbleRoundTrip covers Get/Set/Delete plus partition isolation.
func TestPebbleRoundTrip(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	defer func() { _ = s.Close() }()

	if _, ok := s.Get(NSTask, "k1"); ok {
		t.Fatal("empty store must miss")
	}
	s.Set(NSTask, "k1", []byte("v1"))
	s.Set(NSCustody, "k1", []byte("other-ns")) // the same key in a different partition does not interfere

	v, ok := s.Get(NSTask, "k1")
	if !ok || string(v) != "v1" {
		t.Fatalf("get = %q %v", v, ok)
	}
	s.Delete(NSTask, "k1")
	if _, ok := s.Get(NSTask, "k1"); ok {
		t.Fatal("deleted key must miss")
	}
	if v, ok := s.Get(NSCustody, "k1"); !ok || string(v) != "other-ns" {
		t.Fatal("other namespace must be untouched")
	}
}

func TestTaskDataNamespaceIsolation(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	defer func() { _ = s.Close() }()
	namespaces := []Namespace{
		NSTaskDataMetadata, NSTaskDataReservation, NSTaskDataTombstone,
		NSTaskDataReplay, NSTaskDataReplayExpiry,
	}
	for index, namespace := range namespaces {
		if err := s.Set(namespace, "same-key", []byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	for index, namespace := range namespaces {
		got, ok := s.Get(namespace, "same-key")
		if !ok || len(got) != 1 || got[0] != byte(index) {
			t.Fatalf("namespace %s = %x, %v", namespace, got, ok)
		}
	}
}

func TestPebbleGetWithErrorReportsClosedStore(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, _, err := s.GetWithError(NSTask, "key"); err == nil {
		t.Fatal("GetWithError hid closed-store read failure")
	}
}

func TestPebbleMutationsAndScanReportClosedStore(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.Set(NSTask, "key", []byte("value")); err == nil {
		t.Fatal("Set succeeded after Close")
	}
	if err := s.Delete(NSTask, "key"); err == nil {
		t.Fatal("Delete succeeded after Close")
	}
	if err := s.Scan(NSTask, func(string, []byte) bool { return true }); err == nil {
		t.Fatal("Scan succeeded after Close")
	}
}

func TestPebbleCloseWaitsForInFlightScan(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	if err := s.Set(NSTask, "key", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	deleteErr := make(chan error, 1)
	scanDone := make(chan error, 1)
	go func() {
		scanDone <- s.Scan(NSTask, func(string, []byte) bool {
			close(entered)
			<-release
			deleteErr <- s.Delete(NSTask, "key")
			return true
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Scan callback did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned during in-flight Scan: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-deleteErr; err == nil {
		t.Fatal("nested Delete succeeded after Close began")
	}
	if err := <-scanDone; err != nil {
		t.Fatalf("Scan: %v", err)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after Scan")
	}
}

// TestPebbleScanNamespaceIsolation checks that Scan only sees its own partition and supports early termination.
func TestPebbleScanNamespaceIsolation(t *testing.T) {
	s := newTestPebble(t, t.TempDir())
	defer func() { _ = s.Close() }()

	s.Set(NSTask, "a", []byte("1"))
	s.Set(NSTask, "b", []byte("2"))
	s.Set(NSCustody, "c", []byte("3"))
	s.Set(NSBusCursor, "d", []byte("4"))

	got := map[string]string{}
	if err := s.Scan(NSTask, func(k string, v []byte) bool {
		got[k] = string(v)
		return true
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 2 || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("scan = %v", got)
	}

	n := 0
	if err := s.Scan(NSTask, func(string, []byte) bool { n++; return false }); err != nil {
		t.Fatalf("early-stop scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("early-stop scan visited %d, want 1", n)
	}
}

// TestPebbleReopenPersists checks the data is still there after closing and reopening the store (the basis of restart recovery).
func TestPebbleReopenPersists(t *testing.T) {
	dir := t.TempDir()
	s := newTestPebble(t, dir)
	s.Set(NSTask, "sess|task", []byte(`{"state":2}`))
	s.Set(NSOutputDelivery, "sess|task", []byte(`{"output_text":"hello"}`))
	s.Set(NSOutputTombstone, "sess|task", []byte(`{"status":"ACKED"}`))
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2 := newTestPebble(t, dir)
	defer func() { _ = s2.Close() }()
	v, ok := s2.Get(NSTask, "sess|task")
	if !ok || string(v) != `{"state":2}` {
		t.Fatalf("reopened get = %q %v", v, ok)
	}
	delivery, deliveryOK := s2.Get(NSOutputDelivery, "sess|task")
	tombstone, tombstoneOK := s2.Get(NSOutputTombstone, "sess|task")
	if !deliveryOK || string(delivery) != `{"output_text":"hello"}` ||
		!tombstoneOK || string(tombstone) != `{"status":"ACKED"}` {
		t.Fatalf("output namespaces = delivery %q/%v tombstone %q/%v", delivery, deliveryOK, tombstone, tombstoneOK)
	}
}

// TestMemStoreScan checks that the in-memory implementation's Scan semantics match pebble's.
func TestMemStoreScan(t *testing.T) {
	s := NewMemStore()
	s.Set(NSTask, "a", []byte("1"))
	s.Set(NSCustody, "b", []byte("2"))
	got := map[string]string{}
	if err := s.Scan(NSTask, func(k string, v []byte) bool { got[k] = string(v); return true }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got["a"] != "1" {
		t.Fatalf("scan = %v", got)
	}
}
