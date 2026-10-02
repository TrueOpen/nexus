package taskdata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func tombstoneOf(t *testing.T, store *Store, key ObjectKey) (tombstoneRecord, bool) {
	t.Helper()
	record, found, err := store.tombstoneRecord(objectKeyString(key))
	if err != nil {
		t.Fatal(err)
	}
	return record, found
}

func countTombstones(t *testing.T, store *Store) int {
	t.Helper()
	n := 0
	if err := store.backend.Scan(kv.NSTaskDataTombstone, func(string, []byte) bool { n++; return true }); err != nil {
		t.Fatal(err)
	}
	return n
}

func readyInput(t *testing.T, store *Store, body []byte) ObjectKey {
	t.Helper()
	metadata := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	return metadata.Key
}

// A tombstone written without a height is stamped by the next sweep and kept until
// max(deleted_at_height, retain_until_height) + retention; then the key reads as never stored and
// can be uploaded again.
func TestSweepReclaimsTombstoneAfterRetention(t *testing.T) {
	cfg := testStoreConfig()
	cfg.TombstoneRetentionBlocks = 10
	store, _, _ := newTestStore(t, cfg)
	ctx := context.Background()
	key := readyInput(t, store, []byte("abcdefgh")) // retain_until_height 100
	if err := store.DeleteObject(ctx, key); err != nil {
		t.Fatal(err)
	}
	if record, found := tombstoneOf(t, store, key); !found || record.DeletedAtHeight != 0 {
		t.Fatalf("tombstone after DeleteObject = %+v, %t; want one without a height", record, found)
	}

	if err := store.Sweep(ctx, 50, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if record, found := tombstoneOf(t, store, key); !found || record.DeletedAtHeight != 50 {
		t.Fatalf("tombstone after first sweep = %+v, %t; want deleted_at_height 50", record, found)
	}
	if err := store.Sweep(ctx, 109, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if _, found := tombstoneOf(t, store, key); !found {
		t.Fatal("tombstone reclaimed before max(deleted_at, retain_until) + retention")
	}
	if metadata, err := store.Metadata(ctx, key); err != nil || metadata.RetentionStatus != RetentionDeleted {
		t.Fatalf("metadata before reclamation = %+v, %v; want DELETED", metadata, err)
	}
	if err := store.Sweep(ctx, 110, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if _, found := tombstoneOf(t, store, key); found {
		t.Fatal("tombstone kept past its retention")
	}
	if _, err := store.Metadata(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("metadata after reclamation error = %v, want ErrNotFound", err)
	}
	upload, err := store.Begin(ctx, testHeader([]byte("abcdefgh")))
	if err != nil {
		t.Fatalf("Begin after reclamation: %v", err)
	}
	_ = upload.Abort()
}

// A tombstone written by retention carries the sweep's height, and an INPUT re-uploaded after its
// tombstone was reclaimed is removed again by retention.
func TestReuploadAfterReclamationFollowsRetention(t *testing.T) {
	cfg := testStoreConfig()
	cfg.TombstoneRetentionBlocks = 10
	store, _, _ := newTestStore(t, cfg)
	ctx := context.Background()
	key := readyInput(t, store, []byte("abcdefgh"))
	cleanup := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(key): {Status: RetentionEligibleForCleanup, RetainUntilHeight: 120, Delete: true},
	}}
	if err := store.Sweep(ctx, 120, cleanup); err != nil {
		t.Fatal(err)
	}
	if record, found := tombstoneOf(t, store, key); !found || record.DeletedAtHeight != 120 || record.RetainUntilHeight != 120 {
		t.Fatalf("retention tombstone = %+v, %t; want deleted_at_height 120", record, found)
	}
	if err := store.Sweep(ctx, 130, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if _, found := tombstoneOf(t, store, key); found {
		t.Fatal("retention tombstone kept past 120 + 10")
	}

	// The same INPUT stored again: the next sweep whose retention says cleanup removes it again.
	if again := readyInput(t, store, []byte("abcdefgh")); again != key {
		t.Fatalf("re-uploaded key differs: %+v", again)
	}
	if err := store.Sweep(ctx, 131, cleanup); err != nil {
		t.Fatal(err)
	}
	if metadata, err := store.Metadata(ctx, key); err != nil || metadata.RetentionStatus != RetentionDeleted {
		t.Fatalf("re-uploaded input after cleanup = %+v, %v; want DELETED", metadata, err)
	}
}

// One sweep stamps or reclaims at most tombstoneSweepBatch tombstones; the next takes the rest.
func TestSweepReclaimsTombstonesInBatches(t *testing.T) {
	cfg := testStoreConfig()
	cfg.TombstoneRetentionBlocks = 10
	store, backend, _ := newTestStore(t, cfg)
	ctx := context.Background()
	for i := 0; i < tombstoneSweepBatch+5; i++ {
		raw, err := json.Marshal(tombstoneRecord{RetentionStatus: RetentionDeleted, DeletedAtHeight: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Set(kv.NSTaskDataTombstone, fmt.Sprintf("tombstone-%05d", i), raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Sweep(ctx, 100, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if got := countTombstones(t, store); got != 5 {
		t.Fatalf("tombstones after one sweep = %d, want 5", got)
	}
	if err := store.Sweep(ctx, 101, recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if got := countTombstones(t, store); got != 0 {
		t.Fatalf("tombstones after two sweeps = %d, want 0", got)
	}
}

// With a retention of 0 tombstones are stamped but never reclaimed.
func TestTombstoneRetentionZeroKeepsTombstones(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig()) // TombstoneRetentionBlocks 0
	ctx := context.Background()
	key := readyInput(t, store, []byte("abcdefgh"))
	if err := store.DeleteObject(ctx, key); err != nil {
		t.Fatal(err)
	}
	for _, height := range []uint64{50, 1 << 40} {
		if err := store.Sweep(ctx, height, recoveryResolver{}); err != nil {
			t.Fatal(err)
		}
	}
	if record, found := tombstoneOf(t, store, key); !found || record.DeletedAtHeight != 50 {
		t.Fatalf("tombstone with retention 0 = %+v, %t; want it kept, stamped at 50", record, found)
	}
}

func TestTombstoneExpiryOverflowNeverExpires(t *testing.T) {
	record := tombstoneRecord{DeletedAtHeight: ^uint64(0) - 5}
	if tombstoneExpired(record, ^uint64(0), 10) {
		t.Fatal("an overflowing reclaim height expired")
	}
	if !tombstoneExpired(tombstoneRecord{DeletedAtHeight: 5, RetainUntilHeight: 20}, 30, 10) ||
		tombstoneExpired(tombstoneRecord{DeletedAtHeight: 5, RetainUntilHeight: 20}, 29, 10) {
		t.Fatal("reclaim boundary is not max(deleted_at, retain_until) + window")
	}
}

// An undecodable tombstone is skipped: the sweep succeeds, reclaims what is due, and leaves the
// bad record as it is.
func TestSweepSkipsUndecodableTombstone(t *testing.T) {
	cfg := testStoreConfig()
	cfg.TombstoneRetentionBlocks = 10
	store, backend, _ := newTestStore(t, cfg)
	ctx := context.Background()
	if err := backend.Set(kv.NSTaskDataTombstone, "broken", []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(tombstoneRecord{RetentionStatus: RetentionDeleted, DeletedAtHeight: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(kv.NSTaskDataTombstone, "due", raw); err != nil {
		t.Fatal(err)
	}
	if err := store.Sweep(ctx, 100, recoveryResolver{}); err != nil {
		t.Fatalf("Sweep with an undecodable tombstone: %v", err)
	}
	if _, found := backend.Get(kv.NSTaskDataTombstone, "due"); found {
		t.Fatal("the due tombstone was not reclaimed")
	}
	if got, found := backend.Get(kv.NSTaskDataTombstone, "broken"); !found || string(got) != "{not json" {
		t.Fatalf("the undecodable tombstone was changed: %q, %t", got, found)
	}
}
