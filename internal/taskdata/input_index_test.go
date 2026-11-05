package taskdata

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// otherVersion returns the header of another INPUT version of the same task.
func otherVersion(body []byte) UploadHeader {
	header := testHeader(body)
	header.Key.TaskHash = strings.Repeat("6f", 32)
	return header
}

func resolvedInput(t *testing.T, store *Store) (ObjectRef, bool) {
	t.Helper()
	ref, err := store.ResolveObject(context.Background(), testSessionID, testTaskID, ObjectKindInput)
	if errors.Is(err, ErrNotFound) {
		return ObjectRef{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return ref, true
}

func TestInputIndexWrittenOnlyAtReady(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	prepared := prepareObject(t, store, testHeader(body), body)
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("PREPARED input is indexed: %#v", ref)
	}
	if _, err := store.MarkReady(context.Background(), prepared.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != prepared.Key {
		t.Fatalf("index after MarkReady = %#v, %t", ref, found)
	}
}

// A refused version prepared next to the tracked one is removed without dropping the tracked
// version's index, whether by rollback or by delete.
func TestRemovingAnotherVersionKeepsTrackedIndex(t *testing.T) {
	for _, remove := range []string{"rollback", "delete"} {
		t.Run(remove, func(t *testing.T) {
			store, _, _ := newTestStore(t, testStoreConfig())
			body := []byte("abcdefgh")
			tracked := prepareObject(t, store, testHeader(body), body)
			if _, err := store.MarkReady(context.Background(), tracked.Key); err != nil {
				t.Fatal(err)
			}
			refused := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
			var err error
			if remove == "rollback" {
				err = store.RollbackPrepared(context.Background(), refused.Key)
			} else {
				err = store.DeleteObject(context.Background(), refused.Key)
			}
			if err != nil {
				t.Fatal(err)
			}
			if ref, found := resolvedInput(t, store); !found || ref != tracked.Key {
				t.Fatalf("index after %s = %#v, %t; want the tracked version", remove, ref, found)
			}
		})
	}
}

func TestDeleteObjectClearsItsOwnIndex(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	tracked := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), tracked.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteObject(context.Background(), tracked.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("index survived its object: %#v", ref)
	}
}

// A re-signed retry of an order whose dispatch failed (same task_id, new task_hash) is the only
// way a second INPUT version turns READY: the dispatcher refused every other version before its
// input was marked READY. The retried version takes the index, so its Worker is served its own
// input; the earlier version stays stored until its retention ends.
func TestReadyRetriedInputTakesTheIndex(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	first := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), first.Key); err != nil {
		t.Fatal(err)
	}
	retried := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	if _, err := store.MarkReady(context.Background(), retried.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != retried.Key {
		t.Fatalf("index = %#v, %t; want the retried version", ref, found)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("retry logged an error: %s", logs.String())
	}
	if metadata, err := store.Metadata(context.Background(), first.Key); err != nil || metadata.State != StateReady {
		t.Fatalf("earlier version = %+v, %v; want it kept READY", metadata, err)
	}
	// A repeated MarkReady of the earlier version only repairs a missing index: it does not take
	// the index back.
	if _, err := store.MarkReady(context.Background(), first.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != retried.Key {
		t.Fatalf("index after a repeated MarkReady of the earlier version = %#v, %t", ref, found)
	}
}

func TestRecoverIndexesPromotedInputAndClearsRejectedOne(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	accepted := prepareObject(t, store, testHeader(body), body)
	resolver := recoveryResolver{accepted: map[string]bool{objectKeyString(accepted.Key): true}}
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != accepted.Key {
		t.Fatalf("index after Recover promotion = %#v, %t", ref, found)
	}

	// A rejected version found by a later recovery does not take the index with it.
	rejected := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Metadata(context.Background(), rejected.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected version metadata error = %v", err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != accepted.Key {
		t.Fatalf("index after rejecting another version = %#v, %t", ref, found)
	}
}

func TestSweepIndexesPromotedQuarantinedInput(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if err := store.Recover(context.Background(), recoveryResolver{acceptedErr: errors.New("authority unavailable")}); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("QUARANTINED input is indexed: %#v", ref)
	}
	resolver := recoveryResolver{
		accepted:  map[string]bool{objectKeyString(input.Key): true},
		retention: map[string]RetentionDecision{objectKeyString(input.Key): {Status: RetentionActive}},
	}
	if err := store.Sweep(context.Background(), 10, resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("index after Sweep promotion = %#v, %t", ref, found)
	}
}

func TestSweepRetentionDeleteClearsInputIndex(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	resolver := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(input.Key): {Status: RetentionEligibleForCleanup, RetainUntilHeight: 100, Delete: true},
	}}
	if err := store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("index survived retention delete: %#v", ref)
	}
}

// Recover reports, without changing it, an INPUT index naming a version that has no accepted order.
func TestRecoverReportsInputIndexWithoutAcceptedOrder(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background(), recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "task input index names a version without an accepted order") {
		t.Fatalf("missing index check log: %s", logs.String())
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("index check changed the index: %#v, %t", ref, found)
	}
	logs.Reset()
	accepted := recoveryResolver{accepted: map[string]bool{objectKeyString(input.Key): true}}
	if err := store.Recover(context.Background(), accepted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "task input index") {
		t.Fatalf("index check logged for an accepted version: %s", logs.String())
	}
}
