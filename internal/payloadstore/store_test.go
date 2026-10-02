package payloadstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

const (
	testSession = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	testTask    = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
)

var (
	testTaskHashV1 = strings.Repeat("5e", 32)
	testTaskHashV2 = strings.Repeat("6f", 32)
)

// Delete removes the version it names, not the one the INPUT index happens to point at.
func TestDeleteRemovesNamedInputVersion(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore := newTaskDataStore(t, backend)
	store := newTestStoreWithOptions(t, backend, 1024, WithTaskData(taskStore))
	first := stageInput(t, taskStore, testTaskHashV1, []byte("first version"), true)
	// A later version prepared for the same task repoints the index at itself.
	second := stageInput(t, taskStore, testTaskHashV2, []byte("second version"), false)
	if ref, err := taskStore.ResolveObject(context.Background(), testSession, testTask, taskdata.ObjectKindInput); err != nil || ref != second {
		t.Fatalf("index = %#v, %v; want the second version", ref, err)
	}

	if err := store.Delete(context.Background(), inputOf(first)); err != nil {
		t.Fatal(err)
	}
	if !deleted(t, taskStore, first) {
		t.Fatal("first version survived Delete")
	}
	if deleted(t, taskStore, second) {
		t.Fatal("second version was removed with the first")
	}
}

// A cleanup intent queued by an older release names no version; the INPUT index decides.
func TestDeleteWithoutVersionUsesInputIndex(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore := newTaskDataStore(t, backend)
	store := newTestStoreWithOptions(t, backend, 1024, WithTaskData(taskStore))
	ref := stageInput(t, taskStore, testTaskHashV1, []byte("only version"), true)

	if err := store.Delete(context.Background(), Input{SessionID: testSession, TaskID: testTask}); err != nil {
		t.Fatal(err)
	}
	if !deleted(t, taskStore, ref) {
		t.Fatal("indexed input survived Delete")
	}
}

func TestDeleteOfAbsentInputIsIdempotent(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore := newTaskDataStore(t, backend)
	store := newTestStoreWithOptions(t, backend, 1024, WithTaskData(taskStore))
	absent := Input{SessionID: testSession, TaskID: testTask, TaskHash: testTaskHashV1, ContentHash: payloadHash([]byte("never stored"))}
	for range 2 {
		for _, input := range []Input{absent, {SessionID: testSession, TaskID: testTask}} {
			if err := store.Delete(context.Background(), input); err != nil {
				t.Fatalf("Delete(%+v) = %v", input, err)
			}
		}
	}
}

// Inline payload records written by older releases are removed on Delete and by Sweep.
func TestLegacyRecordsRemovedByDeleteAndSweep(t *testing.T) {
	backend := kv.NewMemStore()
	store := newTestStore(t, backend, 1024)
	putLegacyRecord(t, backend, testSession, testTask, 100)
	otherTask := strings.Repeat("3c", 32)
	putLegacyRecord(t, backend, testSession, otherTask, 50)

	if err := store.Delete(context.Background(), Input{SessionID: testSession, TaskID: testTask}); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Get(kv.NSPayload, payloadKey(testSession, testTask)); ok {
		t.Fatal("legacy record survived Delete")
	}
	if err := store.Sweep(context.Background(), 49); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Get(kv.NSPayload, payloadKey(testSession, otherTask)); !ok {
		t.Fatal("legacy record swept before its deadline")
	}
	if err := store.Sweep(context.Background(), 50); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Get(kv.NSPayload, payloadKey(testSession, otherTask)); ok {
		t.Fatal("legacy record survived Sweep at its deadline")
	}
}

func stageInput(t *testing.T, taskStore *taskdata.Store, taskHash string, payload []byte, ready bool) taskdata.ObjectKey {
	t.Helper()
	ctx := context.Background()
	key := taskdata.ObjectKey{
		TaskHash: taskHash, SessionID: testSession, TaskID: testTask,
		Kind: taskdata.ObjectKindInput, ContentHash: payloadHash(payload),
	}
	upload, err := taskStore.Begin(ctx, taskdata.UploadHeader{
		Key: key, SizeBytes: uint64(len(payload)), SemanticHash: key.ContentHash,
		MediaType: "application/octet-stream", RetainUntilHeight: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Abort()
	for offset := 0; offset < len(payload); offset += int(taskStore.ChunkSize()) {
		end := min(offset+int(taskStore.ChunkSize()), len(payload))
		if err := upload.WriteChunk(payload[offset:end]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := upload.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if ready {
		if _, err := taskStore.MarkReady(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

// deleted reports whether the object is gone: taskdata answers a deleted key with its tombstone.
func deleted(t *testing.T, taskStore *taskdata.Store, key taskdata.ObjectKey) bool {
	t.Helper()
	metadata, err := taskStore.Metadata(context.Background(), key)
	if errors.Is(err, taskdata.ErrNotFound) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	return metadata.RetentionStatus == taskdata.RetentionDeleted
}

func inputOf(key taskdata.ObjectKey) Input {
	return Input{SessionID: key.SessionID, TaskID: key.TaskID, TaskHash: key.TaskHash, ContentHash: key.ContentHash}
}

func putLegacyRecord(t *testing.T, backend kv.Store, sessionID, taskID string, deadline uint64) {
	t.Helper()
	payload := []byte("legacy inline payload")
	raw, err := json.Marshal(record{
		SessionID: sessionID, TaskID: taskID, TaskHash: testTaskHashV1, Ref: RefFor(payload),
		Hash: payloadHash(payload), Payload: payload, DeadlineHeight: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(kv.NSPayload, payloadKey(sessionID, taskID), raw); err != nil {
		t.Fatal(err)
	}
}

func newTestStore(t *testing.T, backend kv.Store, maxBytes int) Store {
	return newTestStoreWithOptions(t, backend, maxBytes)
}

func newTestStoreWithOptions(t *testing.T, backend kv.Store, maxBytes int, options ...Option) Store {
	t.Helper()
	store, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), backend, Config{MaxBytes: maxBytes}, options...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func newTaskDataStore(t *testing.T, backend kv.Store) *taskdata.Store {
	t.Helper()
	store, err := taskdata.NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir(), backend, taskdata.Config{
		InlineMaxBytes: 1024, ChunkSizeBytes: 4, MaxRangeBytes: 1024, MaxBlobBytes: 1024,
		SpoolReservationBytes: 4096, DiskAcceptWatermarkPercent: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func payloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
