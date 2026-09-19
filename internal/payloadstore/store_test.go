package payloadstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

func TestLegacyPayloadAdapterUsesTaskDataWithoutNSPayloadCopy(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore := newTaskDataStore(t, backend)
	store := newTestStoreWithOptions(t, backend, 1024, WithTaskData(taskStore))
	payload := []byte("encrypted inference input")
	submission := Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(payload), Hash: payloadHash(payload),
		Payload: payload, DeadlineHeight: 100,
	}
	if err := store.Put(context.Background(), submission); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Get(kv.NSPayload, payloadKey(submission.SessionID, submission.TaskID)); ok {
		t.Fatal("adapter wrote a duplicate NSPayload record")
	}
	// Objects are located by full ref; the test resolves via the index, same as the production path.
	key, err := taskStore.ResolveObject(context.Background(), submission.SessionID, submission.TaskID, taskdata.ObjectKindInput)
	if err != nil {
		t.Fatal(err)
	}
	metadata, metaErr := taskStore.Metadata(context.Background(), key)
	if metaErr != nil || metadata.State != taskdata.StatePrepared {
		t.Fatalf("prepared metadata = %#v, %v", metadata, metaErr)
	}
	if err := store.(AcceptanceStore).MarkAccepted(context.Background(), submission.SessionID, submission.TaskID); err != nil {
		t.Fatal(err)
	}
	got, err := store.Fetch(context.Background(), submission.SessionID, submission.TaskID, 99)
	if err != nil || !bytes.Equal(got.Payload, payload) || got.Ref != submission.Ref || got.DeadlineHeight != 100 {
		t.Fatalf("Fetch = %#v, %v", got, err)
	}
}

func TestLegacyPayloadAdapterMigratesOldNSPayloadOnRead(t *testing.T) {
	backend := kv.NewMemStore()
	legacy := newTestStore(t, backend, 1024)
	payload := []byte("old encrypted input")
	submission := Submission{
		SessionID: "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c", TaskID: "4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(payload), Hash: payloadHash(payload),
		Payload: payload, DeadlineHeight: 100,
	}
	if err := legacy.Put(context.Background(), submission); err != nil {
		t.Fatal(err)
	}
	taskStore := newTaskDataStore(t, backend)
	adapter := newTestStoreWithOptions(t, backend, 1024, WithTaskData(taskStore))
	got, err := adapter.Fetch(context.Background(), submission.SessionID, submission.TaskID, 99)
	if err != nil || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("Fetch = %#v, %v", got, err)
	}
	if _, ok := backend.Get(kv.NSPayload, payloadKey(submission.SessionID, submission.TaskID)); ok {
		t.Fatal("legacy NSPayload remained after successful migration")
	}
	migratedKey, err := taskStore.ResolveObject(context.Background(), submission.SessionID, submission.TaskID, taskdata.ObjectKindInput)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := taskStore.Metadata(context.Background(), migratedKey)
	if err != nil || metadata.State != taskdata.StateReady {
		t.Fatalf("migrated metadata = %#v, %v", metadata, err)
	}
}

func TestPutFetchPersistsContentAddressedPayload(t *testing.T) {
	backend := kv.NewMemStore()
	store := newTestStore(t, backend, 1024)
	payload := []byte("encrypted inference input")
	hash := payloadHash(payload)
	ref := RefFor(payload)

	err := store.Put(context.Background(), Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: ref,
		Hash: hash, Payload: payload, DeadlineHeight: 100,
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A new manager over the same backend must be able to serve the payload.
	restarted := newTestStore(t, backend, 1024)
	got, err := restarted.Fetch(context.Background(), "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", 99)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Ref != ref || got.Hash != hash || got.DeadlineHeight != 100 || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("Fetch = %+v, want ref=%q hash=%q deadline=100 payload=%q", got, ref, hash, payload)
	}

	got.Payload[0] ^= 0xff
	again, err := restarted.Fetch(context.Background(), "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", 99)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if !bytes.Equal(again.Payload, payload) {
		t.Fatalf("Fetch exposed mutable storage: got %x want %x", again.Payload, payload)
	}
}

func TestPutRequiresMatchingHashAndReference(t *testing.T) {
	store := newTestStore(t, kv.NewMemStore(), 1024)
	payload := []byte("encrypted inference input")
	valid := Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(payload),
		Hash: payloadHash(payload), Payload: payload, DeadlineHeight: 100,
	}

	badHash := valid
	badHash.Hash = payloadHash([]byte("different"))
	if err := store.Put(context.Background(), badHash); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch error = %v, want ErrHashMismatch", err)
	}

	badRef := valid
	badRef.Ref = RefFor([]byte("different"))
	if err := store.Put(context.Background(), badRef); !errors.Is(err, ErrRefMismatch) {
		t.Fatalf("ref mismatch error = %v, want ErrRefMismatch", err)
	}
}

func TestPutIsIdempotentAndRejectsTaskConflicts(t *testing.T) {
	store := newTestStore(t, kv.NewMemStore(), 1024)
	firstPayload := []byte("first encrypted input")
	first := Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(firstPayload),
		Hash: payloadHash(firstPayload), Payload: firstPayload, DeadlineHeight: 100,
	}
	if err := store.Put(context.Background(), first); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(context.Background(), first); err != nil {
		t.Fatalf("idempotent Put: %v", err)
	}

	secondPayload := []byte("second encrypted input")
	conflict := Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(secondPayload),
		Hash: payloadHash(secondPayload), Payload: secondPayload, DeadlineHeight: 100,
	}
	if err := store.Put(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Put error = %v, want ErrConflict", err)
	}
}

func TestConcurrentPutDoesNotOverwriteTaskPayload(t *testing.T) {
	backend := &slowMissingStore{Store: kv.NewMemStore()}
	store := newTestStore(t, backend, 1024)
	firstPayload := []byte("first encrypted input")
	secondPayload := []byte("second encrypted input")
	submissions := []Submission{
		{SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(firstPayload), Hash: payloadHash(firstPayload), Payload: firstPayload, DeadlineHeight: 100},
		{SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(secondPayload), Hash: payloadHash(secondPayload), Payload: secondPayload, DeadlineHeight: 100},
	}

	start := make(chan struct{})
	errs := make(chan error, len(submissions))
	var wg sync.WaitGroup
	for _, submission := range submissions {
		wg.Add(1)
		go func(sub Submission) {
			defer wg.Done()
			<-start
			errs <- store.Put(context.Background(), sub)
		}(submission)
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, conflicted int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("concurrent Put error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent Put results: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestFetchAndSweepExpireAtDeadline(t *testing.T) {
	store := newTestStore(t, kv.NewMemStore(), 1024)
	payload := []byte("encrypted inference input")
	if err := store.Put(context.Background(), Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(payload),
		Hash: payloadHash(payload), Payload: payload, DeadlineHeight: 100,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := store.Fetch(context.Background(), "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", 100); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired Fetch error = %v, want ErrExpired", err)
	}
	if _, err := store.Fetch(context.Background(), "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Fetch after expiry cleanup error = %v, want ErrNotFound", err)
	}

	second := []byte("another encrypted input")
	if err := store.Put(context.Background(), Submission{
		SessionID: "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f", TaskID: "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(second),
		Hash: payloadHash(second), Payload: second, DeadlineHeight: 200,
	}); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if err := store.Sweep(context.Background(), 200); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, err := store.Fetch(context.Background(), "session-2", "task-2", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Fetch after Sweep error = %v, want ErrNotFound", err)
	}
}

func TestPutRejectsOversizedPayload(t *testing.T) {
	store := newTestStore(t, kv.NewMemStore(), 4)
	payload := []byte("12345")
	err := store.Put(context.Background(), Submission{
		SessionID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", TaskID: "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", TaskHash: "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e", Ref: RefFor(payload),
		Hash: payloadHash(payload), Payload: payload, DeadlineHeight: 100,
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Put error = %v, want ErrTooLarge", err)
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

type slowMissingStore struct {
	kv.Store
}

func (s *slowMissingStore) GetWithError(ns kv.Namespace, key string) ([]byte, bool, error) {
	raw, ok, err := s.Store.GetWithError(ns, key)
	if err == nil && !ok {
		time.Sleep(10 * time.Millisecond)
	}
	return raw, ok, err
}
