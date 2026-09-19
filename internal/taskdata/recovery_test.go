package taskdata

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

type recoveryResolver struct {
	accepted      map[string]bool
	revalidate    map[string]bool
	retention     map[string]RetentionDecision
	acceptedErr   error
	revalidateErr error
	retentionErr  error
}

func (r recoveryResolver) HasAcceptedOrder(_ context.Context, key ObjectKey) (bool, error) {
	return r.accepted[objectKeyString(key)], r.acceptedErr
}

func (r recoveryResolver) RevalidatePrepared(_ context.Context, metadata Metadata) (bool, error) {
	return r.revalidate[objectKeyString(metadata.Key)], r.revalidateErr
}

func (r recoveryResolver) Retention(_ context.Context, metadata Metadata, _ uint64) (RetentionDecision, error) {
	return r.retention[objectKeyString(metadata.Key)], r.retentionErr
}

func prepareObject(t *testing.T, store *Store, header UploadHeader, body []byte) Metadata {
	t.Helper()
	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(body); start += int(store.cfg.ChunkSizeBytes) {
		end := start + int(store.cfg.ChunkSizeBytes)
		if end > len(body) {
			end = len(body)
		}
		if err := upload.WriteChunk(body[start:end]); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err := upload.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestRecoverRemovesAbandonedReservationAndSpool(t *testing.T) {
	store, backend, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	upload, err := store.Begin(context.Background(), testHeader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[:4]); err != nil {
		t.Fatal(err)
	}
	if err := upload.file.Close(); err != nil {
		t.Fatal(err)
	}
	upload.file = nil
	if err := store.Recover(context.Background(), recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Get(kv.NSTaskDataReservation, upload.ID()); ok {
		t.Fatal("abandoned reservation remains")
	}
	if _, err := os.Stat(upload.spoolPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool stat = %v", err)
	}
}

func TestRecoverRemovesSpoolWithoutReservation(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	orphan := filepath.Join(store.root, "spool", "orphan.part")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background(), recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan spool stat = %v", err)
	}
}

func TestRecoverPromotesAcceptedInputAndRollsBackRejectedInput(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	accepted := prepareObject(t, store, testHeader(body), body)
	rejectedHeader := testHeader([]byte("12345678"))
	rejectedHeader.Key.TaskID = testOtherTaskID
	rejected := prepareObject(t, store, rejectedHeader, []byte("12345678"))

	resolver := recoveryResolver{accepted: map[string]bool{objectKeyString(accepted.Key): true}}
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	got, err := store.Metadata(context.Background(), accepted.Key)
	if err != nil || got.State != StateReady {
		t.Fatalf("accepted metadata = %+v, %v", got, err)
	}
	if _, err := store.Metadata(context.Background(), rejected.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected metadata error = %v", err)
	}
	if _, err := os.Stat(store.blobPath(rejected.SemanticHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected blob stat = %v", err)
	}
}

func TestRecoverQuarantinesPreparedObjectWhenAuthorityUnavailable(t *testing.T) {
	store, backend, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = "trueopen1worker"
	header.Receipt = &SignedInferReceipt{TaskID: header.Key.TaskID}
	metadata := prepareObject(t, store, header, body)
	if err := store.Recover(context.Background(), recoveryResolver{revalidateErr: errors.New("chain unavailable")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Metadata(context.Background(), metadata.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined metadata visible: %v", err)
	}
	record, found, err := store.metadataRecord(objectKeyString(metadata.Key))
	if err != nil || !found || record.Metadata.State != StateQuarantined {
		t.Fatalf("record = %+v/%v/%v", record, found, err)
	}
	if _, ok := backend.Get(kv.NSTaskDataMetadata, objectKeyString(metadata.Key)); !ok {
		t.Fatal("quarantined metadata was deleted")
	}
	if _, err := os.Stat(store.blobPath(metadata.SemanticHash)); err != nil {
		t.Fatalf("quarantined blob missing: %v", err)
	}
}

func TestRecoverQuarantinesRejectedPreparedOutputAndSweepCanPromoteIt(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = "trueopen1worker"
	header.Receipt = &SignedInferReceipt{TaskID: header.Key.TaskID}
	metadata := prepareObject(t, store, header, body)
	key := objectKeyString(metadata.Key)
	resolver := recoveryResolver{
		revalidate: map[string]bool{key: false},
		retention: map[string]RetentionDecision{
			key: {Status: RetentionActive},
		},
	}
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	record, found, err := store.metadataRecord(key)
	if err != nil || !found || record.Metadata.State != StateQuarantined {
		t.Fatalf("rejected record = %+v/%v/%v", record, found, err)
	}
	resolver.revalidate[key] = true
	if err := store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	ready, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || ready.State != StateReady {
		t.Fatalf("promoted record = %+v/%v", ready, err)
	}
}

func TestSweepRetriesQuarantinedInputAfterAuthorityRecovers(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	metadata := prepareObject(t, store, testHeader(body), body)
	key := objectKeyString(metadata.Key)
	if err := store.Recover(context.Background(), recoveryResolver{acceptedErr: errors.New("kv unavailable")}); err != nil {
		t.Fatal(err)
	}
	record, found, err := store.metadataRecord(key)
	if err != nil || !found || record.Metadata.State != StateQuarantined {
		t.Fatalf("quarantined input = %+v/%v/%v", record, found, err)
	}
	resolver := recoveryResolver{
		accepted: map[string]bool{key: true},
		retention: map[string]RetentionDecision{
			key: {Status: RetentionActive},
		},
	}
	if err := store.Sweep(context.Background(), 50, resolver); err != nil {
		t.Fatal(err)
	}
	ready, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || ready.State != StateReady {
		t.Fatalf("promoted input = %+v/%v", ready, err)
	}
}

func TestRecoverRemovesUnreferencedBlobButKeepsSharedBlob(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	first := prepareObject(t, store, testHeader(body), body)
	secondHeader := testHeader(body)
	secondHeader.Key.TaskID = testOtherTaskID
	second := prepareObject(t, store, secondHeader, body)
	orphan := store.blobPath("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err := os.MkdirAll(filepath.Dir(orphan), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := recoveryResolver{accepted: map[string]bool{objectKeyString(first.Key): true, objectKeyString(second.Key): false}}
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.blobPath(first.SemanticHash)); err != nil {
		t.Fatalf("shared blob removed: %v", err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan blob stat = %v", err)
	}
}

func TestSweepRetainsOnAuthorityFailureAndDeletesAtCleanupHeight(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	metadata := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Sweep(context.Background(), 100, recoveryResolver{retentionErr: errors.New("chain unavailable")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Metadata(context.Background(), metadata.Key); err != nil {
		t.Fatalf("authority failure deleted data: %v", err)
	}
	resolver := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(metadata.Key): {Status: RetentionRetainedForChallenge, RetainUntilHeight: 120},
	}}
	if err := store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	retained, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || retained.RetentionStatus != RetentionRetainedForChallenge || retained.RetainUntilHeight != 120 {
		t.Fatalf("retained metadata = %+v, %v", retained, err)
	}
	resolver.retention[objectKeyString(metadata.Key)] = RetentionDecision{
		Status: RetentionEligibleForCleanup, RetainUntilHeight: 120, Delete: true,
	}
	if err := store.Sweep(context.Background(), 120, resolver); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || deleted.RetentionStatus != RetentionDeleted {
		t.Fatalf("deleted metadata = %+v, %v", deleted, err)
	}
	if _, ok := store.backend.Get(kv.NSTaskDataTombstone, objectKeyString(metadata.Key)); !ok {
		t.Fatal("cleanup tombstone missing")
	}
	if _, err := os.Stat(store.blobPath(metadata.SemanticHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleaned blob stat = %v", err)
	}
}

func TestSweepTombstonePreventsRecreation(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	metadata := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	resolver := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(metadata.Key): {Status: RetentionEligibleForCleanup, RetainUntilHeight: 120, Delete: true},
	}}
	if err := store.Sweep(context.Background(), 120, resolver); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || deleted.RetentionStatus != RetentionDeleted {
		t.Fatalf("deleted metadata = %+v, %v", deleted, err)
	}
	if _, err := store.Begin(context.Background(), testHeader(body)); !errors.Is(err, ErrConflict) {
		t.Fatalf("recreate deleted object error = %v", err)
	}
	// An idempotent upload may already be in flight when terminal cleanup starts.
	// Its finalization must observe the tombstone instead of returning DELETED as
	// a successful idempotent result.
	otherBody := []byte("12345678")
	otherHeader := testHeader(otherBody)
	otherHeader.Key.TaskID = testOtherTaskID
	otherMetadata := prepareObject(t, store, otherHeader, otherBody)
	if _, err := store.MarkReady(context.Background(), otherMetadata.Key); err != nil {
		t.Fatal(err)
	}
	retry, err := store.Begin(context.Background(), otherHeader)
	if err != nil || !retry.Idempotent() {
		t.Fatalf("start idempotent retry = %v, %v", retry, err)
	}
	for start := 0; start < len(otherBody); start += int(store.cfg.ChunkSizeBytes) {
		end := start + int(store.cfg.ChunkSizeBytes)
		if end > len(otherBody) {
			end = len(otherBody)
		}
		if err := retry.WriteChunk(otherBody[start:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteObject(context.Background(), otherMetadata.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := retry.Prepare(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotent retry after deletion error = %v", err)
	}
}

func TestDeleteObjectTombstonesObject(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	metadata := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteObject(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || deleted.RetentionStatus != RetentionDeleted || deleted.RetainUntilHeight != metadata.RetainUntilHeight {
		t.Fatalf("deleted metadata = %+v, %v", deleted, err)
	}
	if _, err := store.Begin(context.Background(), testHeader(body)); !errors.Is(err, ErrConflict) {
		t.Fatalf("recreate deleted object error = %v", err)
	}
	if _, err := os.Stat(store.blobPath(metadata.SemanticHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted blob stat = %v", err)
	}
	if err := store.DeleteObject(context.Background(), metadata.Key); err != nil {
		t.Fatalf("idempotent deletion: %v", err)
	}
}

func TestDeleteObjectTombstonesMissingTerminalObject(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	header := testHeader([]byte("abcdefgh"))
	if err := store.DeleteObject(context.Background(), header.Key); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.Metadata(context.Background(), header.Key)
	if err != nil || deleted.Key != header.Key || deleted.RetentionStatus != RetentionDeleted {
		t.Fatalf("deleted metadata = %+v, %v", deleted, err)
	}
	if _, err := store.Begin(context.Background(), header); !errors.Is(err, ErrConflict) {
		t.Fatalf("create after terminal deletion error = %v", err)
	}
}

func TestTombstoneTakesPrecedenceOverLiveMetadata(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	metadata := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	tombstone := tombstoneRecord{
		Key: metadata.Key, SemanticHash: metadata.SemanticHash, SizeBytes: metadata.SizeBytes,
		RetentionStatus: RetentionDeleted, RetainUntilHeight: 120, DeletedAtUnixMillis: time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(tombstone)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.backend.Set(kv.NSTaskDataTombstone, objectKeyString(metadata.Key), raw); err != nil {
		t.Fatal(err)
	}
	got, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil || got.RetentionStatus != RetentionDeleted {
		t.Fatalf("metadata with tombstone = %+v, %v", got, err)
	}
	if _, err := store.OpenRange(context.Background(), metadata.Key, 0, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("range with tombstone error = %v", err)
	}
}

func TestSweepCannotDeleteBlobBetweenRenameAndMetadataCommit(t *testing.T) {
	root := t.TempDir()
	base := kv.NewMemStore()
	backend := &blockingMetadataStore{
		Store: base, entered: make(chan struct{}), release: make(chan struct{}),
	}
	store, err := NewStore(nil, filepath.Join(root, "objects"), backend, testStoreConfig(),
		WithDiskUsage(func(string) (uint64, uint64, error) { return 1 << 30, 0, nil }))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("abcdefgh")
	upload, err := store.Begin(context.Background(), testHeader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[:4]); err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[4:]); err != nil {
		t.Fatal(err)
	}
	prepared := make(chan error, 1)
	go func() {
		_, err := upload.Prepare(context.Background())
		prepared <- err
	}()
	<-backend.entered
	swept := make(chan error, 1)
	go func() {
		swept <- store.Sweep(context.Background(), 50, recoveryResolver{})
	}()
	select {
	case err := <-swept:
		t.Fatalf("sweep crossed in-flight metadata commit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(backend.release)
	if err := <-prepared; err != nil {
		t.Fatal(err)
	}
	if err := <-swept; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.blobPath(testHeader(body).SemanticHash)); err != nil {
		t.Fatalf("committed blob missing: %v", err)
	}
}

type blockingMetadataStore struct {
	kv.Store
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (s *blockingMetadataStore) Set(namespace kv.Namespace, key string, value []byte) error {
	if namespace == kv.NSTaskDataMetadata {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return s.Store.Set(namespace, key, value)
}

// When the periodic sweep receives a "task not settled" decision (no height), it must not
// reset the object's existing retention height to 0: that is the commitment signed to the
// uploader in the storage confirmation (issue #66).
func TestSweepKeepsRetentionLeaseWhenDecisionHasNoHeight(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = "trueopen1worker"
	header.Receipt = &SignedInferReceipt{TaskID: header.Key.TaskID}
	header.RetainUntilHeight = 0
	metadata := prepareObject(t, store, header, body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordRetentionLease(context.Background(), metadata.Key, 186); err != nil {
		t.Fatal(err)
	}
	key := objectKeyString(metadata.Key)
	resolver := recoveryResolver{
		retention: map[string]RetentionDecision{key: {Status: RetentionActive}},
	}
	if err := store.Sweep(context.Background(), 150, resolver); err != nil {
		t.Fatal(err)
	}
	after, err := store.Metadata(context.Background(), metadata.Key)
	if err != nil {
		t.Fatal(err)
	}
	if after.RetainUntilHeight != 186 || after.RetentionStatus != RetentionActive {
		t.Fatalf("after sweep retain_until_height = %d status = %s, want 186 / ACTIVE", after.RetainUntilHeight, after.RetentionStatus)
	}
}
