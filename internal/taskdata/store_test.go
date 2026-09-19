package taskdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func testStoreConfig() Config {
	return Config{
		InlineMaxBytes: 8, ChunkSizeBytes: 4, MaxRangeBytes: 8,
		MaxBlobBytes: 16, SpoolReservationBytes: 24, DiskAcceptWatermarkPercent: 85,
	}
}

func newTestStore(t *testing.T, cfg Config, options ...Option) (*Store, kv.Store, string) {
	t.Helper()
	root := t.TempDir()
	backend, err := kv.NewPebble(filepath.Join(root, "kv"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	created, err := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(root, "objects"), backend, cfg, options...)
	if err != nil {
		t.Fatal(err)
	}
	return created, backend, root
}

func testHeader(body []byte) UploadHeader {
	digest := sha256.Sum256(body)
	// content_hash is the identity of the object content: the value in the ref must equal
	// SemanticHash, otherwise the same bytes would have two identities.
	contentHash := hex.EncodeToString(digest[:])
	return UploadHeader{
		Key: ObjectKey{
			TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID,
			Kind: ObjectKindInput, ContentHash: contentHash,
		},
		SizeBytes: uint64(len(body)), SemanticHash: contentHash, MediaType: "application/octet-stream",
		RetainUntilHeight: 100,
	}
}

func TestStorePersistsPreparedThenReadyAndReadsExactRange(t *testing.T) {
	store, backend, _ := newTestStore(t, testStoreConfig())
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
	prepared, err := upload.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != StatePrepared {
		t.Fatalf("prepared state = %s", prepared.State)
	}
	if _, err := store.OpenRange(context.Background(), prepared.Key, 0, 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PREPARED range error = %v, want ErrNotFound", err)
	}
	ready, err := store.MarkReady(context.Background(), prepared.Key)
	if err != nil || ready.State != StateReady {
		t.Fatalf("MarkReady = %+v, %v", ready, err)
	}
	reader, err := store.OpenRange(context.Background(), ready.Key, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, []byte("cdef")) {
		t.Fatalf("range = %q, %v", got, err)
	}
	if _, ok := backend.Get(kv.NSTaskDataReservation, upload.ID()); ok {
		t.Fatal("reservation remains after prepare")
	}
	if _, err := os.Stat(store.blobPath(ready.SemanticHash)); err != nil {
		t.Fatalf("blob missing: %v", err)
	}
}

func TestStoreSyncsSpoolDirectoryAcrossReservationAndCommit(t *testing.T) {
	var synced []string
	store, _, _ := newTestStore(t, testStoreConfig(), WithDirectorySync(func(path string) error {
		synced = append(synced, path)
		return nil
	}))
	body := []byte("abcdefgh")
	upload, err := store.Begin(context.Background(), testHeader(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{body[:4], body[4:]} {
		if err := upload.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := upload.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	spoolRoot := filepath.Join(store.root, "spool")
	blobRoot := filepath.Dir(store.blobPath(testHeader(body).SemanticHash))
	if len(synced) != 3 || synced[0] != spoolRoot || synced[1] != spoolRoot || synced[2] != blobRoot {
		t.Fatalf("synced directories = %v", synced)
	}
}

func TestStoreIdempotencyBindsOutputReceipt(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("output")
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = "trueopen1worker"
	header.Receipt = &SignedInferReceipt{TaskID: testTaskID, OutputHash: header.SemanticHash, OutputSizeBytes: uint64(len(body)), TaskHash: strings.Repeat("a", 64)}
	header.AcceptedReceiptHash = "accepted-1"
	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[:4]); err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[4:]); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkReady(context.Background(), header.Key); err != nil {
		t.Fatal(err)
	}

	different := header
	differentReceipt := *header.Receipt
	differentReceipt.TaskHash = strings.Repeat("b", 64)
	different.Receipt = &differentReceipt
	if _, err := store.Begin(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed receipt error = %v", err)
	}
	different = header
	different.AcceptedReceiptHash = "accepted-2"
	retry, err := store.Begin(context.Background(), different)
	if err != nil || !retry.Idempotent() {
		t.Fatalf("accepted receipt cache changed idempotency = %v, %v", retry, err)
	}
	_ = retry.Abort()
	different = header
	different.Uploader = "trueopen1otherworker"
	if _, err := store.Begin(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed uploader error = %v", err)
	}
}

func TestStoreRejectsSizeHashAndChunkViolations(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdef")

	t.Run("chunk too large", func(t *testing.T) {
		upload, err := store.Begin(context.Background(), testHeader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer upload.Abort()
		if err := upload.WriteChunk(body[:5]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("early eof", func(t *testing.T) {
		upload, err := store.Begin(context.Background(), testHeader(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := upload.WriteChunk(body[:4]); err != nil {
			t.Fatal(err)
		}
		if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("extra bytes", func(t *testing.T) {
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
		if err := upload.WriteChunk([]byte("x")); !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong hash", func(t *testing.T) {
		header := testHeader(body)
		header.SemanticHash = hex.EncodeToString(bytes.Repeat([]byte{0xff}, sha256.Size))
		upload, err := store.Begin(context.Background(), header)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range [][]byte{body[:4], body[4:]} {
			if err := upload.WriteChunk(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestStoreIdempotencyConflictAndRangeValidation(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	first, err := store.Begin(context.Background(), testHeader(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{body[:4], body[4:]} {
		if err := first.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkReady(context.Background(), testHeader(body).Key); err != nil {
		t.Fatal(err)
	}

	retry, err := store.Begin(context.Background(), testHeader(body))
	if err != nil || !retry.Idempotent() {
		t.Fatalf("retry = %v, %v", retry, err)
	}
	for _, chunk := range [][]byte{body[:4], body[4:]} {
		if err := retry.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if meta, err := retry.Prepare(context.Background()); err != nil || meta.State != StateReady {
		t.Fatalf("idempotent prepare = %+v, %v", meta, err)
	}

	conflict := testHeader([]byte("ijklmnop"))
	conflict.Key = testHeader(body).Key
	if _, err := store.Begin(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	for name, bounds := range map[string][2]uint64{
		"offset at eof": {8, 1}, "past eof": {7, 2}, "above max": {0, 9},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.OpenRange(context.Background(), testHeader(body).Key, bounds[0], bounds[1]); !errors.Is(err, ErrRangeInvalid) {
				t.Fatalf("range error = %v", err)
			}
		})
	}
}

func TestStoreReservesCapacityBeforeAcceptingBytes(t *testing.T) {
	cfg := testStoreConfig()
	cfg.MaxBlobBytes = 8
	cfg.SpoolReservationBytes = 12
	store, _, _ := newTestStore(t, cfg, WithDiskUsage(func(string) (uint64, uint64, error) {
		return 100, 50, nil
	}))
	first, err := store.Begin(context.Background(), testHeader([]byte("abcdefgh")))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Abort()
	secondHeader := testHeader([]byte("12345"))
	secondHeader.Key.TaskID = testOtherTaskID
	if _, err := store.Begin(context.Background(), secondHeader); !errors.Is(err, ErrCapacity) {
		t.Fatalf("reservation error = %v", err)
	}
}

func TestStoreRejectsProjectedDiskWatermark(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig(), WithDiskUsage(func(string) (uint64, uint64, error) {
		return 100, 80, nil
	}))
	if _, err := store.Begin(context.Background(), testHeader([]byte("abcdefgh"))); !errors.Is(err, ErrCapacity) {
		t.Fatalf("watermark error = %v", err)
	}
}
