package taskdata

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// crashAndRecover reopens the task data under root over what a crash of backend now leaves and
// runs the recovery; the files on disk stay as they are.
func crashAndRecover(t *testing.T, root string, backend *kvtest.Store, resolver RecoveryResolver) (*Store, *kvtest.Store) {
	t.Helper()
	crashed := backend.Crash()
	store, _ := newCountingStore(t, root, crashed)
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatalf("recover: %v", err)
	}
	return store, crashed
}

// assertNoIntakeLeft checks a recovered store holds no trace of an input: no reservation, no
// spool file, no metadata, no blob.
func assertNoIntakeLeft(t *testing.T, store *Store, backend kv.Store, header UploadHeader) {
	t.Helper()
	_ = backend.Scan(kv.NSTaskDataReservation, func(key string, _ []byte) bool {
		t.Fatalf("reservation %s left after recovery", key)
		return false
	})
	entries, err := os.ReadDir(filepath.Join(store.root, "spool"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool after recovery: %v %v", entries, err)
	}
	if _, err := store.Metadata(context.Background(), header.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("metadata after recovery: %v", err)
	}
	if _, err := os.Stat(store.blobPath(header.SemanticHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blob after recovery: %v", err)
	}
}

// A crash in the middle of an upload, whatever of its reservation reached the disk, leaves no
// reservation and no spool file after recovery.
func TestCrashDuringInputUploadLeavesNoReservationOrSpool(t *testing.T) {
	root := t.TempDir()
	backend := kvtest.New()
	store, _ := newCountingStore(t, root, backend)
	body := []byte("abcdefgh")
	header := testHeader(body)
	upload, err := (&Service{store: store}).BeginInput(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[:4]); err != nil {
		t.Fatal(err)
	}
	recovered, crashed := crashAndRecover(t, root, backend, recoveryResolver{})
	assertNoIntakeLeft(t, recovered, crashed, header)

	// The same once the reservation is durable: a later synced write of another caller made it so.
	if err := backend.Set(kv.NSOps, "probe", []byte("x")); err != nil {
		t.Fatal(err)
	}
	recovered, crashed = crashAndRecover(t, root, backend, recoveryResolver{})
	assertNoIntakeLeft(t, recovered, crashed, header)
}

// A prepared input whose order was not committed before a crash (no synced write after it) is
// gone after recovery, blob included: nothing refers to it, since the dispatcher's commit is
// written after it. Once the commit is durable, so is the input: recovery finds it PREPARED and
// the accepted order turns it READY with its bytes.
func TestCrashAfterPrepareInputKeepsTheInputOnlyWithItsCommit(t *testing.T) {
	root := t.TempDir()
	backend := kvtest.New()
	store, _ := newCountingStore(t, root, backend)
	service := &Service{store: store}
	ctx := context.Background()
	body := []byte("abcdefgh")
	header := testHeader(body)
	upload, err := service.BeginInput(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{body[:4], body[4:]} {
		if err := upload.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.PrepareInput(ctx, upload); err != nil {
		t.Fatal(err)
	}
	accepted := recoveryResolver{accepted: map[string]bool{objectKeyString(header.Key): true}}
	recovered, crashed := crashAndRecover(t, root, backend, accepted)
	assertNoIntakeLeft(t, recovered, crashed, header)

	// The blob was removed by that recovery of a copy; write it again as the first run left it.
	root2 := t.TempDir()
	backend2 := kvtest.New()
	store2, _ := newCountingStore(t, root2, backend2)
	service2 := &Service{store: store2}
	upload, err = service2.BeginInput(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{body[:4], body[4:]} {
		if err := upload.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service2.PrepareInput(ctx, upload); err != nil {
		t.Fatal(err)
	}
	// The dispatcher's commit of the order: a synced write after the input.
	if err := backend2.Set(kv.NSInflight, "order/commit", []byte("x")); err != nil {
		t.Fatal(err)
	}
	recovered, _ = crashAndRecover(t, root2, backend2, accepted)
	meta, err := recovered.Metadata(ctx, header.Key)
	if err != nil || meta.State != StateReady {
		t.Fatalf("input after a crash past its commit: %+v %v", meta, err)
	}
	r, err := recovered.OpenRange(ctx, header.Key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || string(got) != string(body) {
		t.Fatalf("input bytes after recovery = %q %v", got, err)
	}
}
