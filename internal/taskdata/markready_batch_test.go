package taskdata

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

// recordingBackend records each WriteBatch and can fail reads of the object index.
type recordingBackend struct {
	kv.Store
	mu        sync.Mutex
	batches   [][]kv.WriteOp
	failIndex bool
}

func (b *recordingBackend) WriteBatch(ops ...kv.WriteOp) error {
	b.mu.Lock()
	b.batches = append(b.batches, append([]kv.WriteOp(nil), ops...))
	b.mu.Unlock()
	return b.Store.WriteBatch(ops...)
}

func (b *recordingBackend) GetWithError(ns kv.Namespace, key string) ([]byte, bool, error) {
	if ns == kv.NSTaskDataObjectIndex && b.failIndex {
		return nil, false, errors.New("index read failed")
	}
	return b.Store.GetWithError(ns, key)
}

func (b *recordingBackend) lastBatch(t *testing.T) []kv.WriteOp {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.batches) == 0 {
		t.Fatal("no batch written")
	}
	return b.batches[len(b.batches)-1]
}

func recordStoreWrites(store *Store) *recordingBackend {
	recorder := &recordingBackend{Store: store.backend}
	store.backend = recorder
	return recorder
}

func batchNamespaces(ops []kv.WriteOp) []kv.Namespace {
	namespaces := make([]kv.Namespace, len(ops))
	for i, op := range ops {
		namespaces[i] = op.NS
	}
	return namespaces
}

func readyState(t *testing.T, store *Store, key ObjectKey) State {
	t.Helper()
	record, found, err := store.metadataRecord(objectKeyString(key))
	if err != nil || !found {
		t.Fatalf("metadata of %v: found=%v err=%v", key, found, err)
	}
	return record.Metadata.State
}

// An INPUT turning READY writes its metadata and its index in one batch.
func TestMarkReadyWritesMetadataAndIndexInOneBatch(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	prepared := prepareObject(t, store, testHeader(body), body)
	recorder := recordStoreWrites(store)
	if _, err := store.MarkReady(context.Background(), prepared.Key); err != nil {
		t.Fatal(err)
	}
	got := batchNamespaces(recorder.lastBatch(t))
	if len(got) != 2 || got[0] != kv.NSTaskDataMetadata || got[1] != kv.NSTaskDataObjectIndex {
		t.Fatalf("MarkReady batch = %v, want metadata then index", got)
	}
	if ref, found := resolvedInput(t, store); !found || ref != prepared.Key {
		t.Fatalf("index = %#v, %t", ref, found)
	}
}

// When the index cannot be decided, the metadata is still written READY and the error returned; a
// repeated MarkReady then repairs the index.
func TestMarkReadyWritesMetadataWhenTheIndexDecisionFails(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	prepared := prepareObject(t, store, testHeader(body), body)
	recorder := recordStoreWrites(store)
	recorder.failIndex = true
	if _, err := store.MarkReady(context.Background(), prepared.Key); !errors.Is(err, ErrStorage) {
		t.Fatalf("MarkReady with a failing index read = %v, want ErrStorage", err)
	}
	if got := batchNamespaces(recorder.lastBatch(t)); len(got) != 1 || got[0] != kv.NSTaskDataMetadata {
		t.Fatalf("batch = %v, want the metadata alone", got)
	}
	if state := readyState(t, store, prepared.Key); state != StateReady {
		t.Fatalf("state = %s, want READY", state)
	}
	recorder.failIndex = false
	if _, err := store.MarkReady(context.Background(), prepared.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != prepared.Key {
		t.Fatalf("index after repair = %#v, %t", ref, found)
	}
}

// When another READY version is already indexed, only the metadata is written and the index keeps
// naming the indexed version.
func TestMarkReadyKeepsTheIndexOfAnotherReadyVersion(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	tracked := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), tracked.Key); err != nil {
		t.Fatal(err)
	}
	other := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	recorder := recordStoreWrites(store)
	if _, err := store.MarkReady(context.Background(), other.Key); err != nil {
		t.Fatal(err)
	}
	if got := batchNamespaces(recorder.lastBatch(t)); len(got) != 1 || got[0] != kv.NSTaskDataMetadata {
		t.Fatalf("batch = %v, want the metadata alone", got)
	}
	if ref, found := resolvedInput(t, store); !found || ref != tracked.Key {
		t.Fatalf("index = %#v, %t; want the tracked version", ref, found)
	}
}
