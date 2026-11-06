package taskdata

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingRetentionResolver answers Retention with decision, after signalling entered and waiting
// for release: it stands for a chain read that is slow while the sweep is between its snapshot
// and its writes.
type blockingRetentionResolver struct {
	recoveryResolver
	decision RetentionDecision
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
}

func newBlockingRetentionResolver(decision RetentionDecision) *blockingRetentionResolver {
	return &blockingRetentionResolver{decision: decision, entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockingRetentionResolver) Retention(ctx context.Context, _ Metadata, _ uint64) (RetentionDecision, error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		return r.decision, nil
	case <-ctx.Done():
		return RetentionDecision{}, ctx.Err()
	}
}

// startBlockedSweep starts a Sweep whose first Retention call blocks until the returned release
// function runs; it returns once the sweep is inside that call.
func startBlockedSweep(t *testing.T, store *Store, height uint64, resolver *blockingRetentionResolver) (<-chan error, func()) {
	t.Helper()
	swept := make(chan error, 1)
	go func() { swept <- store.Sweep(context.Background(), height, resolver) }()
	var once sync.Once
	release := func() { once.Do(func() { close(resolver.release) }) }
	t.Cleanup(release)
	select {
	case <-resolver.entered:
	case err := <-swept:
		t.Fatalf("sweep returned before resolving retention: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("sweep never resolved retention")
	}
	return swept, release
}

// within runs fn and fails the test when it does not return in time.
func within(t *testing.T, what string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked behind the sweep's chain reads", what)
	}
}

func uploadObject(store *Store, header UploadHeader, body []byte) (Metadata, error) {
	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		return Metadata{}, err
	}
	for start := 0; start < len(body); start += int(store.cfg.ChunkSizeBytes) {
		end := min(start+int(store.cfg.ChunkSizeBytes), len(body))
		if err := upload.WriteChunk(body[start:end]); err != nil {
			return Metadata{}, err
		}
	}
	return upload.Prepare(context.Background())
}

func TestSweepResolverDoesNotBlockUploadsAndReads(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	swept := readyInput(t, store, []byte("abcdefgh"))
	rollbackHeader := testHeader([]byte("rollback"))
	rollbackHeader.Key.TaskID = strings.Repeat("6f", 32)
	rolledBack := prepareObject(t, store, rollbackHeader, []byte("rollback"))

	resolver := newBlockingRetentionResolver(RetentionDecision{Status: RetentionActive})
	done, release := startBlockedSweep(t, store, 50, resolver)

	within(t, "upload of another object", func() error {
		header := testHeader([]byte("12345678"))
		header.Key.TaskID = testOtherTaskID
		metadata, err := uploadObject(store, header, []byte("12345678"))
		if err != nil {
			return err
		}
		_, err = store.MarkReady(context.Background(), metadata.Key)
		return err
	})
	within(t, "metadata read", func() error {
		_, err := store.Metadata(context.Background(), swept)
		return err
	})
	within(t, "rollback of a prepared input", func() error {
		return store.RollbackPrepared(context.Background(), rolledBack.Key)
	})
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.blobPath(rolledBack.SemanticHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled back blob stat = %v", err)
	}
}

// A record that changes while the sweep resolves it keeps the change: the decision was made for
// the bytes the sweep read, not for the record as it is now.
func TestSweepSkipsRecordChangedWhileResolving(t *testing.T) {
	for _, decision := range []RetentionDecision{
		{Status: RetentionActive},
		{Status: RetentionEligibleForCleanup, RetainUntilHeight: 40, Delete: true},
	} {
		t.Run(string(decision.Status), func(t *testing.T) {
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

			resolver := newBlockingRetentionResolver(decision)
			done, release := startBlockedSweep(t, store, 50, resolver)
			within(t, "retention lease write", func() error {
				_, err := store.RecordRetentionLease(context.Background(), metadata.Key, 186)
				return err
			})
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			after, err := store.Metadata(context.Background(), metadata.Key)
			if err != nil || after.RetainUntilHeight != 186 || after.RetentionStatus != RetentionActive {
				t.Fatalf("after sweep = %+v, %v; want the lease written during the sweep", after, err)
			}
			if _, found := tombstoneOf(t, store, metadata.Key); found {
				t.Fatal("sweep tombstoned a record that changed after its snapshot")
			}
			if _, err := os.Stat(store.blobPath(metadata.SemanticHash)); err != nil {
				t.Fatalf("blob of the kept record: %v", err)
			}
		})
	}
}

func TestSweepLogsOnlyWhenItActs(t *testing.T) {
	var logged bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logged, nil))
	key := readyInput(t, store, []byte("abcdefgh"))
	retained := recoveryResolver{retention: map[string]RetentionDecision{objectKeyString(key): {Status: RetentionActive}}}
	if err := store.Sweep(context.Background(), 50, retained); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logged.String(), "task data sweep") {
		t.Fatalf("a sweep that changed nothing logged: %s", logged.String())
	}
	deleting := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(key): {Status: RetentionEligibleForCleanup, RetainUntilHeight: 100, Delete: true},
	}}
	if err := store.Sweep(context.Background(), 100, deleting); err != nil {
		t.Fatal(err)
	}
	line := logged.String()
	for _, want := range []string{"task data sweep", "records=1", "deleted=1", "blobs_removed=1", "duration_ms="} {
		if !strings.Contains(line, want) {
			t.Fatalf("sweep log %q lacks %q", line, want)
		}
	}
}
