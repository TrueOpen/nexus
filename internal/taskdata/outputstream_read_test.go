package taskdata

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// streamReadHook runs afterStreamRead once, right after the next read of an output stream record:
// between a reader's read of the record and its open of the stream data.
type streamReadHook struct {
	kv.Store
	mu              sync.Mutex
	afterStreamRead func()
}

func (b *streamReadHook) GetWithError(ns kv.Namespace, key string) ([]byte, bool, error) {
	raw, found, err := b.Store.GetWithError(ns, key)
	if ns == kv.NSTaskDataOutputStream {
		b.mu.Lock()
		hook := b.afterStreamRead
		b.afterStreamRead = nil
		b.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	return raw, found, err
}

func (b *streamReadHook) arm(hook func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.afterStreamRead = hook
}

func newHookedStreamStore(t *testing.T) (*Store, *streamReadHook) {
	t.Helper()
	root := t.TempDir()
	backend, err := kv.NewPebble(filepath.Join(root, "kv"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	hooked := &streamReadHook{Store: backend}
	store, err := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(root, "objects"), hooked, streamStoreConfig())
	if err != nil {
		t.Fatal(err)
	}
	return store, hooked
}

// openWithChunks opens the output stream of task and appends texts; it returns the stream and the
// Fin that seals it.
func openWithChunks(t *testing.T, store *Store, task string, texts ...string) (*OutputStream, OutputFin) {
	t.Helper()
	stream, _, err := store.OpenOutputStream(context.Background(), streamKey(task), "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i, text := range texts {
		if _, err := stream.Append(context.Background(), chunkFor(acc, uint64(i), text)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	root := acc.Root()
	return stream, OutputFin{FinalSeq: uint64(len(texts) - 1), OutputMMRRoot: root[:]}
}

// A reader that read the stream record before Finish moved the spool to the blob store, and opens
// the data only after, still reads the stream: the sealed record names the blob.
func TestOutputFramesReadAcrossFinish(t *testing.T) {
	store, hooked := newHookedStreamStore(t)
	stream, fin := openWithChunks(t, store, testTaskID, "hello, ", "world")
	hooked.arm(func() {
		if _, err := stream.Finish(context.Background(), fin); err != nil {
			t.Errorf("finish: %v", err)
		}
	})
	frames, err := store.OutputFrames(context.Background(), streamKey(testTaskID), nil)
	if err != nil {
		t.Fatalf("frames read across Finish: %v", err)
	}
	if len(frames) != 3 || string(frames[1].Chunk.Text) != "world" || frames[2].Fin == nil {
		t.Fatalf("frames = %+v", frames)
	}
}

// Readers running alongside Finish never find the stream data missing.
func TestOutputFramesConcurrentWithFinish(t *testing.T) {
	store, _ := newHookedStreamStore(t)
	for i := 0; i < 20; i++ {
		task := fmt.Sprintf("%064x", i+1)
		stream, fin := openWithChunks(t, store, task, "hello, ", "world")
		done := make(chan error, 1)
		go func() {
			_, err := stream.Finish(context.Background(), fin)
			done <- err
		}()
		finished := false
		for {
			frames, err := store.OutputFrames(context.Background(), streamKey(task), nil)
			if err != nil {
				t.Fatalf("round %d: frames during Finish: %v", i, err)
			}
			if len(frames) > 0 && frames[len(frames)-1].Fin != nil {
				break
			}
			if finished {
				t.Fatalf("round %d: finished stream read without its Fin", i)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("round %d: finish: %v", i, err)
				}
				finished = true
			default:
			}
		}
		if !finished {
			if err := <-done; err != nil {
				t.Fatalf("round %d: finish: %v", i, err)
			}
		}
	}
}
