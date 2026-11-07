package taskdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// syncCount is what one step cost in durability: synced and deferred kv writes, file and
// directory fsyncs.
type syncCount struct {
	Synced, Deferred, Files, Dirs int
}

func (c syncCount) minus(o syncCount) syncCount {
	return syncCount{c.Synced - o.Synced, c.Deferred - o.Deferred, c.Files - o.Files, c.Dirs - o.Dirs}
}

// syncCounter counts the fsyncs a Store makes and the writes of its kvtest backend.
type syncCounter struct {
	backend     *kvtest.Store
	mu          sync.Mutex
	files, dirs int
}

func (c *syncCounter) options() []Option {
	return []Option{
		WithDirectorySync(func(path string) error {
			c.mu.Lock()
			c.dirs++
			c.mu.Unlock()
			return syncDirectory(path)
		}),
		WithFileSync(func(f *os.File) error {
			c.mu.Lock()
			c.files++
			c.mu.Unlock()
			return f.Sync()
		}),
	}
}

func (c *syncCounter) now() syncCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	return syncCount{Synced: c.backend.Synced(), Deferred: c.backend.Deferred(), Files: c.files, Dirs: c.dirs}
}

// newCountingStore opens a Store over a kvtest backend in root, counting its fsyncs.
func newCountingStore(t *testing.T, root string, backend *kvtest.Store) (*Store, *syncCounter) {
	t.Helper()
	counter := &syncCounter{backend: backend}
	store, err := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(root, "objects"), backend, testStoreConfig(), counter.options()...)
	if err != nil {
		t.Fatal(err)
	}
	return store, counter
}

// TestInputIntakeSyncCount pins what storing one OpenTask input of two chunks costs: up to
// PrepareInput, which comes before the order goes to the coordinator, and MarkInputReady, which
// comes after.
func TestInputIntakeSyncCount(t *testing.T) {
	store, counter := newCountingStore(t, t.TempDir(), kvtest.New())
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
	intake := counter.now()
	if want := (syncCount{Synced: 0, Deferred: 3, Files: 1, Dirs: 1}); intake != want {
		t.Fatalf("input intake cost %+v, want %+v", intake, want)
	}
	if _, err := service.MarkInputReady(ctx, header.Key); err != nil {
		t.Fatal(err)
	}
	if got, want := counter.now().minus(intake), (syncCount{Synced: 1}); got != want {
		t.Fatalf("MarkInputReady cost %+v, want %+v", got, want)
	}
}

// TestOpenTaskNonceSyncCount pins what consuming an OpenTask request nonce costs.
func TestOpenTaskNonceSyncCount(t *testing.T) {
	fx := newAuthorizerFixture(t)
	backend := kvtest.New()
	a, err := NewAuthorizer(fx.authorizer.cfg, backend, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorizeOpenTaskRequest(context.Background(), fx.user.Address(), bytes.Repeat([]byte{3}, 16), 110, 1000); err != nil {
		t.Fatal(err)
	}
	if backend.Synced() != 0 || backend.Deferred() != 1 {
		t.Fatalf("OpenTask nonce cost synced %d deferred %d, want 0 and 1", backend.Synced(), backend.Deferred())
	}
}

// An OpenTask nonce survives a crash once the request's own synced write (the order's commit)
// followed it, and a clean restart either way. A crash before that write loses the nonce together
// with everything the request did: the replay is then the same request again.
func TestOpenTaskNonceCrashRecovery(t *testing.T) {
	fx := newAuthorizerFixture(t)
	ctx := context.Background()
	backend := kvtest.New()
	a, err := NewAuthorizer(fx.authorizer.cfg, backend, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{4}, 16)
	if err := a.AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110, 1000); err != nil {
		t.Fatal(err)
	}
	reopen := func(store kv.Store) *Authorizer {
		t.Helper()
		reopened, err := NewAuthorizer(fx.authorizer.cfg, store, fx.authority, fx.service)
		if err != nil {
			t.Fatal(err)
		}
		return reopened
	}
	if err := reopen(backend).AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110, 1000); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after a clean restart = %v", err)
	}
	if err := reopen(backend.Crash()).AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110, 1000); err != nil {
		t.Fatalf("a request that left nothing durable is judged afresh after a crash: %v", err)
	}
	if err := backend.Set(kv.NSInflight, "order/commit", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := reopen(backend.Crash()).AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110, 1000); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after a crash past the order's commit = %v", err)
	}
}
