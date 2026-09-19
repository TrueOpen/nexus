package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

type scanFailStore struct{ kv.Store }

func (s scanFailStore) Scan(kv.Namespace, func(string, []byte) bool) error {
	return errors.New("injected scan failure")
}

type blockingDeleteStore struct {
	kv.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingDeleteStore) Delete(ns kv.Namespace, key string) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.Store.Delete(ns, key)
}

func TestStopIsIdempotent(t *testing.T) {
	c := NewMem(slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}

func TestHoldRejectsConflictingInferReceipt(t *testing.T) {
	c := NewMem(slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := types.InferReceiptSubmission{
		SessionID: "session", TaskID: "task", OutputHash: []byte("hash"), InferReceiptHash: []byte("receipt-first"),
	}
	if err := c.Hold(first, time.Hour); err != nil {
		t.Fatalf("first Hold: %v", err)
	}
	if err := c.Hold(first, time.Hour); err != nil {
		t.Fatalf("idempotent Hold: %v", err)
	}
	conflict := first
	conflict.InferReceiptHash = []byte("receipt-conflict")
	if err := c.Hold(conflict, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Hold error = %v", err)
	}
	served, err := c.Serve("session", "task", types.AccessPackage)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if string(served.InferReceiptHash) != string(first.InferReceiptHash) {
		t.Fatalf("served infer_receipt_hash = %q", served.InferReceiptHash)
	}
}

func TestHoldWithoutTTLRemainsUntilExplicitRelease(t *testing.T) {
	store := kv.NewMemStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ref := types.InferReceiptSubmission{SessionID: "session", TaskID: "task", InferReceiptHash: []byte("receipt")}
	first := NewKV(log, store)
	if err := first.Hold(ref, 0); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	restored := NewKV(log, store)
	if err := restored.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = restored.Stop(context.Background()) })
	if _, err := restored.Serve("session", "task", types.AccessPackage); err != nil {
		t.Fatalf("Serve after restore: %v", err)
	}
	restored.Release("session", "task")
	if _, err := restored.Serve("session", "task", types.AccessPackage); !errors.Is(err, ErrNotInCustody) {
		t.Fatalf("Serve after Release error = %v", err)
	}
}

func TestStartFailsWhenCustodyScanFails(t *testing.T) {
	c := NewKV(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		scanFailStore{Store: kv.NewMemStore()},
	)
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded after custody scan failure")
	}
}

func TestStopWaitsForInFlightSweep(t *testing.T) {
	store := &blockingDeleteStore{
		Store: kv.NewMemStore(), entered: make(chan struct{}), release: make(chan struct{}),
	}
	c := NewKV(slog.New(slog.NewTextHandler(io.Discard, nil)), store).(*memCustodian)
	c.sweepInterval = time.Millisecond
	c.held[custodyKey("session", "task")] = entry{
		ref:     types.InferReceiptSubmission{SessionID: "session", TaskID: "task"},
		expires: time.Now().Add(-time.Second),
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("sweep did not start")
	}
	stopped := make(chan struct{})
	go func() {
		_ = c.Stop(context.Background())
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned before in-flight sweep completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(store.release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after sweep completed")
	}
}
