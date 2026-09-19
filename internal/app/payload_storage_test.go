package app

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
)

func TestNewRejectsInvalidPayloadStorageAndReleasesKV(t *testing.T) {
	cfg := config.Config{
		DataDir: t.TempDir(),
		TaskData: config.TaskDataConfig{
			InlineMaxBytes: 1024, ChunkSizeBytes: 1024, MaxRangeBytes: 1024, MaxBlobBytes: 1024,
			SpoolReservationBytes: 4096, DiskAcceptWatermarkPercent: 85,
			RequestTTLBlocks: 20, RetentionLeaseBlocks: 1000, SweepInterval: time.Minute,
		},
		PayloadStorage: config.PayloadStorageConfig{
			MaxBytes: 0,
		},
		OutputDelivery: config.OutputDeliveryConfig{
			MaxBytes: 1, PlaintextTTL: time.Hour, TombstoneTTL: time.Hour, SweepInterval: time.Minute,
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(cfg, log); err == nil || !strings.Contains(err.Error(), "payload storage") {
		t.Fatalf("New error = %v, want payload storage validation", err)
	}

	store, err := kv.NewPebble(filepath.Join(cfg.DataDir, "kv"), log)
	if err != nil {
		t.Fatalf("reopen Pebble after failed New: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close reopened Pebble: %v", err)
	}
}
