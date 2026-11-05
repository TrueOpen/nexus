package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/buildersync"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// A re-signed retry of an order whose dispatch failed keeps its task_id with a new task_hash: the
// Worker that wins the retry is served the retry's input, not the failed version's, and storing
// the retry logs no error.
func TestRetriedOrderVersionIsServedItsOwnInput(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	data, err := taskdata.NewStore(log, t.TempDir(), kv.NewMemStore(), taskdata.Config{
		InlineMaxBytes: 64, ChunkSizeBytes: 16, MaxRangeBytes: 64, MaxBlobBytes: 64, SpoolReservationBytes: 256, DiskAcceptWatermarkPercent: 85,
	}, taskdata.WithDiskUsage(func(string) (uint64, uint64, error) { return 1 << 40, 0, nil }))
	if err != nil {
		t.Fatal(err)
	}
	sessionID, taskID := strings.Repeat("2b", 32), strings.Repeat("1a", 32)
	put := func(taskHash string, input []byte) {
		t.Helper()
		digest := sha256.Sum256(input)
		inputHash := hex.EncodeToString(digest[:])
		header := taskdata.UploadHeader{
			Key: taskdata.ObjectKey{TaskHash: taskHash, SessionID: sessionID, TaskID: taskID, Kind: taskdata.ObjectKindInput,
				ContentHash: taskdata.InputContentHash(inputHash)},
			SizeBytes: uint64(len(input)), SemanticHash: inputHash, MediaType: "text/plain", RetainUntilHeight: 100,
		}
		if err := (buildersync.StoredInputs{Store: data}).PutInput(context.Background(), header, input); err != nil {
			t.Fatal(err)
		}
	}
	failed, retried := strings.Repeat("d6", 32), strings.Repeat("0f", 32)
	put(failed, []byte("input of the failed version"))
	put(retried, []byte("input of the retried version"))

	inputs := storedInputs{store: data}
	reader, size, err := inputs.OpenInput(context.Background(), sessionID, taskID, retried)
	if err != nil {
		t.Fatalf("input of the retried version: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || string(got) != "input of the retried version" || size != uint64(len(got)) {
		t.Fatalf("input of the retried version = %q (%d bytes), %v", got, size, err)
	}
	if _, _, err := inputs.OpenInput(context.Background(), sessionID, taskID, failed); err == nil {
		t.Fatal("the failed version's input is still served as the task's")
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("storing the retry logged an error: %s", logs.String())
	}
}
