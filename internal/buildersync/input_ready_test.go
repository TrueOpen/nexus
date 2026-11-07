package buildersync

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// queuedInputChunks counts the input chunk items in D's sync outbox.
func (e *env) queuedInputChunks() int {
	e.t.Helper()
	n := 0
	err := e.dStore.Scan(kv.NSBuilderSyncOutbox, func(key string, val []byte) bool {
		if strings.HasPrefix(key, outItemPrefix) {
			var item nexusv1.BuilderSyncItemV1
			if proto.Unmarshal(val, &item) == nil && item.GetInputChunk() != nil {
				n++
			}
		}
		return true
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// OpenTask hands the order to the dispatcher before it marks the input ready and indexes it: a
// change drained in between finds no input. That is not a failure: nothing is logged above debug,
// no failure is counted, and the next drain sends the change with its input.
func TestChangeBeforeTheInputIsReadyWaitsForIt(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	var logs bytes.Buffer
	e.s.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e.s.cfg.Inputs = StoredInputs{Store: e.dData}
	ctx := context.Background()
	inputHash := hex.EncodeToString(f.order.GetInputHash())
	header := taskdata.UploadHeader{
		Key: taskdata.ObjectKey{
			TaskHash: hex.EncodeToString(f.taskHash), SessionID: f.sessionHex(), TaskID: f.taskHex(), Kind: taskdata.ObjectKindInput,
			ContentHash: taskdata.InputContentHash(inputHash),
		},
		SizeBytes: uint64(len(f.input)), SemanticHash: inputHash, MediaType: "text/plain", RetainUntilHeight: 1000,
	}
	// The input is stored (PREPARED) but not marked ready yet, as while OnOrder runs.
	upload, err := e.dData.Begin(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(f.input); offset += int(e.dData.ChunkSize()) {
		if err := upload.WriteChunk(f.input[offset:min(offset+int(e.dData.ChunkSize()), len(f.input))]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := upload.Prepare(ctx); err != nil {
		t.Fatal(err)
	}

	e.s.OrderChanged(f.issued())
	e.s.drain()
	if n := e.queuedInputChunks(); n != 0 {
		t.Fatalf("%d input chunks queued before the input is ready", n)
	}
	if c := e.s.Counts(); c.Failures != 0 {
		t.Fatalf("counted %d failures for an input not ready yet", c.Failures)
	}
	if logs.Len() != 0 {
		t.Fatalf("logged for an input not ready yet: %s", logs.String())
	}

	if _, err := e.dData.MarkReady(ctx, header.Key); err != nil {
		t.Fatal(err)
	}
	// Any later drain (another change wakes it) applies the change again.
	e.s.drain()
	if n := e.queuedInputChunks(); n == 0 {
		t.Fatal("input not queued once ready")
	}
	if c := e.s.Counts(); c.Failures != 0 {
		t.Fatalf("counted %d failures", c.Failures)
	}
	e.s.qmu.Lock()
	waiting := len(e.s.redo)
	e.s.qmu.Unlock()
	if waiting != 0 {
		t.Fatalf("%d changes still waiting after the input was sent", waiting)
	}
}

// A change still missing its input after maxChangeRetries prune ticks is given up as before.
func TestChangeWhoseInputNeverComesIsGivenUp(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	var logs bytes.Buffer
	e.s.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e.s.cfg.Inputs = StoredInputs{Store: e.dData}
	e.s.OrderChanged(f.issued())
	e.s.drain()
	for i := 0; i < maxChangeRetries; i++ {
		e.s.retryFailed()
		e.s.drain()
	}
	if !strings.Contains(logs.String(), "given up after retries") {
		t.Fatalf("change not given up: %s", logs.String())
	}
}

// A change whose input stays missing is quiet only for the first half of its prune ticks: then it
// is logged once as a warning (the input may be gone), however often drains apply it again, and
// it is given up after maxChangeRetries prune ticks.
func TestChangeWaitingForItsInputWarnsOnceHalfwayThrough(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	var logs bytes.Buffer
	e.s.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e.s.cfg.Inputs = StoredInputs{Store: e.dData}
	e.s.OrderChanged(f.issued())
	e.s.drain()
	const warning = "order change still waits for its input"
	for tick := 1; tick <= maxChangeRetries; tick++ {
		e.s.retryFailed()
		e.s.drain()
		e.s.drain() // drains between prune ticks apply it again too
		warned := strings.Count(logs.String(), warning)
		switch {
		case tick < maxChangeRetries/2 && logs.Len() != 0:
			t.Fatalf("prune tick %d: logged while quiet: %s", tick, logs.String())
		case tick >= maxChangeRetries/2 && warned != 1:
			t.Fatalf("prune tick %d: warned %d times, want once: %s", tick, warned, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "level=WARN msg=\""+warning) {
		t.Fatalf("not a warning: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "given up after retries") {
		t.Fatalf("change not given up: %s", logs.String())
	}
}
