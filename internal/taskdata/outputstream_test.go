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
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

func testStreamConfig() OutputStreamConfig {
	return OutputStreamConfig{MaxLeaves: 8, MinFrameBytes: 4, MaxFrameBytes: 16, MaxAttachmentBytes: 8}
}

func streamKey(task string) ObjectKey {
	return ObjectKey{
		TaskHash: testTaskHash, SessionID: testSessionID, TaskID: task,
		Kind: ObjectKindOutput, ContentHash: testContent,
	}
}

// chunkFor produces chunk seq the way the Worker does: text + root after append. Signatures
// are verified by the Service layer and omitted in storage-layer tests.
func chunkFor(acc *mmr.Accumulator, seq uint64, text string) OutputChunk {
	root := acc.Append([]byte(text))
	return OutputChunk{Seq: seq, Text: []byte(text), MMRRoot: root[:], WorkerSignature: bytes.Repeat([]byte{1}, 64)}
}

func streamStoreConfig() Config {
	return Config{
		InlineMaxBytes: 8, ChunkSizeBytes: 16, MaxRangeBytes: 64,
		MaxBlobBytes: 64, SpoolReservationBytes: 128, DiskAcceptWatermarkPercent: 85,
	}
}

func TestOutputStreamAppendFinishAndMetadata(t *testing.T) {
	store, backend, _ := newTestStore(t, streamStoreConfig())
	key := streamKey(testTaskID)
	stream, progress, err := store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	if progress.Received || progress.Sealed || !bytes.Equal(progress.MMRRoot, func() []byte { r := mmr.EmptyRoot(nodecontract.DomainOutputMMRV1); return r[:] }()) {
		t.Fatalf("fresh progress = %+v", progress)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	texts := []string{"hello, ", "world", "!!"} // last chunk shorter than 4 bytes is allowed
	for i, text := range texts {
		root, err := stream.Append(context.Background(), chunkFor(acc, uint64(i), text))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if root != acc.Root() {
			t.Fatalf("append %d root mismatch", i)
		}
	}
	if p := stream.Progress(); !p.Received || p.LastSeq != 2 || p.TotalBytes != 14 || !p.LastFrameShort || p.LeafCount != 3 {
		t.Fatalf("progress after 3 chunks = %+v", p)
	}
	// After a short chunk only Fin may follow.
	if _, err := stream.Append(context.Background(), chunkFor(acc.Clone(), 3, "more")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("chunk after short chunk error = %v", err)
	}
	// The previous step closed the stream; reopen (take over) and resume from the progress.
	stream, progress, err = store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	if progress.LastSeq != 2 || !progress.LastFrameShort {
		t.Fatalf("reopened progress = %+v", progress)
	}
	final := acc.Root()
	if _, err := stream.Finish(context.Background(), OutputFin{FinalSeq: 1, OutputMMRRoot: final[:]}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fin with wrong final_seq error = %v", err)
	}
	stream, _, err = store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("x"))
	if _, err := stream.Finish(context.Background(), OutputFin{FinalSeq: 2, OutputMMRRoot: wrong[:]}); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("fin with wrong root error = %v", err)
	}
	stream, _, err = store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := stream.Finish(context.Background(), OutputFin{FinalSeq: 2, OutputMMRRoot: final[:]})
	if err != nil {
		t.Fatal(err)
	}
	// The object identity (content_hash / semantic_hash) is the MMR root, i.e.
	// receipt.output_hash; the SHA-256 of the concatenated text is only for blob file addressing.
	if meta.State != StateStored || meta.SizeBytes != 14 || meta.SemanticHash != hex.EncodeToString(final[:]) ||
		meta.Key.ContentHash != hex.EncodeToString(final[:]) ||
		meta.OutputMMRRoot != hex.EncodeToString(final[:]) || meta.OutputLeafCount != 3 ||
		len(meta.ChunkLengths) != 3 || meta.ChunkLengths[0] != 7 || meta.ChunkLengths[2] != 2 || meta.MediaType != OutputStreamMediaType {
		t.Fatalf("metadata = %+v", meta)
	}
	// The concatenated text can be read whole (Verifier / offline retrieval path).
	// After finalization the object is addressed by the full object ref: content_hash is the MMR root.
	sealedKey := key
	sealedKey.ContentHash = hex.EncodeToString(final[:])
	// Fin only reaches STORED and reads require READY; do that step here on behalf of FinalizeTaskResult.
	if _, err := store.MarkReady(context.Background(), sealedKey); err != nil {
		t.Fatal(err)
	}
	reader, err := store.OpenRange(context.Background(), sealedKey, 0, 14)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(body) != "hello, world!!" {
		t.Fatalf("blob = %q", body)
	}
	// Opening again after finalization: report progress and conflict.
	if _, progress, err := store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig()); !errors.Is(err, ErrConflict) || !progress.Sealed || progress.LastSeq != 2 {
		t.Fatalf("open after seal = %+v / %v", progress, err)
	}
	// Replay: three chunks + Fin; resume replays only what follows.
	frames, err := store.OutputFrames(context.Background(), key, nil)
	if err != nil || len(frames) != 4 || frames[3].Fin == nil || string(frames[1].Chunk.Text) != "world" {
		t.Fatalf("frames = %d / %v", len(frames), err)
	}
	one := uint64(1)
	frames, _ = store.OutputFrames(context.Background(), key, &one)
	if len(frames) != 2 || frames[0].Chunk.Seq != 2 || frames[1].Fin == nil {
		t.Fatalf("resumed frames = %+v", frames)
	}
	// Stream record and metadata are both in kv.
	if _, found := backend.Get(kv.NSTaskDataOutputStream, streamKeyString(key)); !found {
		t.Fatal("stream record missing")
	}
	// After finalization metadata lives under the full object ref key; progress stays under the stream key.
	if _, found := backend.Get(kv.NSTaskDataMetadata, objectKeyString(sealedKey)); !found {
		t.Fatal("metadata missing")
	}
}

func TestOutputStreamRejectsBadFrames(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	key := streamKey(testTaskID)
	open := func() *OutputStream {
		s, _, err := store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	// seq must start at 0.
	if _, err := open().Append(context.Background(), chunkFor(acc.Clone(), 1, "abcd")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("first seq 1 error = %v", err)
	}
	// Wrong root: DataLoss.
	bad := chunkFor(acc.Clone(), 0, "abcd")
	bad.MMRRoot = bytes.Repeat([]byte{9}, 32)
	if _, err := open().Append(context.Background(), bad); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("wrong root error = %v", err)
	}
	// In Phase 0 both attachment and attachment_signature must be empty: either non-empty
	// is fail-closed. These fields cannot enter the MMR leaves, so admitting them would let
	// uncommitted bytes ride along with the signed stream.
	bad = chunkFor(acc.Clone(), 0, "abcd")
	bad.AttachmentSignature = []byte{1}
	if _, err := open().Append(context.Background(), bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("attachment signature without attachment error = %v", err)
	}
	bad = chunkFor(acc.Clone(), 0, "abcd")
	bad.Attachment = []byte{1}
	if _, err := open().Append(context.Background(), bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("attachment without signature error = %v", err)
	}
	bad = chunkFor(acc.Clone(), 0, "abcd")
	bad.Attachment = []byte{1}
	bad.AttachmentSignature = bytes.Repeat([]byte{2}, 64)
	if _, err := open().Append(context.Background(), bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("signed attachment error = %v", err)
	}
	// Over the per-chunk limit: ResourceExhausted.
	if _, err := open().Append(context.Background(), chunkFor(acc.Clone(), 0, "0123456789abcdefg")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversize frame error = %v", err)
	}
	// A short chunk may only be the last one: a Chunk after it is rejected (see the Append test); the short chunk itself is accepted and marked.
	stream := open()
	if _, err := stream.Append(context.Background(), chunkFor(acc, 0, "ab")); err != nil {
		t.Fatal(err)
	}
	if !stream.Progress().LastFrameShort {
		t.Fatal("short frame must be flagged")
	}
	// Leaf count limit.
	store2, _, _ := newTestStore(t, testStoreConfig())
	cfg := testStreamConfig()
	cfg.MaxLeaves = 2
	s2, _, _ := store2.OpenOutputStream(context.Background(), key, "worker-1", cfg)
	acc2, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i := 0; i < 2; i++ {
		if _, err := s2.Append(context.Background(), chunkFor(acc2, uint64(i), "abcd")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s2.Append(context.Background(), chunkFor(acc2.Clone(), 2, "abcd")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("leaf limit error = %v", err)
	}
}

func TestOutputStreamTakeoverAndRestart(t *testing.T) {
	root := t.TempDir()
	backend, err := kv.NewPebble(filepath.Join(root, "kv"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	newStore := func() *Store {
		s, err := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(root, "objects"), backend, testStoreConfig())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	store := newStore()
	key := streamKey(testTaskID)
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	first, _, err := store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Append(context.Background(), chunkFor(acc, 0, "abcd")); err != nil {
		t.Fatal(err)
	}
	// A new connection takes over: further writes on the old stream are rejected, received chunks are not rewritten.
	second, progress, err := store.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil || !progress.Received || progress.LastSeq != 0 {
		t.Fatalf("takeover = %+v / %v", progress, err)
	}
	if _, err := first.Append(context.Background(), chunkFor(acc.Clone(), 1, "efgh")); !errors.Is(err, ErrConflict) {
		t.Fatalf("superseded stream error = %v", err)
	}
	if _, err := second.Append(context.Background(), chunkFor(acc, 1, "efgh")); err != nil {
		t.Fatal(err)
	}
	// Another uploader cannot take over someone else's stream.
	if _, _, err := store.OpenOutputStream(context.Background(), key, "worker-2", testStreamConfig()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign uploader error = %v", err)
	}
	// "Process restart": a new Store instance runs recovery first; progress is read back from kv, not recomputed; unrecorded extra bytes in the spool are truncated.
	second.Close()
	spool := store.streamPath(second.record.SpoolID)
	f, _ := os.OpenFile(spool, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("junk")
	_ = f.Close()
	restarted := newStore()
	if err := restarted.recoverOutputStreams(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool); err != nil {
		t.Fatal("in-progress spool must survive recovery")
	}
	resumed, progress, err := restarted.OpenOutputStream(context.Background(), key, "worker-1", testStreamConfig())
	if err != nil || progress.LastSeq != 1 || progress.TotalBytes != 8 {
		t.Fatalf("resumed progress = %+v / %v", progress, err)
	}
	if !bytes.Equal(progress.MMRRoot, func() []byte { r := acc.Root(); return r[:] }()) {
		t.Fatal("resumed root must equal the worker's root at the same seq")
	}
	if _, err := resumed.Append(context.Background(), chunkFor(acc, 2, "ij")); err != nil {
		t.Fatal(err)
	}
	final := acc.Root()
	meta, err := resumed.Finish(context.Background(), OutputFin{FinalSeq: 2, OutputMMRRoot: final[:]})
	if err != nil {
		t.Fatal(err)
	}
	// The object identity is the MMR root (output_hash), not the SHA-256 of the concatenated text; the latter is only for blob addressing.
	if meta.Key.ContentHash != hex.EncodeToString(final[:]) || meta.SemanticHash != meta.Key.ContentHash ||
		meta.OutputMMRRoot != meta.Key.ContentHash || meta.SizeBytes != 10 || meta.OutputLeafCount != 3 {
		t.Fatalf("metadata after restart = %+v", meta)
	}
	blob := sha256.Sum256([]byte("abcdefghij"))
	if _, err := os.Stat(restarted.blobPath(hex.EncodeToString(blob[:]))); err != nil {
		t.Fatalf("blob must be content-addressed by sha256(text): %v", err)
	}
	// Orphan spools are removed during recovery.
	orphan := restarted.streamPath("orphan")
	_ = os.WriteFile(orphan, []byte("x"), 0o600)
	if err := newStore().recoverOutputStreams(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan spool must be removed")
	}
}

func TestOutputDispatcherReplayAndOverflow(t *testing.T) {
	d := NewOutputDispatcher(2)
	key := streamKey(testTaskID)
	sub := d.Subscribe(key)
	other := d.Subscribe(streamKey("other-task"))
	for i := 0; i < 3; i++ {
		seq := uint64(i)
		d.Publish(key, OutputFrame{Chunk: &OutputChunk{Seq: seq}})
	}
	// Buffer of 2, the third frame overflows: the subscriber is disconnected.
	got := 0
	for range sub.Frames {
		got++
	}
	if got != 2 || !sub.Overflowed() {
		t.Fatalf("got %d frames, overflowed=%v", got, sub.Overflowed())
	}
	select {
	case <-other.Frames:
		t.Fatal("frames must not cross tasks")
	default:
	}
	d.Stop()
	if _, ok := <-other.Frames; ok {
		t.Fatal("stop must close subscribers")
	}
	if late := d.Subscribe(key); func() bool { _, ok := <-late.Frames; return ok }() {
		t.Fatal("subscribe after stop must be closed")
	}
}

// One record per chunk, attachments not in kv: the progress record grows only with the
// number of MMR peaks (O(log n)), not linearly with the chunk count. A single record for
// the whole stream would rewrite every earlier chunk's signature and root on each new chunk,
// O(n^2) write amplification. Chunk records must be one per chunk: a whole-stream record
// would force a full rewrite per chunk and the progress record would grow to thousands of
// bytes. Attachments used to be verified here too; since Phase 0 attachment is fail-closed
// (see TestOutputStreamAppendRejects), so only the chunk records themselves remain.
func TestOutputStreamFramesArePerSeq(t *testing.T) {
	const chunks = 64
	storeCfg := streamStoreConfig()
	storeCfg.MaxBlobBytes = 4096
	storeCfg.MaxRangeBytes = 4096
	storeCfg.SpoolReservationBytes = 8192
	streamCfg := testStreamConfig()
	streamCfg.MaxLeaves = chunks
	store, backend, _ := newTestStore(t, storeCfg)
	key := streamKey(testTaskID)
	stream, _, err := store.OpenOutputStream(context.Background(), key, "worker-1", streamCfg)
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	var progressSize int
	for i := 0; i < chunks; i++ {
		if _, err := stream.Append(context.Background(), chunkFor(acc, uint64(i), "abcd")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		raw, found := backend.Get(kv.NSTaskDataOutputStream, streamKeyString(key))
		if !found {
			t.Fatal("progress record missing")
		}
		progressSize = len(raw)
	}
	// With 64 chunks there are at most 6 peaks (popcount bound) and the progress record is
	// a few hundred bytes; a whole-stream record would be thousands of bytes here and be
	// fully rewritten per chunk.
	if progressSize > 800 {
		t.Fatalf("progress record is %d bytes after %d chunks; frame records must be separate", progressSize, chunks)
	}
	frames := 0
	if err := backend.Scan(kv.NSTaskDataOutputFrame, func(_ string, _ []byte) bool { frames++; return true }); err != nil {
		t.Fatal(err)
	}
	if frames != chunks {
		t.Fatalf("frame records = %d, want %d", frames, chunks)
	}
	// Chunks replay unchanged as frames.
	replayed, err := store.OutputFrames(context.Background(), key, nil)
	if err != nil || len(replayed) != chunks {
		t.Fatalf("frames = %d / %v", len(replayed), err)
	}
	if replayed[1].Chunk.Seq != 1 || string(replayed[1].Chunk.Text) != "abcd" {
		t.Fatalf("frame round-trip = %+v", replayed[1].Chunk)
	}
	// Chunk records are removed together with the object.
	if err := store.DeleteObject(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	frames = 0
	_ = backend.Scan(kv.NSTaskDataOutputFrame, func(_ string, _ []byte) bool { frames++; return true })
	if frames != 0 {
		t.Fatalf("frame records after delete = %d", frames)
	}
}

// Opening a stream goes through the same capacity reservation and disk watermark checks as whole-object upload: concurrent streams must not write past the watermark.
func TestOutputStreamOpenHonoursCapacityAndWatermark(t *testing.T) {
	cfg := streamStoreConfig()
	cfg.SpoolReservationBytes = cfg.MaxBlobBytes + 8 // enough for the worst case of only one stream
	store, _, _ := newTestStore(t, cfg)
	first, _, err := store.OpenOutputStream(context.Background(), streamKey(testTaskID), "worker-1", testStreamConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenOutputStream(context.Background(), streamKey(testOtherTaskID), "worker-1", testStreamConfig()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second concurrent stream error = %v", err)
	}
	// Closing the first stream releases its reservation.
	first.Close()
	second, _, err := store.OpenOutputStream(context.Background(), streamKey(testOtherTaskID), "worker-1", testStreamConfig())
	if err != nil {
		t.Fatalf("stream after release: %v", err)
	}
	second.Close()

	full, _, _ := newTestStore(t, streamStoreConfig(), WithDiskUsage(func(string) (uint64, uint64, error) {
		return 1 << 20, 1 << 20, nil // disk full
	}))
	if _, _, err := full.OpenOutputStream(context.Background(), streamKey(testTaskID), "worker-1", testStreamConfig()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("watermark error = %v", err)
	}
}
