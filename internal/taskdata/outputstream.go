package taskdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// Storage semantics of the streamed OUTPUT upload (streamed output delivery design §5.2-§5.5,
// Data Plane & Evidence Transport §9).
//
// A Task has at most one write stream at a time. When a chunk arrives: the text is appended to the
// stream's spool file and the attachment to the .attach file of the same name, each fsynced; then
// "the record of that chunk" and "the progress of the whole stream" are written into kv in one
// atomic batch (progress and chunk record in the same transaction, see design §5.4).
//
// There is one chunk record per chunk (key = object key|zero-padded seq), not one record per stream:
// the latter would rewrite the signatures and roots of all previous chunks on every chunk received,
// which is O(n²) write amplification. Attachment bytes do not go into kv; the chunk record only
// keeps their offset and length.
//
// After Fin the spool is promoted to a content-addressed blob, the metadata becomes READY,
// output_hash is filled with the MMR root, and the chunk boundaries and leaf count are stored with
// it for GetTaskDataMetadata to return.
//
// Persisted chunks are never rolled back: a failed check only closes the stream, and after
// reconnecting the Worker resumes from the acknowledged progress (§9.5).

// OutputStreamConfig holds the limits that decide whether a stream is valid (design §6): every
// nexus in the network must use the same values.
type OutputStreamConfig struct {
	// MaxLeaves is the upper bound on the number of chunks (parameter max_output_mmr_leaves).
	MaxLeaves uint64
	// MinFrameBytes is the minimum byte count of a single chunk (parameter
	// min_output_stream_frame_bytes), except for the last chunk.
	MinFrameBytes uint64
	// MaxFrameBytes is the upper bound on the text of a single chunk; exceeding it is
	// ResourceExhausted.
	MaxFrameBytes uint64
	// MaxAttachmentBytes is the upper bound on the attachment of a single frame; 0 means attachments
	// are not accepted.
	MaxAttachmentBytes uint64
}

func (c OutputStreamConfig) validate() error {
	if c.MaxLeaves == 0 || c.MaxFrameBytes == 0 {
		return fmt.Errorf("%w: output stream limits must be positive", ErrMalformed)
	}
	if c.MinFrameBytes > c.MaxFrameBytes {
		return fmt.Errorf("%w: output stream min frame exceeds max frame", ErrMalformed)
	}
	return nil
}

// OutputChunk is one chunk of OUTPUT text with its cumulative commitment (wire OutputChunkV1).
type OutputChunk struct {
	Seq                 uint64
	Text                []byte
	MMRRoot             []byte
	WorkerSignature     []byte
	Attachment          []byte
	AttachmentSignature []byte
}

// OutputFin is the closing frame of a stream (wire OutputFinV1). FinishReason and WorkerSignature
// are stored and replayed as received so subscribers see the Worker's frame byte-identically
// (TRUEOPEN_OUTPUT_FIN_V1); the Builder does not verify the signature yet.
type OutputFin struct {
	FinalSeq        uint64
	OutputMMRRoot   []byte
	FinishReason    uint32
	WorkerSignature []byte
}

// OutputFrame is one frame forwarded to subscribers: either a Chunk or a Fin, never both.
type OutputFrame struct {
	Chunk *OutputChunk
	Fin   *OutputFin
}

// OutputStreamProgress is the Builder's received progress for a stream (the internal form of wire
// OutputStreamProgressV1). Received being false means no chunk has been received at all, and LastSeq
// is meaningless in that case.
type OutputStreamProgress struct {
	Received       bool
	LastSeq        uint64
	MMRRoot        []byte
	LastFrameShort bool
	TotalBytes     uint64
	LeafCount      uint64
	Sealed         bool
}

// outputFrameRecord is the persisted record of one chunk (one record per chunk). The text and the
// attachment bytes are each read from their file by offset.
type outputFrameRecord struct {
	Seq                 uint64 `json:"seq"`
	Offset              uint64 `json:"offset"`
	Length              uint32 `json:"length"`
	Root                string `json:"root"`
	Signature           []byte `json:"signature"`
	AttachmentOffset    uint64 `json:"attachment_offset,omitempty"`
	AttachmentLength    uint32 `json:"attachment_length,omitempty"`
	AttachmentSignature []byte `json:"attachment_signature,omitempty"`
}

// outputStreamRecord is the progress of one stream. The chunk records are not here; see
// NSTaskDataOutputFrame.
type outputStreamRecord struct {
	Key            ObjectKey `json:"key"`
	Uploader       string    `json:"uploader"`
	SpoolID        string    `json:"spool_id"`
	Received       bool      `json:"received"`
	LastSeq        uint64    `json:"last_seq"`
	TotalBytes     uint64    `json:"total_bytes"`
	AttachBytes    uint64    `json:"attach_bytes"`
	LeafCount      uint64    `json:"leaf_count"`
	Peaks          []string  `json:"peaks"`
	LastFrameShort bool      `json:"last_frame_short"`
	// ContentHash is filled in at Fin (= the MMR root, i.e. output_hash): once finalized the object
	// is located by its full object ref.
	ContentHash string `json:"content_hash,omitempty"`
	Sealed      bool   `json:"sealed"`
	// The Worker's Fin fields as received, kept for byte-identical replay to subscribers.
	FinishReason       uint32 `json:"finish_reason,omitempty"`
	FinWorkerSignature []byte `json:"fin_worker_signature,omitempty"`
}

func (r outputStreamRecord) progress(root mmr.Hash) OutputStreamProgress {
	return OutputStreamProgress{
		Received: r.Received, LastSeq: r.LastSeq, MMRRoot: root[:], LastFrameShort: r.LastFrameShort,
		TotalBytes: r.TotalBytes, LeafCount: r.LeafCount, Sealed: r.Sealed,
	}
}

func (r outputStreamRecord) accumulator() (*mmr.Accumulator, error) {
	peaks := make([]mmr.Hash, 0, len(r.Peaks))
	for _, encoded := range r.Peaks {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("%w: persisted MMR peak", ErrStorage)
		}
		var h mmr.Hash
		copy(h[:], raw)
		peaks = append(peaks, h)
	}
	acc, err := mmr.Restore(nodecontract.DomainOutputMMRV1, r.LeafCount, peaks)
	if err != nil {
		return nil, fmt.Errorf("%w: restore MMR: %v", ErrStorage, err)
	}
	return acc, nil
}

// OutputStream is one in-progress write stream. It is not a concurrency-safe writer; the caller
// calls it serially in frame order.
type OutputStream struct {
	store      *Store
	key        ObjectKey
	encoded    string
	cfg        OutputStreamConfig
	record     outputStreamRecord
	acc        *mmr.Accumulator
	file       *os.File
	attach     *os.File
	hash       hash.Hash
	closed     bool
	superseded bool
}

func (s *Store) streamPath(id string) string { return filepath.Join(s.root, "stream", id+".stream") }

func (s *Store) streamAttachPath(id string) string {
	return filepath.Join(s.root, "stream", id+".attach")
}

func outputFrameKey(encoded string, seq uint64) string {
	return fmt.Sprintf("%s|%020d", encoded, seq)
}

// streamPendingLocked is the sum over all active streams of "how many bytes they may still write in
// the worst case": it takes part in the capacity and watermark decisions together with whole-object
// upload reservations, so that several concurrent streams cannot write the disk past the
// watermark.
func (s *Store) streamPendingLocked() uint64 {
	var pending uint64
	for _, stream := range s.outputStreams {
		pending += stream.pendingBytes()
	}
	return pending
}

func (st *OutputStream) pendingBytes() uint64 {
	if st.store.cfg.MaxBlobBytes <= st.record.TotalBytes {
		return 0
	}
	return st.store.cfg.MaxBlobBytes - st.record.TotalBytes
}

// admitStreamLocked performs the same capacity reservation and disk watermark checks as a
// whole-object upload, based on "this stream may still write pending bytes in the worst case"
// (design §5.4 reuses the existing Task data storage rules).
func (s *Store) admitStreamLocked(pending uint64) error {
	committed := s.reserved + s.streamPendingLocked()
	if committed > s.cfg.SpoolReservationBytes || pending > s.cfg.SpoolReservationBytes-committed {
		return fmt.Errorf("%w: spool reservation exhausted", ErrCapacity)
	}
	total, used, err := s.diskUsage(s.root)
	if err != nil {
		return fmt.Errorf("%w: inspect filesystem: %v", ErrStorage, err)
	}
	if exceedsWatermark(total, used, s.remainingReservedLocked()+s.streamPendingLocked(), pending, s.cfg.DiskAcceptWatermarkPercent) {
		return fmt.Errorf("%w: disk acceptance watermark", ErrCapacity)
	}
	return nil
}

// OpenOutputStream opens (or takes over) the write stream of key and returns the current progress.
//
// If a complete OUTPUT object already exists or the stream is already sealed: it returns the
// progress and ErrConflict (on the wire: return Progress, then end with AlreadyExists) with a nil
// stream. If the same Task already has an in-progress stream: the new stream takes over, any later
// operation on the old one returns ErrConflict, and the chunks it already received are not
// rewritten.
func (s *Store) OpenOutputStream(_ context.Context, key ObjectKey, uploader string, cfg OutputStreamConfig) (*OutputStream, OutputStreamProgress, error) {
	// A stream in transfer is located by (task_hash, session_id, task_id): content_hash can only be
	// computed at Fin, so a full object ref cannot be required here.
	if err := validateStreamKey(key); err != nil {
		return nil, OutputStreamProgress{}, err
	}
	if key.Kind != ObjectKindOutput || !canonicalText(uploader) {
		return nil, OutputStreamProgress{}, fmt.Errorf("%w: output stream key", ErrMalformed)
	}
	if err := cfg.validate(); err != nil {
		return nil, OutputStreamProgress{}, err
	}
	encoded := streamKeyString(key)
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found, err := s.tombstoneRecord(encoded); err != nil {
		return nil, OutputStreamProgress{}, err
	} else if found {
		return nil, OutputStreamProgress{}, fmt.Errorf("%w: object key was deleted", ErrConflict)
	}
	record, found, err := s.outputStreamRecord(encoded)
	if err != nil {
		return nil, OutputStreamProgress{}, err
	}
	if found && record.Sealed {
		acc, err := record.accumulator()
		if err != nil {
			return nil, OutputStreamProgress{}, err
		}
		return nil, record.progress(acc.Root()), fmt.Errorf("%w: output stream is sealed", ErrConflict)
	}
	if _, exists, err := s.metadataRecord(encoded); err != nil {
		return nil, OutputStreamProgress{}, err
	} else if exists {
		// The old whole-object upload path has already stored a complete OUTPUT: there is no stream
		// progress to report, only the conflict.
		return nil, OutputStreamProgress{Sealed: true}, fmt.Errorf("%w: output object already committed", ErrConflict)
	}
	if found && record.Uploader != uploader {
		return nil, OutputStreamProgress{}, fmt.Errorf("%w: output stream uploader", ErrUnauthorized)
	}
	// Release the old stream's reservation before taking over, otherwise the same stream would be
	// counted twice.
	if active, ok := s.outputStreams[encoded]; ok {
		active.supersedeLocked()
	}
	pending := s.cfg.MaxBlobBytes
	if found && s.cfg.MaxBlobBytes > record.TotalBytes {
		pending = s.cfg.MaxBlobBytes - record.TotalBytes
	}
	if err := s.admitStreamLocked(pending); err != nil {
		return nil, OutputStreamProgress{}, err
	}

	stream := &OutputStream{store: s, key: key, encoded: encoded, cfg: cfg, hash: sha256.New()}
	if found {
		acc, err := record.accumulator()
		if err != nil {
			return nil, OutputStreamProgress{}, err
		}
		file, attach, err := s.reopenStreamFiles(record)
		if err != nil {
			return nil, OutputStreamProgress{}, err
		}
		if _, err := io.Copy(stream.hash, io.NewSectionReader(file, 0, int64(record.TotalBytes))); err != nil {
			_ = file.Close()
			_ = attach.Close()
			return nil, OutputStreamProgress{}, fmt.Errorf("%w: rehash stream spool: %v", ErrStorage, err)
		}
		if _, err := file.Seek(int64(record.TotalBytes), io.SeekStart); err != nil {
			_ = file.Close()
			_ = attach.Close()
			return nil, OutputStreamProgress{}, fmt.Errorf("%w: seek stream spool: %v", ErrStorage, err)
		}
		stream.record, stream.acc, stream.file, stream.attach = record, acc, file, attach
	} else {
		id, err := randomID()
		if err != nil {
			return nil, OutputStreamProgress{}, fmt.Errorf("%w: stream id: %v", ErrStorage, err)
		}
		file, attach, err := s.createStreamFiles(id)
		if err != nil {
			return nil, OutputStreamProgress{}, err
		}
		acc, err := mmr.New(nodecontract.DomainOutputMMRV1)
		if err != nil {
			_ = file.Close()
			_ = attach.Close()
			return nil, OutputStreamProgress{}, fmt.Errorf("%w: %v", ErrStorage, err)
		}
		stream.record = outputStreamRecord{Key: key, Uploader: uploader, SpoolID: id}
		stream.acc, stream.file, stream.attach = acc, file, attach
		if err := s.persistOutputStreamRecord(encoded, stream.record); err != nil {
			_ = file.Close()
			_ = attach.Close()
			_ = os.Remove(s.streamPath(id))
			_ = os.Remove(s.streamAttachPath(id))
			return nil, OutputStreamProgress{}, err
		}
	}
	s.outputStreams[encoded] = stream
	return stream, stream.record.progress(stream.acc.Root()), nil
}

func (s *Store) createStreamFiles(id string) (*os.File, *os.File, error) {
	path := s.streamPath(id)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: create stream spool: %v", ErrStorage, err)
	}
	attach, err := os.OpenFile(s.streamAttachPath(id), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, nil, fmt.Errorf("%w: create stream attachment spool: %v", ErrStorage, err)
	}
	if err := s.directorySync(filepath.Dir(path)); err != nil {
		_ = file.Close()
		_ = attach.Close()
		_ = os.Remove(path)
		_ = os.Remove(s.streamAttachPath(id))
		return nil, nil, fmt.Errorf("%w: sync stream directory: %v", ErrStorage, err)
	}
	return file, attach, nil
}

// reopenStreamFiles reopens the files of a stream. The progress is authoritative: bytes in the spool
// beyond the progress are writes that were never recorded (a crash before the batch write) and are
// truncated.
func (s *Store) reopenStreamFiles(record outputStreamRecord) (*os.File, *os.File, error) {
	file, err := os.OpenFile(s.streamPath(record.SpoolID), os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reopen stream spool: %v", ErrStorage, err)
	}
	// The attachment file is opened with O_CREATE: a stream that has not received any attachment may
	// not have this file (an old record, or it was cleaned up), and a missing file should not make
	// resumption fail.
	attach, err := os.OpenFile(s.streamAttachPath(record.SpoolID), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: reopen stream attachment spool: %v", ErrStorage, err)
	}
	for _, item := range []struct {
		file *os.File
		size uint64
		name string
	}{{file, record.TotalBytes, "spool"}, {attach, record.AttachBytes, "attachment spool"}} {
		info, err := item.file.Stat()
		if err != nil || uint64(info.Size()) < item.size {
			_ = file.Close()
			_ = attach.Close()
			return nil, nil, fmt.Errorf("%w: stream %s shorter than recorded progress", ErrStorage, item.name)
		}
		if uint64(info.Size()) > item.size {
			if err := item.file.Truncate(int64(item.size)); err != nil {
				_ = file.Close()
				_ = attach.Close()
				return nil, nil, fmt.Errorf("%w: truncate stream %s: %v", ErrStorage, item.name, err)
			}
		}
	}
	if _, err := attach.Seek(int64(record.AttachBytes), io.SeekStart); err != nil {
		_ = file.Close()
		_ = attach.Close()
		return nil, nil, fmt.Errorf("%w: seek stream attachment spool: %v", ErrStorage, err)
	}
	return file, attach, nil
}

// Progress returns the current progress (wire OutputStreamProgressV1).
func (st *OutputStream) Progress() OutputStreamProgress { return st.record.progress(st.acc.Root()) }

// Key returns the object key of this stream.
func (st *OutputStream) Key() ObjectKey { return st.key }

func (st *OutputStream) usable() error {
	if st.superseded {
		return fmt.Errorf("%w: output stream superseded by a newer connection", ErrConflict)
	}
	if st.closed {
		return fmt.Errorf("%w: output stream is closed", ErrMalformed)
	}
	return nil
}

// Append receives one chunk: it runs checks (2)(3)(4) (check (1), the signature, is done in the
// Service layer), then appends the text and the attachment, persists the chunk record and the
// progress in one atomic batch write, and returns the root after the append. Any failed check
// returns an error; persisted chunks are not rolled back and the stream becomes unusable (the caller
// closes it).
func (st *OutputStream) Append(_ context.Context, chunk OutputChunk) (mmr.Hash, error) {
	if err := st.usable(); err != nil {
		return mmr.Hash{}, err
	}
	expected := uint64(0)
	if st.record.Received {
		expected = st.record.LastSeq + 1
	}
	switch {
	case chunk.Seq != expected:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: chunk seq %d, expected %d", ErrMalformed, chunk.Seq, expected))
	case st.record.LastFrameShort:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: only fin may follow a short chunk", ErrMalformed))
	case len(chunk.MMRRoot) != sha256.Size:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: chunk mmr_root", ErrMalformed))
	// Phase 0 requires both attachment and attachment_signature to be empty; anything non-empty fails
	// closed. Neither field enters the MMR leaf (a leaf covers only the text), so letting them
	// through would carry bytes nobody committed to along with a signed output stream.
	case len(chunk.Attachment) != 0 || len(chunk.AttachmentSignature) != 0:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: attachment is not available in Phase 0", ErrMalformed))
	case uint64(len(chunk.Text)) > st.cfg.MaxFrameBytes || uint64(len(chunk.Attachment)) > st.cfg.MaxAttachmentBytes:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: chunk exceeds frame or attachment limit", ErrCapacity))
	case st.record.LeafCount >= st.cfg.MaxLeaves:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: output leaf count limit", ErrCapacity))
	case st.record.TotalBytes > st.store.cfg.MaxBlobBytes || uint64(len(chunk.Text)) > st.store.cfg.MaxBlobBytes-st.record.TotalBytes:
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: output object limit", ErrCapacity))
	}
	candidate := st.acc.Clone()
	root := candidate.Append(chunk.Text)
	if !bytes.Equal(root[:], chunk.MMRRoot) {
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: chunk mmr_root does not match recomputed prefix root", ErrHashMismatch))
	}
	if _, err := st.file.Write(chunk.Text); err != nil {
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: write stream spool: %v", ErrStorage, err))
	}
	if err := st.file.Sync(); err != nil {
		return mmr.Hash{}, st.fail(fmt.Errorf("%w: sync stream spool: %v", ErrStorage, err))
	}
	frame := outputFrameRecord{
		Seq: chunk.Seq, Offset: st.record.TotalBytes, Length: uint32(len(chunk.Text)), Root: hex.EncodeToString(root[:]),
		Signature: append([]byte(nil), chunk.WorkerSignature...),
	}
	next := st.record
	if len(chunk.Attachment) > 0 {
		if _, err := st.attach.Write(chunk.Attachment); err != nil {
			return mmr.Hash{}, st.fail(fmt.Errorf("%w: write stream attachment: %v", ErrStorage, err))
		}
		if err := st.attach.Sync(); err != nil {
			return mmr.Hash{}, st.fail(fmt.Errorf("%w: sync stream attachment: %v", ErrStorage, err))
		}
		frame.AttachmentOffset = st.record.AttachBytes
		frame.AttachmentLength = uint32(len(chunk.Attachment))
		frame.AttachmentSignature = append([]byte(nil), chunk.AttachmentSignature...)
		next.AttachBytes += uint64(len(chunk.Attachment))
	}
	next.Received, next.LastSeq = true, chunk.Seq
	next.TotalBytes += uint64(len(chunk.Text))
	next.LeafCount++
	next.LastFrameShort = uint64(len(chunk.Text)) < st.cfg.MinFrameBytes
	next.Peaks = next.Peaks[:0:0]
	for _, p := range candidate.Peaks() {
		next.Peaks = append(next.Peaks, hex.EncodeToString(p[:]))
	}
	if err := st.store.persistOutputFrame(st.encoded, frame, next); err != nil {
		return mmr.Hash{}, st.fail(err)
	}
	_, _ = st.hash.Write(chunk.Text)
	st.record, st.acc = next, candidate
	return root, nil
}

// Finish receives the Fin: final_seq and the root must both match; the spool is promoted to a blob,
// the metadata becomes READY, output_hash is filled with the MMR root, and the chunk boundaries and
// leaf count are stored with it.
func (st *OutputStream) Finish(ctx context.Context, fin OutputFin) (Metadata, error) {
	if err := st.usable(); err != nil {
		return Metadata{}, err
	}
	if !st.record.Received {
		return Metadata{}, st.fail(fmt.Errorf("%w: fin before any chunk", ErrMalformed))
	}
	if fin.FinalSeq != st.record.LastSeq {
		return Metadata{}, st.fail(fmt.Errorf("%w: fin final_seq %d, expected %d", ErrMalformed, fin.FinalSeq, st.record.LastSeq))
	}
	root := st.acc.Root()
	if !bytes.Equal(root[:], fin.OutputMMRRoot) {
		return Metadata{}, st.fail(fmt.Errorf("%w: fin output_mmr_root does not match recomputed root", ErrHashMismatch))
	}
	chunkLengths, err := st.store.chunkLengths(st.encoded, st.record.LeafCount)
	if err != nil {
		return Metadata{}, st.fail(err)
	}
	if err := st.file.Sync(); err != nil {
		return Metadata{}, st.fail(fmt.Errorf("%w: sync stream spool: %v", ErrStorage, err))
	}
	if err := st.file.Close(); err != nil {
		st.file = nil
		return Metadata{}, st.fail(fmt.Errorf("%w: close stream spool: %v", ErrStorage, err))
	}
	st.file = nil
	contentHash := hex.EncodeToString(st.hash.Sum(nil))
	spoolPath := st.store.streamPath(st.record.SpoolID)
	blobPath := st.store.blobPath(contentHash)

	st.store.maintenance.RLock()
	defer st.store.maintenance.RUnlock()
	st.store.mu.Lock()
	defer st.store.mu.Unlock()
	if _, found, err := st.store.tombstoneRecord(st.encoded); err != nil {
		return Metadata{}, st.failLocked(err)
	} else if found {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: object key was deleted", ErrConflict))
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: create blob directory: %v", ErrStorage, err))
	}
	if info, err := os.Stat(blobPath); err == nil {
		if uint64(info.Size()) != st.record.TotalBytes {
			return Metadata{}, st.failLocked(fmt.Errorf("%w: content-addressed blob size conflict", ErrConflict))
		}
		if err := os.Remove(spoolPath); err != nil {
			return Metadata{}, st.failLocked(fmt.Errorf("%w: remove deduplicated stream spool: %v", ErrStorage, err))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: inspect blob: %v", ErrStorage, err))
	} else if err := os.Rename(spoolPath, blobPath); err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: commit stream blob: %v", ErrStorage, err))
	}
	for _, dir := range []string{filepath.Dir(spoolPath), filepath.Dir(blobPath)} {
		if err := st.store.directorySync(dir); err != nil {
			return Metadata{}, st.failLocked(fmt.Errorf("%w: sync directory: %v", ErrStorage, err))
		}
	}
	// The object identity is only completed at Fin. The content_hash of an OUTPUT is exactly its
	// output_hash (the closed-set semantics of TaskDataObjectRefV1), and after ADR-0017 output_hash
	// is the MMR root — the Worker's InferReceipt, the lookup in FinalizeTaskResult and the user's
	// fetch all locate the object by that root. The SHA-256 of the concatenated content is used only
	// to content-address the blob file (BlobHash); it enters neither the object identity nor any
	// interface.
	// A stream in transfer is located by (task_hash, session, task); once finalized the object is
	// located by its full object ref.
	rootHex := hex.EncodeToString(root[:])
	objectKey := st.key
	objectKey.ContentHash = rootHex
	meta := Metadata{
		Key: objectKey, Uploader: st.record.Uploader, SemanticHash: rootHex, SizeBytes: st.record.TotalBytes,
		// Fin only proves that the OUTPUT bytes are fully persisted and that the root can be computed;
		// it cannot prove they agree with the Receipt and the Worker manifest — that is
		// FinalizeTaskResult's job, so this stops at STORED.
		MediaType: OutputStreamMediaType, State: StateStored, RetentionStatus: RetentionActive,
		OutputMMRRoot: rootHex, ChunkLengths: chunkLengths, OutputLeafCount: st.record.LeafCount,
	}
	record := metadataRecord{Metadata: meta, BlobHash: contentHash}
	raw, err := json.Marshal(record)
	if err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: encode stream metadata: %v", ErrStorage, err))
	}
	sealed := st.record
	sealed.Sealed = true
	sealed.ContentHash = rootHex
	sealed.FinishReason = fin.FinishReason
	sealed.FinWorkerSignature = append([]byte(nil), fin.WorkerSignature...)
	progress, err := json.Marshal(sealed)
	if err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: encode output stream: %v", ErrStorage, err))
	}
	// The metadata and "the stream is sealed" are written in the same atomic batch: the object can
	// never be READY while the stream can still be appended to.
	indexed, err := json.Marshal(objectKey)
	if err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: encode object index: %v", ErrStorage, err))
	}
	if err := st.store.backend.WriteBatch(
		kv.WriteOp{NS: kv.NSTaskDataMetadata, Key: objectKeyString(objectKey), Val: raw},
		kv.WriteOp{NS: kv.NSTaskDataObjectIndex,
			Key: objectIndexKey(objectKey.SessionID, objectKey.TaskID, objectKey.Kind), Val: indexed},
		kv.WriteOp{NS: kv.NSTaskDataOutputStream, Key: st.encoded, Val: progress},
	); err != nil {
		return Metadata{}, st.failLocked(fmt.Errorf("%w: persist stream metadata: %v", ErrStorage, err))
	}
	st.record = sealed
	if st.attach != nil {
		_ = st.attach.Sync()
		_ = st.attach.Close()
		st.attach = nil
	}
	if sealed.AttachBytes == 0 {
		_ = os.Remove(st.store.streamAttachPath(sealed.SpoolID))
	}
	st.closed = true
	delete(st.store.outputStreams, st.encoded)
	_ = ctx
	return cloneMetadata(meta), nil
}

// OutputStreamMediaType is the media type of a streamed OUTPUT object: the leaves are the UTF-8
// bytes of the TEXT component.
const OutputStreamMediaType = "text/plain; charset=utf-8"

// Close closes this stream on an error or a broken connection: the files are closed, the progress
// and chunk records are kept, and the capacity reservation is released.
func (st *OutputStream) Close() {
	st.store.mu.Lock()
	defer st.store.mu.Unlock()
	st.closeLocked()
}

func (st *OutputStream) fail(err error) error {
	st.store.mu.Lock()
	defer st.store.mu.Unlock()
	return st.failLocked(err)
}

func (st *OutputStream) failLocked(err error) error {
	st.closeLocked()
	return err
}

func (st *OutputStream) closeLocked() {
	st.closeFilesLocked()
	st.closed = true
	if current, ok := st.store.outputStreams[st.encoded]; ok && current == st {
		delete(st.store.outputStreams, st.encoded)
	}
}

// supersedeLocked invalidates the stream of the old connection and gives up its capacity
// reservation; persisted chunks are left untouched.
func (st *OutputStream) supersedeLocked() {
	st.superseded = true
	st.closeFilesLocked()
	if current, ok := st.store.outputStreams[st.encoded]; ok && current == st {
		delete(st.store.outputStreams, st.encoded)
	}
}

func (st *OutputStream) closeFilesLocked() {
	if st.file != nil {
		_ = st.file.Close()
		st.file = nil
	}
	if st.attach != nil {
		_ = st.attach.Close()
		st.attach = nil
	}
}

// OutputStreamProgressOf reads the stream progress of key (without opening the stream). When there
// is no stream it returns found=false.
func (s *Store) OutputStreamProgressOf(_ context.Context, key ObjectKey) (OutputStreamProgress, bool, error) {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	record, found, err := s.outputStreamRecord(streamKeyString(key))
	if err != nil || !found {
		return OutputStreamProgress{}, false, err
	}
	acc, err := record.accumulator()
	if err != nil {
		return OutputStreamProgress{}, false, err
	}
	return record.progress(acc.Root()), true, nil
}

// OutputFrames replays the persisted chunks of key (seq > afterSeq; a nil afterSeq means from the
// beginning) and appends the Fin at the end when the stream is sealed. The text is read by offset
// from the spool (in progress) or the blob (sealed), and the attachment from the .attach file of the
// same name.
func (s *Store) OutputFrames(_ context.Context, key ObjectKey, afterSeq *uint64) ([]OutputFrame, error) {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	encoded := streamKeyString(key)
	record, found, err := s.outputStreamRecord(encoded)
	if err != nil || !found {
		return nil, err
	}
	path := s.streamPath(record.SpoolID)
	if record.Sealed {
		// Once sealed the metadata lives under the full object ref key, not the stream key. The ref is
		// the one recorded when the stream was opened (it carries task_hash) — the key the subscriber
		// passes in has only session and task.
		objectKey := record.Key
		objectKey.ContentHash = record.ContentHash
		meta, metaFound, err := s.metadataRecord(objectKeyString(objectKey))
		if err != nil {
			return nil, err
		}
		if !metaFound {
			return nil, fmt.Errorf("%w: sealed stream without metadata", ErrStorage)
		}
		path = s.blobPath(meta.BlobHash)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open stream data: %v", ErrStorage, err)
	}
	defer file.Close()
	var attach *os.File
	if record.AttachBytes > 0 {
		attach, err = os.Open(s.streamAttachPath(record.SpoolID))
		if err != nil {
			return nil, fmt.Errorf("%w: open stream attachments: %v", ErrStorage, err)
		}
		defer attach.Close()
	}
	frames := make([]OutputFrame, 0, record.LeafCount+1)
	for seq := uint64(0); seq < record.LeafCount; seq++ {
		if afterSeq != nil && seq <= *afterSeq {
			continue
		}
		frame, found, err := s.outputFrameRecord(encoded, seq)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: output frame %d missing", ErrStorage, seq)
		}
		text, err := readSection(file, frame.Offset, uint64(frame.Length))
		if err != nil {
			return nil, fmt.Errorf("%w: read stream chunk %d: %v", ErrStorage, seq, err)
		}
		root, err := hex.DecodeString(frame.Root)
		if err != nil {
			return nil, fmt.Errorf("%w: persisted chunk root", ErrStorage)
		}
		chunk := &OutputChunk{
			Seq: seq, Text: text, MMRRoot: root,
			WorkerSignature:     append([]byte(nil), frame.Signature...),
			AttachmentSignature: append([]byte(nil), frame.AttachmentSignature...),
		}
		if frame.AttachmentLength > 0 {
			chunk.Attachment, err = readSection(attach, frame.AttachmentOffset, uint64(frame.AttachmentLength))
			if err != nil {
				return nil, fmt.Errorf("%w: read stream attachment %d: %v", ErrStorage, seq, err)
			}
		}
		frames = append(frames, OutputFrame{Chunk: chunk})
	}
	if record.Sealed && record.Received {
		acc, err := record.accumulator()
		if err != nil {
			return nil, err
		}
		root := acc.Root()
		frames = append(frames, OutputFrame{Fin: &OutputFin{
			FinalSeq: record.LastSeq, OutputMMRRoot: root[:],
			FinishReason: record.FinishReason, WorkerSignature: append([]byte(nil), record.FinWorkerSignature...),
		}})
	}
	return frames, nil
}

func readSection(file *os.File, offset, length uint64) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := file.ReadAt(buf, int64(offset)); err != nil {
		return nil, err
	}
	return buf, nil
}

// chunkLengths reads back the byte count of each chunk in order (chunk_lengths of
// GetTaskDataMetadata).
func (s *Store) chunkLengths(encoded string, leafCount uint64) ([]uint32, error) {
	lengths := make([]uint32, 0, leafCount)
	for seq := uint64(0); seq < leafCount; seq++ {
		frame, found, err := s.outputFrameRecord(encoded, seq)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: output frame %d missing", ErrStorage, seq)
		}
		lengths = append(lengths, frame.Length)
	}
	return lengths, nil
}

func (s *Store) outputStreamRecord(encoded string) (outputStreamRecord, bool, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataOutputStream, encoded)
	if err != nil {
		return outputStreamRecord{}, false, fmt.Errorf("%w: read output stream: %v", ErrStorage, err)
	}
	if !found {
		return outputStreamRecord{}, false, nil
	}
	var record outputStreamRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return outputStreamRecord{}, false, fmt.Errorf("%w: decode output stream: %v", ErrStorage, err)
	}
	return record, true, nil
}

func (s *Store) outputFrameRecord(encoded string, seq uint64) (outputFrameRecord, bool, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataOutputFrame, outputFrameKey(encoded, seq))
	if err != nil {
		return outputFrameRecord{}, false, fmt.Errorf("%w: read output frame: %v", ErrStorage, err)
	}
	if !found {
		return outputFrameRecord{}, false, nil
	}
	var record outputFrameRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return outputFrameRecord{}, false, fmt.Errorf("%w: decode output frame: %v", ErrStorage, err)
	}
	return record, true, nil
}

func (s *Store) persistOutputStreamRecord(encoded string, record outputStreamRecord) error {
	raw, err := json.Marshal(record)
	if err == nil {
		err = s.backend.Set(kv.NSTaskDataOutputStream, encoded, raw)
	}
	if err != nil {
		return fmt.Errorf("%w: persist output stream: %v", ErrStorage, err)
	}
	return nil
}

// persistOutputFrame writes the chunk record and the progress to disk in one atomic batch (design
// §5.4, "the same transaction").
func (s *Store) persistOutputFrame(encoded string, frame outputFrameRecord, progress outputStreamRecord) error {
	frameRaw, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("%w: encode output frame: %v", ErrStorage, err)
	}
	progressRaw, err := json.Marshal(progress)
	if err != nil {
		return fmt.Errorf("%w: encode output stream: %v", ErrStorage, err)
	}
	if err := s.backend.WriteBatch(
		kv.WriteOp{NS: kv.NSTaskDataOutputFrame, Key: outputFrameKey(encoded, frame.Seq), Val: frameRaw},
		kv.WriteOp{NS: kv.NSTaskDataOutputStream, Key: encoded, Val: progressRaw},
	); err != nil {
		return fmt.Errorf("%w: persist output frame: %v", ErrStorage, err)
	}
	return nil
}

// recoverOutputStreams on restart: in-progress streams are not recomputed, their progress stays in
// kv and the Worker resumes from it when it reconnects; only spool files that no progress record
// references are cleaned up.
func (s *Store) recoverOutputStreams() error {
	referenced := make(map[string]struct{})
	var decodeErr error
	if err := s.backend.Scan(kv.NSTaskDataOutputStream, func(_ string, raw []byte) bool {
		var record outputStreamRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			decodeErr = fmt.Errorf("%w: decode output stream: %v", ErrStorage, err)
			return false
		}
		// Once sealed the spool has been renamed to a blob; the attachment file is always kept while
		// the stream is unsealed (a later chunk may carry an attachment) and, once sealed, only when
		// there really is an attachment.
		if !record.Sealed {
			referenced[s.streamPath(record.SpoolID)] = struct{}{}
			referenced[s.streamAttachPath(record.SpoolID)] = struct{}{}
		} else if record.AttachBytes > 0 {
			referenced[s.streamAttachPath(record.SpoolID)] = struct{}{}
		}
		return true
	}); err != nil {
		return fmt.Errorf("%w: scan output streams: %v", ErrStorage, err)
	}
	if decodeErr != nil {
		return decodeErr
	}
	root := filepath.Join(s.root, "stream")
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("%w: scan stream directory: %v", ErrStorage, err)
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		extension := filepath.Ext(entry.Name())
		if entry.IsDir() || (extension != ".stream" && extension != ".attach") {
			return fmt.Errorf("%w: unexpected stream path %q", ErrStorage, path)
		}
		if _, ok := referenced[path]; ok {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: remove orphan stream spool: %v", ErrStorage, err)
		}
	}
	if err := s.directorySync(root); err != nil {
		return fmt.Errorf("%w: sync stream directory: %v", ErrStorage, err)
	}
	s.mu.Lock()
	s.outputStreams = make(map[string]*OutputStream)
	s.mu.Unlock()
	return nil
}

// deleteOutputStreamLocked cleans up the progress, all chunk records and the stream files together
// with the object.
func (s *Store) deleteOutputStreamLocked(encoded string) error {
	record, found, err := s.outputStreamRecord(encoded)
	if err != nil || !found {
		return err
	}
	ops := make([]kv.WriteOp, 0, record.LeafCount+1)
	for seq := uint64(0); seq < record.LeafCount; seq++ {
		ops = append(ops, kv.WriteOp{NS: kv.NSTaskDataOutputFrame, Key: outputFrameKey(encoded, seq), Delete: true})
	}
	ops = append(ops, kv.WriteOp{NS: kv.NSTaskDataOutputStream, Key: encoded, Delete: true})
	if err := s.backend.WriteBatch(ops...); err != nil {
		return fmt.Errorf("%w: delete output stream: %v", ErrStorage, err)
	}
	for _, path := range []string{s.streamPath(record.SpoolID), s.streamAttachPath(record.SpoolID)} {
		if record.Sealed && path == s.streamPath(record.SpoolID) {
			continue // already renamed to a blob; handled by removeUnreferencedBlobs
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: remove stream spool: %v", ErrStorage, err)
		}
	}
	return nil
}
