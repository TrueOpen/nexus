package taskdata

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/TrueOpen/nexus/internal/kv"
)

type Config struct {
	InlineMaxBytes             uint64
	ChunkSizeBytes             uint64
	MaxRangeBytes              uint64
	MaxBlobBytes               uint64
	SpoolReservationBytes      uint64
	DiskAcceptWatermarkPercent uint32
}

func (c Config) validate() error {
	switch {
	case c.InlineMaxBytes == 0 || c.ChunkSizeBytes == 0 || c.MaxRangeBytes == 0 || c.MaxBlobBytes == 0 || c.SpoolReservationBytes == 0:
		return fmt.Errorf("%w: byte limits must be positive", ErrMalformed)
	case c.ChunkSizeBytes > c.MaxRangeBytes || c.MaxRangeBytes > c.MaxBlobBytes || c.InlineMaxBytes > c.MaxBlobBytes:
		return fmt.Errorf("%w: inconsistent byte limits", ErrMalformed)
	case c.SpoolReservationBytes < c.MaxBlobBytes:
		return fmt.Errorf("%w: reservation capacity below max blob", ErrMalformed)
	case c.DiskAcceptWatermarkPercent == 0 || c.DiskAcceptWatermarkPercent >= 100:
		return fmt.Errorf("%w: invalid disk watermark", ErrMalformed)
	default:
		return nil
	}
}

type UploadHeader struct {
	Key                 ObjectKey
	Uploader            string
	SizeBytes           uint64
	SemanticHash        string
	MediaType           string
	Receipt             *SignedInferReceipt
	AcceptedReceiptHash string
	RetainUntilHeight   uint64
}

type Option func(*Store)

func WithDiskUsage(usage diskUsageFunc) Option {
	return func(s *Store) {
		if usage != nil {
			s.diskUsage = usage
		}
	}
}

func WithDirectorySync(syncFn func(string) error) Option {
	return func(s *Store) {
		if syncFn != nil {
			s.directorySync = syncFn
		}
	}
}

type Store struct {
	log           *slog.Logger
	root          string
	backend       kv.Store
	cfg           Config
	diskUsage     diskUsageFunc
	directorySync func(string) error

	mu           sync.Mutex
	maintenance  sync.RWMutex
	reservations map[string]*reservationState
	activeKeys   map[string]string
	reserved     uint64
	// outputStreams holds the in-progress streamed OUTPUT write streams, keyed by object key; a Task
	// has at most one at a time.
	outputStreams map[string]*OutputStream
}

func (s *Store) ChunkSize() uint64 { return s.cfg.ChunkSizeBytes }

type metadataRecord struct {
	Metadata Metadata `json:"metadata"`
	BlobHash string   `json:"blob_hash"`
}

type reservationRecord struct {
	ID        string       `json:"id"`
	Header    UploadHeader `json:"header"`
	SpoolPath string       `json:"spool_path"`
	Written   uint64       `json:"written"`
}

type reservationState struct {
	record reservationRecord
}

type Upload struct {
	store     *Store
	header    UploadHeader
	id        string
	spoolPath string
	file      *os.File
	// hash computes the §6.2 content_hash: SHA256(bytes) for INPUT / OUTPUT / EVIDENCE_ARTIFACT, and
	// evidence_bundle_hash for EVIDENCE_MANIFEST — the H_V1 preimage has only one variable-length
	// segment whose length is already known from the header, so it can be fed chunk by chunk too.
	hash hash.Hash
	// manifestBody is collected only for EVIDENCE_MANIFEST: Prepare parses the exact bytes strictly
	// once, and a non-canonical manifest is not allowed to reach STORED.
	manifestBody []byte
	// manifest is the result parsed by Prepare, persisted together with the metadata.
	manifest   EvidenceBundleManifest
	written    uint64
	idempotent bool
	done       bool
	mu         sync.Mutex
}

// newContentHasher returns the hasher that computes content_hash for a given object kind. The
// content_hash of EVIDENCE_MANIFEST is H_V1(TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1, bytes), not
// SHA256(bytes): using the wrong one would reject every valid manifest as a hash mismatch.
func newContentHasher(kind ObjectKind, sizeBytes uint64) hash.Hash {
	h := sha256.New()
	if kind != ObjectKindEvidenceManifest {
		return h
	}
	domain := []byte(DomainEvidenceBundleManifest)
	prefix := make([]byte, 0, len(frameV1Prefix)+4+len(domain)+8)
	prefix = append(prefix, frameV1Prefix...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(domain)))
	prefix = append(prefix, domain...)
	prefix = binary.BigEndian.AppendUint64(prefix, sizeBytes)
	h.Write(prefix)
	return h
}

func NewStore(log *slog.Logger, root string, backend kv.Store, cfg Config, options ...Option) (*Store, error) {
	if backend == nil || root == "" {
		return nil, fmt.Errorf("%w: store backend and root required", ErrMalformed)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := ensureObjectDirectories(root); err != nil {
		return nil, fmt.Errorf("%w: create object directories: %v", ErrStorage, err)
	}
	if log == nil {
		log = slog.Default()
	}
	store := &Store{
		log: log, root: root, backend: backend, cfg: cfg, diskUsage: filesystemUsage, directorySync: syncDirectory,
		reservations: make(map[string]*reservationState), activeKeys: make(map[string]string),
		outputStreams: make(map[string]*OutputStream),
	}
	for _, option := range options {
		option(store)
	}
	return store, nil
}

func (s *Store) Begin(_ context.Context, header UploadHeader) (*Upload, error) {
	key, err := validateUploadHeader(header, s.cfg)
	if err != nil {
		return nil, err
	}

	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.activeKeys[key]; exists {
		return nil, fmt.Errorf("%w: upload already active", ErrConflict)
	}
	if _, found, err := s.tombstoneRecord(key); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("%w: object key was deleted", ErrConflict)
	}
	current, found, err := s.metadataRecord(key)
	if err != nil {
		return nil, err
	}
	idempotent := false
	if found {
		if !sameObject(current.Metadata, header) {
			return nil, fmt.Errorf("%w: object key already committed", ErrConflict)
		}
		idempotent = true
	}
	if s.reserved > s.cfg.SpoolReservationBytes || header.SizeBytes > s.cfg.SpoolReservationBytes-s.reserved {
		return nil, fmt.Errorf("%w: spool reservation exhausted", ErrCapacity)
	}
	total, used, err := s.diskUsage(s.root)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect filesystem: %v", ErrStorage, err)
	}
	remaining := s.remainingReservedLocked()
	if exceedsWatermark(total, used, remaining, header.SizeBytes, s.cfg.DiskAcceptWatermarkPercent) {
		return nil, fmt.Errorf("%w: disk acceptance watermark", ErrCapacity)
	}
	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("%w: reservation id: %v", ErrStorage, err)
	}
	spoolPath := filepath.Join(s.root, "spool", id+".part")
	file, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: create spool: %v", ErrStorage, err)
	}
	if err := s.directorySync(filepath.Dir(spoolPath)); err != nil {
		_ = file.Close()
		_ = os.Remove(spoolPath)
		_ = s.directorySync(filepath.Dir(spoolPath))
		return nil, fmt.Errorf("%w: sync spool directory: %v", ErrStorage, err)
	}
	record := reservationRecord{ID: id, Header: header, SpoolPath: spoolPath}
	raw, err := json.Marshal(record)
	if err == nil {
		err = s.backend.Set(kv.NSTaskDataReservation, id, raw)
	}
	if err != nil {
		_ = file.Close()
		_ = os.Remove(spoolPath)
		_ = s.directorySync(filepath.Dir(spoolPath))
		return nil, fmt.Errorf("%w: persist reservation: %v", ErrStorage, err)
	}
	s.reservations[id] = &reservationState{record: record}
	s.activeKeys[key] = id
	s.reserved += header.SizeBytes
	return &Upload{
		store: s, header: header, id: id, spoolPath: spoolPath, file: file,
		hash: newContentHasher(header.Key.Kind, header.SizeBytes), idempotent: idempotent,
	}, nil
}

func (u *Upload) ID() string { return u.id }

func (u *Upload) Idempotent() bool { return u.idempotent }

func (u *Upload) WriteChunk(chunk []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return fmt.Errorf("%w: upload is closed", ErrMalformed)
	}
	if len(chunk) == 0 || uint64(len(chunk)) > u.store.cfg.ChunkSizeBytes {
		return fmt.Errorf("%w: invalid chunk size", ErrMalformed)
	}
	if u.written > u.header.SizeBytes || uint64(len(chunk)) > u.header.SizeBytes-u.written {
		u.abortLocked()
		return fmt.Errorf("%w: received bytes exceed declaration", ErrHashMismatch)
	}
	if _, err := u.file.Write(chunk); err != nil {
		u.abortLocked()
		return fmt.Errorf("%w: write spool: %v", ErrStorage, err)
	}
	_, _ = u.hash.Write(chunk)
	if u.header.Key.Kind == ObjectKindEvidenceManifest {
		u.manifestBody = append(u.manifestBody, chunk...)
	}
	u.written += uint64(len(chunk))
	if err := u.store.updateWritten(u.id, u.written); err != nil {
		u.abortLocked()
		return err
	}
	return nil
}

func (u *Upload) Prepare(_ context.Context) (Metadata, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return Metadata{}, fmt.Errorf("%w: upload is closed", ErrMalformed)
	}
	computedHash := hex.EncodeToString(u.hash.Sum(nil))
	// Blobs are addressed by the hash of their bytes. Only a Worker manifest's ref content_hash is
	// not a byte hash (it is the receipt's evidence_hash_or_root, see Metadata.EvidenceBundleHash);
	// for every other object the content_hash must equal the hash of the received bytes.
	blobHash := u.header.SemanticHash
	if isWorkerManifest(u.header.Key) {
		blobHash = computedHash
	} else if computedHash != u.header.SemanticHash {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: received bytes do not match declaration", ErrHashMismatch)
	}
	if u.written != u.header.SizeBytes {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: received bytes do not match declaration", ErrHashMismatch)
	}
	// The manifest is parsed strictly right here: STORED means "it parses", and non-canonical bytes
	// should neither occupy a ref nor be discovered only at Finalize.
	manifest := EvidenceBundleManifest{}
	if u.header.Key.Kind == ObjectKindEvidenceManifest {
		parsed, err := ParseEvidenceBundleManifest(u.manifestBody)
		if err != nil {
			u.abortLocked()
			return Metadata{}, err
		}
		// The Task identity and producer the manifest claims must agree with the ref it is stored
		// under, otherwise the same bytes could be attached to a different Task or a different
		// producer.
		if manifestErr := matchManifestToRef(parsed, u.header.Key); manifestErr != nil {
			u.abortLocked()
			return Metadata{}, manifestErr
		}
		manifest = parsed
	}
	u.manifest = manifest
	if err := u.file.Sync(); err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: sync spool: %v", ErrStorage, err)
	}
	if err := u.file.Close(); err != nil {
		u.file = nil
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: close spool: %v", ErrStorage, err)
	}
	u.file = nil
	u.store.maintenance.RLock()
	defer u.store.maintenance.RUnlock()
	if _, found, err := u.store.tombstoneRecord(objectKeyString(u.header.Key)); err != nil {
		u.abortLocked()
		return Metadata{}, err
	} else if found {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: object key was deleted", ErrConflict)
	}
	if u.idempotent {
		_ = os.Remove(u.spoolPath)
		if err := u.store.directorySync(filepath.Dir(u.spoolPath)); err != nil {
			u.abortLocked()
			return Metadata{}, fmt.Errorf("%w: sync spool directory: %v", ErrStorage, err)
		}
		u.done = true
		u.store.releaseReservation(u.id, u.header)
		meta, err := u.store.metadataLocked(u.header.Key)
		return meta, err
	}

	blobPath := u.store.blobPath(blobHash)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: create blob directory: %v", ErrStorage, err)
	}
	if info, err := os.Stat(blobPath); err == nil {
		if uint64(info.Size()) != u.header.SizeBytes {
			u.abortLocked()
			return Metadata{}, fmt.Errorf("%w: content-addressed blob size conflict", ErrConflict)
		}
		if err := os.Remove(u.spoolPath); err != nil {
			u.abortLocked()
			return Metadata{}, fmt.Errorf("%w: remove deduplicated spool: %v", ErrStorage, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: inspect blob: %v", ErrStorage, err)
	} else if err := os.Rename(u.spoolPath, blobPath); err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: commit blob: %v", ErrStorage, err)
	}
	if err := u.store.directorySync(filepath.Dir(u.spoolPath)); err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: sync spool directory: %v", ErrStorage, err)
	}
	if err := u.store.directorySync(filepath.Dir(blobPath)); err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: sync blob directory: %v", ErrStorage, err)
	}
	meta := Metadata{
		Key: u.header.Key, Uploader: u.header.Uploader, SemanticHash: u.header.SemanticHash, SizeBytes: u.header.SizeBytes,
		MediaType: u.header.MediaType, State: StatePrepared, RetentionStatus: RetentionActive,
		Receipt: cloneReceipt(u.header.Receipt), AcceptedReceiptHash: u.header.AcceptedReceiptHash,
		RetainUntilHeight:      u.header.RetainUntilHeight,
		ArtifactTotalSizeBytes: u.manifest.ArtifactTotalSizeBytes,
		EvidenceSchemaHash:     u.manifest.EvidenceSchemaHash,
		Artifacts:              u.manifest.Artifacts,
	}
	if u.header.Key.Kind == ObjectKindEvidenceManifest {
		meta.EvidenceBundleHash = computedHash
	}
	record := metadataRecord{Metadata: meta, BlobHash: blobHash}
	raw, err := json.Marshal(record)
	if err == nil {
		err = u.store.backend.Set(kv.NSTaskDataMetadata, objectKeyString(u.header.Key), raw)
	}
	if err == nil {
		// The index shares the metadata's source of truth: it is written only after the metadata
		// write succeeds.
		var indexed []byte
		if indexed, err = json.Marshal(u.header.Key); err == nil {
			err = u.store.backend.Set(kv.NSTaskDataObjectIndex,
				objectIndexKey(u.header.Key.SessionID, u.header.Key.TaskID, u.header.Key.Kind), indexed)
		}
	}
	if err != nil {
		u.abortLocked()
		return Metadata{}, fmt.Errorf("%w: persist metadata: %v", ErrStorage, err)
	}
	u.done = true
	u.store.releaseReservation(u.id, u.header)
	return meta, nil
}

func (u *Upload) Abort() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return nil
	}
	u.abortLocked()
	return nil
}

func (u *Upload) abortLocked() {
	if u.done {
		return
	}
	u.done = true
	if u.file != nil {
		_ = u.file.Close()
		u.file = nil
	}
	if err := os.Remove(u.spoolPath); err == nil || errors.Is(err, os.ErrNotExist) {
		if err := u.store.directorySync(filepath.Dir(u.spoolPath)); err != nil {
			u.store.log.Error("task data spool directory sync failed", "reservation_id", u.id, "err", err)
		}
	}
	u.store.releaseReservation(u.id, u.header)
}

// RecordRetentionLease writes the retention height signed in the storage confirmation back into the
// object metadata.
//
// The confirmation is a promise to the uploader and the metadata is the queryable copy of that
// promise; the two must be the same value, otherwise nexus has signed a promise it did not record
// and the retention decision during recovery cannot obtain that height.
// An existing non-zero value is not overwritten: it is an earlier signed promise, and neither
// shortening nor extending it should happen here.
func (s *Store) RecordRetentionLease(_ context.Context, key ObjectKey, height uint64) (Metadata, error) {
	if height == 0 {
		return Metadata{}, fmt.Errorf("%w: retention lease height", ErrMalformed)
	}
	encoded := objectKeyString(key)
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found, err := s.metadataRecord(encoded)
	if err != nil {
		return Metadata{}, err
	}
	if !found {
		return Metadata{}, ErrNotFound
	}
	if record.Metadata.RetainUntilHeight != 0 {
		return cloneMetadata(record.Metadata), nil
	}
	record.Metadata.RetainUntilHeight = height
	if err := s.persistMetadataRecord(encoded, record); err != nil {
		return Metadata{}, err
	}
	return cloneMetadata(record.Metadata), nil
}

// MarkStored commits the first boundary of §5.5: an object reaches STORED only after the bytes are
// persisted and the hash/size checks have passed. An object that is already READY stays READY — a
// finalized bundle is not rolled back by a replayed upload.
func (s *Store) MarkStored(_ context.Context, key ObjectKey) (Metadata, error) {
	return s.advanceState(key, StateStored, nil)
}

// MarkReady switches an object to READY. It has only two legitimate sources: the INPUT of OpenTask,
// and the atomic commit of FinalizeTaskResult / FinalizeVerifierEvidence.
func (s *Store) MarkReady(_ context.Context, key ObjectKey) (Metadata, error) {
	return s.advanceState(key, StateReady, nil)
}

// MarkOutputReady is how FinalizeTaskResult switches the OUTPUT to READY: it also records the
// InferReceiptV2 that Finalize verified onto the object, so that GetTaskDataMetadata has a
// convenience copy of infer_receipt to return (Task Data Interface Design §6.5; a Cortex Verifier
// requires it to be present when confirming the OUTPUT). A streamed object has no receipt when it is
// finalized, so this is its only source. An object that is already READY is returned unchanged and
// its receipt is not modified.
func (s *Store) MarkOutputReady(_ context.Context, key ObjectKey, receipt SignedInferReceipt) (Metadata, error) {
	if key.Kind != ObjectKindOutput {
		return Metadata{}, fmt.Errorf("%w: MarkOutputReady requires an OUTPUT object", ErrMalformed)
	}
	return s.advanceState(key, StateReady, func(meta *Metadata) {
		if meta.Receipt == nil {
			meta.Receipt = cloneReceipt(&receipt)
		}
	})
}

// advanceState moves one way along STAGING -> STORED -> READY, never backwards and never skipping a
// check: if the target state has already been reached or passed it returns unchanged, and entering
// from any other state (QUARANTINED, for example) is a conflict.
// mutate runs only on the call that actually advances, in the same write as the state.
func (s *Store) advanceState(key ObjectKey, target State, mutate func(*Metadata)) (Metadata, error) {
	encoded := objectKeyString(key)
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found, err := s.metadataRecord(encoded)
	if err != nil {
		return Metadata{}, err
	}
	if !found {
		return Metadata{}, ErrNotFound
	}
	current := record.Metadata.State
	if stateRank(current) >= stateRank(target) && stateRank(current) > 0 {
		return cloneMetadata(record.Metadata), nil
	}
	if stateRank(current) == 0 {
		return Metadata{}, fmt.Errorf("%w: object state %s", ErrConflict, current)
	}
	record.Metadata.State = target
	if mutate != nil {
		mutate(&record.Metadata)
	}
	raw, err := json.Marshal(record)
	if err == nil {
		err = s.backend.Set(kv.NSTaskDataMetadata, encoded, raw)
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: persist %s metadata: %v", ErrStorage, target, err)
	}
	return cloneMetadata(record.Metadata), nil
}

// stateRank gives the three forward states an order; 0 means the state is not on this path
// (QUARANTINED and the like).
func stateRank(state State) int {
	switch state {
	case StatePrepared:
		return 1
	case StateStored:
		return 2
	case StateReady:
		return 3
	default:
		return 0
	}
}

// RollbackPrepared removes only a PREPARED logical reference. READY objects
// are never removed by a failed idempotent OpenTask retry.
func (s *Store) RollbackPrepared(_ context.Context, key ObjectKey) error {
	encoded := objectKeyString(key)
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	s.mu.Lock()
	record, found, err := s.metadataRecord(encoded)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !found || record.Metadata.State == StateReady {
		s.mu.Unlock()
		return nil
	}
	if record.Metadata.State != StatePrepared {
		s.mu.Unlock()
		return fmt.Errorf("%w: object is not prepared", ErrConflict)
	}
	// The index is deleted along with the object: leaving a dangling index would make later lifecycle
	// operations resolve to an object that no longer exists.
	_ = s.backend.Delete(kv.NSTaskDataObjectIndex, objectIndexKey(key.SessionID, key.TaskID, key.Kind))
	if err := s.backend.Delete(kv.NSTaskDataMetadata, encoded); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: delete prepared metadata: %v", ErrStorage, err)
	}
	s.mu.Unlock()
	records, err := s.loadMetadataRecords()
	if err != nil {
		return err
	}
	return s.removeUnreferencedBlobs(records)
}

func (s *Store) DeleteObject(_ context.Context, key ObjectKey) error {
	if _, err := validateObjectKey(key); err != nil {
		return err
	}
	encoded := objectKeyString(key)
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	s.mu.Lock()
	record, metadataFound, err := s.metadataRecord(encoded)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	tombstone, tombstoneFound, err := s.tombstoneRecord(encoded)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	var source Metadata
	switch {
	case metadataFound:
		source = record.Metadata
	case tombstoneFound:
		source = Metadata{
			Key: tombstone.Key, SemanticHash: tombstone.SemanticHash, SizeBytes: tombstone.SizeBytes,
			RetentionStatus: RetentionDeleted, RetainUntilHeight: tombstone.RetainUntilHeight,
		}
	case s.activeKeys[encoded] != "" && s.reservations[s.activeKeys[encoded]] != nil:
		header := s.reservations[s.activeKeys[encoded]].record.Header
		source = Metadata{
			Key: header.Key, SemanticHash: header.SemanticHash, SizeBytes: header.SizeBytes,
			RetainUntilHeight: header.RetainUntilHeight,
		}
	default:
		source = Metadata{Key: key}
	}
	if !tombstoneFound {
		if err := s.persistTombstone(source); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	if metadataFound {
		// The index is deleted along with the object: leaving a dangling index would make later
		// lifecycle operations resolve to an object that no longer exists.
		_ = s.backend.Delete(kv.NSTaskDataObjectIndex, objectIndexKey(key.SessionID, key.TaskID, key.Kind))
		if err := s.backend.Delete(kv.NSTaskDataMetadata, encoded); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("%w: delete metadata: %v", ErrStorage, err)
		}
	}
	// The chunk records of a streamed OUTPUT are cleaned up together with the object (design §5.4).
	if active, ok := s.outputStreams[encoded]; ok {
		active.supersedeLocked()
	}
	// A stream's progress and chunk records live under the stream key (which has no content_hash),
	// which is not the same key as the object metadata.
	if err := s.deleteOutputStreamLocked(streamKeyString(key)); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	records, err := s.loadMetadataRecords()
	if err != nil {
		return err
	}
	return s.removeUnreferencedBlobs(records)
}

func (s *Store) Metadata(_ context.Context, key ObjectKey) (Metadata, error) {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	return s.metadataLocked(key)
}

func (s *Store) metadataLocked(key ObjectKey) (Metadata, error) {
	encoded := objectKeyString(key)
	tombstone, tombstoneFound, err := s.tombstoneRecord(encoded)
	if err != nil {
		return Metadata{}, err
	}
	if tombstoneFound {
		return Metadata{
			Key: tombstone.Key, SemanticHash: tombstone.SemanticHash, SizeBytes: tombstone.SizeBytes,
			RetentionStatus: RetentionDeleted, RetainUntilHeight: tombstone.RetainUntilHeight,
		}, nil
	}
	record, found, err := s.metadataRecord(encoded)
	if err != nil {
		return Metadata{}, err
	}
	if !found {
		return Metadata{}, ErrNotFound
	}
	if record.Metadata.State == StateQuarantined {
		return Metadata{}, ErrNotFound
	}
	return cloneMetadata(record.Metadata), nil
}

func (s *Store) OpenRange(_ context.Context, key ObjectKey, offset, length uint64) (io.ReadCloser, error) {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	encoded := objectKeyString(key)
	if _, found, err := s.tombstoneRecord(encoded); err != nil {
		return nil, err
	} else if found {
		return nil, ErrNotFound
	}
	record, found, err := s.metadataRecord(encoded)
	if err != nil {
		return nil, err
	}
	if !found || record.Metadata.State != StateReady {
		return nil, ErrNotFound
	}
	if offset >= record.Metadata.SizeBytes {
		return nil, ErrRangeInvalid
	}
	if length == 0 {
		length = record.Metadata.SizeBytes - offset
	}
	if length == 0 || length > s.cfg.MaxRangeBytes || length > record.Metadata.SizeBytes-offset {
		return nil, ErrRangeInvalid
	}
	file, err := os.Open(s.blobPath(record.BlobHash))
	if err != nil {
		return nil, fmt.Errorf("%w: open blob: %v", ErrStorage, err)
	}
	return &sectionReadCloser{Reader: io.NewSectionReader(file, int64(offset), int64(length)), closer: file}, nil
}

type sectionReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *sectionReadCloser) Close() error { return r.closer.Close() }

func (s *Store) metadataRecord(key string) (metadataRecord, bool, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataMetadata, key)
	if err != nil {
		return metadataRecord{}, false, fmt.Errorf("%w: read metadata: %v", ErrStorage, err)
	}
	if !found {
		return metadataRecord{}, false, nil
	}
	var record metadataRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return metadataRecord{}, false, fmt.Errorf("%w: decode metadata: %v", ErrStorage, err)
	}
	return record, true, nil
}

func (s *Store) tombstoneRecord(key string) (tombstoneRecord, bool, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataTombstone, key)
	if err != nil {
		return tombstoneRecord{}, false, fmt.Errorf("%w: read tombstone: %v", ErrStorage, err)
	}
	if !found {
		return tombstoneRecord{}, false, nil
	}
	var record tombstoneRecord
	if err := json.Unmarshal(raw, &record); err != nil || objectKeyString(record.Key) != key || record.RetentionStatus != RetentionDeleted {
		return tombstoneRecord{}, false, fmt.Errorf("%w: decode tombstone", ErrStorage)
	}
	return record, true, nil
}

func (s *Store) updateWritten(id string, written uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.reservations[id]
	if state == nil {
		return fmt.Errorf("%w: reservation disappeared", ErrStorage)
	}
	state.record.Written = written
	raw, err := json.Marshal(state.record)
	if err != nil {
		return fmt.Errorf("%w: encode reservation progress: %v", ErrStorage, err)
	}
	if err := s.backend.Set(kv.NSTaskDataReservation, id, raw); err != nil {
		return fmt.Errorf("%w: persist reservation progress: %v", ErrStorage, err)
	}
	return nil
}

func (s *Store) releaseReservation(id string, header UploadHeader) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.reservations[id]
	if state == nil {
		return
	}
	delete(s.reservations, id)
	delete(s.activeKeys, objectKeyString(header.Key))
	if s.reserved >= header.SizeBytes {
		s.reserved -= header.SizeBytes
	} else {
		s.reserved = 0
	}
	if err := s.backend.Delete(kv.NSTaskDataReservation, id); err != nil {
		s.log.Error("task data reservation cleanup failed", "reservation_id", id, "err", err)
	}
}

func (s *Store) remainingReservedLocked() uint64 {
	remaining := uint64(0)
	for _, state := range s.reservations {
		if state.record.Header.SizeBytes > state.record.Written {
			remaining += state.record.Header.SizeBytes - state.record.Written
		}
	}
	return remaining
}

func (s *Store) blobPath(hash string) string {
	return filepath.Join(s.root, "blobs", "sha256", hash[:2], hash)
}

// isWorkerManifest: a Worker's EVIDENCE_MANIFEST. Its ref content_hash is the
// evidence_hash_or_root of required_evidence_commitments[] in the receipt, which is how Finalize
// finds the manifest from the receipt; the content_hash of a Verifier manifest is instead the
// verifier_evidence_bundle_hash in VerifierResult, i.e. the byte hash itself.
func isWorkerManifest(key ObjectKey) bool {
	return key.Kind == ObjectKindEvidenceManifest && key.EvidenceProducerKind == EvidenceProducerWorker
}

func validateUploadHeader(header UploadHeader, cfg Config) (string, error) {
	if _, err := validateObjectKey(header.Key); err != nil {
		return "", err
	}
	if header.SizeBytes == 0 || header.SizeBytes > cfg.MaxBlobBytes || !canonicalSHA256(header.SemanticHash) || !validMediaType(header.Key.Kind, header.MediaType) {
		return "", fmt.Errorf("%w: upload header", ErrMalformed)
	}
	if header.Key.Kind == ObjectKindInput && header.RetainUntilHeight == 0 {
		return "", fmt.Errorf("%w: input retention height", ErrMalformed)
	}
	if header.Key.Kind != ObjectKindInput && !canonicalText(header.Uploader) {
		return "", fmt.Errorf("%w: uploader", ErrMalformed)
	}
	return objectKeyString(header.Key), nil
}

// objectKeyString is the local storage key: it takes the object ref's identity digest directly, so
// it covers the same fields the caller's signature commits to. When the ref is invalid the digest is
// the zero value, and the call path has already rejected it upstream.
// streamKeyString is the local key of a stream being transferred: it takes only
// (session_id, task_id, kind).
//
// It has no content_hash — that can only be computed at Fin; and no task_hash — the subscriber
// (SubscribeOutputRequest) carries only session and task, and both sides must land on the same key.
// task_hash is checked at the Header authorization step, which is a separate matter from local
// addressing.
func streamKeyString(key ObjectKey) string {
	digest := sha256.Sum256([]byte(key.SessionID + "|" + key.TaskID + "|" + key.Kind.String()))
	return hex.EncodeToString(digest[:])
}

// objectIndexKey is the three things a lifecycle operation can obtain: (session, task, kind).
// content_hash is not among them — it is precisely because it is unavailable that this index
// exists.
func objectIndexKey(sessionID, taskID string, kind ObjectKind) string {
	return sessionID + "|" + taskID + "|" + kind.String()
}

// ResolveObject recovers the full object ref from (session, task, kind). A Task has only one INPUT,
// so this key is unambiguous; not found is ErrNotFound, with no guessing.
func (s *Store) ResolveObject(_ context.Context, sessionID, taskID string, kind ObjectKind) (ObjectRef, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataObjectIndex, objectIndexKey(sessionID, taskID, kind))
	if err != nil {
		return ObjectRef{}, fmt.Errorf("%w: read object index: %v", ErrStorage, err)
	}
	if !found {
		return ObjectRef{}, ErrNotFound
	}
	var ref ObjectRef
	if err := json.Unmarshal(raw, &ref); err != nil {
		return ObjectRef{}, fmt.Errorf("%w: decode object index: %v", ErrStorage, err)
	}
	return ref, nil
}

func objectKeyString(key ObjectKey) string {
	digest, _ := ObjectRefDigest(key)
	return hex.EncodeToString(digest[:])
}

func sameObject(metadata Metadata, header UploadHeader) bool {
	return metadata.Uploader == header.Uploader && metadata.SemanticHash == header.SemanticHash && metadata.SizeBytes == header.SizeBytes && metadata.MediaType == header.MediaType &&
		metadata.RetainUntilHeight == header.RetainUntilHeight &&
		sameReceipt(metadata.Receipt, header.Receipt)
}

func sameReceipt(left, right *SignedInferReceipt) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	// EvidenceCommitments is a slice, so SignedInferReceipt is not comparable with ==; compare entry
	// by entry, with order counting as a difference (the §5.14 frozen list is in strictly ascending
	// evidence_kind order, so a reordering is a different receipt).
	if len(left.EvidenceCommitments) != len(right.EvidenceCommitments) {
		return false
	}
	for i := range left.EvidenceCommitments {
		if left.EvidenceCommitments[i] != right.EvidenceCommitments[i] {
			return false
		}
	}
	return left.SchemaVersion == right.SchemaVersion && left.ChainID == right.ChainID &&
		left.TaskID == right.TaskID && left.TaskHash == right.TaskHash &&
		left.WorkerOperatorAddress == right.WorkerOperatorAddress &&
		left.ServiceAuthorizationNonce == right.ServiceAuthorizationNonce &&
		left.GenerationParamsDigest == right.GenerationParamsDigest &&
		left.OutputHash == right.OutputHash && left.OutputSizeBytes == right.OutputSizeBytes &&
		left.ExpiryHeight == right.ExpiryHeight && left.ServiceSignature == right.ServiceSignature
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.Receipt = cloneReceipt(metadata.Receipt)
	if metadata.ChunkLengths != nil {
		metadata.ChunkLengths = append([]uint32(nil), metadata.ChunkLengths...)
	}
	return metadata
}

func cloneReceipt(receipt *SignedInferReceipt) *SignedInferReceipt {
	if receipt == nil {
		return nil
	}
	clone := *receipt
	clone.EvidenceCommitments = append([]EvidenceCommitment(nil), receipt.EvidenceCommitments...)
	return &clone
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func exceedsWatermark(total, used, reserved, declared uint64, watermark uint32) bool {
	if total == 0 || used > total || reserved > ^uint64(0)-used || declared > ^uint64(0)-used-reserved {
		return true
	}
	projected := used + reserved + declared
	percent := uint64(watermark)
	threshold := (total/100)*percent + (total%100)*percent/100
	return projected > threshold
}
