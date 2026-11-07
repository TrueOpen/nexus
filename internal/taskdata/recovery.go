package taskdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

type RetentionDecision struct {
	Status            RetentionStatus
	RetainUntilHeight uint64
	Delete            bool
}

type RecoveryResolver interface {
	HasAcceptedOrder(context.Context, ObjectKey) (bool, error)
	RevalidatePrepared(context.Context, Metadata) (bool, error)
	Retention(context.Context, Metadata, uint64) (RetentionDecision, error)
}

type tombstoneRecord struct {
	Key                 ObjectKey       `json:"key"`
	SemanticHash        string          `json:"semantic_hash"`
	SizeBytes           uint64          `json:"size_bytes"`
	RetentionStatus     RetentionStatus `json:"retention_status"`
	RetainUntilHeight   uint64          `json:"retain_until_height"`
	DeletedAtUnixMillis int64           `json:"deleted_at_unix_millis"`
	// DeletedAtHeight is the chain height the tombstone counts its retention from. A tombstone
	// written without a height (DeleteObject, or an older release) gets one from the next Sweep.
	DeletedAtHeight uint64 `json:"deleted_at_height,omitempty"`
}

// tombstoneSweepBatch bounds the tombstones one Sweep stamps or reclaims, so a large backlog is
// worked off over several sweeps instead of stalling one.
const tombstoneSweepBatch = 1000

func (s *Store) Recover(ctx context.Context, resolver RecoveryResolver) error {
	if resolver == nil {
		return fmt.Errorf("%w: recovery resolver required", ErrMalformed)
	}
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	if err := s.recoverReservations(); err != nil {
		return err
	}
	if err := s.recoverOutputStreams(); err != nil {
		return err
	}
	records, err := s.loadMetadataRecords()
	if err != nil {
		return err
	}
	for key, record := range records {
		if record.Metadata.State != StatePrepared && record.Metadata.State != StateQuarantined {
			continue
		}
		var accepted bool
		var authorityErr error
		if record.Metadata.Key.Kind == ObjectKindInput {
			accepted, authorityErr = resolver.HasAcceptedOrder(ctx, record.Metadata.Key)
		} else {
			accepted, authorityErr = resolver.RevalidatePrepared(ctx, cloneMetadata(record.Metadata))
		}
		switch {
		case authorityErr != nil:
			record.Metadata.State = StateQuarantined
			if err := s.persistMetadataRecord(key, record); err != nil {
				return err
			}
			records[key] = record
		case accepted:
			record.Metadata.State = StateReady
			if err := s.persistMetadataRecord(key, record); err != nil {
				return err
			}
			if record.Metadata.Key.Kind == ObjectKindInput {
				if err := s.indexInput(record.Metadata.Key, true); err != nil {
					return err
				}
			}
			records[key] = record
		case record.Metadata.Key.Kind == ObjectKindInput:
			s.unindex(record.Metadata.Key)
			if err := s.backend.Delete(kv.NSTaskDataMetadata, key); err != nil {
				return fmt.Errorf("%w: delete rejected prepared metadata: %v", ErrStorage, err)
			}
			delete(records, key)
		default:
			record.Metadata.State = StateQuarantined
			if err := s.persistMetadataRecord(key, record); err != nil {
				return err
			}
			records[key] = record
		}
	}
	s.checkInputIndex(ctx, resolver, records)
	return s.removeUnreferencedBlobs(records)
}

// checkInputIndex checks every INPUT index against the resolver's accepted orders. An index naming
// a version without an accepted order can be left by a release that kept the index on a failed
// version when a re-signed retry of the order turned READY: when exactly one other READY version
// of the task has the accepted order, the index moves to it, as a version turning READY takes it
// (indexInput). Otherwise it is left and warned about: a version whose order never reached the
// chain is released by retention once its retention ends, and the index with it. An index naming a
// missing object is only reported. records are all the metadata records; caller holds the
// exclusive maintenance lock.
func (s *Store) checkInputIndex(ctx context.Context, resolver RecoveryResolver, records map[string]metadataRecord) {
	suffix := "|" + ObjectKindInput.String()
	var refs []ObjectRef
	if err := s.backend.Scan(kv.NSTaskDataObjectIndex, func(indexKey string, raw []byte) bool {
		if !strings.HasSuffix(indexKey, suffix) {
			return true
		}
		var ref ObjectRef
		if err := json.Unmarshal(raw, &ref); err != nil {
			s.log.Error("task input index entry is not decodable", "index_key", indexKey, "err", err)
			return true
		}
		refs = append(refs, ref)
		return true
	}); err != nil {
		s.log.Warn("task input index check skipped", "err", err)
		return
	}
	for _, ref := range refs {
		if _, found, err := s.metadataRecord(objectKeyString(ref)); err != nil || !found {
			s.log.Warn("task input index names a missing object",
				"session_id", ref.SessionID, "task_id", ref.TaskID, "task_hash", ref.TaskHash, "err", err)
			continue
		}
		accepted, err := resolver.HasAcceptedOrder(ctx, ref)
		if err != nil {
			s.log.Warn("task input index check failed", "session_id", ref.SessionID, "task_id", ref.TaskID, "err", err)
			continue
		}
		if accepted {
			continue
		}
		target, found, err := acceptedReadyVersion(ctx, resolver, ref, records)
		if err != nil {
			s.log.Warn("task input index check failed", "session_id", ref.SessionID, "task_id", ref.TaskID, "err", err)
			continue
		}
		if !found {
			s.log.Warn("task input index names a version without an accepted order and no other version has one; left for retention",
				"session_id", ref.SessionID, "task_id", ref.TaskID, "task_hash", ref.TaskHash, "content_hash", ref.ContentHash)
			continue
		}
		if err := s.indexInput(target, true); err != nil {
			s.log.Warn("task input index not moved to the accepted version", "session_id", ref.SessionID, "task_id", ref.TaskID,
				"task_hash", target.TaskHash, "err", err)
		}
	}
}

// acceptedReadyVersion is the only READY INPUT version of ref's task, other than ref, that the
// resolver has an accepted order for; found is false when there is none or more than one.
func acceptedReadyVersion(ctx context.Context, resolver RecoveryResolver, ref ObjectRef, records map[string]metadataRecord) (ObjectKey, bool, error) {
	var target ObjectKey
	count := 0
	for _, record := range records {
		key := record.Metadata.Key
		if record.Metadata.State != StateReady || key.Kind != ObjectKindInput || key == ref ||
			key.SessionID != ref.SessionID || key.TaskID != ref.TaskID {
			continue
		}
		accepted, err := resolver.HasAcceptedOrder(ctx, key)
		if err != nil {
			return ObjectKey{}, false, err
		}
		if accepted {
			target = key
			count++
		}
	}
	return target, count == 1, nil
}

// Sweep promotes or drops quarantined objects, applies the retention decision of every READY
// object, reclaims expired tombstones and removes what is no longer referenced.
//
// The resolver may read the chain, so it never runs under the maintenance lock: the metadata is
// read once without it, each decision is resolved on its own, and then applied under a short
// exclusive lock only if the record still has the exact bytes the decision was made for. A record
// that changed or went away meanwhile is left as it is for the next sweep.
func (s *Store) Sweep(ctx context.Context, height uint64, resolver RecoveryResolver) error {
	if height == 0 || resolver == nil {
		return fmt.Errorf("%w: cleanup height and resolver required", ErrMalformed)
	}
	started := time.Now()
	var stats sweepStats
	err := s.sweep(ctx, height, resolver, &stats)
	if elapsed := time.Since(started); elapsed > slowSweep || stats.acted() {
		s.log.Info("task data sweep", "height", height, "duration_ms", elapsed.Milliseconds(),
			"records", stats.scanned, "promoted", stats.promoted, "dropped", stats.dropped,
			"retention_updated", stats.updated, "deleted", stats.deleted, "changed_during_sweep", stats.changed,
			"tombstones_stamped", stats.stamped, "tombstones_reclaimed", stats.reclaimed, "blobs_removed", stats.blobs)
	}
	return err
}

// slowSweep is the duration above which a sweep that changed nothing is still logged.
const slowSweep = time.Second

// sweepStats counts what one Sweep did.
type sweepStats struct {
	scanned, promoted, dropped, updated, deleted, changed int
	stamped, reclaimed, blobs                             int
}

func (st sweepStats) acted() bool {
	return st.promoted+st.dropped+st.updated+st.deleted+st.changed+st.stamped+st.reclaimed+st.blobs > 0
}

func (s *Store) sweep(ctx context.Context, height uint64, resolver RecoveryResolver, stats *sweepStats) error {
	snapshot, err := s.loadMetadataEntries()
	if err != nil {
		return err
	}
	stats.scanned = len(snapshot)
	for key, entry := range snapshot {
		record, raw := entry.record, entry.raw
		if record.Metadata.State == StateQuarantined {
			var accepted bool
			var err error
			if record.Metadata.Key.Kind == ObjectKindInput {
				accepted, err = resolver.HasAcceptedOrder(ctx, record.Metadata.Key)
			} else {
				accepted, err = resolver.RevalidatePrepared(ctx, cloneMetadata(record.Metadata))
			}
			if err != nil {
				continue
			}
			if !accepted {
				if record.Metadata.Key.Kind == ObjectKindInput {
					applied, err := s.applyIfUnchanged(key, raw, func() error {
						s.unindex(record.Metadata.Key)
						if err := s.backend.Delete(kv.NSTaskDataMetadata, key); err != nil {
							return fmt.Errorf("%w: delete rejected quarantined input: %v", ErrStorage, err)
						}
						return nil
					})
					if err != nil {
						return err
					}
					stats.count(applied, &stats.dropped)
				}
				continue
			}
			record.Metadata.State = StateReady
			promoted, err := json.Marshal(record)
			if err != nil {
				return fmt.Errorf("%w: encode metadata: %v", ErrStorage, err)
			}
			applied, err := s.applyIfUnchanged(key, raw, func() error {
				if err := s.persistMetadataRecord(key, record); err != nil {
					return err
				}
				if record.Metadata.Key.Kind == ObjectKindInput {
					return s.indexInput(record.Metadata.Key, true)
				}
				return nil
			})
			if err != nil {
				return err
			}
			stats.count(applied, &stats.promoted)
			if !applied {
				continue
			}
			raw = promoted
		}
		if record.Metadata.State != StateReady {
			continue
		}
		decision, err := resolver.Retention(ctx, cloneMetadata(record.Metadata), height)
		if err != nil {
			continue
		}
		if !validRetentionDecision(decision, height) {
			return fmt.Errorf("%w: invalid retention decision for %s", ErrAuthorityUnavailable, record.Metadata.Key.TaskID)
		}
		record.Metadata.RetentionStatus = decision.Status
		// Keep the existing value when the decision carries no height: it is the
		// commitment signed to the uploader in the storage confirmation, the same rule
		// as RecordRetentionLease's "never overwrite an existing non-zero value".
		if decision.RetainUntilHeight != 0 {
			record.Metadata.RetainUntilHeight = decision.RetainUntilHeight
		}
		if !decision.Delete {
			updated, err := json.Marshal(record)
			if err != nil {
				return fmt.Errorf("%w: encode metadata: %v", ErrStorage, err)
			}
			if bytes.Equal(updated, raw) {
				continue
			}
			applied, err := s.applyIfUnchanged(key, raw, func() error {
				return s.persistMetadataRecord(key, record)
			})
			if err != nil {
				return err
			}
			stats.count(applied, &stats.updated)
			continue
		}
		record.Metadata.RetainUntilHeight = decision.RetainUntilHeight
		applied, err := s.applyIfUnchanged(key, raw, func() error {
			if err := s.persistTombstone(record.Metadata, height); err != nil {
				return err
			}
			s.unindex(record.Metadata.Key)
			if err := s.backend.Delete(kv.NSTaskDataMetadata, key); err != nil {
				return fmt.Errorf("%w: delete task data metadata: %v", ErrStorage, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		stats.count(applied, &stats.deleted)
	}
	s.maintenance.RLock()
	stats.stamped, stats.reclaimed, err = s.reclaimTombstones(height)
	s.maintenance.RUnlock()
	if err != nil {
		return err
	}
	// Both the receipt pruning and the blob collection need the records as they are now, not the
	// snapshot above: an object uploaded during the sweep keeps its receipts and its blob.
	watch := s.watchBlobs()
	defer s.unwatchBlobs(watch)
	records, err := s.pruneFetchReceipts()
	if err != nil {
		return err
	}
	stats.blobs, err = s.collectBlobs(watch, records, nil)
	return err
}

// count adds an applied change to counter, or a skipped one to changed.
func (st *sweepStats) count(applied bool, counter *int) {
	if applied {
		*counter++
	} else {
		st.changed++
	}
}

// applyIfUnchanged runs apply under the exclusive maintenance lock, only when the metadata stored
// under key still has the bytes snapshot read; it reports whether apply ran.
func (s *Store) applyIfUnchanged(key string, snapshot []byte, apply func() error) (bool, error) {
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	current, found, err := s.backend.GetWithError(kv.NSTaskDataMetadata, key)
	if err != nil {
		return false, fmt.Errorf("%w: read metadata: %v", ErrStorage, err)
	}
	if !found || !bytes.Equal(current, snapshot) {
		return false, nil
	}
	return true, apply()
}

// reclaimTombstones stamps tombstones that have no deletion height yet and removes those whose
// retention has run out: height >= max(deleted_at_height, retain_until_height) +
// TombstoneRetentionBlocks. Until then a tombstone keeps refusing a re-upload of the deleted key
// and keeps answering it as deleted; retain_until_height is the order's expiry for an INPUT and
// the signed retention lease otherwise, so no upload of the key can be authorized once a
// tombstone is reclaimed (OpenTask refuses an expired order). A retention of 0 stamps but never
// reclaims. It returns how many tombstones it stamped and reclaimed. Caller holds the maintenance
// lock, at least for reading: the only other tombstone writer, DeleteObject, holds it exclusively.
func (s *Store) reclaimTombstones(height uint64) (int, int, error) {
	window := s.cfg.TombstoneRetentionBlocks
	stamps := map[string]tombstoneRecord{}
	var reclaim []string
	if err := s.backend.Scan(kv.NSTaskDataTombstone, func(key string, raw []byte) bool {
		var record tombstoneRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			// One undecodable record must not stop the sweep at the same place every minute;
			// it is left as it is for the operator.
			s.log.Warn("task data tombstone is not decodable; skipping it", "key", key, "err", err)
			return true
		}
		switch {
		case record.DeletedAtHeight == 0:
			record.DeletedAtHeight = height
			stamps[key] = record
		case window > 0 && tombstoneExpired(record, height, window):
			reclaim = append(reclaim, key)
		}
		return len(stamps)+len(reclaim) < tombstoneSweepBatch
	}); err != nil {
		return 0, 0, fmt.Errorf("%w: scan tombstones: %v", ErrStorage, err)
	}
	for key, record := range stamps {
		raw, err := json.Marshal(record)
		if err == nil {
			err = s.backend.Set(kv.NSTaskDataTombstone, key, raw)
		}
		if err != nil {
			return 0, 0, fmt.Errorf("%w: stamp tombstone: %v", ErrStorage, err)
		}
	}
	for _, key := range reclaim {
		if err := s.backend.Delete(kv.NSTaskDataTombstone, key); err != nil {
			return len(stamps), 0, fmt.Errorf("%w: reclaim tombstone: %v", ErrStorage, err)
		}
	}
	return len(stamps), len(reclaim), nil
}

// tombstoneExpired reports height >= max(deleted_at_height, retain_until_height) + window; a sum
// that overflows never expires.
func tombstoneExpired(record tombstoneRecord, height, window uint64) bool {
	from := max(record.DeletedAtHeight, record.RetainUntilHeight)
	until := from + window
	return until >= from && height >= until
}

// persistTombstone records that key was deleted. height is the chain height of the deletion, or 0
// when the caller does not know it; the next Sweep then stamps its own height.
func (s *Store) persistTombstone(metadata Metadata, height uint64) error {
	tombstone := tombstoneRecord{
		Key: metadata.Key, SemanticHash: metadata.SemanticHash, SizeBytes: metadata.SizeBytes,
		RetentionStatus: RetentionDeleted, RetainUntilHeight: metadata.RetainUntilHeight,
		DeletedAtUnixMillis: time.Now().UnixMilli(), DeletedAtHeight: height,
	}
	raw, err := json.Marshal(tombstone)
	if err != nil {
		return fmt.Errorf("%w: encode task data tombstone: %v", ErrStorage, err)
	}
	if err := s.backend.Set(kv.NSTaskDataTombstone, objectKeyString(metadata.Key), raw); err != nil {
		return fmt.Errorf("%w: persist task data tombstone: %v", ErrStorage, err)
	}
	return nil
}

func validRetentionDecision(decision RetentionDecision, height uint64) bool {
	switch decision.Status {
	case RetentionActive:
		return !decision.Delete
	case RetentionRetainedForChallenge:
		return !decision.Delete && decision.RetainUntilHeight > height
	case RetentionEligibleForCleanup:
		return decision.RetainUntilHeight != 0 && height >= decision.RetainUntilHeight && decision.Delete
	default:
		return false
	}
}

func (s *Store) recoverReservations() error {
	var records []reservationRecord
	reservedPaths := make(map[string]struct{})
	var decodeErr error
	if err := s.backend.Scan(kv.NSTaskDataReservation, func(_ string, raw []byte) bool {
		var record reservationRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			decodeErr = fmt.Errorf("%w: decode reservation: %v", ErrStorage, err)
			return false
		}
		records = append(records, record)
		return true
	}); err != nil {
		return fmt.Errorf("%w: scan reservations: %v", ErrStorage, err)
	}
	if decodeErr != nil {
		return decodeErr
	}
	for _, record := range records {
		if filepath.Dir(record.SpoolPath) != filepath.Join(s.root, "spool") || filepath.Ext(record.SpoolPath) != ".part" {
			return fmt.Errorf("%w: invalid persisted spool path", ErrStorage)
		}
		reservedPaths[record.SpoolPath] = struct{}{}
		if err := os.Remove(record.SpoolPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: remove abandoned spool: %v", ErrStorage, err)
		}
		if err := s.backend.Delete(kv.NSTaskDataReservation, record.ID); err != nil {
			return fmt.Errorf("%w: delete abandoned reservation: %v", ErrStorage, err)
		}
	}
	spoolRoot := filepath.Join(s.root, "spool")
	entries, err := os.ReadDir(spoolRoot)
	if err != nil {
		return fmt.Errorf("%w: scan spool directory: %v", ErrStorage, err)
	}
	for _, entry := range entries {
		path := filepath.Join(spoolRoot, entry.Name())
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".part" {
			return fmt.Errorf("%w: unexpected spool path %q", ErrStorage, path)
		}
		if _, wasReserved := reservedPaths[path]; wasReserved {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: remove orphan spool: %v", ErrStorage, err)
		}
	}
	if err := s.directorySync(spoolRoot); err != nil {
		return fmt.Errorf("%w: sync spool directory: %v", ErrStorage, err)
	}
	s.mu.Lock()
	s.reservations = make(map[string]*reservationState)
	s.activeKeys = make(map[string]string)
	s.reserved = 0
	s.mu.Unlock()
	return nil
}

// metadataEntry is a metadata record with the exact bytes it is stored as.
type metadataEntry struct {
	record metadataRecord
	raw    []byte
}

func (s *Store) loadMetadataRecords() (map[string]metadataRecord, error) {
	entries, err := s.loadMetadataEntries()
	if err != nil {
		return nil, err
	}
	records := make(map[string]metadataRecord, len(entries))
	for key, entry := range entries {
		records[key] = entry.record
	}
	return records, nil
}

func (s *Store) loadMetadataEntries() (map[string]metadataEntry, error) {
	entries := make(map[string]metadataEntry)
	var decodeErr error
	if err := s.backend.Scan(kv.NSTaskDataMetadata, func(key string, raw []byte) bool {
		var record metadataRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			decodeErr = fmt.Errorf("%w: decode metadata %q: %v", ErrStorage, key, err)
			return false
		}
		if !canonicalSHA256(record.BlobHash) || objectKeyString(record.Metadata.Key) != key {
			decodeErr = fmt.Errorf("%w: invalid metadata identity %q", ErrStorage, key)
			return false
		}
		entries[key] = metadataEntry{record: record, raw: raw}
		return true
	}); err != nil {
		return nil, fmt.Errorf("%w: scan metadata: %v", ErrStorage, err)
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	return entries, nil
}

func (s *Store) persistMetadataRecord(key string, record metadataRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encode metadata: %v", ErrStorage, err)
	}
	if err := s.backend.Set(kv.NSTaskDataMetadata, key, raw); err != nil {
		return fmt.Errorf("%w: persist metadata: %v", ErrStorage, err)
	}
	return nil
}

// removeUnreferencedBlobs removes every blob no record names. Caller holds the exclusive
// maintenance lock and records are all the metadata records.
func (s *Store) removeUnreferencedBlobs(records map[string]metadataRecord) error {
	unreferenced, err := s.unreferencedBlobFiles(referencedBlobs(records))
	if err != nil {
		return err
	}
	for _, hash := range unreferenced {
		if err := os.Remove(s.blobPath(hash)); err != nil {
			return fmt.Errorf("%w: reconcile blobs: %v", ErrStorage, err)
		}
	}
	return nil
}
