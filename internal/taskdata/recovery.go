package taskdata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
}

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
			records[key] = record
		case record.Metadata.Key.Kind == ObjectKindInput:
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
	return s.removeUnreferencedBlobs(records)
}

func (s *Store) Sweep(ctx context.Context, height uint64, resolver RecoveryResolver) error {
	if height == 0 || resolver == nil {
		return fmt.Errorf("%w: cleanup height and resolver required", ErrMalformed)
	}
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	records, err := s.loadMetadataRecords()
	if err != nil {
		return err
	}
	for key, record := range records {
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
					if err := s.backend.Delete(kv.NSTaskDataMetadata, key); err != nil {
						return fmt.Errorf("%w: delete rejected quarantined input: %v", ErrStorage, err)
					}
					delete(records, key)
				}
				continue
			}
			record.Metadata.State = StateReady
			if err := s.persistMetadataRecord(key, record); err != nil {
				return err
			}
			records[key] = record
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
			if err := s.persistMetadataRecord(key, record); err != nil {
				return err
			}
			records[key] = record
			continue
		}
		record.Metadata.RetainUntilHeight = decision.RetainUntilHeight
		if err := s.persistTombstone(record.Metadata); err != nil {
			return err
		}
		if err := s.backend.Delete(kv.NSTaskDataMetadata, key); err != nil {
			return fmt.Errorf("%w: delete task data metadata: %v", ErrStorage, err)
		}
		delete(records, key)
	}
	if err := s.pruneFetchReceiptsLocked(records); err != nil {
		return err
	}
	return s.removeUnreferencedBlobs(records)
}

func (s *Store) persistTombstone(metadata Metadata) error {
	tombstone := tombstoneRecord{
		Key: metadata.Key, SemanticHash: metadata.SemanticHash, SizeBytes: metadata.SizeBytes,
		RetentionStatus: RetentionDeleted, RetainUntilHeight: metadata.RetainUntilHeight,
		DeletedAtUnixMillis: time.Now().UnixMilli(),
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

func (s *Store) loadMetadataRecords() (map[string]metadataRecord, error) {
	records := make(map[string]metadataRecord)
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
		records[key] = record
		return true
	}); err != nil {
		return nil, fmt.Errorf("%w: scan metadata: %v", ErrStorage, err)
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
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

func (s *Store) removeUnreferencedBlobs(records map[string]metadataRecord) error {
	referenced := make(map[string]struct{}, len(records))
	for _, record := range records {
		referenced[record.BlobHash] = struct{}{}
	}
	root := filepath.Join(s.root, "blobs", "sha256")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !canonicalSHA256(name) || path != s.blobPath(name) {
			return fmt.Errorf("unexpected blob path %q", path)
		}
		if _, ok := referenced[name]; ok {
			return nil
		}
		return os.Remove(path)
	})
	if err != nil {
		return fmt.Errorf("%w: reconcile blobs: %v", ErrStorage, err)
	}
	return nil
}
