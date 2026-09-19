// Package payloadstore persists encrypted task inputs until their chain
// deadline or explicit task termination.
package payloadstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

var (
	ErrInvalid      = errors.New("payloadstore: invalid submission")
	ErrHashMismatch = errors.New("payloadstore: payload hash mismatch")
	ErrRefMismatch  = errors.New("payloadstore: payload ref mismatch")
	ErrTooLarge     = errors.New("payloadstore: payload too large")
	ErrConflict     = errors.New("payloadstore: conflicting payload")
	ErrNotFound     = errors.New("payloadstore: payload not found")
	ErrExpired      = errors.New("payloadstore: payload expired")
	ErrStore        = errors.New("payloadstore: storage failure")
)

type Config struct {
	MaxBytes int
}

type Submission struct {
	SessionID string
	TaskID    string
	// TaskHash is the first field of the object ref (wire v0.4.1). INPUT is created
	// together with the Task, so the caller already knows it at submission.
	TaskHash       string
	Ref            string
	Hash           string
	Payload        []byte
	DeadlineHeight uint64
}

type Payload struct {
	SessionID string
	TaskID    string
	// TaskHash is the first field of the object ref. Records written before V1 lack it; migration skips them.
	TaskHash       string
	Ref            string
	Hash           string
	Payload        []byte
	DeadlineHeight uint64
}

type Store interface {
	Put(context.Context, Submission) error
	Fetch(context.Context, string, string, uint64) (Payload, error)
	Delete(context.Context, string, string) error
	Sweep(context.Context, uint64) error
}

// AcceptanceStore is implemented by the taskdata adapter. Coordinator uses
// it to move INPUT from PREPARED to READY only after local order acceptance.
type AcceptanceStore interface {
	Store
	MarkAccepted(context.Context, string, string) error
	RollbackPrepared(context.Context, string, string) error
}

type Option func(*store)

func WithTaskData(taskStore *taskdata.Store) Option {
	return func(s *store) { s.taskData = taskStore }
}

type store struct {
	log      *slog.Logger
	backend  kv.Store
	max      int
	mu       sync.Mutex
	taskData *taskdata.Store
}

type record struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	// TaskHash is the first field of the object ref. Records written before V1 lack it
	// and read back as empty; migration skips them rather than inventing an identity.
	TaskHash       string `json:"task_hash,omitempty"`
	Ref            string `json:"payload_ref"`
	Hash           string `json:"payload_hash"`
	Payload        []byte `json:"payload"`
	DeadlineHeight uint64 `json:"deadline_height"`
}

func New(log *slog.Logger, backend kv.Store, cfg Config, options ...Option) (Store, error) {
	if backend == nil {
		return nil, fmt.Errorf("payloadstore: nil backend")
	}
	if cfg.MaxBytes <= 0 {
		return nil, fmt.Errorf("payloadstore: max bytes must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	created := &store{log: log, backend: backend, max: cfg.MaxBytes}
	for _, option := range options {
		option(created)
	}
	return created, nil
}

func RefFor(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "nexus://sha256/" + hex.EncodeToString(sum[:])
}

func RefForHash(hash string) string {
	if !canonicalSHA256(hash) {
		return ""
	}
	return "nexus://sha256/" + hash
}

func (s *store) Put(_ context.Context, sub Submission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taskData != nil {
		return s.putTaskData(context.Background(), sub)
	}

	if sub.SessionID == "" || sub.TaskID == "" || sub.TaskHash == "" || len(sub.Payload) == 0 || sub.DeadlineHeight == 0 {
		return ErrInvalid
	}
	if len(sub.Payload) > s.max {
		return ErrTooLarge
	}
	sum := sha256.Sum256(sub.Payload)
	wantHash := hex.EncodeToString(sum[:])
	if sub.Hash != wantHash || !canonicalSHA256(sub.Hash) {
		return ErrHashMismatch
	}
	if sub.Ref != RefFor(sub.Payload) {
		return ErrRefMismatch
	}

	rec := record{
		SessionID: sub.SessionID, TaskID: sub.TaskID, TaskHash: sub.TaskHash, Ref: sub.Ref,
		Hash: sub.Hash, Payload: append([]byte(nil), sub.Payload...), DeadlineHeight: sub.DeadlineHeight,
	}
	key := payloadKey(sub.SessionID, sub.TaskID)
	if raw, ok, err := s.backend.GetWithError(kv.NSPayload, key); err != nil {
		return fmt.Errorf("%w: inspect existing payload: %v", ErrStore, err)
	} else if ok {
		var current record
		if err := json.Unmarshal(raw, &current); err != nil {
			return fmt.Errorf("%w: decode existing payload: %v", ErrStore, err)
		}
		if equalRecord(current, rec) {
			return nil
		}
		return ErrConflict
	}

	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("%w: encode payload: %v", ErrStore, err)
	}
	if err := s.backend.Set(kv.NSPayload, key, raw); err != nil {
		return fmt.Errorf("%w: persist payload: %v", ErrStore, err)
	}
	return nil
}

func (s *store) Fetch(_ context.Context, sessionID, taskID string, height uint64) (Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taskData != nil {
		if payload, err := s.fetchTaskData(context.Background(), sessionID, taskID, height); err == nil {
			return payload, nil
		} else if !errors.Is(err, ErrNotFound) {
			return Payload{}, err
		}
	}

	key := payloadKey(sessionID, taskID)
	raw, ok, err := s.backend.GetWithError(kv.NSPayload, key)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: read payload: %v", ErrStore, err)
	}
	if !ok {
		return Payload{}, ErrNotFound
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Payload{}, fmt.Errorf("%w: decode payload: %v", ErrStore, err)
	}
	if rec.SessionID != sessionID || rec.TaskID != taskID || key != payloadKey(rec.SessionID, rec.TaskID) {
		return Payload{}, fmt.Errorf("%w: payload key mismatch", ErrStore)
	}
	if height != 0 && height >= rec.DeadlineHeight {
		if err := s.backend.Delete(kv.NSPayload, key); err != nil {
			return Payload{}, fmt.Errorf("%w: delete expired payload: %v", ErrStore, err)
		}
		return Payload{}, ErrExpired
	}
	payload := payloadFromRecord(rec)
	// A legacy record without task_hash cannot be migrated: it is the first field of the
	// object ref, was never stored, and cannot be derived elsewhere. Such records keep
	// serving as-is; we do not invent an identity.
	if s.taskData != nil && payload.TaskHash != "" {
		if err := s.migrateLegacy(context.Background(), payload); err != nil {
			return Payload{}, err
		}
		if err := s.backend.Delete(kv.NSPayload, key); err != nil {
			return Payload{}, fmt.Errorf("%w: delete migrated payload: %v", ErrStore, err)
		}
	}
	return payload, nil
}

func (s *store) Delete(_ context.Context, sessionID, taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.taskData != nil {
		ref, err := s.taskData.ResolveObject(context.Background(), sessionID, taskID, taskdata.ObjectKindInput)
		switch {
		case err == nil:
			if err := s.taskData.DeleteObject(context.Background(), ref); err != nil {
				return mapTaskDataError(err)
			}
		case errors.Is(err, taskdata.ErrNotFound):
			// Object already absent: deletion is idempotent, continue clearing the local payload record.
		default:
			return mapTaskDataError(err)
		}
	}
	if err := s.backend.Delete(kv.NSPayload, payloadKey(sessionID, taskID)); err != nil {
		return fmt.Errorf("%w: delete payload: %v", ErrStore, err)
	}
	return nil
}

func (s *store) MarkAccepted(ctx context.Context, sessionID, taskID string) error {
	if s.taskData == nil {
		return nil
	}
	ref, err := s.taskData.ResolveObject(ctx, sessionID, taskID, taskdata.ObjectKindInput)
	if err != nil {
		return mapTaskDataError(err)
	}
	_, err = s.taskData.MarkReady(ctx, ref)
	return mapTaskDataError(err)
}

func (s *store) RollbackPrepared(ctx context.Context, sessionID, taskID string) error {
	if s.taskData == nil {
		return s.Delete(ctx, sessionID, taskID)
	}
	ref, err := s.taskData.ResolveObject(ctx, sessionID, taskID, taskdata.ObjectKindInput)
	if err != nil {
		return mapTaskDataError(err)
	}
	return mapTaskDataError(s.taskData.RollbackPrepared(ctx, ref))
}

func (s *store) putTaskData(ctx context.Context, sub Submission) error {
	if err := validateSubmission(sub, s.max); err != nil {
		return err
	}
	upload, err := s.taskData.Begin(ctx, taskdata.UploadHeader{
		Key: inputKey(sub), SizeBytes: uint64(len(sub.Payload)), SemanticHash: sub.Hash,
		MediaType: "application/octet-stream", RetainUntilHeight: sub.DeadlineHeight,
	})
	if err != nil {
		return mapTaskDataError(err)
	}
	defer upload.Abort()
	for offset := 0; offset < len(sub.Payload); {
		end := offset + int(s.taskDataChunkSize())
		if end > len(sub.Payload) {
			end = len(sub.Payload)
		}
		if err := upload.WriteChunk(sub.Payload[offset:end]); err != nil {
			return mapTaskDataError(err)
		}
		offset = end
	}
	_, err = upload.Prepare(ctx)
	return mapTaskDataError(err)
}

func (s *store) taskDataChunkSize() uint64 {
	return s.taskData.ChunkSize()
}

func (s *store) fetchTaskData(ctx context.Context, sessionID, taskID string, height uint64) (Payload, error) {
	key, err := s.taskData.ResolveObject(ctx, sessionID, taskID, taskdata.ObjectKindInput)
	if err != nil {
		if errors.Is(err, taskdata.ErrNotFound) {
			return Payload{}, ErrNotFound
		}
		return Payload{}, mapTaskDataError(err)
	}
	metadata, err := s.taskData.Metadata(ctx, key)
	if err != nil || metadata.State != taskdata.StateReady {
		if errors.Is(err, taskdata.ErrNotFound) || err == nil {
			return Payload{}, ErrNotFound
		}
		return Payload{}, mapTaskDataError(err)
	}
	if height != 0 && metadata.RetainUntilHeight != 0 && height >= metadata.RetainUntilHeight {
		return Payload{}, ErrExpired
	}
	reader, err := s.taskData.OpenRange(ctx, key, 0, 0)
	if err != nil {
		return Payload{}, mapTaskDataError(err)
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, int64(s.max)+1))
	if err != nil || len(body) > s.max {
		return Payload{}, ErrStore
	}
	return Payload{
		SessionID: sessionID, TaskID: taskID, Ref: RefForHash(metadata.SemanticHash), Hash: metadata.SemanticHash,
		Payload: body, DeadlineHeight: metadata.RetainUntilHeight,
	}, nil
}

func (s *store) migrateLegacy(ctx context.Context, payload Payload) error {
	if err := s.putTaskData(ctx, Submission{
		SessionID: payload.SessionID, TaskID: payload.TaskID, TaskHash: payload.TaskHash,
		Ref: payload.Ref, Hash: payload.Hash,
		Payload: payload.Payload, DeadlineHeight: payload.DeadlineHeight,
	}); err != nil {
		return err
	}
	return s.MarkAccepted(ctx, payload.SessionID, payload.TaskID)
}

func validateSubmission(sub Submission, max int) error {
	if sub.SessionID == "" || sub.TaskID == "" || sub.TaskHash == "" || len(sub.Payload) == 0 || sub.DeadlineHeight == 0 {
		return ErrInvalid
	}
	if len(sub.Payload) > max {
		return ErrTooLarge
	}
	sum := sha256.Sum256(sub.Payload)
	wantHash := hex.EncodeToString(sum[:])
	if sub.Hash != wantHash || !canonicalSHA256(sub.Hash) {
		return ErrHashMismatch
	}
	if sub.Ref != RefFor(sub.Payload) {
		return ErrRefMismatch
	}
	return nil
}

// inputKey builds the full object ref used for upload. content_hash is the payload hash:
// the same bytes can have only one identity, so it must equal UploadHeader.SemanticHash.
func inputKey(sub Submission) taskdata.ObjectKey {
	return taskdata.ObjectKey{
		TaskHash: sub.TaskHash, SessionID: sub.SessionID, TaskID: sub.TaskID,
		Kind: taskdata.ObjectKindInput, ContentHash: sub.Hash,
	}
}

func mapTaskDataError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, taskdata.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, taskdata.ErrExpired):
		return ErrExpired
	case errors.Is(err, taskdata.ErrCapacity):
		return ErrTooLarge
	case errors.Is(err, taskdata.ErrConflict):
		return ErrConflict
	case errors.Is(err, taskdata.ErrHashMismatch):
		return ErrHashMismatch
	case errors.Is(err, taskdata.ErrMalformed):
		return ErrInvalid
	default:
		return fmt.Errorf("%w: %v", ErrStore, err)
	}
}

func (s *store) Sweep(_ context.Context, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if height == 0 {
		return nil
	}
	var expired []string
	var scanErr error
	err := s.backend.Scan(kv.NSPayload, func(key string, raw []byte) bool {
		var rec record
		if err := json.Unmarshal(raw, &rec); err != nil {
			scanErr = fmt.Errorf("%w: decode payload %q: %v", ErrStore, key, err)
			return false
		}
		if key != payloadKey(rec.SessionID, rec.TaskID) {
			scanErr = fmt.Errorf("%w: payload key mismatch %q", ErrStore, key)
			return false
		}
		if height >= rec.DeadlineHeight {
			expired = append(expired, key)
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("%w: scan payloads: %v", ErrStore, err)
	}
	if scanErr != nil {
		return scanErr
	}
	for _, key := range expired {
		if err := s.backend.Delete(kv.NSPayload, key); err != nil {
			return fmt.Errorf("%w: delete expired payload %q: %v", ErrStore, key, err)
		}
	}
	if len(expired) > 0 {
		s.log.Debug("expired payloads deleted", "height", height, "count", len(expired))
	}
	return nil
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func payloadKey(sessionID, taskID string) string { return sessionID + "|" + taskID }

func equalRecord(a, b record) bool {
	return a.SessionID == b.SessionID && a.TaskID == b.TaskID && a.Ref == b.Ref &&
		a.Hash == b.Hash && a.DeadlineHeight == b.DeadlineHeight && bytes.Equal(a.Payload, b.Payload)
}

func payloadFromRecord(rec record) Payload {
	return Payload{
		SessionID: rec.SessionID, TaskID: rec.TaskID, TaskHash: rec.TaskHash, Ref: rec.Ref, Hash: rec.Hash,
		Payload: append([]byte(nil), rec.Payload...), DeadlineHeight: rec.DeadlineHeight,
	}
}
