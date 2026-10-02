// Package payloadstore removes task inputs when a task terminates and sweeps the inline payload
// records older releases wrote, by their chain deadline. Inputs themselves are stored and served
// by taskdata.
package payloadstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Input names a task's INPUT for deletion. TaskHash and ContentHash identify the exact version
// (the order's task_hash and input hash); when either is empty the version is unknown and the
// INPUT index decides which object is removed.
type Input struct {
	SessionID   string
	TaskID      string
	TaskHash    string
	ContentHash string
}

// Store removes task inputs. The bytes are written and served by taskdata; what is left here is
// the cleanup when a task terminates, and the sweep of inline payload records written by older
// releases.
type Store interface {
	Delete(context.Context, Input) error
	Sweep(context.Context, uint64) error
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

func (s *store) Delete(ctx context.Context, input Input) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.taskData != nil {
		if err := s.deleteTaskData(ctx, input); err != nil {
			return err
		}
	}
	if err := s.backend.Delete(kv.NSPayload, payloadKey(input.SessionID, input.TaskID)); err != nil {
		return fmt.Errorf("%w: delete payload: %v", ErrStore, err)
	}
	return nil
}

// deleteTaskData removes the INPUT object of the named version; DeleteObject is idempotent. A
// version that was never stored here (a Builder that knows the task only from the chain) gets a
// tombstone only, which also stops that input from being uploaded after the task ended. Without a version it falls back to the
// INPUT index, which is how cleanup intents queued by older releases name the object, and an
// unresolvable index means there is nothing to delete.
func (s *store) deleteTaskData(ctx context.Context, input Input) error {
	ref := taskdata.ObjectKey{
		TaskHash: input.TaskHash, SessionID: input.SessionID, TaskID: input.TaskID,
		Kind: taskdata.ObjectKindInput, ContentHash: input.ContentHash,
	}
	if input.TaskHash == "" || input.ContentHash == "" {
		resolved, err := s.taskData.ResolveObject(ctx, input.SessionID, input.TaskID, taskdata.ObjectKindInput)
		if errors.Is(err, taskdata.ErrNotFound) {
			return nil
		} else if err != nil {
			return mapTaskDataError(err)
		}
		ref = resolved
	}
	return mapTaskDataError(s.taskData.DeleteObject(ctx, ref))
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
