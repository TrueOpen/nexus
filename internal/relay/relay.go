// Package relay is a credential store: it holds only fetch credentials (key + reference), never the blob
// itself (implementation design §4.4 / detailed design §2.4). In-memory first + optional KV write-through:
// held credentials are restored after restart until the authoritative chain height and final settlement allow explicit release.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

var (
	ErrNotInCustody = errors.New("relay: not in custody")
	ErrExpired      = errors.New("relay: custody expired")
	ErrConflict     = errors.New("relay: conflicting output ref")
)

// Custodian is the credential store interface.
// The credential store key is the composite session_id + task_id.
//
// The Nexus<->Cortex contract "target-state baseline" removed the OutputRef object and sealed-key delivery: the
// held object is now just the selected Worker's signed InferReceipt (commitment + signature, no locator, no key),
// so access_level tiers no longer affect the returned content; they are kept only for the pending FetchOutputRef.
type Custodian interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	// Hold stores a reference until ttl expires; ttl <= 0 requires explicit Release.
	Hold(receipt types.InferReceiptSubmission, ttl time.Duration) error
	Serve(sessionID, taskID string, level types.AccessLevel) (types.InferReceiptSubmission, error)
	Release(sessionID, taskID string)
}

// custodyKey is the composite credential store key = session_id|task_id.
func custodyKey(sessionID, taskID string) string { return sessionID + "|" + taskID }

type entry struct {
	ref     types.InferReceiptSubmission
	expires time.Time
}

// custodyRecord is the persisted encoding (NSCustody, key = session_id|task_id).
type custodyRecord struct {
	Ref       types.InferReceiptSubmission `json:"receipt"`
	ExpiresMS int64                        `json:"expires_ms"`
}

type memCustodian struct {
	log           *slog.Logger
	store         kv.Store // may be nil = pure in-memory (tests/degraded)
	mu            sync.RWMutex
	held          map[string]entry
	stopOnce      sync.Once
	stop          chan struct{}
	wg            sync.WaitGroup
	sweepInterval time.Duration
}

// NewMem returns an in-memory credential store.
func NewMem(log *slog.Logger) Custodian {
	return &memCustodian{
		log: log, held: make(map[string]entry), stop: make(chan struct{}), sweepInterval: time.Minute,
	}
}

// NewKV returns a credential store with KV write-through: Hold/Release persist synchronously,
// Start restores unexpired held credentials into memory.
func NewKV(log *slog.Logger, store kv.Store) Custodian {
	return &memCustodian{
		log: log, store: store, held: make(map[string]entry), stop: make(chan struct{}), sweepInterval: time.Minute,
	}
}

func (c *memCustodian) Start(_ context.Context) error {
	if err := c.restore(); err != nil {
		return err
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.sweepLoop()
	}()
	return nil
}

// restore reloads held credentials from KV (dropping expired ones along the way).
func (c *memCustodian) restore() error {
	if c.store == nil {
		return nil
	}
	now := time.Now()
	restored, dropped := 0, 0
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.store.Scan(kv.NSCustody, func(key string, val []byte) bool {
		var rec custodyRecord
		if err := json.Unmarshal(val, &rec); err != nil {
			c.log.Warn("custody record corrupt, dropping", "key", key, "err", err)
			_ = c.store.Delete(kv.NSCustody, key)
			return true
		}
		var exp time.Time
		if rec.ExpiresMS > 0 {
			exp = time.UnixMilli(rec.ExpiresMS)
		}
		if !exp.IsZero() && now.After(exp) {
			_ = c.store.Delete(kv.NSCustody, key)
			dropped++
			return true
		}
		c.held[key] = entry{ref: rec.Ref, expires: exp}
		restored++
		return true
	})
	if err != nil {
		return fmt.Errorf("relay: restore custody: %w", err)
	}
	if restored > 0 || dropped > 0 {
		c.log.Info("custody restored from kv", "restored", restored, "expired_dropped", dropped)
	}
	return nil
}

func (c *memCustodian) Stop(_ context.Context) error {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.wg.Wait()
	})
	return nil
}

func (c *memCustodian) Hold(ref types.InferReceiptSubmission, ttl time.Duration) error {
	key := custodyKey(ref.SessionID, ref.TaskID)
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, exists := c.held[key]; exists && !reflect.DeepEqual(current.ref, ref) {
		return ErrConflict
	}
	c.held[key] = entry{ref: ref, expires: exp}
	if c.store != nil {
		// A persist failure must propagate: silently keeping it in memory means "held credential lost after restart" --
		// the caller (Worker retransmitting InferReceipt) can retry; Hold is idempotent.
		var expiresMS int64
		if !exp.IsZero() {
			expiresMS = exp.UnixMilli()
		}
		b, err := json.Marshal(custodyRecord{Ref: ref, ExpiresMS: expiresMS})
		if err != nil {
			return fmt.Errorf("relay: encode custody record: %w", err)
		}
		if err := c.store.Set(kv.NSCustody, key, b); err != nil {
			return fmt.Errorf("relay: persist custody (in memory for now, retry to be safe): %w", err)
		}
	}
	c.log.Debug("custody hold", "session_id", ref.SessionID, "task_id", ref.TaskID, "ttl", ttl)
	return nil
}

func (c *memCustodian) Serve(sessionID, taskID string, _ types.AccessLevel) (types.InferReceiptSubmission, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.held[custodyKey(sessionID, taskID)]
	if !ok {
		return types.InferReceiptSubmission{}, ErrNotInCustody
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		return types.InferReceiptSubmission{}, ErrExpired
	}
	return e.ref, nil
}

func (c *memCustodian) Release(sessionID, taskID string) {
	key := custodyKey(sessionID, taskID)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.held, key)
	if c.store != nil {
		_ = c.store.Delete(kv.NSCustody, key) // a failed delete only leaves a stale record; restore cleans it up as expired
	}
}

// sweepLoop periodically removes expired held credentials.
func (c *memCustodian) sweepLoop() {
	t := time.NewTicker(c.sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			now := time.Now()
			c.mu.Lock()
			for id, e := range c.held {
				if !e.expires.IsZero() && now.After(e.expires) {
					delete(c.held, id)
					if c.store != nil {
						_ = c.store.Delete(kv.NSCustody, id)
					}
					c.log.Debug("custody expired", "task_id", id)
				}
			}
			c.mu.Unlock()
		}
	}
}
