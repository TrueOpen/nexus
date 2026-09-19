// Package kv is the local persistence wrapper (Implementation Design §4.6 / Detailed Design §2.6).
// The in-memory implementation is for tests/degraded runs; production uses pebble (see pebble.go).
// Task snapshots can be rebuilt from the chain; held credential keys, plaintext outputs and terminal delivery state cannot,
// so their callers must handle persistence and scan errors explicitly.
package kv

import (
	"maps"
	"sort"
	"sync"
)

// Namespace is the partition prefix.
type Namespace string

const (
	NSTask            Namespace = "task"
	NSCustody         Namespace = "custody"
	NSCustodyTTL      Namespace = "custody_ttl"
	NSReward          Namespace = "reward"
	NSCapability      Namespace = "capability"
	NSBusCursor       Namespace = "bus_cursor"
	NSBuilderReg      Namespace = "builder_registration"
	NSOutputDelivery  Namespace = "output_delivery"
	NSOutputTombstone Namespace = "output_tombstone"
	NSPayload         Namespace = "payload"
	NSPayloadCleanup  Namespace = "payload_cleanup"
	NSTerminalTask    Namespace = "terminal_task"
	// NSTaskSession is the task_id -> session_id index. A wire v0.4.1 relay request carries only the
	// on-chain message body, the on-chain task_id contains no session, and the FSM is keyed by (session, task).
	NSTaskSession      Namespace = "task_session"
	NSChainState       Namespace = "chain_state"
	NSChainEventCursor Namespace = "chain_event_cursor"
	NSTaskDataMetadata Namespace = "task_data_metadata"
	// NSTaskDataObjectIndex is the (session, task, kind) -> object ref index.
	// Once content_hash became part of the object identity, lifecycle operations only have the first three and resolve the ref through this index.
	NSTaskDataObjectIndex  Namespace = "task_data_object_index"
	NSTaskDataReservation  Namespace = "task_data_reservation"
	NSTaskDataTombstone    Namespace = "task_data_tombstone"
	NSTaskDataReplay       Namespace = "task_data_replay"
	NSTaskDataReplayExpiry Namespace = "task_data_replay_expiry"
	// NSTaskDataOutputStream is the write progress of a streaming OUTPUT (ADR-0017); key = object key, one record.
	NSTaskDataOutputStream Namespace = "task_data_output_stream"
	// NSTaskDataOutputFrame holds the frame records of a streaming OUTPUT; key = object key|zero-padded seq, one record per frame.
	// It is kept separate from the progress record to avoid rewriting the whole record on every frame (O(n^2) write amplification).
	NSTaskDataOutputFrame Namespace = "task_data_output_frame"
	// NSTaskDataFinalize is the idempotency record of Finalize: key = body digest + requester,
	// value = the save acknowledgement issued the first time. An exact replay returns the original bytes and signature instead of re-signing.
	NSTaskDataFinalize Namespace = "task_data_finalize"
	// NSOutputAck is the user's local delivery progress for a streaming OUTPUT (task, last_seq); it is not a consensus fact.
	NSOutputAck Namespace = "output_ack"
	NSBusReplay Namespace = "bus_replay"
	NSBusOutbox Namespace = "bus_outbox"
)

type Store interface {
	Get(ns Namespace, key string) ([]byte, bool)
	// GetWithError is for security-sensitive existence checks; it must never degrade an underlying read error into "not present".
	GetWithError(ns Namespace, key string) ([]byte, bool, error)
	// Set/Delete return the underlying write error: for data that cannot be rebuilt from the chain, such as held credential keys,
	// the caller must see the write failure (disk full / store closed) instead of silently degrading to in-memory state.
	Set(ns Namespace, key string, val []byte) error
	Delete(ns Namespace, key string) error
	// Scan walks every key/value in a partition (used for restart recovery); returning false from fn stops early.
	// Iteration follows byte order of the keys; concurrent writes during iteration are not guaranteed to be visible.
	Scan(ns Namespace, fn func(key string, val []byte) bool) error
	// WriteBatch applies several writes atomically: either all of them are persisted or none takes effect.
	// It is what guarantees "progress and frame record in the same transaction" for a streaming OUTPUT (ADR-0017).
	WriteBatch(ops ...WriteOp) error
	Close() error
}

// WriteOp is one operation in a batch write: Delete true means delete the key, otherwise write Val.
type WriteOp struct {
	NS     Namespace
	Key    string
	Val    []byte
	Delete bool
}

// memStore is the in-process implementation (not persistent).
type memStore struct {
	mu sync.RWMutex
	m  map[Namespace]map[string][]byte
}

// NewMemStore returns the in-memory Store.
func NewMemStore() Store {
	return &memStore{m: make(map[Namespace]map[string][]byte)}
}

func (s *memStore) Get(ns Namespace, key string) ([]byte, bool) {
	val, ok, _ := s.GetWithError(ns, key)
	return val, ok
}

func (s *memStore) GetWithError(ns Namespace, key string) ([]byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b, ok := s.m[ns]; ok {
		v, ok := b[key]
		return v, ok, nil
	}
	return nil, false, nil
}

func (s *memStore) Set(ns Namespace, key string, val []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[ns] == nil {
		s.m[ns] = make(map[string][]byte)
	}
	s.m[ns][key] = append([]byte(nil), val...)
	return nil
}

func (s *memStore) WriteBatch(ops ...WriteOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			if b, ok := s.m[op.NS]; ok {
				delete(b, op.Key)
			}
			continue
		}
		if s.m[op.NS] == nil {
			s.m[op.NS] = make(map[string][]byte)
		}
		s.m[op.NS][op.Key] = append([]byte(nil), op.Val...)
	}
	return nil
}

func (s *memStore) Delete(ns Namespace, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.m[ns]; ok {
		delete(b, key)
	}
	return nil
}

func (s *memStore) Scan(ns Namespace, fn func(key string, val []byte) bool) error {
	// Snapshot first, then call back, so the callback cannot re-enter while the lock is held.
	s.mu.RLock()
	b := s.m[ns]
	cp := make(map[string][]byte, len(b))
	maps.Copy(cp, b)
	s.mu.RUnlock()
	keys := make([]string, 0, len(cp))
	for key := range cp {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := cp[k]
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (s *memStore) Close() error { return nil }
