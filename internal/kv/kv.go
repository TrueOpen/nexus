// Package kv is the local persistence wrapper.
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
	NSBuilderReg      Namespace = "builder_registration"
	NSOutputDelivery  Namespace = "output_delivery"
	NSOutputTombstone Namespace = "output_tombstone"
	NSPayload         Namespace = "payload"
	NSPayloadCleanup  Namespace = "payload_cleanup"
	NSTerminalTask    Namespace = "terminal_task"
	// NSAbandonedOrder marks an order version this Builder dropped before it reached the chain, so
	// its INPUT is released once its retention ends; key = session_id|task_id|task_hash (package
	// coordinator).
	NSAbandonedOrder Namespace = "abandoned_order"
	// NSTaskSession is the task_id -> session_id index. A relay request carries only the
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
	// NSTaskDataOutputStream is the write progress of a streaming OUTPUT; key = object key, one record.
	NSTaskDataOutputStream Namespace = "task_data_output_stream"
	// NSTaskDataOutputFrame holds the frame records of a streaming OUTPUT; key = object key|zero-padded seq, one record per frame.
	// It is kept separate from the progress record to avoid rewriting the whole record on every frame (O(n^2) write amplification).
	NSTaskDataOutputFrame Namespace = "task_data_output_frame"
	// NSTaskDataFinalize is the idempotency record of Finalize: key = body digest + requester,
	// value = the save acknowledgement issued the first time. An exact replay returns the original bytes and signature instead of re-signing.
	NSTaskDataFinalize Namespace = "task_data_finalize"
	// NSTaskDataFetchReceipt keeps a Cortex Node's signed FetchTaskData request, so the Builder can
	// later show what that node downloaded; key = session|task|requester|request digest.
	NSTaskDataFetchReceipt Namespace = "task_data_fetch_receipt"
	// NSTaskDataFetchReceiptIndex lists the receipts of one (session, task, requester) with their
	// count and the number dropped over the cap; key = session|task|requester.
	NSTaskDataFetchReceiptIndex Namespace = "task_data_fetch_receipt_index"
	// NSOutputAck is the user's local delivery progress for a streaming OUTPUT (task, last_seq); it is not a consensus fact.
	NSOutputAck Namespace = "output_ack"
	// NSLocalSchema holds the version of the local state layout, see package localschema.
	NSLocalSchema Namespace = "local_schema"
	// NSHandraise holds the direct dispatch handraise registry: the current standing handraise of
	// each Cortex operator, reject-rate suspensions, the RTT admission threshold history and the
	// pointer to the latest issued handraise root.
	NSHandraise Namespace = "handraise"
	// NSHandraiseRoot holds every issued signed handraise root with its leaves, as the bytes that
	// were signed and sent; key = zero-padded root_height/root_version. A root is never re-signed.
	NSHandraiseRoot Namespace = "handraise_root"
	// NSHandraiseRootDigest is the handraise_root_digest -> NSHandraiseRoot key index used to
	// look up a root named by a ticket or a challenge.
	NSHandraiseRootDigest Namespace = "handraise_root_digest"
	// NSStreamSession holds the Cortex dispatch stream state: the StoreOnce marker of every stream
	// binding and the Builder-signed downlink messages a Cortex has not acknowledged yet, as the
	// exact bytes first sent (package dispatchstream).
	NSStreamSession Namespace = "stream_session"
	// NSInflight holds the in-flight order ledger: per session, the orders this Builder dispatched
	// whose dispatch entry the chain has not admitted yet, the suspension mark and the pending order
	// cancellations (package inflight).
	NSInflight Namespace = "inflight"
	// NSDispatch holds the dispatch state of every order this Builder dispatches: the round, cursor
	// and skip count, every ticket as the exact signed bytes offered, the rejects and the accept
	// received (package dispatcher).
	NSDispatch Namespace = "dispatch"
	// NSRecordOutbox holds the dispatch entries waiting for their record on chain, as the exact
	// entry bytes, and every signed record transaction before it is broadcast (package recorder).
	NSRecordOutbox Namespace = "record_outbox"
	// NSTakeover holds the takeovers this Builder registers as candidate, one per session: the
	// order held for each, its registration and activation height (package takeover).
	NSTakeover Namespace = "takeover"
	// NSDispatchAttempt holds the winning dispatch attempt of each task this Builder dispatched:
	// the winner ticket, the accept, the record status and the signed result header at that
	// status; key = task_id (package attempt).
	NSDispatchAttempt Namespace = "dispatch_attempt"
	// NSDispatchAttemptVoided holds the PENDING attempts a binding change voided: the chain may
	// still admit one whose withdrawal came too late, and it is then the task's attempt again;
	// key = task_id|ticket_hash hex (package attempt).
	NSDispatchAttemptVoided Namespace = "dispatch_attempt_voided"
	// NSReceiptStaging holds the InferReceipt a winner submitted before its dispatch entry was
	// recorded; it is relayed once the record is admitted and dropped if it is refused; key =
	// session_id|task_id (package coordinator).
	NSReceiptStaging Namespace = "receipt_staging"
	// NSDispatchEvidence holds the evidence of every dispatched order until its claim and challenge
	// windows close: rosters, tickets, answers and the signed record as exact bytes, with indexes
	// by ticket, task and handraise root, and the open claims and challenges being answered
	// (packages dispatchevidence and dispatchresponse).
	NSDispatchEvidence Namespace = "dispatch_evidence"
	// NSDispatchEvidencePrune orders NSDispatchEvidence by the height its evidence may be pruned
	// at; key = zero-padded height/evidence key.
	NSDispatchEvidencePrune Namespace = "dispatch_evidence_prune"
	// NSBuilderSyncOutbox holds what the dispatching Builder still has to sync to the other members
	// of each order's Task Builders group: per order, the sync stream with each member's progress,
	// and the items not every member acknowledged yet, as the exact bytes sent (package
	// buildersync).
	NSBuilderSyncOutbox Namespace = "builder_sync_outbox"
	// NSBuilderSyncMember holds, per order synced to this Builder as a group member, how far the
	// sync stream was applied, the recorded winner and the input pieces not assembled yet
	// (package buildersync).
	NSBuilderSyncMember Namespace = "builder_sync_member"
	// NSOps holds operator state: the optional drain (package drain) and the
	// readiness write probe.
	NSOps Namespace = "ops"
	// NSSupportRelay holds the Cortex model support confirmations this Builder accepted to relay
	// and has not seen settled on chain yet; key = chain id/epoch/operator (package supportrelay).
	NSSupportRelay Namespace = "support_relay"
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
	// It is what guarantees "progress and frame record in the same transaction" for a streaming OUTPUT.
	WriteBatch(ops ...WriteOp) error
	Close() error
}

// DeferredWriter is implemented by a Store that can apply a batch without waiting for it to be
// durable (see WriteDeferred).
type DeferredWriter interface {
	WriteBatchDeferred(ops ...WriteOp) error
}

// WriteDeferred applies ops atomically, like Store.WriteBatch, and makes them visible at once, but
// does not wait for them to reach the disk. A store that cannot defer writes them synced.
//
// The store keeps one ordered log of writes: a crash loses a suffix of it, never a write in the
// middle, and every synced write that returns (Set, Delete, WriteBatch, from any caller) makes
// every write before it durable too. A deferred write is therefore durable once a later synced
// write returned, and a crash before that loses it together with everything written after it.
// Use it only where that is safe: a synced write on the same path follows before anything outside
// the process can learn of the change, or the change is rebuilt on restart.
func WriteDeferred(s Store, ops ...WriteOp) error {
	if d, ok := s.(DeferredWriter); ok {
		return d.WriteBatchDeferred(ops...)
	}
	return s.WriteBatch(ops...)
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

// WriteBatchDeferred is WriteBatch: the in-memory store has no disk to wait for.
func (s *memStore) WriteBatchDeferred(ops ...WriteOp) error { return s.WriteBatch(ops...) }

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
