// Package busadapter is the Nexus-side wiring layer for the TRUEOPEN_BUS_ENVELOPE_V2 bus envelope.
// The canonical implementation of the signing projection, the verification
// order and the replay semantics lives in github.com/TrueOpen/wire/bus; this package only supplies
// the Nexus local facts: the pebble-persisted replay store and outbox, the chain query and signing of the
// current service key, and the conversion between the proto envelope and bus.Fields. Do not
// reimplement any byte-level convention here.
package busadapter

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/kv"
)

// KVReplayStore is the persistent implementation of bus.ReplayStore (kv.NSBusReplay).
// Its semantics match the wire MemoryReplayStore: two-key StoreOnce, the same key with the same digest is
// a legitimate retry, and a key is released once its tombstone expires. Tombstones must survive restarts,
// so production must back this with the pebble kv.Store.
//
// Value encoding: signDigest(32B) || tombstoneUntilMS(8B big-endian).
type KVReplayStore struct {
	mu    sync.Mutex
	store kv.Store
}

// NewKVReplayStore constructs the replay store on the given kv.Store.
func NewKVReplayStore(store kv.Store) *KVReplayStore {
	return &KVReplayStore{store: store}
}

const replayValueSize = 32 + 8

func encodeReplayValue(signDigest [32]byte, tombstoneUntilMS uint64) []byte {
	value := make([]byte, replayValueSize)
	copy(value[:32], signDigest[:])
	binary.BigEndian.PutUint64(value[32:], tombstoneUntilMS)
	return value
}

// StoreOnce implements bus.ReplayStore.
func (s *KVReplayStore) StoreOnce(record bus.ReplayRecord, nowUnixMS uint64) error {
	if record.ChainID == "" || record.SenderOperator == "" || record.MessageID == "" ||
		len(record.Nonce) != bus.NonceSize {
		return fmt.Errorf("%w: incomplete replay record", bus.ErrStoreFailure)
	}
	messageKey, err := record.MessageKey()
	if err != nil {
		return err
	}
	nonceKey, err := record.NonceKey()
	if err != nil {
		return err
	}
	keys := []string{messageKey, nonceKey}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		value, found, err := s.store.GetWithError(kv.NSBusReplay, key)
		if err != nil {
			return fmt.Errorf("%w: read replay key: %v", bus.ErrStoreFailure, err)
		}
		if !found {
			continue
		}
		if len(value) != replayValueSize {
			return fmt.Errorf("%w: corrupt replay value", bus.ErrStoreFailure)
		}
		if nowUnixMS > binary.BigEndian.Uint64(value[32:]) {
			continue // the tombstone has expired, the key is released
		}
		if [32]byte(value[:32]) != record.SignDigest {
			return fmt.Errorf("%w: same replay key with a different signing digest", bus.ErrReplay)
		}
	}
	value := encodeReplayValue(record.SignDigest, record.TombstoneUntilMS)
	// The two Sets of the two-key write are not atomic: a crash in between leaves only the message key.
	// The same sender redelivering the same digest fills in the other key (self-healing), while exploiting
	// the missing key for a replay requires the sender's private key to re-sign a different message_id,
	// which only harms the sender itself and is no third-party attack surface. This can be tightened once
	// kv offers batch writes.
	for _, key := range keys {
		if err := s.store.Set(kv.NSBusReplay, key, value); err != nil {
			return fmt.Errorf("%w: write replay key: %v", bus.ErrStoreFailure, err)
		}
	}
	return nil
}

// Prune deletes records whose tombstone has expired, keeping the partition from growing without bound. The
// owner calls it periodically; even if it never does, expired keys are already treated as released when
// StoreOnce reads them, so correctness does not depend on it.
func (s *KVReplayStore) Prune(nowUnixMS uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []string
	if err := s.store.Scan(kv.NSBusReplay, func(key string, value []byte) bool {
		if len(value) != replayValueSize || nowUnixMS > binary.BigEndian.Uint64(value[32:]) {
			expired = append(expired, key)
		}
		return true
	}); err != nil {
		return fmt.Errorf("%w: scan replay keys: %v", bus.ErrStoreFailure, err)
	}
	for _, key := range expired {
		if err := s.store.Delete(kv.NSBusReplay, key); err != nil {
			return fmt.Errorf("%w: delete replay key: %v", bus.ErrStoreFailure, err)
		}
	}
	return nil
}
