package busadapter

import (
	"errors"
	"testing"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/kv"
)

func testReplayRecord() bus.ReplayRecord {
	nonce := make([]byte, bus.NonceSize)
	for i := range nonce {
		nonce[i] = 0xAB
	}
	return bus.ReplayRecord{
		ChainID: "trueopen-localnet-1",
		// Since wire v0.4.1 the replay key is domain-separated by the address codec bytes, so operator must be canonical bech32.
		SenderOperator:     "trueopen1e9rxz3ssv5sqf4n23nfnlh4atv3uf3fs9s0pvm",
		AuthorizationNonce: 7,
		MessageID:          "01890000-0000-7000-8000-000000000000",
		Nonce:              nonce,
		SignDigest:         [32]byte{0xCC},
		TombstoneUntilMS:   2_000,
	}
}

// KVReplayStore must match the semantics of the wire MemoryReplayStore: two keys, the same key with the
// same digest is a legitimate retry, a different digest reports a replay, and a key is released once its
// tombstone expires.
func TestKVReplayStoreSemantics(t *testing.T) {
	store := NewKVReplayStore(kv.NewMemStore())
	record := testReplayRecord()

	if err := store.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("first store: %v", err)
	}
	if err := store.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("legal retry rejected: %v", err)
	}
	conflicting := record
	conflicting.SignDigest = [32]byte{0xDD}
	if err := store.StoreOnce(conflicting, 1_000); !errors.Is(err, bus.ErrReplay) {
		t.Fatalf("err = %v, want replay conflict on message_id", err)
	}
	reusedNonce := record
	reusedNonce.MessageID = "01890000-0000-7000-8000-000000000001"
	reusedNonce.SignDigest = [32]byte{0xEE}
	if err := store.StoreOnce(reusedNonce, 1_000); !errors.Is(err, bus.ErrReplay) {
		t.Fatalf("err = %v, want replay conflict on nonce", err)
	}
	if err := store.StoreOnce(conflicting, record.TombstoneUntilMS+1); err != nil {
		t.Fatalf("post-tombstone store: %v", err)
	}
}

// Tombstones must not be lost across a restart: rebuilding KVReplayStore on the same kv.Store must still block the conflict.
func TestKVReplayStoreSurvivesRestart(t *testing.T) {
	backing := kv.NewMemStore()
	record := testReplayRecord()
	if err := NewKVReplayStore(backing).StoreOnce(record, 1_000); err != nil {
		t.Fatalf("first store: %v", err)
	}

	reopened := NewKVReplayStore(backing)
	conflicting := record
	conflicting.SignDigest = [32]byte{0xDD}
	if err := reopened.StoreOnce(conflicting, 1_000); !errors.Is(err, bus.ErrReplay) {
		t.Fatalf("err = %v, want replay conflict after reopen", err)
	}
	if err := reopened.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("legal retry after reopen: %v", err)
	}
}

func TestKVReplayStoreRejectsIncompleteRecords(t *testing.T) {
	store := NewKVReplayStore(kv.NewMemStore())
	record := testReplayRecord()
	record.Nonce = record.Nonce[:16]
	if err := store.StoreOnce(record, 1_000); !errors.Is(err, bus.ErrStoreFailure) {
		t.Fatalf("err = %v, want store failure for short nonce", err)
	}
}

// Prune clears expired tombstones to keep the partition from growing without bound; unexpired ones are kept.
func TestKVReplayStorePrune(t *testing.T) {
	backing := kv.NewMemStore()
	store := NewKVReplayStore(backing)
	expired := testReplayRecord()
	kept := testReplayRecord()
	kept.MessageID = "01890000-0000-7000-8000-00000000aaaa"
	kept.Nonce = append([]byte(nil), kept.Nonce...)
	kept.Nonce[0] = 0x01
	kept.TombstoneUntilMS = 9_000
	if err := store.StoreOnce(expired, 1_000); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreOnce(kept, 1_000); err != nil {
		t.Fatal(err)
	}

	if err := store.Prune(expired.TombstoneUntilMS + 1); err != nil {
		t.Fatalf("prune: %v", err)
	}
	count := 0
	if err := backing.Scan(kv.NSBusReplay, func(string, []byte) bool { count++; return true }); err != nil {
		t.Fatal(err)
	}
	if count != 2 { // the two keys of the kept entry
		t.Fatalf("after prune %d keys remain, want 2", count)
	}
}
