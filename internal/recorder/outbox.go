package recorder

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Keys of kv.NSRecordOutbox: "entry/<object id hex>" and "tx/<tx hash hex>".
const (
	entryPrefix = "entry/"
	txPrefix    = "tx/"
)

// entry is one accepted order's dispatch entry, or a takeover entry, waiting for its record.
type entry struct {
	// ObjectID is the entry's dispatch_record_entry_digest (takeover_entry_digest of a takeover
	// entry), the object_id of its result.
	ObjectID   string `json:"object_id"`
	SessionID  string `json:"session_id"`
	Sequence   uint64 `json:"sequence"`
	TaskID     string `json:"task_id"`
	TicketHash []byte `json:"ticket_hash"`
	// TicketNonce is the winner ticket's service_authorization_nonce: no record notice is signed
	// under an older one.
	TicketNonce uint64 `json:"ticket_nonce,omitempty"`
	// Worker is the winner's operator address, who gets the record notice.
	Worker string `json:"worker"`
	// Deadline is the last height the entry can be recorded at, as handed over; see
	// Recorder.deadlineLocked.
	Deadline uint64 `json:"deadline"`
	// EarliestSubmit and BoundChange are the order's earliest_submit_height and the winner
	// ticket's bound_change_height, the base of the record deadline; DeadlineBlocks the
	// record_deadline_blocks the session froze.
	EarliestSubmit uint64 `json:"earliest_submit_height"`
	BoundChange    uint64 `json:"bound_change_height"`
	DeadlineBlocks uint64 `json:"deadline_blocks,omitempty"`
	// OrderExpire is the order's order_expire_height, past which no deadline moves.
	OrderExpire uint64 `json:"order_expire_height,omitempty"`
	// Entry is the DispatchRecordEntryV1 as handed over; it is never built again.
	Entry []byte `json:"entry"`
	// Tx is the hash of the transaction carrying the entry; empty while it waits for a block.
	Tx string `json:"tx,omitempty"`
	// Withdrawn is set when the winner ticket was voided after the entry was sent: its refusal is
	// expected and changes nothing.
	Withdrawn bool `json:"withdrawn,omitempty"`
	// Held is set when the entry was refused SEQUENCE_NOT_NEXT: it goes out again once the
	// session's next expected sequence reached it.
	Held bool `json:"held,omitempty"`
	// Takeover marks a takeover entry: it has no ticket or Worker, Deadline alone bounds it and
	// its result goes to the Takeovers.
	Takeover bool `json:"takeover,omitempty"`
	// packing is set, in memory, while pack has chosen the entry for a transaction that is being
	// signed: the transaction may carry it even though Tx is still empty.
	packing bool
}

// txRecord is one signed record transaction, stored before it is broadcast.
type txRecord struct {
	Hash string `json:"hash"`
	Raw  []byte `json:"raw"`
	// Objects are the object IDs of the transaction's entries, in entry order.
	Objects []string `json:"objects"`
	// SentHeight is the head when the transaction was last broadcast.
	SentHeight uint64 `json:"sent_height"`
	// GasFactor is the gas factor the transaction was signed with; 0 (stored before it was kept)
	// counts as 1.
	GasFactor uint64 `json:"gas_factor,omitempty"`
	// replay is set after a restart: the transaction is broadcast again, as stored, the first
	// time the chain does not show it.
	replay bool
	// succeeded is set once the transaction counted as executed for the sizing (succeeded).
	succeeded bool
}

func entryKey(objectID string) string { return entryPrefix + objectID }
func txKey(hash string) string        { return txPrefix + hash }

func putOp(key string, v any) (kv.WriteOp, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return kv.WriteOp{}, fmt.Errorf("encode record outbox %s: %w", key, err)
	}
	return kv.WriteOp{NS: kv.NSRecordOutbox, Key: key, Val: raw}, nil
}

func deleteOp(key string) kv.WriteOp {
	return kv.WriteOp{NS: kv.NSRecordOutbox, Key: key, Delete: true}
}

// loadOutbox reads the stored entries and transactions. A record that does not parse fails the
// load: its entry may be out and must be followed.
func loadOutbox(store kv.Store) (map[string]*entry, map[string]*txRecord, error) {
	entries, txs := map[string]*entry{}, map[string]*txRecord{}
	var loadErr error
	err := store.Scan(kv.NSRecordOutbox, func(key string, val []byte) bool {
		switch {
		case strings.HasPrefix(key, entryPrefix):
			var e entry
			if err := json.Unmarshal(val, &e); err != nil || entryKey(e.ObjectID) != key || len(e.Entry) == 0 {
				loadErr = fmt.Errorf("record outbox %q is malformed", key)
				return false
			}
			entries[e.ObjectID] = &e
		case strings.HasPrefix(key, txPrefix):
			var tx txRecord
			if err := json.Unmarshal(val, &tx); err != nil || txKey(tx.Hash) != key || len(tx.Raw) == 0 {
				loadErr = fmt.Errorf("record outbox %q is malformed", key)
				return false
			}
			tx.replay = true
			txs[tx.Hash] = &tx
		default:
			loadErr = fmt.Errorf("unknown record outbox key %q", key)
			return false
		}
		return true
	})
	if err != nil {
		return nil, nil, fmt.Errorf("scan record outbox: %w", err)
	}
	return entries, txs, loadErr
}
