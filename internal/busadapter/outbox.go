package busadapter

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/TrueOpen/nexus/internal/kv"
)

// OutboxEntry is the persisted record of one envelope pending publication. Wire is the complete signed
// envelope bytes: the contract requires a retry to reuse the message_id, nonce and original payload bytes,
// so a resend may only replay the bytes stored here verbatim, never reassemble or re-sign them.
type OutboxEntry struct {
	MessageID       string
	Subject         string
	Tier            Tier
	Wire            []byte
	ExpiresAtUnixMS uint64
}

// Outbox persists envelopes before publication (kv.NSBusOutbox, key = message_id). This is a blocking
// requirement rather than an optimization: without it, an envelope whose broadcast went out before the
// process crashed ahead of the acknowledgement could only be reassembled and re-signed, and the receiver's
// two-key replay store would treat the old and new copies as conflicting.
//
// Lifecycle: Put (before publishing) -> publish -> Pending resends verbatim after a restart -> Delete on
// expiry or a terminal task state, or cleaned up by Pending along the way. Once the envelope TTL has
// passed the message is no longer worth receiving, so there is nothing to resend.
type Outbox struct {
	store kv.Store
}

// NewOutbox constructs an outbox on the given kv.Store.
func NewOutbox(store kv.Store) *Outbox {
	return &Outbox{store: store}
}

// Value encoding: expiresAt(8B big-endian) || tier(1B) || subjectLen(4B big-endian) || subject || wire.
func encodeOutboxValue(entry OutboxEntry) ([]byte, error) {
	if uint64(len(entry.Subject)) > math.MaxUint32 {
		return nil, fmt.Errorf("bus outbox: subject too large")
	}
	value := make([]byte, 0, 8+1+4+len(entry.Subject)+len(entry.Wire))
	value = binary.BigEndian.AppendUint64(value, entry.ExpiresAtUnixMS)
	value = append(value, byte(entry.Tier))
	value = binary.BigEndian.AppendUint32(value, uint32(len(entry.Subject)))
	value = append(value, entry.Subject...)
	return append(value, entry.Wire...), nil
}

func decodeOutboxValue(messageID string, value []byte) (OutboxEntry, error) {
	if len(value) < 8+1+4 {
		return OutboxEntry{}, fmt.Errorf("bus outbox: corrupt entry %s", messageID)
	}
	expiresAt := binary.BigEndian.Uint64(value[:8])
	tier := Tier(value[8])
	subjectLen := int(binary.BigEndian.Uint32(value[9:13]))
	if len(value) < 13+subjectLen {
		return OutboxEntry{}, fmt.Errorf("bus outbox: corrupt entry %s", messageID)
	}
	return OutboxEntry{
		MessageID:       messageID,
		Subject:         string(value[13 : 13+subjectLen]),
		Tier:            tier,
		Wire:            append([]byte(nil), value[13+subjectLen:]...),
		ExpiresAtUnixMS: expiresAt,
	}, nil
}

// Put persists one envelope pending publication. It must be called and confirmed successful before the first publish.
func (o *Outbox) Put(entry OutboxEntry) error {
	if entry.MessageID == "" || entry.Subject == "" || len(entry.Wire) == 0 || entry.ExpiresAtUnixMS == 0 ||
		(entry.Tier != TierCore && entry.Tier != TierJetStream) {
		return fmt.Errorf("bus outbox: incomplete entry")
	}
	value, err := encodeOutboxValue(entry)
	if err != nil {
		return err
	}
	if err := o.store.Set(kv.NSBusOutbox, entry.MessageID, value); err != nil {
		return fmt.Errorf("bus outbox: persist entry: %w", err)
	}
	return nil
}

// Delete removes an envelope that no longer needs resending (terminal task state or explicit abandonment).
func (o *Outbox) Delete(messageID string) error {
	if err := o.store.Delete(kv.NSBusOutbox, messageID); err != nil {
		return fmt.Errorf("bus outbox: delete entry: %w", err)
	}
	return nil
}

// Pending returns every unexpired entry (in message_id byte order) and deletes the expired ones along the
// way: an expired envelope is always rejected by the receiver (verification step 3), so resending is pointless.
func (o *Outbox) Pending(nowUnixMS uint64) ([]OutboxEntry, error) {
	var entries []OutboxEntry
	var expired []string
	var scanErr error
	if err := o.store.Scan(kv.NSBusOutbox, func(key string, value []byte) bool {
		entry, err := decodeOutboxValue(key, value)
		if err != nil {
			scanErr = err
			return false
		}
		if nowUnixMS > entry.ExpiresAtUnixMS {
			expired = append(expired, key)
			return true
		}
		entries = append(entries, entry)
		return true
	}); err != nil {
		return nil, fmt.Errorf("bus outbox: scan: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}
	for _, key := range expired {
		if err := o.store.Delete(kv.NSBusOutbox, key); err != nil {
			return nil, fmt.Errorf("bus outbox: drop expired entry: %w", err)
		}
	}
	return entries, nil
}
