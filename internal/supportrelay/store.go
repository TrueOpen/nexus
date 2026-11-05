package supportrelay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/kv"
)

// entry is one accepted confirmation held until it is settled; it is stored as JSON under
// chain id/epoch/operator in kv.NSSupportRelay.
type entry struct {
	Epoch uint64 `json:"epoch"`
	// Confirmation is the canonical protobuf encoding of the decoded confirmation.
	Confirmation []byte `json:"confirmation"`
	Digest       []byte `json:"digest"`
	QueuedAtMs   int64  `json:"queued_at_ms"`
	// TxHashes are the sent batches carrying the confirmation whose block result is not known yet.
	TxHashes [][]byte `json:"tx_hashes,omitempty"`
	// Blind is set when a batch carrying it may have been broadcast without its hash being known.
	Blind bool `json:"blind,omitempty"`
	// Rejected is set once the chain refused it in a batch of its own: it is not sent again.
	Rejected bool `json:"rejected,omitempty"`

	c Confirmation
}

// inFlight reports whether a transaction already sent may still get the confirmation accepted.
func (e *entry) inFlight() bool { return len(e.TxHashes) > 0 || e.Blind }

func (e *entry) clone() *entry {
	out := *e
	out.TxHashes = append([][]byte(nil), e.TxHashes...)
	return &out
}

// slotKey is the store key of an (epoch, operator) slot on this chain. The zero-padded epoch keeps
// a scan in epoch order.
func (r *Relay) slotKey(epoch uint64, operator []byte) string {
	return fmt.Sprintf("%s/%020d/%s", r.cfg.ChainID, epoch, hex.EncodeToString(operator))
}

func (r *Relay) save(key string, e *entry) error {
	raw, err := proto.Marshal(e.c.Proto())
	if err != nil {
		return err
	}
	e.Confirmation = raw
	value, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return r.store.Set(kv.NSSupportRelay, key, value)
}

// load restores the confirmations of this chain a previous run held. An entry that no longer
// decodes or sits under the wrong key is dropped: it could not be relayed.
func (r *Relay) load() error {
	prefix := r.cfg.ChainID + "/"
	var broken []string
	err := r.store.Scan(kv.NSSupportRelay, func(key string, value []byte) bool {
		if !strings.HasPrefix(key, prefix) {
			return true
		}
		e := &entry{}
		if err := json.Unmarshal(value, e); err != nil {
			broken = append(broken, key)
			return true
		}
		c, err := Decode(e.Confirmation, r.cfg.AddressPrefix)
		if err != nil || r.slotKey(e.Epoch, c.OperatorRaw) != key {
			broken = append(broken, key)
			return true
		}
		digest, err := c.Digest(r.cfg.ChainID, e.Epoch)
		if err != nil || !bytes.Equal(digest[:], e.Digest) {
			broken = append(broken, key)
			return true
		}
		e.c = c
		r.entries[key] = e
		return true
	})
	if err != nil {
		return fmt.Errorf("support relay: load: %w", err)
	}
	for _, key := range broken {
		r.log.Warn("support relay: dropping an unreadable stored confirmation", "key", key)
		if err := r.store.Delete(kv.NSSupportRelay, key); err != nil {
			return fmt.Errorf("support relay: drop %s: %w", key, err)
		}
	}
	if len(r.entries) > 0 {
		r.log.Info("support relay: resumed stored confirmations", "count", len(r.entries))
	}
	return nil
}
