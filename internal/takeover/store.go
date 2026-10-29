package takeover

import (
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Keys of kv.NSTakeover are session ids, one takeover each.

// load reads the stored takeovers. A record that does not parse fails the load: its takeover may
// be registered and must be followed.
func (m *Manager) load() error {
	var loadErr error
	err := m.cfg.Store.Scan(kv.NSTakeover, func(key string, val []byte) bool {
		var r record
		if err := json.Unmarshal(val, &r); err != nil || r.SessionID != key || (r.Phase != phaseSubmitted && r.Phase != phaseRegistered) {
			loadErr = fmt.Errorf("takeover record %q is malformed", key)
			return false
		}
		m.records[key] = &r
		return true
	})
	if err != nil {
		return fmt.Errorf("scan takeovers: %w", err)
	}
	return loadErr
}

func (m *Manager) saveLocked(r *record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode takeover: %w", err)
	}
	if err := m.cfg.Store.Set(kv.NSTakeover, r.SessionID, raw); err != nil {
		return fmt.Errorf("store takeover: %w", err)
	}
	return nil
}

// forget drops r from memory and the store.
func (m *Manager) forget(r *record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.records[r.SessionID] != r {
		return
	}
	delete(m.records, r.SessionID)
	if err := m.cfg.Store.Delete(kv.NSTakeover, r.SessionID); err != nil {
		m.log.Error("takeover record not deleted; a restart resolves it with the chain", "session_id", r.SessionID, "err", err)
	}
}
