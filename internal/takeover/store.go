package takeover

import (
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Keys of kv.NSTakeover are session ids, one takeover each.

// load reads the stored takeovers. A record that does not decode is dropped with an error log.
// One that decodes but is stored under another session's key, or is not a takeover in progress,
// is dropped and kept in broken for Start to end its task as TASK_FAILED. None stops the start.
func (m *Manager) load() error {
	var drop []string
	err := m.cfg.Store.Scan(kv.NSTakeover, func(key string, val []byte) bool {
		var r record
		switch err := json.Unmarshal(val, &r); {
		case err != nil:
			m.log.Error("takeover record does not decode; dropped", "key", key, "err", err)
			drop = append(drop, key)
		case r.SessionID != key || r.Phase != phaseSubmitted && r.Phase != phaseRegistered:
			m.log.Error("takeover record cannot be resumed; its task fails", "key", key, "session_id", r.SessionID, "phase", r.Phase)
			drop = append(drop, key)
			if r.SessionID != "" && r.TaskID != "" {
				m.broken = append(m.broken, &r)
			}
		default:
			m.records[key] = &r
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("scan takeovers: %w", err)
	}
	for _, key := range drop {
		if err := m.cfg.Store.Delete(kv.NSTakeover, key); err != nil {
			m.log.Error("takeover record not deleted", "key", key, "err", err)
		}
	}
	return nil
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
