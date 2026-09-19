package chaincli

import (
	"fmt"
	"strings"

	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	eventCursorKindTask     = "task"
	eventCursorKindProtocol = "protocol"
)

type eventCursorStore struct {
	store kv.Store
}

func (s eventCursorStore) Load(chainID, kind, scope string) (string, error) {
	key, err := eventCursorKey(chainID, kind, scope)
	if err != nil {
		return "", err
	}
	if s.store == nil {
		return "", nil
	}
	raw, ok, err := s.store.GetWithError(kv.NSChainEventCursor, key)
	if err != nil {
		return "", fmt.Errorf("load chain event cursor: %w", err)
	}
	if !ok {
		return "", nil
	}
	return string(raw), nil
}

func (s eventCursorStore) Save(chainID, kind, scope, cursor string) error {
	key, err := eventCursorKey(chainID, kind, scope)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cursor) == "" {
		return fmt.Errorf("chain event cursor is required")
	}
	if s.store == nil {
		return nil
	}
	if err := s.store.Set(kv.NSChainEventCursor, key, []byte(cursor)); err != nil {
		return fmt.Errorf("save chain event cursor: %w", err)
	}
	return nil
}

func (s eventCursorStore) Delete(chainID, kind, scope string) error {
	key, err := eventCursorKey(chainID, kind, scope)
	if err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	if err := s.store.Delete(kv.NSChainEventCursor, key); err != nil {
		return fmt.Errorf("delete chain event cursor: %w", err)
	}
	return nil
}

func eventCursorKey(chainID, kind, scope string) (string, error) {
	chainID = strings.TrimSpace(chainID)
	if chainID == "" || strings.Contains(chainID, "|") {
		return "", fmt.Errorf("chain event cursor chain_id is invalid")
	}
	switch kind {
	case eventCursorKindTask:
		scope = strings.TrimSpace(scope)
		if scope == "" || strings.Contains(scope, "|") {
			return "", fmt.Errorf("chain event cursor task scope is invalid")
		}
		return chainID + "|" + kind + "|" + scope, nil
	case eventCursorKindProtocol:
		if strings.TrimSpace(scope) != "" {
			return "", fmt.Errorf("chain event cursor protocol scope must be empty")
		}
		return chainID + "|" + kind, nil
	default:
		return "", fmt.Errorf("chain event cursor kind %q is invalid", kind)
	}
}
