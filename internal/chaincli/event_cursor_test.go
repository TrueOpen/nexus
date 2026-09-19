package chaincli

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func TestEventCursorStoreTaskRoundTripAndDelete(t *testing.T) {
	store := kv.NewMemStore()
	cursors := eventCursorStore{store: store}
	const cursor = "v1:42:0:3:1"
	if err := cursors.Save("chain-a", eventCursorKindTask, "session-a", cursor); err != nil {
		t.Fatal(err)
	}
	if raw, ok := store.Get(kv.NSChainEventCursor, "chain-a|task|session-a"); !ok || string(raw) != cursor {
		t.Fatalf("stored cursor = %q, found=%v", raw, ok)
	}
	got, err := cursors.Load("chain-a", eventCursorKindTask, "session-a")
	if err != nil || got != cursor {
		t.Fatalf("Load() = %q, %v", got, err)
	}
	if err := cursors.Delete("chain-a", eventCursorKindTask, "session-a"); err != nil {
		t.Fatal(err)
	}
	if got, err := cursors.Load("chain-a", eventCursorKindTask, "session-a"); err != nil || got != "" {
		t.Fatalf("Load() after delete = %q, %v", got, err)
	}
}

func TestEventCursorStoreProtocolKeyHasNoScope(t *testing.T) {
	store := kv.NewMemStore()
	cursors := eventCursorStore{store: store}
	if err := cursors.Save("hub-a", eventCursorKindProtocol, "", "opaque-protocol"); err != nil {
		t.Fatal(err)
	}
	if raw, ok := store.Get(kv.NSChainEventCursor, "hub-a|protocol"); !ok || string(raw) != "opaque-protocol" {
		t.Fatalf("stored protocol cursor = %q, found=%v", raw, ok)
	}
}
