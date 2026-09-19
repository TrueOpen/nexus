package busadapter

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Outbox persists before publishing: after a restart Pending must hand back the unexpired wire bytes
// verbatim, a retry may neither re-sign nor alter bytes, and expired entries are cleaned up by Pending.
func TestOutboxPersistsExactBytesAcrossRestart(t *testing.T) {
	backing := kv.NewMemStore()
	outbox := NewOutbox(backing)
	wire := []byte{0x0a, 0x01, 0x02, 0x03}
	if err := outbox.Put(OutboxEntry{
		MessageID:       "01890000-0000-7000-8000-000000000001",
		Subject:         "trueopen.task.open.model-a",
		Tier:            TierJetStream,
		Wire:            wire,
		ExpiresAtUnixMS: 5_000,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	reopened := NewOutbox(backing)
	pending, err := reopened.Pending(1_000)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d entries, want 1", len(pending))
	}
	got := pending[0]
	if got.MessageID != "01890000-0000-7000-8000-000000000001" ||
		got.Subject != "trueopen.task.open.model-a" || got.Tier != TierJetStream ||
		!bytes.Equal(got.Wire, wire) || got.ExpiresAtUnixMS != 5_000 {
		t.Fatalf("entry round-trip mismatch: %+v", got)
	}
}

func TestOutboxDropsExpiredAndDeletes(t *testing.T) {
	outbox := NewOutbox(kv.NewMemStore())
	if err := outbox.Put(OutboxEntry{
		MessageID: "m-expired", Subject: "s", Tier: TierCore, Wire: []byte{0x01}, ExpiresAtUnixMS: 1_000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Put(OutboxEntry{
		MessageID: "m-live", Subject: "s", Tier: TierCore, Wire: []byte{0x02}, ExpiresAtUnixMS: 9_000,
	}); err != nil {
		t.Fatal(err)
	}

	pending, err := outbox.Pending(2_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].MessageID != "m-live" {
		t.Fatalf("pending = %+v, want only m-live", pending)
	}
	// The expired entry has been removed: it does not reappear even if the clock is turned back.
	pending, err = outbox.Pending(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expired entry resurfaced: %+v", pending)
	}

	if err := outbox.Delete("m-live"); err != nil {
		t.Fatal(err)
	}
	pending, err = outbox.Pending(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after delete = %+v, want empty", pending)
	}
}

func TestOutboxRejectsIncompleteEntry(t *testing.T) {
	outbox := NewOutbox(kv.NewMemStore())
	for name, entry := range map[string]OutboxEntry{
		"no message id": {Subject: "s", Tier: TierCore, Wire: []byte{1}, ExpiresAtUnixMS: 1},
		"no subject":    {MessageID: "m", Tier: TierCore, Wire: []byte{1}, ExpiresAtUnixMS: 1},
		"no wire":       {MessageID: "m", Subject: "s", Tier: TierCore, ExpiresAtUnixMS: 1},
		"no expiry":     {MessageID: "m", Subject: "s", Tier: TierCore, Wire: []byte{1}},
		"no tier":       {MessageID: "m", Subject: "s", Wire: []byte{1}, ExpiresAtUnixMS: 1},
	} {
		if err := outbox.Put(entry); err == nil {
			t.Fatalf("%s: incomplete entry accepted", name)
		}
	}
}
