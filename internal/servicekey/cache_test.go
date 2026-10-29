package servicekey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type countingResolver struct {
	mu     sync.Mutex
	calls  int
	nonce  uint64
	err    error
	during func() // runs inside a read, before it returns
}

func (r *countingResolver) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	r.mu.Lock()
	r.calls++
	state := chaincli.ServiceKeyState{ParticipantType: participantType, OperatorAddress: operator, AuthorizationNonce: r.nonce}
	err, during := r.err, r.during
	r.mu.Unlock()
	if during != nil {
		during()
	}
	return state, err
}

func TestCacheServesWithinTTLAndDropsOnRotation(t *testing.T) {
	resolver := &countingResolver{nonce: 1}
	now := time.Unix(1_800_000_000, 0)
	cache := NewCache(resolver, time.Second)
	cache.now = func() time.Time { return now }
	read := func(op string) uint64 {
		t.Helper()
		state, err := cache.QueryCurrentServiceKey(context.Background(), ParticipantCortex, op)
		if err != nil {
			t.Fatal(err)
		}
		return state.AuthorizationNonce
	}

	read("op1")
	read("op1")
	if resolver.calls != 1 {
		t.Fatalf("chain reads = %d, want 1 within the TTL", resolver.calls)
	}
	now = now.Add(time.Second)
	read("op1")
	if resolver.calls != 2 {
		t.Fatalf("chain reads = %d, want a fresh read after the TTL", resolver.calls)
	}

	resolver.nonce = 2
	read("op2")
	cache.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATED",
		Typed: chaincli.ServiceKeyRotated{Operator: "op1"}})
	if got := read("op1"); got != 2 {
		t.Fatalf("op1 nonce after rotation = %d, want 2", got)
	}
	calls := resolver.calls
	read("op2")
	if resolver.calls != calls {
		t.Fatal("another operator's entry was dropped by op1's rotation")
	}
	// A rotation without a readable operator drops everything.
	cache.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATED"})
	read("op2")
	if resolver.calls != calls+1 {
		t.Fatal("an untyped rotation kept cached keys")
	}
	cache.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "BUILDER_COMPENSATION_FUNDED"})
	read("op2")
	if resolver.calls != calls+1 {
		t.Fatal("an unrelated event dropped cached keys")
	}
}

// Registering a replacement leaves the current key in force but changes what the binding allows
// (a pending Builder issues no new roots), so it drops the operator's entries like an activation.
func TestCacheDropsOnRotationRegistration(t *testing.T) {
	resolver := &countingResolver{nonce: 1}
	cache := NewCache(resolver, time.Minute)
	read := func(op string) {
		t.Helper()
		if _, err := cache.QueryCurrentServiceKey(context.Background(), ParticipantBuilder, op); err != nil {
			t.Fatal(err)
		}
	}
	read("op1")
	read("op2")
	cache.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATION_REGISTERED",
		Typed: chaincli.ServiceKeyRotationRegistered{Operator: "op1"}})
	read("op1")
	read("op2")
	if resolver.calls != 3 {
		t.Fatalf("chain reads = %d, want only op1 read again", resolver.calls)
	}
	cache.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATION_REGISTERED"})
	read("op2")
	if resolver.calls != 4 {
		t.Fatal("an untyped registration kept cached keys")
	}
}

func TestCacheDoesNotKeepFailuresOrReadsRacingARotation(t *testing.T) {
	resolver := &countingResolver{err: chaincli.ErrNotFound}
	cache := NewCache(resolver, time.Minute)
	for i := 0; i < 2; i++ {
		if _, err := cache.QueryCurrentServiceKey(context.Background(), ParticipantCortex, "op"); !errors.Is(err, chaincli.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	}
	if resolver.calls != 2 {
		t.Fatalf("chain reads = %d, failures must not be cached", resolver.calls)
	}

	resolver.err = nil
	resolver.during = func() { cache.Invalidate("op") }
	if _, err := cache.QueryCurrentServiceKey(context.Background(), ParticipantCortex, "op"); err != nil {
		t.Fatal(err)
	}
	resolver.during = nil
	if _, err := cache.QueryCurrentServiceKey(context.Background(), ParticipantCortex, "op"); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 4 {
		t.Fatalf("chain reads = %d; a read that raced a rotation was cached", resolver.calls)
	}
}

// Current goes through the cache like any Resolver.
func TestCurrentReadsThroughTheCache(t *testing.T) {
	resolver := &countingResolver{}
	cache := NewCache(resolver, time.Minute)
	for i := 0; i < 3; i++ {
		_, _, _ = Current(context.Background(), cache, "trueopen", ParticipantBuilder, "op")
	}
	if resolver.calls != 1 {
		t.Fatalf("chain reads = %d, want 1", resolver.calls)
	}
}
