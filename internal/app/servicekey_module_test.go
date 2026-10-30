package app

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// The service key module reads the binding at startup so the ring signs before anything is
// served; a chain that does not answer in time does not stop the start, and the binding is read
// again in the background until it answers.
func TestServiceKeyModuleReadsTheBindingAtStartup(t *testing.T) {
	wait, retry := serviceKeyStartupWait, serviceKeyRetry
	serviceKeyStartupWait, serviceKeyRetry = 20*time.Millisecond, time.Millisecond
	t.Cleanup(func() { serviceKeyStartupWait, serviceKeyRetry = wait, retry })

	builder := mustSigner(t, 0x01)
	chain := &wiringChain{
		Client: chaincli.NewStub(slog.New(slog.DiscardHandler), config.ChainConfig{}),
		keys:   map[string]chaincli.ServiceKeyState{"BUILDER/" + builder.Address(): serviceKeyState("BUILDER", builder.Address(), builder, 7)},
		keyErr: errors.New("node offline"),
	}
	ring, err := servicekey.NewRing(chain, wiringPrefix, builder.Address(), nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	m := serviceKeyModule(slog.New(slog.DiscardHandler), ring)
	if err := m.start(context.Background()); err != nil {
		t.Fatalf("an unreadable binding stopped the start: %v", err)
	}
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, servicekey.ErrNotRefreshed) {
		t.Fatalf("Sign before the binding was read = %v", err)
	}
	chain.mu.Lock()
	chain.keyErr = nil
	chain.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for ring.Key().Nonce != 7 {
		if time.Now().After(deadline) {
			t.Fatal("binding not read in the background")
		}
		time.Sleep(time.Millisecond)
	}
	if err := m.stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	ready, err := servicekey.NewRing(chain, wiringPrefix, builder.Address(), nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	m = serviceKeyModule(slog.New(slog.DiscardHandler), ready)
	if err := m.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ready.Sign([]byte("m")); err != nil {
		t.Fatalf("Sign after the startup read = %v", err)
	}
	_ = m.stop(context.Background())
}

// A revoked current key does not hold up the start and starts no background read: nothing is
// signed, and the error log says so.
func TestServiceKeyModuleStartsWithARevokedKey(t *testing.T) {
	wait := serviceKeyStartupWait
	serviceKeyStartupWait = time.Minute
	t.Cleanup(func() { serviceKeyStartupWait = wait })

	builder := mustSigner(t, 0x01)
	revoked := serviceKeyState("BUILDER", builder.Address(), builder, 7)
	revoked.Status = servicekey.StatusRevoked
	chain := &wiringChain{
		Client: chaincli.NewStub(slog.New(slog.DiscardHandler), config.ChainConfig{}),
		keys:   map[string]chaincli.ServiceKeyState{"BUILDER/" + builder.Address(): revoked},
	}
	ring, err := servicekey.NewRing(chain, wiringPrefix, builder.Address(), nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	logs := &countingHandler{}
	m := serviceKeyModule(slog.New(logs), ring)
	started := time.Now()
	if err := m.start(context.Background()); err != nil {
		t.Fatalf("a revoked key stopped the start: %v", err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("the start waited for a revoked key")
	}
	if k := ring.Key(); !k.Revoked || k.Nonce != 7 || logs.count(slog.LevelError) != 1 {
		t.Fatalf("key %+v, %d error logs", k, logs.count(slog.LevelError))
	}
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, servicekey.ErrRevoked) {
		t.Fatalf("Sign with a revoked key = %v", err)
	}
	if err := m.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The service key events reach the ring: this Builder's own SERVICE_KEY_REVOKED stops its
// signing at once, and the cache drops the revoked binding in the same pass. The ring's switch log
// reports the revocation as an error.
func TestServiceKeyEventsRevokeTheRing(t *testing.T) {
	builder := mustSigner(t, 0x01)
	chain := &wiringChain{
		Client: chaincli.NewStub(slog.New(slog.DiscardHandler), config.ChainConfig{}),
		keys:   map[string]chaincli.ServiceKeyState{"BUILDER/" + builder.Address(): serviceKeyState("BUILDER", builder.Address(), builder, 7)},
	}
	cache := servicekey.NewCache(chain, time.Hour)
	logs := &countingHandler{}
	ring, err := servicekey.NewRing(cache, wiringPrefix, builder.Address(), logServiceKeySwitch(slog.New(logs)), builder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := &serviceKeyEvents{}
	events.cache.Store(cache)
	events.ring.Store(ring)
	events.observe(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_REVOKED",
		Typed: chaincli.ServiceKeyRevoked{ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, Operator: builder.Address(), AuthorizationNonce: 7}})
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, servicekey.ErrRevoked) {
		t.Fatalf("Sign after the revocation event = %v", err)
	}
	if logs.count(slog.LevelError) != 1 {
		t.Fatalf("%d error logs, want the revocation", logs.count(slog.LevelError))
	}
	revoked := serviceKeyState("BUILDER", builder.Address(), builder, 7)
	revoked.Status = servicekey.StatusRevoked
	chain.mu.Lock()
	chain.keys["BUILDER/"+builder.Address()] = revoked
	chain.mu.Unlock()
	if state, err := cache.QueryCurrentServiceKey(context.Background(), "BUILDER", builder.Address()); err != nil || state.Status != servicekey.StatusRevoked {
		t.Fatalf("cache after the event = %+v, %v", state, err)
	}
}
