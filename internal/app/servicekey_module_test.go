package app

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

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
