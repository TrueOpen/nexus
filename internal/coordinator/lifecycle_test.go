package coordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
)

func TestStopIsIdempotent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(
		log,
		msgbus.NewStub(log, nil),
		chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log),
		kv.NewMemStore(),
		"",
		testChainID,
	)

	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}
