package app

import (
	"context"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

type supportRelayTestChain struct {
	chaincli.Client
}

func (supportRelayTestChain) QueryTx(context.Context, []byte) (chaincli.TxResult, error) {
	return chaincli.TxResult{}, chaincli.ErrNotFound
}

// The relay is served only when enabled and the Builder account can sign; its configuration is
// validated, and it needs a chain client that reads transaction results.
func TestNewSupportRelay(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	authority := config.BuilderAuthority{Chain: config.ChainConfig{ChainID: "trueopen-localnet-1"}}
	sg, err := signer.NewFromHex("0000000000000000000000000000000000000000000000000000000000000001", "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	enabled := config.Load().SupportRelay
	chain := supportRelayTestChain{}

	relay, err := newSupportRelay(log, enabled, config.TxConfirmConfig{}, authority, "trueopen", kv.NewMemStore(), chain, sg, nil)
	if err != nil || relay == nil {
		t.Fatalf("enabled relay = %v, %v", relay, err)
	}
	disabled := enabled
	disabled.Enabled = false
	if relay, err := newSupportRelay(log, disabled, config.TxConfirmConfig{}, authority, "trueopen", kv.NewMemStore(), chain, sg, nil); relay != nil || err != nil {
		t.Fatalf("disabled relay = %v, %v", relay, err)
	}
	if relay, err := newSupportRelay(log, enabled, config.TxConfirmConfig{}, authority, "trueopen", kv.NewMemStore(), chain, nil, nil); relay != nil || err != nil {
		t.Fatalf("relay without a signer = %v, %v", relay, err)
	}
	invalid := enabled
	invalid.FlushItems = 0
	if _, err := newSupportRelay(log, invalid, config.TxConfirmConfig{}, authority, "trueopen", kv.NewMemStore(), chain, sg, nil); err == nil {
		t.Fatal("an invalid configuration was accepted")
	}
	if _, err := newSupportRelay(log, enabled, config.TxConfirmConfig{}, authority, "trueopen", kv.NewMemStore(), chain.Client, sg, nil); err == nil {
		t.Fatal("a chain client without transaction results was accepted")
	}
}
