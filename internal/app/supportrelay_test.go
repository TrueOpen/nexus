package app

import (
	"context"
	"log/slog"
	"testing"
	"time"

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

// The three readers of chain.tx_confirm -- its validation, the Verifier relay wait and the support
// batch wait -- take the same effective values; only the Verifier relay caps the wait (a
// configuration above the cap does not pass validation).
func TestTxConfirmCallSitesAgree(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      config.TxConfirmConfig
		interval time.Duration
		wait     time.Duration
		valid    bool
	}{
		{"defaults", config.TxConfirmConfig{}, 500 * time.Millisecond, 15 * time.Second, true},
		{"interval only", config.TxConfirmConfig{BlockInterval: 600 * time.Millisecond}, 600 * time.Millisecond, 18 * time.Second, true},
		{"blocks only", config.TxConfirmConfig{WaitBlocks: 4}, 500 * time.Millisecond, 2 * time.Second, true},
		{"old complete", config.TxConfirmConfig{BlockInterval: 5 * time.Second, WaitBlocks: 3}, 5 * time.Second, 15 * time.Second, true},
		{"at the cap", config.TxConfirmConfig{BlockInterval: time.Second, WaitBlocks: 20}, time.Second, config.MaxTxConfirmWait, true},
		{"over the cap", config.TxConfirmConfig{BlockInterval: time.Second}, time.Second, 30 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("validate = %v, want valid %v", err, tc.valid)
			}
			interval, blocks := tc.cfg.Effective()
			if interval != tc.interval || interval*time.Duration(blocks) != tc.wait {
				t.Fatalf("config effective = %s x %d, want %s / %s", interval, blocks, tc.interval, tc.wait)
			}
			wait := supportRelayTxWait(tc.cfg)
			if wait.Interval != tc.interval || wait.Timeout != tc.wait {
				t.Fatalf("support relay wait = %s / %s, want %s / %s", wait.Interval, wait.Timeout, tc.interval, tc.wait)
			}
			relayInterval, relayWait := txConfirmPolicy(tc.cfg).Effective()
			if relayInterval != tc.interval || relayWait != min(tc.wait, config.MaxTxConfirmWait) {
				t.Fatalf("verifier relay wait = %s / %s, want %s / %s", relayInterval, relayWait, tc.interval, min(tc.wait, config.MaxTxConfirmWait))
			}
		})
	}
}
