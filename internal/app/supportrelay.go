package app

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/supportrelay"
)

// supportRelayChain is what the support relay reads from the chain that runs the Hub.
type supportRelayChain struct {
	chaincli.Client
	chaincli.TxQuerier
}

// newSupportRelay builds the model support relay on the Hub chain (the registration chain, with
// the authority chain's signing parameters). The Builder account signs and pays for the batches,
// on the task submitter's sequence when that is the same account on the same chain. It returns
// nil when the relay is disabled or there is no account signer.
func newSupportRelay(
	log *slog.Logger, cfg config.SupportRelayConfig, txConfirm config.TxConfirmConfig, authority config.BuilderAuthority,
	addressPrefix string, store kv.Store, chain chaincli.Client, accountSigner chaincli.TxSigner, shared coordinator.Submitter,
) (*supportrelay.Relay, error) {
	if !cfg.Enabled || accountSigner == nil {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	txs, ok := chain.(chaincli.TxQuerier)
	if !ok {
		return nil, fmt.Errorf("support relay needs a chain client that reads transaction results")
	}
	interval, blocks := txConfirm.BlockInterval, txConfirm.WaitBlocks
	if interval == 0 {
		interval = config.DefaultTxConfirmBlockInterval
	}
	if blocks == 0 {
		blocks = config.DefaultTxConfirmWaitBlocks
	}
	return supportrelay.New(supportrelay.Config{
		ChainID: authority.Chain.ChainID, AddressPrefix: addressPrefix, SubmitterAddress: accountSigner.Address(),
		FlushInterval: cfg.FlushInterval, FlushItems: cfg.FlushItems, MaxQueued: cfg.MaxQueued,
		InclusionMarginBlocks: cfg.InclusionMarginBlocks,
		GasBase:               cfg.GasBase, GasPerConfirmation: cfg.GasPerConfirmation, GasPerModel: cfg.GasPerModel,
		TxWait: chaincli.TxWait{Kind: "MsgBatchConfirmModelSupport", Interval: interval, Timeout: interval * time.Duration(blocks)},
	}, log, supportRelayChain{Client: chain, TxQuerier: txs},
		coordinator.NewSupportSubmitter(log, chain, accountSigner, authority.Chain, shared), store)
}
