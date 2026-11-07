package coordinator

import (
	"context"
	"log/slog"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
)

// SupportSubmitter sends MsgBatchConfirmModelSupport transactions from the Builder account: the
// Builder relays Cortex-signed support confirmations, signing the outer transaction and paying its
// gas; any account may submit the message.
type SupportSubmitter interface {
	// SubmitBatchConfirmModelSupport signs msg at the account's next sequence with gasLimit (0
	// keeps the chain config's) and broadcasts it; submitter_address must be the account.
	SubmitBatchConfirmModelSupport(ctx context.Context, msg *hubv1.MsgBatchConfirmModelSupport, gasLimit uint64) (chaincli.TxResult, error)
}

// NewSupportSubmitter builds the SupportSubmitter of accountSigner on chain. When shared is the
// signed task submitter of the same account on the same chain it is reused, so both keep one
// sequence.
func NewSupportSubmitter(log *slog.Logger, chain chaincli.Client, accountSigner chaincli.TxSigner, chainCfg config.ChainConfig, shared Submitter) SupportSubmitter {
	if s, ok := shared.(*defaultSubmitter); ok && s.signer != nil && s.chain == chain && s.signer.Address() == accountSigner.Address() {
		return s
	}
	return &defaultSubmitter{log: log, chain: chain, hub: chain, signer: accountSigner, chainCfg: chainCfg}
}

// SubmitBatchConfirmModelSupport implements SupportSubmitter.
func (s *defaultSubmitter) SubmitBatchConfirmModelSupport(ctx context.Context, msg *hubv1.MsgBatchConfirmModelSupport, gasLimit uint64) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgBatchConfirmModelSupport: account signer is required")
	}
	build := func(p chaincli.TxParams) ([]byte, error) {
		return chaincli.BuildBatchConfirmModelSupportTx(s.signer, s.withGas(p, gasLimit), msg)
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitBuiltLocked(ctx, "MsgBatchConfirmModelSupport", chaincli.TypeURLMsgBatchConfirmModelSupport, build, nil)
}
