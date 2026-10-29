package coordinator

import (
	"context"
	"fmt"
	"log/slog"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
)

// RecordSubmitter sends MsgRecordDispatch transactions from the Builder service account: the
// chain takes a record only with the dispatching Builder's current service address as
// submitter_address and Cosmos signer.
type RecordSubmitter interface {
	// SubmitRecordDispatch signs msg at the account's next sequence and broadcasts it. Every
	// signed transaction goes to persist first and is broadcast only once persist succeeded; a
	// sequence mismatch signs, persists and broadcasts once more at the chain's sequence.
	SubmitRecordDispatch(ctx context.Context, msg *taskv1.MsgRecordDispatch, persist func(raw []byte) error) (chaincli.TxResult, error)
	// BroadcastTx sends signed transaction bytes again, unchanged.
	BroadcastTx(ctx context.Context, raw []byte) (chaincli.TxResult, error)
}

// NewRecordSubmitter builds the RecordSubmitter of serviceSigner. When shared is the signed task
// submitter of the same account (the service key is the account key) it is reused, so both keep
// one sequence.
func NewRecordSubmitter(log *slog.Logger, chain chaincli.Client, serviceSigner chaincli.TxSigner, chainCfg config.ChainConfig, shared Submitter) RecordSubmitter {
	if s, ok := shared.(*defaultSubmitter); ok && s.signer != nil && s.signer.Address() == serviceSigner.Address() {
		return s
	}
	return &defaultSubmitter{log: log, chain: chain, signer: serviceSigner, chainCfg: chainCfg}
}

// SubmitRecordDispatch implements RecordSubmitter.
func (s *defaultSubmitter) SubmitRecordDispatch(ctx context.Context, msg *taskv1.MsgRecordDispatch, persist func(raw []byte) error) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRecordDispatch: service signer is required")
	}
	if msg.GetSubmitterAddress() != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRecordDispatch: submitter_address must be the service account %s", s.signer.Address())
	}
	build := func(p chaincli.TxParams) ([]byte, error) { return chaincli.BuildRecordDispatchTx(s.signer, p, msg) }
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitBuiltLocked(ctx, "MsgRecordDispatch", chaincli.TypeURLMsgRecordDispatch, build, persist)
}

// BroadcastTx implements RecordSubmitter.
func (s *defaultSubmitter) BroadcastTx(ctx context.Context, raw []byte) (chaincli.TxResult, error) {
	res, err := s.chain.BroadcastTx(ctx, raw)
	if err != nil {
		return res, &SubmissionError{Phase: SubmissionBroadcast, Result: res, Err: fmt.Errorf("rebroadcast tx: %w", err)}
	}
	return res, nil
}
