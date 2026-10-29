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
	// SubmitRecordDispatch signs msg at the account's next sequence with gasLimit (0 keeps the
	// chain config's) and broadcasts it. Every signed transaction goes to persist first and is
	// broadcast only once persist succeeded; a sequence mismatch signs, persists and broadcasts
	// once more at the chain's sequence.
	SubmitRecordDispatch(ctx context.Context, msg *taskv1.MsgRecordDispatch, gasLimit uint64, persist func(raw []byte) error) (chaincli.TxResult, error)
	// BroadcastTx sends signed transaction bytes again, unchanged.
	BroadcastTx(ctx context.Context, raw []byte) (chaincli.TxResult, error)
	// SubmitRebutDispatchCompensation signs and broadcasts, with gasLimit (0 keeps the chain
	// config's), a rebuttal of a compensation claim on one of this Builder's tickets;
	// responder_address must be the service account.
	SubmitRebutDispatchCompensation(ctx context.Context, msg *taskv1.MsgRebutDispatchCompensation, gasLimit uint64) (chaincli.TxResult, error)
	// SubmitRespondDispatchChallenge signs and broadcasts, with gasLimit (0 keeps the chain
	// config's), the answer to a dispatch challenge; responder_address must be the service account.
	SubmitRespondDispatchChallenge(ctx context.Context, msg *taskv1.MsgRespondDispatchChallenge, gasLimit uint64) (chaincli.TxResult, error)
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
func (s *defaultSubmitter) SubmitRecordDispatch(ctx context.Context, msg *taskv1.MsgRecordDispatch, gasLimit uint64, persist func(raw []byte) error) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRecordDispatch: service signer is required")
	}
	if msg.GetSubmitterAddress() != s.signer.Address() {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRecordDispatch: submitter_address must be the service account %s", s.signer.Address())
	}
	build := func(p chaincli.TxParams) ([]byte, error) {
		if gasLimit != 0 {
			p.GasLimit = gasLimit
		}
		return chaincli.BuildRecordDispatchTx(s.signer, p, msg)
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitBuiltLocked(ctx, "MsgRecordDispatch", chaincli.TypeURLMsgRecordDispatch, build, persist)
}

// SubmitRebutDispatchCompensation implements RecordSubmitter.
func (s *defaultSubmitter) SubmitRebutDispatchCompensation(ctx context.Context, msg *taskv1.MsgRebutDispatchCompensation, gasLimit uint64) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRebutDispatchCompensation: service signer is required")
	}
	build := func(p chaincli.TxParams) ([]byte, error) {
		return chaincli.BuildRebutDispatchCompensationTx(s.signer, withGas(p, gasLimit), msg)
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitBuiltLocked(ctx, "MsgRebutDispatchCompensation", chaincli.TypeURLMsgRebutDispatchCompensation, build, nil)
}

// SubmitRespondDispatchChallenge implements RecordSubmitter.
func (s *defaultSubmitter) SubmitRespondDispatchChallenge(ctx context.Context, msg *taskv1.MsgRespondDispatchChallenge, gasLimit uint64) (chaincli.TxResult, error) {
	if s.signer == nil {
		return chaincli.TxResult{}, prepareSubmissionError("MsgRespondDispatchChallenge: service signer is required")
	}
	build := func(p chaincli.TxParams) ([]byte, error) {
		return chaincli.BuildRespondDispatchChallengeTx(s.signer, withGas(p, gasLimit), msg)
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return s.submitBuiltLocked(ctx, "MsgRespondDispatchChallenge", chaincli.TypeURLMsgRespondDispatchChallenge, build, nil)
}

// withGas sets gasLimit on p unless it is 0.
func withGas(p chaincli.TxParams, gasLimit uint64) chaincli.TxParams {
	if gasLimit != 0 {
		p.GasLimit = gasLimit
	}
	return p
}

// BroadcastTx implements RecordSubmitter.
func (s *defaultSubmitter) BroadcastTx(ctx context.Context, raw []byte) (chaincli.TxResult, error) {
	res, err := s.chain.BroadcastTx(ctx, raw)
	if err != nil {
		return res, &SubmissionError{Phase: SubmissionBroadcast, Result: res, Err: fmt.Errorf("rebroadcast tx: %w", err)}
	}
	return res, nil
}
