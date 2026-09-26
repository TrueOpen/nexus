package coordinator

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// ProposalResult is the outcome of a handraise proposal: the broadcast result and the
// handraises left out because the chain refused them on their own.
type ProposalResult struct {
	chaincli.TxResult
	Excluded []ExcludedHandraise
}

// ExcludedHandraise is one handraise the chain refused when simulated alone.
type ExcludedHandraise struct {
	Operator string
	Reason   string
}

// simulateCounters tell on a running node whether proposals are really simulated before
// they are broadcast; they appear in the proposal log lines.
type simulateCounters struct {
	unavailable atomic.Uint64
	excluded    atomic.Uint64
}

// handraiseProposal is one MsgSubmitWorkerHandraises or MsgSubmitVerifierHandraises in
// the making: build returns the message carrying the handraises at the given indexes, in
// the order given.
type handraiseProposal struct {
	kind      string
	typeURL   string
	operators []string
	build     func(keep []int) proto.Message
}

// submitHandraiseProposal simulates a handraise proposal before broadcasting it and leaves
// out the handraises the chain refuses.
//
// The Keeper rejects the whole proposal when any one handraise fails its candidate checks
// (x/task/keeper msg_server_worker_handraises.go and msg_server_open_verify.go), and CheckTx
// does not run those checks, so a single ineligible handraise -- a Cortex that raised its hand
// too early, or one doing it on purpose -- would otherwise fail the assignment of the task on
// every Builder. The chain's own rules decide which handraise is at fault; nexus does not
// restate them.
//
//  1. The whole proposal is simulated. If the chain takes it, it is broadcast as is.
//  2. If the chain refuses it, each handraise is simulated alone. Those refused alone are left
//     out, the rest keep their order (the Keeper wants strictly increasing slots).
//  3. The remaining proposal is simulated again, since handraises that pass one by one need
//     not pass together. Only a proposal the chain takes is broadcast; otherwise nothing is.
//
// A node that cannot simulate at all leaves the proposal to be broadcast unfiltered, as
// before, and each such proposal is counted in the log.
func (s *defaultSubmitter) submitHandraiseProposal(ctx context.Context, p handraiseProposal) (ProposalResult, error) {
	if s.signer == nil {
		return ProposalResult{}, prepareSubmissionError("submit %s: account signer is required", p.kind)
	}
	all := make([]int, len(p.operators))
	for i := range all {
		all[i] = i
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	if !s.seqValid {
		if err := s.refreshSequence(ctx); err != nil {
			return ProposalResult{}, &SubmissionError{Phase: SubmissionPrepare, Err: fmt.Errorf("submit %s: account info: %w", p.kind, err)}
		}
	}

	whole, err := s.simulateLocked(ctx, p, all)
	if err != nil {
		count := s.simulate.unavailable.Add(1)
		s.log.Warn("handraise proposal broadcast without simulation: the node cannot simulate",
			"kind", p.kind, "handraises", len(all), "unsimulated_total", count, "err", err)
		return s.broadcastProposalLocked(ctx, p, all, nil)
	}
	if whole.OK {
		return s.broadcastProposalLocked(ctx, p, all, nil)
	}

	var kept []int
	var excluded []ExcludedHandraise
	for _, i := range all {
		alone, err := s.simulateLocked(ctx, p, []int{i})
		if err != nil {
			return ProposalResult{}, &SubmissionError{Phase: SubmissionPrepare,
				Err: fmt.Errorf("submit %s: simulate handraise of %s: %w", p.kind, p.operators[i], err)}
		}
		if alone.OK {
			kept = append(kept, i)
			continue
		}
		excluded = append(excluded, ExcludedHandraise{Operator: p.operators[i], Reason: alone.Error})
	}
	if len(kept) == 0 {
		// No handraise passes alone: the fault is not in one of them (a window not open yet,
		// the task in another state). Nothing is broadcast; the caller retries as before.
		return ProposalResult{}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true,
			Err: fmt.Errorf("submit %s: the chain refuses the proposal and every handraise in it: %s", p.kind, whole.Error)}
	}
	for _, e := range excluded {
		count := s.simulate.excluded.Add(1)
		s.log.Warn("handraise left out of the proposal: the chain refuses it",
			"kind", p.kind, "operator", e.Operator, "reason", e.Reason, "excluded_total", count)
	}
	if len(excluded) == 0 {
		// Every handraise passes alone but not all together: there is no single one to blame.
		return ProposalResult{}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true,
			Err: fmt.Errorf("submit %s: the chain refuses the proposal although each handraise passes alone: %s", p.kind, whole.Error)}
	}
	remaining, err := s.simulateLocked(ctx, p, kept)
	if err != nil {
		return ProposalResult{}, &SubmissionError{Phase: SubmissionPrepare, Err: fmt.Errorf("submit %s: simulate remaining handraises: %w", p.kind, err)}
	}
	if !remaining.OK {
		return ProposalResult{Excluded: excluded}, &SubmissionError{Phase: SubmissionPrepare, Definitive: true,
			Err: fmt.Errorf("submit %s: the chain refuses the proposal without the excluded handraises: %s", p.kind, remaining.Error)}
	}
	return s.broadcastProposalLocked(ctx, p, kept, excluded)
}

// simulateLocked signs the proposal with the cached sequence and simulates it. The node checks
// the sequence even when simulating, so a mismatch refreshes it and simulates once more. The
// caller holds seqMu.
func (s *defaultSubmitter) simulateLocked(ctx context.Context, p handraiseProposal, keep []int) (chaincli.SimResult, error) {
	msgAny, err := chaincli.PackAny(p.typeURL, p.build(keep))
	if err != nil {
		return chaincli.SimResult{}, err
	}
	result, err := s.simulateAnyLocked(ctx, msgAny)
	if err != nil || result.OK || !strings.Contains(result.Error, "account sequence mismatch") {
		return result, err
	}
	// The simulate response carries no ABCI code, only the node's message; this match is
	// limited to our own sequence bookkeeping.
	if err := s.refreshSequence(ctx); err != nil {
		return chaincli.SimResult{}, err
	}
	return s.simulateAnyLocked(ctx, msgAny)
}

func (s *defaultSubmitter) simulateAnyLocked(ctx context.Context, msgAny *anypb.Any) (chaincli.SimResult, error) {
	raw, err := chaincli.BuildSignedTx(s.signer, s.txParams(), msgAny)
	if err != nil {
		return chaincli.SimResult{}, err
	}
	return s.chain.Simulate(ctx, raw)
}

func (s *defaultSubmitter) broadcastProposalLocked(ctx context.Context, p handraiseProposal, keep []int, excluded []ExcludedHandraise) (ProposalResult, error) {
	res, err := s.submitLocked(ctx, p.kind, p.typeURL, p.build(keep))
	return ProposalResult{TxResult: res, Excluded: excluded}, err
}
