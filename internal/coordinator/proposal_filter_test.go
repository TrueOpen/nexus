package coordinator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

const refusedSupport = "failed to execute message; message index: 0: verifier bond cannot cover stake and liability: invalid verifier handraise"

func newFilterSubmitter(t *testing.T, chain *captureChain) (Submitter, *bytes.Buffer, string) {
	t.Helper()
	var logs bytes.Buffer
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	if chain.acc == (chaincli.AccountInfo{}) {
		chain.acc = chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}
	}
	sub := NewSignedSubmitter(slog.New(slog.NewTextHandler(&logs, nil)), chain, chain, sg, sg, config.ChainConfig{
		ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})
	return sub, &logs, sg.Address()
}

// refuse returns a judge that refuses any proposal carrying one of the operators.
func refuse(operators ...string) func([]string) chaincli.SimResult {
	return func(carried []string) chaincli.SimResult {
		for _, o := range carried {
			if slices.Contains(operators, o) {
				return chaincli.SimResult{Error: refusedSupport}
			}
		}
		return chaincli.SimResult{OK: true}
	}
}

// filterTaskID is the task the proposal filter cases propose Verifier handraises for.
var filterTaskID = strings.Repeat("1a", 32)

// filterHandraises returns Verifier handraises in the given slots, operator trueopen1verifier<slot>.
func filterHandraises(t *testing.T, slots ...uint32) []*taskv1.VerifierHandraiseV1 {
	t.Helper()
	base := testVerifierHandraises(filterTaskID, t)[0]
	hrs := make([]*taskv1.VerifierHandraiseV1, 0, len(slots))
	for _, slot := range slots {
		hr := proto.Clone(base).(*taskv1.VerifierHandraiseV1)
		hr.Member.Slot, hr.Member.OperatorAddress = slot, fmt.Sprintf("trueopen1verifier%d", slot)
		hrs = append(hrs, hr)
	}
	return hrs
}

func broadcastOperators(t *testing.T, chain *captureChain) [][]string {
	t.Helper()
	var out [][]string
	for _, tx := range chain.broadcast {
		out = append(out, signedProposalOperators(tx))
	}
	return out
}

func submitProposal(t *testing.T, sub Submitter, user string, hrs []*taskv1.VerifierHandraiseV1) (ProposalResult, error) {
	t.Helper()
	return sub.SubmitVerifierHandraises(context.Background(), chaincli.OpenVerifyTx{
		TaskID: filterTaskID, VerifierHandraises: hrs, Submitter: user,
	})
}

// A proposal the chain takes is simulated once and broadcast unchanged.
func TestHandraiseProposalTakenIsBroadcastUnchanged(t *testing.T) {
	chain := &captureChain{}
	sub, _, user := newFilterSubmitter(t, chain)
	res, err := submitProposal(t, sub, user, filterHandraises(t, 3, 9))
	if err != nil || len(res.Excluded) != 0 {
		t.Fatalf("SubmitVerifierHandraises = %+v, %v", res, err)
	}
	if len(chain.simulated) != 1 {
		t.Fatalf("simulations = %v, want one", chain.simulated)
	}
	if got := broadcastOperators(t, chain); len(got) != 1 || !slices.Equal(got[0], []string{"trueopen1verifier3", "trueopen1verifier9"}) {
		t.Fatalf("broadcast = %v", got)
	}
}

// One ineligible handraise no longer fails the task: it is left out, the rest go on chain in order.
func TestHandraiseProposalLeavesOutWhatTheChainRefuses(t *testing.T) {
	chain := &captureChain{judge: refuse("trueopen1verifier9")}
	sub, logs, user := newFilterSubmitter(t, chain)
	res, err := submitProposal(t, sub, user, filterHandraises(t, 3, 9, 12))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].Operator != "trueopen1verifier9" || res.Excluded[0].Reason != refusedSupport {
		t.Fatalf("excluded = %+v", res.Excluded)
	}
	if got := broadcastOperators(t, chain); len(got) != 1 || !slices.Equal(got[0], []string{"trueopen1verifier3", "trueopen1verifier12"}) {
		t.Fatalf("broadcast = %v, want the two eligible handraises in slot order", got)
	}
	// whole, each alone, then the remaining proposal once more
	if len(chain.simulated) != 5 || !slices.Equal(chain.simulated[4], []string{"trueopen1verifier3", "trueopen1verifier12"}) {
		t.Fatalf("simulations = %v", chain.simulated)
	}
	if !strings.Contains(logs.String(), "handraise left out of the proposal") || !strings.Contains(logs.String(), "trueopen1verifier9") {
		t.Fatalf("no WARN for the excluded handraise:\n%s", logs.String())
	}
}

// When the chain refuses the proposal for a reason that is not one handraise, nothing is broadcast.
func TestHandraiseProposalRefusedAsAWholeIsNotBroadcast(t *testing.T) {
	tests := map[string]func([]string) chaincli.SimResult{
		"every handraise refused": func([]string) chaincli.SimResult { return chaincli.SimResult{Error: "window is unavailable"} },
		"each passes alone, not together": func(carried []string) chaincli.SimResult {
			return chaincli.SimResult{OK: len(carried) == 1, Error: "too many"}
		},
		"remaining still refused": func(carried []string) chaincli.SimResult {
			if slices.Contains(carried, "trueopen1verifier9") {
				return chaincli.SimResult{Error: refusedSupport}
			}
			return chaincli.SimResult{OK: len(carried) == 1, Error: "slot relation"}
		},
	}
	for name, judge := range tests {
		t.Run(name, func(t *testing.T) {
			chain := &captureChain{judge: judge}
			sub, _, user := newFilterSubmitter(t, chain)
			_, err := submitProposal(t, sub, user, filterHandraises(t, 3, 9, 12))
			var subErr *SubmissionError
			if !errors.As(err, &subErr) || !subErr.Definitive {
				t.Fatalf("err = %v, want a definitive submission error", err)
			}
			if len(chain.broadcast) != 0 {
				t.Fatalf("broadcast %d txs for a proposal the chain refuses", len(chain.broadcast))
			}
		})
	}
}

// A node that cannot simulate leaves the proposal broadcast as before, and it is counted.
func TestHandraiseProposalWithoutSimulationIsBroadcast(t *testing.T) {
	chain := &captureChain{simulateErr: chaincli.ErrNotSupportedOnChain}
	sub, logs, user := newFilterSubmitter(t, chain)
	for i := 1; i <= 2; i++ {
		if _, err := submitProposal(t, sub, user, filterHandraises(t, 3, 9)); err != nil {
			t.Fatal(err)
		}
	}
	if len(chain.broadcast) != 2 {
		t.Fatalf("broadcast = %d, want 2", len(chain.broadcast))
	}
	if !strings.Contains(logs.String(), "unsimulated_total=2") {
		t.Fatalf("no count of unsimulated proposals:\n%s", logs.String())
	}
}

// The node checks the sequence even when simulating: a stale one is refreshed, not taken
// as the proposal's fault.
func TestHandraiseProposalRefreshesAStaleSequence(t *testing.T) {
	stale := true
	chain := &captureChain{}
	chain.judge = func([]string) chaincli.SimResult {
		if stale {
			stale = false
			return chaincli.SimResult{Error: "account sequence mismatch, expected 43, got 42: incorrect account sequence"}
		}
		return chaincli.SimResult{OK: true}
	}
	sub, _, user := newFilterSubmitter(t, chain)
	if _, err := submitProposal(t, sub, user, filterHandraises(t, 3, 9)); err != nil {
		t.Fatal(err)
	}
	if chain.accountCalls != 2 || len(chain.broadcast) != 1 || len(signedProposalOperators(chain.broadcast[0])) != 2 {
		t.Fatalf("account reads = %d, broadcast = %v", chain.accountCalls, broadcastOperators(t, chain))
	}
}

func TestVerifierHandraiseProposalLeavesOutWhatTheChainRefuses(t *testing.T) {
	chain := &captureChain{judge: refuse("trueopen1verifier5")}
	sub, _, user := newFilterSubmitter(t, chain)
	taskID := strings.Repeat("1a", 32)
	hrs := testVerifierHandraises(taskID, t)
	second := proto.Clone(hrs[0]).(*taskv1.VerifierHandraiseV1)
	second.Member.Slot, second.Member.OperatorAddress = 8, "trueopen1verifier8"
	res, err := sub.SubmitVerifierHandraises(context.Background(), chaincli.OpenVerifyTx{
		TaskID: taskID, VerifierHandraises: append(hrs, second), Submitter: user,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].Operator != "trueopen1verifier5" {
		t.Fatalf("excluded = %+v", res.Excluded)
	}
	if got := broadcastOperators(t, chain); len(got) != 1 || !slices.Equal(got[0], []string{"trueopen1verifier8"}) {
		t.Fatalf("broadcast = %v", got)
	}
}

// A Verifier handraise the chain refused is not simulated again in the same epoch, and is
// given another chance once the epoch changes.
func TestExcludedVerifierHandraiseWaitsForTheNextEpoch(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal-excluded")
	epoch := uint64(5)
	fx.fsm.mu.Lock()
	fx.fsm.currentEpoch = func() (uint64, bool) { return epoch, true }
	fx.fsm.mu.Unlock()
	refused := testOperator("verifier-1")
	fx.fake.mu.Lock()
	fx.fake.verifierExcluded = []ExcludedHandraise{{Operator: refused, Reason: "verifier bond cannot cover stake and liability"}}
	fx.fake.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()
	fx.deliver(refused)
	fx.fake.mu.Lock()
	fx.fake.verifierExcluded = nil
	fx.fake.mu.Unlock()

	fx.fsm.onInferReceiptAccepted() // reconcile, same epoch
	if n := len(fx.proposed()); n != 1 {
		t.Fatalf("proposals = %d, want the refused handraise not proposed again in the same epoch", n)
	}
	fx.fsm.mu.Lock()
	proposed := fx.fsm.verifierHRProposed[refused]
	fx.fsm.mu.Unlock()
	if proposed {
		t.Fatal("a refused handraise was recorded as on chain")
	}

	epoch = 6
	fx.fsm.onInferReceiptAccepted()
	if got := proposalOperators(t, fx.proposed()); len(got) != 2 {
		t.Fatalf("proposed operators = %v, want the handraise tried again in the next epoch", got)
	}
}

type epochSelection struct {
	BuilderSelectionQuerier
	calls  int
	length uint64
	err    error
}

func (q *epochSelection) QueryEpochLengthBlocks(context.Context) (uint64, error) {
	q.calls++
	return q.length, q.err
}

// The epoch length is read from the reconcile loop, and a failed read waits before the next;
// the task state machine only reads the cached value.
func TestEpochLengthIsReadOutsideTheTaskLock(t *testing.T) {
	c, _ := newTestCoordinator(t)
	query := &epochSelection{err: errors.New("hub unreachable")}
	c.selection = query
	c.refreshEpochLength(context.Background())
	c.refreshEpochLength(context.Background())
	if query.calls != 1 {
		t.Fatalf("hub reads = %d, want 1 within the retry pause", query.calls)
	}
	if _, ok := c.currentEpoch(); ok {
		t.Fatal("epoch known without an epoch length")
	}
	query.err, query.length = nil, 200
	c.epochTriedAt.Store(0)
	c.refreshEpochLength(context.Background())
	c.chainStateMu.Lock()
	c.chainState.LastObservedHeight, c.heightAuthoritative = 1050, true
	c.chainStateMu.Unlock()
	if epoch, ok := c.currentEpoch(); !ok || epoch != 5 {
		t.Fatalf("epoch = %d, %v; want 5", epoch, ok)
	}
	c.refreshEpochLength(context.Background())
	if query.calls != 2 {
		t.Fatalf("hub reads = %d, want the cached length reused", query.calls)
	}
}
