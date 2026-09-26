package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
	wirebus "github.com/TrueOpen/wire/bus"
)

// verifierProposalFixture advances a Task to "the receipt has been accepted locally": from there the
// test decides when to declare on-chain acceptance and when to deliver Verifier hand-raises.
type verifierProposalFixture struct {
	c        *Coordinator
	bus      msgbus.Bus
	keys     *testServiceKeys
	fake     *fakeSubmitter
	fsm      *taskFSM
	session  string
	task     string
	output   []byte
	receipt  []byte
	deliver  func(candidate string)
	proposed func() []chaincli.OpenVerifyTx
}

func newVerifierProposalFixture(t *testing.T, name string) *verifierProposalFixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	fake := &fakeSubmitter{}

	workerService, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("worker service signer: %v", err)
	}
	winner := workerService.Address()

	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = fake
	c.SetResultReadiness(&fakeResultReadiness{ready: true})

	session := "sess-" + name
	task := testTaskID(name)
	outputHashSum := sha256.Sum256([]byte("canonical output " + name))
	outputHash := outputHashSum[:]

	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{
		SessionID: session, TaskID: task,
		AssignedSet: []types.BuilderRef{{Address: testBuilderSelf, Endpoint: "https://b/1"}},
		Height:      100,
	})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
		SessionID: session, TaskID: task, Winner: winner, AssignSeed: []byte("assign-seed"), Height: 101,
	})

	receipt := testInferReceipt(session, task, winner, outputHash)
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(receipt)
	if err != nil {
		t.Fatalf("derive receipt digest: %v", err)
	}
	receipt.InferReceiptHash = digest[:]
	signature, err := workerService.Sign(digest[:])
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	receipt.WorkerServiceSignature = signature
	if err := c.OnInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}
	// No batching by default: the cases here check the "submit on arrival" semantics; batching has
	// its own cases.
	fsm.mu.Lock()
	fsm.verifierProposalDelay = 0
	fsm.mu.Unlock()

	fx := &verifierProposalFixture{
		c: c, bus: bus, keys: keys, fake: fake, fsm: fsm, session: session, task: task,
		output: outputHash, receipt: receipt.InferReceiptHash,
	}
	fx.deliver = func(candidate string) {
		hr := testVerifierHandraise(session, task, candidate, outputHash, receipt.InferReceiptHash)
		publishEnvelope(t, bus, keys, candidate, msgbus.SubjectVerifierHandraiseV1(task),
			wirebus.KindVerifierHandraise, hr)
	}
	fx.proposed = func() []chaincli.OpenVerifyTx {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return append([]chaincli.OpenVerifyTx(nil), fake.verifierHandraises...)
	}
	return fx
}

// proposalOperators flattens the hand-raisers across a batch of proposals, and also checks that each
// proposal is strictly ascending by slot (one of the keeper's §4.2.1 acceptance conditions).
func proposalOperators(t *testing.T, proposals []chaincli.OpenVerifyTx) []string {
	t.Helper()
	var operators []string
	for i, tx := range proposals {
		if tx.Submitter != testBuilderSelf || tx.TaskID == "" {
			t.Fatalf("proposal %d: submitter=%q task=%q", i, tx.Submitter, tx.TaskID)
		}
		previous := -1
		for _, hr := range tx.VerifierHandraises {
			slot := int(hr.GetMember().GetSlot())
			if slot <= previous {
				t.Fatalf("proposal %d: handraises are not slot-ascending", i)
			}
			previous = slot
			operators = append(operators, hr.GetMember().GetOperatorAddress())
		}
	}
	return operators
}

func TestVerifierHandraisesGoOnChainAsProposal(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal")
	fx.fsm.onInferReceiptAccepted()

	v1, v2, v3 := testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")
	fx.deliver(v1)
	fx.deliver(v2)

	got := proposalOperators(t, fx.proposed())
	if len(got) != 2 {
		t.Fatalf("hand-raises that reached the chain = %d (%v), want 2: a legal hand-raise must be followed by MsgSubmitVerifierHandraises", len(got), got)
	}

	// A late hand-raise: the new proposal carries only the one not yet on chain (resubmitting one
	// already on chain would be treated as a duplicate by the keeper).
	fx.deliver(v3)
	proposals := fx.proposed()
	last := proposals[len(proposals)-1]
	if len(last.VerifierHandraises) != 1 || last.VerifierHandraises[0].GetMember().GetOperatorAddress() != v3 {
		t.Fatalf("the follow-up proposal must contain only %s, got %d entries", v3, len(last.VerifierHandraises))
	}
	seen := map[string]int{}
	for _, op := range proposalOperators(t, proposals) {
		seen[op]++
	}
	for _, op := range []string{v1, v2, v3} {
		if seen[op] != 1 {
			t.Fatalf("%s reached the chain %d times, want 1", op, seen[op])
		}
	}
}

func TestVerifierHandraisesWaitForReceiptOnChain(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal-wait")
	fx.deliver(testOperator("verifier-1"))
	if n := len(fx.proposed()); n != 0 {
		t.Fatalf("%d proposals were submitted before the receipt reached the chain; the keeper would reject them", n)
	}
	// The chain accepts the receipt (both the event and reconcile go through this entry point) ->
	// submit the hand-raises accumulated so far.
	fx.fsm.onInferReceiptAccepted()
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 {
		t.Fatalf("1 hand-raise must be submitted once the receipt is on chain, got %d", len(got))
	}
}

func TestVerifierProposalRetriesAfterSubmitFailure(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal-retry")
	fx.fsm.onInferReceiptAccepted()

	// The keeper rejects while the candidate window is not READY yet; the hand-raise must not be lost
	// and the next reconcile has to retry it.
	fx.fake.mu.Lock()
	fx.fake.verifierHandraisesErr = errors.New("verifier handraise window is unavailable")
	fx.fake.mu.Unlock()
	fx.deliver(testOperator("verifier-1"))
	fx.fake.mu.Lock()
	fx.fake.verifierHandraisesErr = nil
	fx.fake.mu.Unlock()

	fx.fsm.onInferReceiptAccepted() // reconcile runs again
	got := proposalOperators(t, fx.proposed())
	if len(got) != 1 {
		t.Fatalf("hand-raises on chain after the retry = %d (including the failed one), want 1", len(got))
	}
}

// When hand-raises trickle in over a few hundred milliseconds they are not submitted one by one:
// once selectedVerifierCount of them have accumulated, one submission goes out immediately.
func TestVerifierHandraisesAreBatchedIntoOneProposal(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal-batch")
	fx.fsm.mu.Lock()
	fx.fsm.verifierProposalDelay = time.Hour // a long enough batching window, so only the count triggers
	fx.fsm.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()

	fx.deliver(testOperator("verifier-1"))
	fx.deliver(testOperator("verifier-2"))
	if n := len(fx.proposed()); n != 0 {
		t.Fatalf("%d submissions went out after only two hand-raises, it must keep accumulating", n)
	}
	fx.deliver(testOperator("verifier-3"))
	proposals := fx.proposed()
	if len(proposals) != 1 || len(proposals[0].VerifierHandraises) != 3 {
		t.Fatalf("proposals = %d (the first carries %d entries), want 1 submission with 3 entries", len(proposals), len(proposals[0].VerifierHandraises))
	}
}

// Below selectedVerifierCount entries, it waits for the batching window to expire before submitting,
// rather than dropping them.
func TestVerifierHandraiseBatchFlushesAfterDelay(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-proposal-batch-delay")
	fx.fsm.mu.Lock()
	fx.fsm.verifierProposalDelay = 30 * time.Millisecond
	fx.fsm.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()

	fx.deliver(testOperator("verifier-1"))
	if n := len(fx.proposed()); n != 0 {
		t.Fatalf("%d submissions went out immediately after a single hand-raise", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(fx.proposed()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	proposals := fx.proposed()
	if len(proposals) != 1 || len(proposals[0].VerifierHandraises) != 1 {
		t.Fatalf("once the batching window expires there must be 1 submission with 1 entry, got %d submissions", len(proposals))
	}
}
