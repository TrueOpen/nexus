package coordinator

import (
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/types"
)

// anchorOnlyWindow is the window the chain freezes for a task it verifies by the anchor audit
// alone: READY at the receipt, with no members.
var anchorOnlyWindow = chaincli.VerifierWindow{
	WindowRandomnessHeight: 105, GeneratedHeight: 100,
	BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230, Ready: true, AnchorOnly: true,
}

// The chain draws no Verifier for an anchor-only task and refuses every hand-raise proposal, so a
// Builder sends no OPEN_VERIFY for it and submits no proposal, whatever hand-raises still arrive.
func TestAnchorOnlyWindowSendsNoOpenVerifyAndNoProposal(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-only-window")
	openVerify := openVerifyCounter{link: fx.link}
	fx.fsm.setVerifierWindow(anchorOnlyWindow)
	fx.setHeight(150)
	fx.chainAcceptsReceipt(t, 150)
	fx.chainAcceptsReceipt(t, 151) // a repeated reconciliation changes nothing
	if n := openVerify.count(); n != 0 {
		t.Fatalf("OPEN_VERIFY sent for an anchor-only task: %d", n)
	}
	if !fx.closed() {
		t.Fatal("an anchor-only window must close this Builder's Verifier proposals")
	}
	if fx.fsm.needsVerifierWindow() {
		t.Fatal("the window of an anchor-only task must not be re-read")
	}
	fx.deliver(testOperator("verifier-1"))
	fx.fsm.onInferReceiptAccepted()
	if n := fx.attempts(); n != 0 {
		t.Fatalf("Verifier proposals submitted for an anchor-only task: %d", n)
	}
	assertState(t, fx.c, fx.session, fx.task, types.Assigned)
}

// anchorOnlySettling is the QueryTask view of an anchor-only task once the chain has sampled it:
// round 1 is assigned to nobody and already closed, and the task is SETTLING.
func (fx *verifierProposalFixture) anchorOnlySettling(openVerifyHeight uint64) chaincli.OnChainTask {
	commit := int64(openVerifyHeight) + 1
	return chaincli.OnChainTask{
		SessionID: fx.session, TaskID: fx.task, Status: "SETTLING", State: types.Verifying, Winner: fx.fsm.winner,
		Assignment:      chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		ReceiptAccepted: true,
		Deadlines:       types.Deadlines{Commit: commit, Verify: commit + 1},
		VerifierAssignment: chaincli.VerifierAssignmentState{
			OpenVerifyHeight: openVerifyHeight, CommitDeadlineHeight: uint64(commit), VerifyDeadlineHeight: uint64(commit) + 1,
		},
	}
}

// Once the chain has closed the zero-Verifier round, the task is Verifying with an empty Verifier
// set and the only thing left is its settlement, which this Builder submits in its slot of the
// schedule the chain counts from the assignment's commit deadline. No assignment notice is sent
// and no Verifier deadline is swept.
func TestAnchorOnlyRoundIsSettledByTheBuilder(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-only-settle")
	assignments := assignmentCounter{link: fx.link}
	fx.fsm.setVerifierWindow(anchorOnlyWindow)
	fx.setHeight(150)
	fx.chainAcceptsReceipt(t, 150)

	fx.c.applyAuthoritativeTask(fx.fsm, fx.anchorOnlySettling(160), 160)
	assertState(t, fx.c, fx.session, fx.task, types.Verifying)
	if n := assignments.count(); n != 0 {
		t.Fatalf("assignment notices sent with no Verifier selected: %d", n)
	}

	fx.fsm.mu.Lock()
	if !fx.fsm.anchorOnlyRound || fx.fsm.deadlines.Commit != 161 {
		t.Fatalf("anchorOnlyRound = %v, commit deadline = %d; want true, 161", fx.fsm.anchorOnlyRound, fx.fsm.deadlines.Commit)
	}
	fx.fsm.settleGraceBlocks = 2
	fx.fsm.settleSelection = chaincli.StageBuilderSelectionState{
		SessionID: fx.session, SelectedBuilders: []string{testBuilderSelf, "builder-b", "builder-c"},
	}
	// The chain holds a sampled task for its anchor verdict: nothing is sent while it does.
	fx.fsm.setSettleStageLocked(settleStageFrom(chaincli.TaskStage{
		TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "PENDING", NextDeadlineKind: "ANCHOR_VERDICT", NextDeadlineHeight: 30_000,
	}))
	fx.fsm.mu.Unlock()
	fx.fsm.onHeight(161)
	if n := len(fx.settles()); n != 0 {
		t.Fatalf("settlement submitted while the chain holds the task for its verdict: %d", n)
	}

	// Verdict final (or the task was not sampled): the chain reports the settlement itself next,
	// and this Builder, rank 1, submits in its slot (execution height 162 <= 161 + grace).
	fx.fsm.mu.Lock()
	fx.fsm.setSettleStageLocked(settleStageFrom(chaincli.TaskStage{
		TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "PENDING", NextDeadlineKind: "TASK_SETTLEMENT", NextDeadlineHeight: 30_001,
	}))
	fx.fsm.mu.Unlock()
	got := fx.settles()
	if len(got) != 1 || got[0].TaskID != fx.task || got[0].Submitter != testBuilderSelf {
		t.Fatalf("settlements = %+v, want one for the task by this Builder", got)
	}

	fx.fsm.sweepDueDeadlines(DeadlineSweepPolicy{Enabled: true}, 400)
	if n := len(fx.fake.sweepTxs()); n != 0 {
		t.Fatalf("Verifier deadlines swept on a round with no Verifier: %d", n)
	}
}

// RECEIPT_COMMITTED with no assignment yet is still "Verifiers undecided": only a round 1
// assignment that exists and selected nobody marks an anchor-only round.
func TestUndecidedVerifiersAreNotReadAsAnAnchorOnlyRound(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-only-undecided")
	fx.chainAcceptsReceipt(t, 150)
	assertState(t, fx.c, fx.session, fx.task, types.Assigned)
	fx.fsm.mu.Lock()
	defer fx.fsm.mu.Unlock()
	if fx.fsm.anchorOnlyRound {
		t.Fatal("a task without a round 1 assignment was read as anchor-only")
	}
}

func (fx *verifierProposalFixture) settles() []chaincli.SettleTx {
	fx.fake.mu.Lock()
	defer fx.fake.mu.Unlock()
	return append([]chaincli.SettleTx(nil), fx.fake.settle...)
}

// holdAnchorReceipt puts the fixture back to "receipt accepted locally, not yet relayed" with a
// receipt that carries the anchor commitment and a data plane that is not ready for it.
func holdAnchorReceipt(t *testing.T, fx *verifierProposalFixture, anchor bool) *fakeResultReadiness {
	t.Helper()
	readiness := &fakeResultReadiness{}
	fx.c.SetResultReadiness(readiness)
	fx.fake.mu.Lock()
	fx.fake.openVerify = nil
	fx.fake.mu.Unlock()
	fx.fsm.mu.Lock()
	defer fx.fsm.mu.Unlock()
	fx.fsm.resultReadiness = readiness
	fx.fsm.dataReady = false
	fx.fsm.openVerifySubmitted = false
	fx.fsm.receiptTx = submittedTx{}
	if anchor {
		fx.fsm.inferReceipt.EvidenceCommitments = append(fx.fsm.inferReceipt.EvidenceCommitments,
			types.EvidenceCommitment{Kind: anchorEvidenceKind, HashOrRoot: make([]byte, 32), EncodedSizeBytes: 64})
	}
	fx.fsm.submitOpenVerifyLocked()
	return readiness
}

func (fx *verifierProposalFixture) receiptsRelayed() int {
	fx.fake.mu.Lock()
	defer fx.fake.mu.Unlock()
	return len(fx.fake.openVerify)
}

// A receipt that carries the anchor commitment is not relayed to the chain until the Worker's
// result is finalized on this Builder: the chain draws no Verifier for it, so nothing later would
// state that a Builder holds the output, and the round would close and pay without it.
func TestAnchorReceiptIsRelayedOnlyOnceTheResultIsFinalized(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold")
	readiness := holdAnchorReceipt(t, fx, true)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("anchor receipt relayed before the result was finalized: %d", n)
	}
	fx.fsm.onHeight(151) // a new height alone does not release it
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("anchor receipt relayed on a new height without the result: %d", n)
	}
	readiness.set(true)
	fx.resultFinalized(t)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("anchor receipt relays after Finalize = %d, want 1", n)
	}
	fx.fsm.onHeight(152)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("anchor receipt relayed again: %d", n)
	}
}

// A data-ready check that failed when the result was finalized is asked again on the next height,
// so an honest Worker's receipt is not left unrelayed by one failed read.
func TestHeldAnchorReceiptIsRetriedOnTheNextHeight(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-retry")
	readiness := holdAnchorReceipt(t, fx, true)
	readiness.mu.Lock()
	readiness.ready, readiness.err = true, errors.New("storage unavailable")
	readiness.mu.Unlock()
	fx.resultFinalized(t)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("relayed although the data-ready check failed: %d", n)
	}
	readiness.mu.Lock()
	readiness.err = nil
	readiness.mu.Unlock()
	fx.fsm.onHeight(151)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relays after the retry = %d, want 1", n)
	}
}

// A receipt without the anchor commitment is relayed at once, as before; so is an anchor receipt on
// a Builder that holds another input version and can never be data-ready.
func TestOnlyAnchorReceiptsWaitForTheResult(t *testing.T) {
	fx := newVerifierProposalFixture(t, "legacy-receipt-no-hold")
	holdAnchorReceipt(t, fx, false)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("legacy receipt relays = %d, want 1", n)
	}

	fx = newVerifierProposalFixture(t, "anchor-receipt-mismatch")
	fx.fsm.mu.Lock()
	fx.fsm.versionMismatch = true
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("anchor receipt relays on an input-version mismatch = %d, want 1", n)
	}
}

// The hold is bounded. A result that never finalizes on this Builder (a storage fault here, a
// restart during the upload) while the Worker has stopped retrying must not cost an honest
// Worker its receipt: after the hold the receipt is relayed without data-ready, once.
func TestAnchorReceiptHoldEndsAfterItsBlocks(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold-bound")
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = 150
	fx.fsm.receiptHoldBlocks = 40
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	for h := uint64(151); h < 190; h++ {
		fx.fsm.onHeight(h)
	}
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("relayed inside the hold: %d", n)
	}
	fx.fsm.onHeight(190) // held since 150, 40 blocks
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relays at the end of the hold = %d, want 1", n)
	}
	for h := uint64(191); h < 200; h++ {
		fx.fsm.onHeight(h)
	}
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relayed again after the hold: %d", n)
	}
}

// Whatever its age, the hold ends a margin before the infer deadline (and before the receipt's
// own expiry), well ahead of the few blocks at which a Worker submits its receipt itself.
func TestAnchorReceiptHoldEndsBeforeTheInferDeadline(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold-deadline")
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = 150
	fx.fsm.receiptHoldBlocks = 100_000
	fx.fsm.receiptHoldDeadlineMargin = 50
	fx.fsm.inferDeadlineHeight = 400
	fx.fsm.inferReceipt.ExpiryHeight = 1_000_000
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	fx.fsm.onHeight(349)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("relayed %d blocks before the infer deadline: %d", 400-349, n)
	}
	fx.fsm.onHeight(350)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relays at the deadline margin = %d, want 1", n)
	}
}

// The start of the hold is persisted and restored, so a restart does not start the bound again.
func TestAnchorReceiptHoldStartSurvivesARestart(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold-restart")
	var last taskSnapshot
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = 150
	fx.fsm.persist = func(sn taskSnapshot) error { last = sn; return nil }
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	if last.ReceiptHeldSince != 150 {
		t.Fatalf("persisted hold start = %d, want 150", last.ReceiptHeldSince)
	}
	restored := &taskFSM{}
	restored.restoreFrom(last)
	if restored.receiptHeldSince != 150 || restored.receiptRelayCleared {
		t.Fatalf("restored hold start = %d, relay cleared = %v; want 150 and not cleared before a reconcile",
			restored.receiptHeldSince, restored.receiptRelayCleared)
	}
}

// After a restart this process does not know whether the chain already holds the receipt. The
// per-height retry and the data-ready release wait for the first reconcile: a receipt the chain
// holds is not sent again (one wasted fee per task), one it does not hold is relayed then.
func TestRestoredAnchorReceiptIsNotRelayedBeforeTheChainIsRead(t *testing.T) {
	for _, onChain := range []bool{true, false} {
		fx := newVerifierProposalFixture(t, "anchor-receipt-restored")
		readiness := holdAnchorReceipt(t, fx, true)
		fx.fsm.mu.Lock()
		fx.fsm.receiptRelayCleared = false // as restored from the store
		fx.fsm.mu.Unlock()
		readiness.set(true)
		fx.resultFinalized(t)
		fx.fsm.onHeight(151)
		waitDataReadyIdle(t, fx.fsm)
		if n := fx.receiptsRelayed(); n != 0 {
			t.Fatalf("on chain %v: a restored receipt was relayed before any reconcile: %d", onChain, n)
		}
		if onChain {
			fx.chainAcceptsReceipt(t, 152)
		} else {
			fx.fsm.receiptReconciled(0)
		}
		fx.fsm.onHeight(153)
		waitDataReadyIdle(t, fx.fsm)
		want := 1
		if onChain {
			want = 0
		}
		if n := fx.receiptsRelayed(); n != want {
			t.Fatalf("on chain %v: relays after the reconcile = %d, want %d", onChain, n, want)
		}
	}
}

// On a network whose infer window is shorter than the deadline margin (a devnet with a window of
// 100 blocks against a margin of 200) the hold is not void: it covers the first half of what was
// left of the window when it began.
func TestAnchorReceiptHoldCoversHalfOfAShortInferWindow(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold-short-window")
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = 150
	fx.fsm.inferDeadlineHeight = 250 // 100 blocks left, default margin 200
	fx.fsm.inferReceipt.ExpiryHeight = 1_000_000
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	fx.fsm.onHeight(199)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 0 {
		t.Fatalf("relayed in the first half of a short window: %d", n)
	}
	fx.fsm.onHeight(200)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relays at half of the short window = %d, want 1", n)
	}
}

// A hold that begins before any height was observed gets its start at the first height, not at
// height 1 (which would end it at once on any chain past the hold length).
func TestAnchorReceiptHoldStartsAtTheFirstObservedHeight(t *testing.T) {
	fx := newVerifierProposalFixture(t, "anchor-receipt-hold-no-height")
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = 0
	fx.fsm.receiptHoldBlocks = 40
	fx.fsm.inferReceipt.ExpiryHeight = 1_000_000
	fx.fsm.mu.Unlock()
	holdAnchorReceipt(t, fx, true)
	fx.fsm.onHeight(5000)
	waitDataReadyIdle(t, fx.fsm)
	fx.fsm.mu.Lock()
	since := fx.fsm.receiptHeldSince
	fx.fsm.mu.Unlock()
	if since != 5000 || fx.receiptsRelayed() != 0 {
		t.Fatalf("hold start = %d, relays = %d; want 5000 and none", since, fx.receiptsRelayed())
	}
	fx.fsm.onHeight(5040)
	waitDataReadyIdle(t, fx.fsm)
	if n := fx.receiptsRelayed(); n != 1 {
		t.Fatalf("relays at the end of the hold = %d, want 1", n)
	}
}
