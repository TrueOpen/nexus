package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

func settleSelection(session, task string, builders ...string) chaincli.StageBuilderSelectionState {
	return chaincli.StageBuilderSelectionState{
		SessionID: session, TaskID: task, Stage: prepareStageSettle,
		SelectedBuilders: builders, SelectedHeight: 200,
	}
}

// Settlement window fixture (§10.10a): the reveal deadline is rankRevealDeadline, the verify
// deadline is rankVerifyDeadline, and each rank gets a grace of rankGraceBlocks blocks. The three
// Builders' submission slots are (3,13], (13,23] and (23,33] in order; after 33 anyone may submit.
const (
	rankRevealDeadline = 3
	rankVerifyDeadline = 1000
	rankGraceBlocks    = 10
	rankPermissionless = rankRevealDeadline + 3*rankGraceBlocks
)

// newRankCoordinator builds a coordinator with the given self + roster (stub bus).
func newRankCoordinator(t *testing.T, self string, members []types.BuilderRef) (*Coordinator, *fakeSubmitter, msgbus.Bus) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), self, testChainID)
	_ = enableTestBusEnvelopes(c)
	sub := &fakeSubmitter{}
	c.submit = sub
	c.active.Update(1, members, testBuilderSetRef)
	return c, sub, bus
}

// driveToSettleReady advances a task to Verifying with two Verifier results and the chain
// reporting it ready to settle (as reconciliation would after QueryTaskStage).
func driveToSettleReady(t *testing.T, c *Coordinator, session, task string, selection *chaincli.StageBuilderSelectionState) {
	t.Helper()
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1", Height: 101})
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: []string{"v1", "v2", "v3"},
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	c.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("sample-seed"), Height: 210})
	c.OnWorkerRevealAccepted(chaincli.WorkerRevealAccepted{SessionID: session, TaskID: task, Height: 300})

	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm not found")
	}
	if selection != nil {
		fsm.mu.Lock()
		fsm.settleSelection = *selection
		fsm.settleGraceBlocks = rankGraceBlocks
		fsm.mu.Unlock()
	}
	vals := [][]byte{[]byte("x1"), []byte("x2")}
	if err := fsm.onVerifyResult(testVerifyResult(task, "v1", vals)); err != nil {
		t.Fatalf("onVerifyResult v1: %v", err)
	}
	if err := fsm.onVerifyResult(testVerifyResult(task, "v2", vals)); err != nil {
		t.Fatalf("onVerifyResult v2: %v", err)
	}
	markSettleReady(fsm, 0)
}

// markSettleReady records the chain reporting the task ready to settle, with the given settlement
// deadline (0 = unknown).
func markSettleReady(fsm *taskFSM, deadline uint64) {
	fsm.mu.Lock()
	fsm.setSettleStageLocked(settleStage{ready: true, deadline: deadline})
	fsm.mu.Unlock()
}

func settleCount(s *fakeSubmitter) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.settle)
}

// TestSettleUsesFrozenBuilderOrder rank 2: it does not submit once the settlement inputs are ready; it takes
// over only after the chain height passes the start of its own grace window.
func TestSettleUsesFrozenBuilderOrder(t *testing.T) {
	c, sub, _ := newRankCoordinator(t, testOperator("builder-b"), nil)
	selection := settleSelection("session-1", testTaskID("rank-task-1"), testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	driveToSettleReady(t, c, "session-1", testTaskID("rank-task-1"), &selection)
	if settleCount(sub) != 0 {
		t.Fatal("rank 2 submitted immediately")
	}
	c.onNewBlock(rankRevealDeadline + rankGraceBlocks - 1) // sending now would execute inside rank 1's slot
	if settleCount(sub) != 0 {
		t.Fatal("rank 2 submitted inside rank 1's grace window")
	}
	c.onNewBlock(rankRevealDeadline + rankGraceBlocks)
	if settleCount(sub) != 1 {
		t.Fatalf("rank 2 did not take over once its window opened, got %d", settleCount(sub))
	}
}

// TestSettleRank3WaitsTwoGraceWindows rank 3 must wait for both grace windows to pass.
func TestSettleRank3WaitsTwoGraceWindows(t *testing.T) {
	c, sub, _ := newRankCoordinator(t, testOperator("builder-c"), nil)
	selection := settleSelection("session-1", testTaskID("rank-task-3"), testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	driveToSettleReady(t, c, "session-1", testTaskID("rank-task-3"), &selection)
	c.onNewBlock(rankRevealDeadline + 2*rankGraceBlocks - 1)
	if settleCount(sub) != 0 {
		t.Fatal("rank 3 submitted inside rank 2's grace window")
	}
	c.onNewBlock(rankRevealDeadline + 2*rankGraceBlocks)
	if settleCount(sub) != 1 {
		t.Fatalf("rank 3 did not take over, got %d", settleCount(sub))
	}
}

func TestMissingSettleSelectionNeverDefaultsToRankOne(t *testing.T) {
	c, sub, _ := newRankCoordinator(t, testOperator("builder-a"), nil)
	driveToSettleReady(t, c, "session-1", testTaskID("rank-task-nil"), nil)
	c.onNewBlock(rankPermissionless + 1)
	if settleCount(sub) != 0 {
		t.Fatal("missing selection submitted as rank 1")
	}
}

// TestSettleBackupWithoutGraceBlocksStandsBy the grace block count is unknown (an old snapshot):
// rank 2 does not invent a window of its own.
func TestSettleBackupWithoutGraceBlocksStandsBy(t *testing.T) {
	c, sub, _ := newRankCoordinator(t, testOperator("builder-b"), nil)
	selection := settleSelection("session-1", testTaskID("rank-task-ng"), testOperator("builder-a"), testOperator("builder-b"))
	driveToSettleReady(t, c, "session-1", testTaskID("rank-task-ng"), &selection)
	fsm, _ := c.getFSM("session-1", testTaskID("rank-task-ng"))
	fsm.mu.Lock()
	fsm.settleGraceBlocks = 0
	fsm.mu.Unlock()
	c.onNewBlock(rankPermissionless + 1)
	if settleCount(sub) != 0 {
		t.Fatal("rank 2 submitted without knowing the grace window")
	}
}

func TestRecoveredSettleSelectionKeepsRank(t *testing.T) {
	selection := settleSelection("session-1", "task-1", "builder-a", "builder-b", "builder-c")
	snapshot := taskSnapshot{
		Version: snapshotVersionProtoPayloadV4, SessionID: "session-1", TaskID: "task-1",
		State: types.Verifying, WorkerRevealed: true,
		SettleSelection: selection, SettleGraceBlocks: 7,
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var restored taskSnapshot
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.SettleSelection, selection) || restored.SettleGraceBlocks != 7 {
		t.Fatalf("selection=%+v grace=%d", restored.SettleSelection, restored.SettleGraceBlocks)
	}
}

// TestSettleRank1SubmitsOnceChainReady rank 1's slot has no start: the chain accepts its
// settlement at any height up to reveal + grace once the task is ready to settle. It broadcasts
// prepare before sending.
func TestSettleRank1SubmitsOnceChainReady(t *testing.T) {
	session, task := "sess-r1", testTaskID("task-r1")
	selection := settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	c, sub, bus := newRankCoordinator(t, testOperator("builder-a"), nil)
	var prepares captured
	if _, err := bus.Subscribe(msgbus.SubjectBuilderPrepare(task), func(_ string, data []byte) error {
		prepares.add(data)
		return nil
	}); err != nil {
		t.Fatalf("subscribe prepare: %v", err)
	}

	driveToSettleReady(t, c, session, task, &selection)
	if settleCount(sub) != 0 {
		t.Fatalf("rank 1 must wait for a block, got %d", settleCount(sub))
	}
	c.onNewBlock(rankRevealDeadline - 2)
	if settleCount(sub) != 1 {
		t.Fatalf("rank 1 must submit once the chain reports the task ready, got %d", settleCount(sub))
	}
	if prepares.count() != 1 {
		t.Fatalf("rank1 must broadcast prepare before submit, got %d", prepares.count())
	}
	// prepare is a nexus-internal signed message (prepare.go), not wrapped in BusEnvelopeV1;
	// run it through the receiving codec for a full signature verification.
	p, err := c.prepares.decode(context.Background(), prepares.last(), uint64(nowMS()))
	if err != nil {
		t.Fatalf("prepare notice does not verify: %v", err)
	}
	if p.Stage != prepareStageSettle || p.Submitter != c.active.self {
		t.Fatalf("prepare notice fields: %+v", p)
	}
}

// TestSettleOnlyInsideOwnSegment past its own slot it stops sending: by then the submitter has
// moved on to the next rank, so sending would only be rejected by the chain. It resumes once every
// slot has passed (anyone may submit), after giving rank 1 its g blocks.
func TestSettleOnlyInsideOwnSegment(t *testing.T) {
	session, task := "sess-seg", testTaskID("task-seg")
	selection := settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	c, sub, _ := newRankCoordinator(t, testOperator("builder-b"), nil)
	driveToSettleReady(t, c, session, task, &selection)

	c.onNewBlock(rankRevealDeadline + 2*rankGraceBlocks) // would execute inside rank 3's slot
	if settleCount(sub) != 0 {
		t.Fatalf("rank 2 submitted inside rank 3's segment, got %d", settleCount(sub))
	}
	c.onNewBlock(rankPermissionless) // executing any later means every slot has passed
	if settleCount(sub) != 0 {
		t.Fatalf("rank 2 must give rank 1 g blocks once anyone may submit, got %d", settleCount(sub))
	}
	c.onNewBlock(rankPermissionless + rankGraceBlocks)
	if settleCount(sub) != 1 {
		t.Fatalf("rank 2 must submit g blocks after anyone may submit, got %d", settleCount(sub))
	}
}

// TestSettleRetriesNextBlockWhenNotSettled the transaction passed CheckTx but the chain did not
// settle (execution rejected or it never made it into a block): send again on the next block while
// the window is open, it must not abstain forever. This holds when block results cannot be read
// (no Tx Query); with them the resend waits for the result, see txconfirm_test.go.
func TestSettleRetriesNextBlockWhenNotSettled(t *testing.T) {
	session, task := "sess-retry", testTaskID("task-retry")
	selection := settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	c, sub, _ := newRankCoordinator(t, testOperator("builder-a"), nil)
	driveToSettleReady(t, c, session, task, &selection)

	c.onNewBlock(rankRevealDeadline)
	if settleCount(sub) != 1 {
		t.Fatalf("first submission missing, got %d", settleCount(sub))
	}
	c.onNewBlock(rankRevealDeadline) // the same height must not send twice
	if settleCount(sub) != 1 {
		t.Fatalf("same height must not submit twice, got %d", settleCount(sub))
	}
	c.onNewBlock(rankRevealDeadline + 1) // still not settled on chain -> send again
	if settleCount(sub) != 2 {
		t.Fatalf("must retry on the next block while the segment is open, got %d", settleCount(sub))
	}
}

// TestSettleRank2RetriesOnNextBlockAfterSubmitFailure the take-over submission fails -> retry on
// the next block.
func TestSettleRank2RetriesOnNextBlockAfterSubmitFailure(t *testing.T) {
	session, task := "sess-r2", testTaskID("task-r2")
	selection := settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	c, sub, _ := newRankCoordinator(t, testOperator("builder-b"), nil)
	driveToSettleReady(t, c, session, task, &selection)

	sub.mu.Lock()
	sub.settleErr = errors.New("broadcast failed")
	sub.mu.Unlock()
	c.onNewBlock(rankRevealDeadline + rankGraceBlocks)
	if settleCount(sub) != 0 {
		t.Fatal("failed submit must not count")
	}
	sub.mu.Lock()
	sub.settleErr = nil
	sub.mu.Unlock()
	c.onNewBlock(rankRevealDeadline + rankGraceBlocks + 1)
	if settleCount(sub) != 1 {
		t.Fatalf("rank2 must retry on the next block, got %d", settleCount(sub))
	}
}

// TestSettleRank2StandsDownWhenSettled a settlement lands on chain while rank2 is standing by ->
// it does not submit even once its window opens.
func TestSettleRank2StandsDownWhenSettled(t *testing.T) {
	session, task := "sess-rs", testTaskID("task-rs")
	selection := settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c"))
	c, sub, _ := newRankCoordinator(t, testOperator("builder-b"), nil)
	driveToSettleReady(t, c, session, task, &selection)
	// rank1 (someone else) settles on chain, ahead of rank2's window.
	c.OnSettleAccepted(chaincli.SettleAccepted{
		SessionID: session, TaskID: task, TaskVerdict: types.VerdictPass,
		Settlement: chaincli.TaskSettlementState{
			SettlementStatus: "SETTLED_PASS", SettlementHeight: 400, TaskFinalityHeight: 600,
		}, Height: 400,
	})

	c.onNewBlock(rankPermissionless + 1)
	if settleCount(sub) != 0 {
		t.Fatalf("rank2 must stand down after SettleAccepted, got %d submissions", settleCount(sub))
	}
	st, err := c.TaskStatus(context.Background(), session, task)
	if err != nil || st.State != "SETTLED" {
		t.Fatalf("state = %v (%v), want SETTLED", st.State, err)
	}
}

// TestProposalGroupGating ASSIGN proposal gate (§4.1): outside the group it does not submit; inside
// the group it submits right away (without waiting for others).
func TestProposalGroupGating(t *testing.T) {
	members := []types.BuilderRef{{Address: testOperator("builder-a")}, {Address: testOperator("builder-b")}}

	feedHandraises := func(c *Coordinator, session, task string) {
		if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
			t.Fatalf("OnOrder: %v", err)
		}
		fsm, _ := c.getFSM(session, task)
		for _, w := range []string{"w1", "w2", "w3"} {
			fsm.onWorkerHandraise(testWorkerHandraise(session, task, w))
		}
	}

	// Outside the group: the roster is non-empty and self is not in it -> no AssignTx is submitted.
	cOut, subOut, _ := newRankCoordinator(t, testOperator("builder-outsider"), members)
	feedHandraises(cOut, "sess-po", testTaskID("task-po"))
	subOut.mu.Lock()
	nOut := len(subOut.assign)
	subOut.mu.Unlock()
	if nOut != 0 {
		t.Fatalf("outsider must not submit AssignTx, got %d", nOut)
	}

	// Inside the group: submit immediately, with no rank wait (proposal window semantics).
	cIn, subIn, _ := newRankCoordinator(t, testOperator("builder-a"), members)
	feedHandraises(cIn, "sess-pi", testTaskID("task-pi"))
	subIn.mu.Lock()
	nIn := len(subIn.assign)
	subIn.mu.Unlock()
	if nIn != 1 {
		t.Fatalf("group member must submit AssignTx immediately, got %d", nIn)
	}
}

// TestSettleFollowsChainNotLocalResults whether to settle is the chain's call: local Verifier
// results that disagree, or none at all, change nothing.
func TestSettleFollowsChainNotLocalResults(t *testing.T) {
	session, task := "sess-chain", testTaskID("task-chain")
	c, sub, _ := newRankCoordinator(t, testOperator("builder-a"), nil)
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1", Height: 101})
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: []string{"v1", "v2", "v3"},
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.settleSelection = settleSelection(session, task, testOperator("builder-a"), testOperator("builder-b"))
	fsm.settleGraceBlocks = rankGraceBlocks
	fsm.mu.Unlock()

	c.onNewBlock(rankPermissionless + 1)
	if settleCount(sub) != 0 {
		t.Fatal("settled before the chain reported the task ready")
	}
	markSettleReady(fsm, 0)
	if settleCount(sub) != 1 {
		t.Fatalf("no local results: settle submissions = %d, want 1 once the chain reports ready", settleCount(sub))
	}
}

// TestSettleStageFromChain only SETTLING, not settled and not final is ready; the settlement
// deadline is taken only from a TASK_SETTLEMENT next deadline.
func TestSettleStageFromChain(t *testing.T) {
	tests := []struct {
		name  string
		stage chaincli.TaskStage
		want  settleStage
	}{
		{"settling", chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "PENDING",
			NextDeadlineKind: "TASK_SETTLEMENT", NextDeadlineHeight: 90}, settleStage{ready: true, deadline: 90}},
		{"settling without deadline", chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "PENDING"},
			settleStage{ready: true}},
		{"revealing", chaincli.TaskStage{TaskPhase: "REVEALING", SettlementStatus: "NONE", FinalityStatus: "PENDING",
			NextDeadlineKind: "CHALLENGE_WINDOW_CLOSE", NextDeadlineHeight: 80}, settleStage{}},
		{"settled", chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "SETTLED_PASS", FinalityStatus: "PENDING"}, settleStage{}},
		{"final", chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "FINAL"}, settleStage{}},
	}
	for _, test := range tests {
		if got := settleStageFrom(test.stage); got != test.want {
			t.Errorf("%s: got %+v, want %+v", test.name, got, test.want)
		}
	}
}

// TestReconcileSettleStage reconciliation asks the chain only once the task shows SETTLING. A
// failed query leaves the task as it was and asks for a retry; it neither settles nor gives up.
func TestReconcileSettleStage(t *testing.T) {
	session, task := "sess-stage", testTaskID("task-stage")
	selection := settleSelection(session, task, testOperator("builder-a"))
	c, sub, _ := newRankCoordinator(t, testOperator("builder-a"), nil)
	driveToSettleReady(t, c, session, task, &selection)
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.settleStage = settleStage{}
	fsm.mu.Unlock()
	c.onNewBlock(rankRevealDeadline + 1)
	chain := &chainFactsFake{stage: chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "NONE",
		FinalityStatus: "PENDING", NextDeadlineKind: "TASK_SETTLEMENT", NextDeadlineHeight: 90}}
	c.challenge = chain

	if !c.reconcileSettleStage(fsm, chaincli.OnChainTask{Status: "REVEALING"}) {
		t.Fatal("a task that is not SETTLING must reconcile without a query")
	}
	if settleCount(sub) != 0 {
		t.Fatal("settled a task the chain has not closed")
	}

	chain.mu.Lock()
	chain.stageErr = errors.New("node unavailable")
	chain.mu.Unlock()
	if c.reconcileSettleStage(fsm, chaincli.OnChainTask{Status: "SETTLING"}) {
		t.Fatal("a failed stage query must ask for a retry")
	}
	if settleCount(sub) != 0 {
		t.Fatal("settled on a failed stage query")
	}

	chain.mu.Lock()
	chain.stageErr = nil
	chain.mu.Unlock()
	if !c.reconcileSettleStage(fsm, chaincli.OnChainTask{Status: "SETTLING"}) {
		t.Fatal("stage query failed")
	}
	if settleCount(sub) != 1 {
		t.Fatalf("settle submissions = %d once the chain reports the task ready", settleCount(sub))
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if fsm.settleStage != (settleStage{ready: true, deadline: 90}) {
		t.Fatalf("stage = %+v", fsm.settleStage)
	}
}

// TestChallengeWindowCloseReconcilesTheTask the task turns SETTLING when its challenge window
// closes; the task is read again at once instead of at the next periodic reconciliation.
func TestChallengeWindowCloseReconcilesTheTask(t *testing.T) {
	session, task := "sess-cw", testTaskID("task-cw")
	selection := settleSelection(session, task, testOperator("builder-a"))
	c, _, _ := newRankCoordinator(t, testOperator("builder-a"), nil)
	driveToSettleReady(t, c, session, task, &selection)
	pending := func() bool {
		c.reconcilePendingMu.Lock()
		defer c.reconcilePendingMu.Unlock()
		_, ok := c.reconcilePending["task|"+session+"|"+task]
		return ok
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{SessionID: session, TaskID: task, Height: 50,
		TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_COMMIT_CLOSED})
	if pending() {
		t.Fatal("a closed commit window must not trigger a task reconciliation")
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{SessionID: session, TaskID: task, Height: 60,
		TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_CHALLENGE_WINDOW_CLOSED})
	if !pending() {
		t.Fatal("a closed challenge window must reconcile the task")
	}
}

// TestReconcileSettlesWithoutSettlementFacts the chain serves no settlement build facts query;
// reconciliation still reads the task stage and the settlement order, and the task is settled.
func TestReconcileSettlesWithoutSettlementFacts(t *testing.T) {
	session, task := "sess-nofacts", testTaskID("task-nofacts")
	chain := &chainFactsFake{
		height:   rankRevealDeadline,
		factsErr: chaincli.ErrNotSupportedOnChain,
		stage: chaincli.TaskStage{TaskPhase: "SETTLING", SettlementStatus: "NONE", FinalityStatus: "PENDING",
			NextDeadlineKind: "TASK_SETTLEMENT", NextDeadlineHeight: 90},
	}
	selection := &selectionFactsFake{selection: taskBuilders(task, testBuilderSelf, "builder-b"), grace: rankGraceBlocks}
	c, _ := newTestCoordinator(t, WithHeightQuerier(chain), WithTaskQuerier(chain), WithBuilderSelectionQuerier(selection))
	driveToSettleReady(t, c, session, task, nil)
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.settleStage = settleStage{}
	fsm.mu.Unlock()
	c.onNewBlock(rankRevealDeadline)
	sub := c.submit.(*fakeSubmitter)
	if settleCount(sub) != 0 {
		t.Fatal("settled before reconciliation read the chain")
	}
	chain.mu.Lock()
	chain.tasks = map[string]chaincli.OnChainTask{
		taskKey(session, task): {SessionID: session, TaskID: task, State: types.Verifying, Status: "SETTLING",
			Settlement: chaincli.TaskSettlementState{SettlementStatus: "NONE", FinalityStatus: "PENDING"}},
	}
	chain.mu.Unlock()
	if !c.reconcileTask(session, task, 0, "test", nil) {
		t.Fatal("reconciliation did not complete")
	}
	if chain.factsCalls != 1 {
		t.Fatalf("settlement facts queried %d times", chain.factsCalls)
	}
	if settleCount(sub) != 1 {
		t.Fatalf("settle submissions = %d, want 1 without settlement facts", settleCount(sub))
	}
}

// TestPermissionlessSettleIsStaggeredByRank once anyone may submit, three Builders that see the
// task ready in the same block do not all submit: rank 1 goes at once, rank i waits (i-1)·g
// blocks, and nobody submits after the chain settled the task.
func TestPermissionlessSettleIsStaggeredByRank(t *testing.T) {
	session, task := "sess-stagger", testTaskID("task-stagger")
	builders := []string{testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c")}
	selection := settleSelection(session, task, builders...)
	type node struct {
		c   *Coordinator
		sub *fakeSubmitter
	}
	nodes := make([]node, len(builders))
	for i, self := range builders {
		c, sub, _ := newRankCoordinator(t, self, nil)
		driveToSettleReady(t, c, session, task, &selection)
		nodes[i] = node{c, sub}
	}
	ready := int64(rankPermissionless + 100) // settling opens long after every slot has passed
	for _, n := range nodes {
		n.c.onNewBlock(ready)
	}
	if got := []int{settleCount(nodes[0].sub), settleCount(nodes[1].sub), settleCount(nodes[2].sub)}; !reflect.DeepEqual(got, []int{1, 0, 0}) {
		t.Fatalf("submissions by rank = %v, want only rank 1 in the first block", got)
	}
	for _, n := range nodes {
		n.c.onNewBlock(ready + rankGraceBlocks - 1)
	}
	if settleCount(nodes[1].sub) != 0 || settleCount(nodes[2].sub) != 0 {
		t.Fatal("rank 2 or 3 submitted before its wait")
	}
	// Rank 1's settlement lands.
	for _, n := range nodes {
		n.c.OnSettleAccepted(chaincli.SettleAccepted{SessionID: session, TaskID: task, TaskVerdict: types.VerdictPass,
			Settlement: chaincli.TaskSettlementState{SettlementStatus: "SETTLED_PASS", SettlementHeight: uint64(ready + 1)}, Height: ready + 1})
	}
	for h := ready + rankGraceBlocks; h <= ready+3*rankGraceBlocks; h++ {
		for _, n := range nodes {
			n.c.onNewBlock(h)
		}
	}
	if settleCount(nodes[1].sub) != 0 || settleCount(nodes[2].sub) != 0 {
		t.Fatal("rank 2 or 3 submitted after the chain settled the task")
	}
}

// TestPermissionlessSettleBackupTakesOver when rank 1 does not settle, rank 2 submits after g
// blocks and rank 3 after 2·g.
func TestPermissionlessSettleBackupTakesOver(t *testing.T) {
	session, task := "sess-backup", testTaskID("task-backup")
	builders := []string{testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c")}
	selection := settleSelection(session, task, builders...)
	subs := make([]*fakeSubmitter, 0, 2)
	coords := make([]*Coordinator, 0, 2)
	for _, self := range builders[1:] {
		c, sub, _ := newRankCoordinator(t, self, nil)
		driveToSettleReady(t, c, session, task, &selection)
		coords, subs = append(coords, c), append(subs, sub)
	}
	ready := int64(rankPermissionless + 100)
	for h := ready; h < ready+2*rankGraceBlocks; h++ {
		for _, c := range coords {
			c.onNewBlock(h)
		}
		if h == ready+rankGraceBlocks-1 && (settleCount(subs[0]) != 0 || settleCount(subs[1]) != 0) {
			t.Fatal("a backup submitted before its wait")
		}
		if h == ready+rankGraceBlocks && settleCount(subs[0]) != 1 {
			t.Fatalf("rank 2 submissions = %d after its wait", settleCount(subs[0]))
		}
	}
	if settleCount(subs[1]) != 0 {
		t.Fatal("rank 3 submitted before 2·g blocks")
	}
	coords[1].onNewBlock(ready + 2*rankGraceBlocks)
	if settleCount(subs[1]) != 1 {
		t.Fatalf("rank 3 submissions = %d after 2·g blocks", settleCount(subs[1]))
	}
}

// TestPermissionlessStaggerCountsFromFirstAcceptedHeight the chain can report a task ready a few
// blocks before its challenge window closes and refuse settlements until then. The stagger counts
// from the first height the chain accepts one, so rank 1 held by the window does not end up in the
// same block as ranks whose waits ran out meanwhile.
func TestPermissionlessStaggerCountsFromFirstAcceptedHeight(t *testing.T) {
	session, task := "sess-open", testTaskID("task-open")
	builders := []string{testOperator("builder-a"), testOperator("builder-b"), testOperator("builder-c")}
	selection := settleSelection(session, task, builders...)
	subs := make([]*simulatingSubmitter, len(builders))
	coords := make([]*Coordinator, len(builders))
	for i, self := range builders {
		c, _, _ := newRankCoordinator(t, self, nil)
		sub := &simulatingSubmitter{confirmSubmitter: newConfirmSubmitter(),
			sim: chaincli.SimResult{OK: false, Error: "round 1 challenge window is still open"}}
		c.submit = sub
		driveToSettleReady(t, c, session, task, &selection)
		coords[i], subs[i] = c, sub
	}
	ready := int64(rankPermissionless + 100)
	for h := ready; h < ready+2*rankGraceBlocks; h++ { // longer than rank 3's wait
		for _, c := range coords {
			c.onNewBlock(h)
		}
	}
	for i, sub := range subs {
		if settleCount(sub.fakeSubmitter) != 0 {
			t.Fatalf("rank %d submitted while the chain refused settlements", i+1)
		}
		sub.setSimulation(chaincli.SimResult{OK: true}, nil)
	}
	open := ready + 2*rankGraceBlocks
	for _, c := range coords {
		c.onNewBlock(open)
	}
	got := []int{settleCount(subs[0].fakeSubmitter), settleCount(subs[1].fakeSubmitter), settleCount(subs[2].fakeSubmitter)}
	if !reflect.DeepEqual(got, []int{1, 0, 0}) {
		t.Fatalf("submissions by rank at the first accepted height = %v, want only rank 1", got)
	}
}
