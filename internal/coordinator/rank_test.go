package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

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

// driveToSettleReady advances until the settlement preconditions are met: Verifying + WorkerReveal
// + 2 matching V_i.
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

// TestSettleRank1WaitsForRevealDeadline rank 1 must also wait until after the reveal deadline
// before sending: the chain only accepts a settlement transaction after the reveal deadline
// (§10.10a), so sending early is always rejected. It broadcasts prepare before sending.
func TestSettleRank1WaitsForRevealDeadline(t *testing.T) {
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
		t.Fatalf("rank 1 must not submit before the reveal deadline, got %d", settleCount(sub))
	}
	c.onNewBlock(rankRevealDeadline - 1) // sending now would execute in the reveal deadline block itself, still too early
	if settleCount(sub) != 0 {
		t.Fatalf("rank 1 submitted too early, got %d", settleCount(sub))
	}

	c.onNewBlock(rankRevealDeadline) // sending now executes in the block after the reveal deadline, exactly the first block of this slot
	if settleCount(sub) != 1 {
		t.Fatalf("rank 1 must submit as soon as its transaction would execute after the reveal deadline, got %d", settleCount(sub))
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
// moved on to the next rank, so sending would only be rejected by the chain. It resumes only once
// every slot has passed (anyone may submit).
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
	if settleCount(sub) != 1 {
		t.Fatalf("rank 2 must submit once every segment has passed, got %d", settleCount(sub))
	}
}

// TestSettleRetriesNextBlockWhenNotSettled the transaction passed CheckTx but the chain did not
// settle (execution rejected or it never made it into a block): send again on the next block while
// the window is open, it must not abstain forever.
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
