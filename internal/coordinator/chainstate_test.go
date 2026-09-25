package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

type chainFactsFake struct {
	mu             sync.Mutex
	height         uint64
	heightErr      error
	heightFailures int
	heightCalls    int
	taskErr        error
	taskFailures   int
	tasks          map[string]chaincli.OnChainTask
	queryCalls     int
	txResult       chaincli.TxResult
	txErr          error
	txCalls        int
	txHash         []byte
	maxVerifyRound uint32
	paramsErr      error
	stage          chaincli.TaskStage
	stageErr       error
}

func (f *chainFactsFake) QueryTaskStage(context.Context, string) (chaincli.TaskStage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stageErr != nil {
		return chaincli.TaskStage{}, f.stageErr
	}
	return f.stage, nil
}

func (f *chainFactsFake) QueryMaxVerifyRound(context.Context) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paramsErr != nil {
		return 0, f.paramsErr
	}
	return f.maxVerifyRound, nil
}

func (f *chainFactsFake) QueryTx(_ context.Context, txHash []byte) (chaincli.TxResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txCalls++
	f.txHash = append([]byte(nil), txHash...)
	return f.txResult, f.txErr
}

func (f *chainFactsFake) LatestHeight(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heightCalls++
	if f.heightFailures > 0 {
		f.heightFailures--
		return 0, errors.New("temporary height query failure")
	}
	return f.height, f.heightErr
}

func (f *chainFactsFake) QueryTask(_ context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queryCalls++
	if f.taskFailures > 0 {
		f.taskFailures--
		return chaincli.OnChainTask{}, errors.New("temporary task query failure")
	}
	if f.taskErr != nil {
		return chaincli.OnChainTask{}, f.taskErr
	}
	task, ok := f.tasks[taskKey(key.SessionID, key.TaskID)]
	if !ok {
		return chaincli.OnChainTask{}, chaincli.ErrNotFound
	}
	return task, nil
}

func (f *chainFactsFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queryCalls
}

func (f *chainFactsFake) QuerySettlementBuildFacts(context.Context, chaincli.TaskKey) (chaincli.SettlementBuildFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return chaincli.SettlementBuildFacts{SnapshotHeight: f.height}, nil
}

func eventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}

func TestRefreshChainHeightPersistsAuthoritativeCursor(t *testing.T) {
	store := kv.NewMemStore()
	facts := &chainFactsFake{height: 77, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	c.kv = store
	height, err := c.refreshChainHeight(context.Background())
	if err != nil || height != 77 {
		t.Fatalf("height=%d err=%v", height, err)
	}
	raw, ok := store.Get(kv.NSChainState, chainStateKey)
	if !ok {
		t.Fatal("chain cursor not persisted")
	}
	var record chainStateRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Version != chainStateVersion || record.LastObservedHeight != 77 {
		t.Fatalf("record=%+v", record)
	}
}

func TestLoadedChainCursorIsNotAuthoritativeUntilFreshQuery(t *testing.T) {
	store := kv.NewMemStore()
	raw, err := json.Marshal(chainStateRecord{Version: chainStateVersion, LastObservedHeight: 999})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSChainState, chainStateKey, raw); err != nil {
		t.Fatal(err)
	}
	facts := &chainFactsFake{height: 77, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts))
	c.kv = store
	if err := c.loadChainState(); err != nil {
		t.Fatal(err)
	}
	if height, authoritative := c.currentChainHeight(); height != 999 || authoritative {
		t.Fatalf("loaded height=%d authoritative=%v", height, authoritative)
	}
	if height, err := c.refreshChainHeight(context.Background()); err != nil || height != 77 {
		t.Fatalf("fresh height=%d err=%v", height, err)
	}
	if height, authoritative := c.currentChainHeight(); height != 77 || !authoritative {
		t.Fatalf("refreshed height=%d authoritative=%v", height, authoritative)
	}
}

func TestRefreshChainHeightNeverReturnsBelowAuthoritativeCursor(t *testing.T) {
	facts := &chainFactsFake{height: 109, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts))
	c.onNewBlock(110)

	height, err := c.refreshChainHeight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if height != 110 {
		t.Fatalf("refreshed height=%d, want monotonic authoritative height 110", height)
	}
}

func TestResyncAndGapTriggersAreSerializedAndCoalesced(t *testing.T) {
	facts := &chainFactsFake{height: 102, tasks: map[string]chaincli.OnChainTask{
		taskKey("session-1", "task-1"): {
			SessionID: "session-1", TaskID: "task-1",
			State: types.Assigned, Winner: "worker-1",
		},
	}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)
	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired})
	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 100})
	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 102})
	eventually(t, func() bool { return facts.calls() >= 1 })
	if facts.calls() > 2 {
		t.Fatalf("coalesced triggers produced %d queries", facts.calls())
	}
}

func TestGlobalReconciliationDoesNotAdvanceCursorPastQueryFailure(t *testing.T) {
	facts := &chainFactsFake{
		height: 77, taskErr: errors.New("temporary task query failure"),
		tasks: map[string]chaincli.OnChainTask{},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	c.reconcileRetryBase = 100 * time.Millisecond
	c.reconcileRetryMax = 100 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired})
	eventually(t, func() bool { return facts.calls() == 1 })
	time.Sleep(20 * time.Millisecond)
	c.chainStateMu.RLock()
	reconciled := c.chainState.LastReconciledHeight
	c.chainStateMu.RUnlock()
	if reconciled != 0 {
		t.Fatalf("last reconciled height = %d, want 0 after task query failure", reconciled)
	}
}

func TestGlobalReconciliationRetriesHeightFailure(t *testing.T) {
	facts := &chainFactsFake{
		height: 77, heightFailures: 1,
		tasks: map[string]chaincli.OnChainTask{
			taskKey("session-1", "task-1"): {SessionID: "session-1", TaskID: "task-1", State: types.Pending},
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired})
	eventually(t, func() bool {
		facts.mu.Lock()
		heightCalls := facts.heightCalls
		facts.mu.Unlock()
		c.chainStateMu.RLock()
		reconciled := c.chainState.LastReconciledHeight
		c.chainStateMu.RUnlock()
		return heightCalls == 2 && reconciled == 77
	})
}

func TestGlobalReconciliationRetriesWholeScopeBeforeAdvancingCursor(t *testing.T) {
	facts := &chainFactsFake{
		height: 77, taskFailures: 1,
		tasks: map[string]chaincli.OnChainTask{
			taskKey("session-1", "task-1"): {SessionID: "session-1", TaskID: "task-1", State: types.Pending},
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired})
	eventually(t, func() bool {
		c.chainStateMu.RLock()
		reconciled := c.chainState.LastReconciledHeight
		c.chainStateMu.RUnlock()
		return facts.calls() == 2 && reconciled == 77
	})
}

func TestPeriodicReconciliationAtTenthBlock(t *testing.T) {
	facts := &chainFactsFake{height: 10, tasks: map[string]chaincli.OnChainTask{
		taskKey("session-1", "task-1"): {SessionID: "session-1", TaskID: "task-1", State: types.Pending},
	}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)
	for height := int64(1); height <= 10; height++ {
		c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: height})
	}
	eventually(t, func() bool { return facts.calls() == 1 })
}

func TestReconcilePendingAbandonsDeliverTxRejectionWithoutTerminalMarker(t *testing.T) {
	sessionID, taskID := "session-assign-rejected", testTaskID("task-assign-rejected")
	txHash := []byte{0x0a, 0x0b}
	facts := &chainFactsFake{
		height:   1001,
		taskErr:  chaincli.ErrNotFound,
		txResult: chaincli.TxResult{TxHash: txHash, Height: 99, Code: 7, RawLog: "session not found"},
	}
	submit := &fakeSubmitter{assignResult: chaincli.TxResult{TxHash: txHash}}
	c, _ := newTestCoordinator(t,
		WithHeightQuerier(facts),
		WithTaskQuerier(facts),
		WithTxQuerier(facts),
	)
	c.submit = submit
	order := testCurrentOrder(sessionID, taskID, testUserAddress)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		t.Fatal("task FSM was not created")
	}
	for _, worker := range []string{"worker-1", "worker-2", "worker-3"} {
		fsm.onWorkerHandraise(testWorkerHandraise(sessionID, taskID, worker))
	}
	if string(fsm.assignTxHash) != string(txHash) {
		t.Fatalf("assign tx hash = %x, want %x", fsm.assignTxHash, txHash)
	}

	c.reconcileTask(sessionID, taskID, 1001, "test", nil)
	facts.mu.Lock()
	txCalls, queriedHash := facts.txCalls, append([]byte(nil), facts.txHash...)
	facts.mu.Unlock()
	if txCalls != 1 || !bytes.Equal(queriedHash, txHash) {
		t.Fatalf("QueryTx calls=%d hash=%x, want 1/%x", txCalls, queriedHash, txHash)
	}
	if _, ok := c.getFSM(sessionID, taskID); ok {
		t.Fatal("DeliverTx-rejected task remains active")
	}
	if _, terminal := c.terminalTasks[taskKey(sessionID, taskID)]; terminal {
		t.Fatal("pre-chain rejection wrote a terminal marker")
	}
	if _, ok := c.kv.Get(kv.NSTask, taskKey(sessionID, taskID)); ok {
		t.Fatal("pre-chain rejection retained the task snapshot")
	}
	events := c.journalFor(taskKey(sessionID, taskID)).snapshot()
	if len(events) == 0 || events[len(events)-1].EventCode != EvAssignRejected {
		t.Fatalf("last event = %+v, want %s", events, EvAssignRejected)
	}
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("resubmit after pre-chain rejection: %v", err)
	}
	if _, ok := c.getFSM(sessionID, taskID); !ok {
		t.Fatal("same session sequence could not be resubmitted")
	}
}

func TestAssignTxHashPersistsAcrossRecovery(t *testing.T) {
	sessionID, taskID := "session-assign-recovery", testTaskID("task-assign-recovery")
	txHash := []byte{0x0c, 0x0d}
	submit := &fakeSubmitter{assignResult: chaincli.TxResult{TxHash: txHash}}
	c, _ := newTestCoordinator(t)
	c.submit = submit
	order := testCurrentOrder(sessionID, taskID, testUserAddress)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM(sessionID, taskID)
	for _, worker := range []string{"worker-1", "worker-2", "worker-3"} {
		fsm.onWorkerHandraise(testWorkerHandraise(sessionID, taskID, worker))
	}
	raw, ok := c.kv.Get(kv.NSTask, taskKey(sessionID, taskID))
	if !ok {
		t.Fatal("assign snapshot was not persisted")
	}
	var snapshot taskSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if string(snapshot.AssignTxHash) != string(txHash) {
		t.Fatalf("snapshot tx hash = %x, want %x", snapshot.AssignTxHash, txHash)
	}

	restored := c.newFSM(order)
	restored.restoreFrom(snapshot)
	if string(restored.assignTxHash) != string(txHash) || !restored.assignSubmitted {
		t.Fatalf("restored assign state: hash=%x submitted=%v", restored.assignTxHash, restored.assignSubmitted)
	}
}

func TestReconcileExpiresPendingAfterOrderDeadline(t *testing.T) {
	const sessionID, taskID = "session-no-workers", "task-no-workers"
	facts := &chainFactsFake{
		height: 1001,
		tasks:  map[string]chaincli.OnChainTask{},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	order := testCurrentOrder(sessionID, taskID, testUserAddress)
	order.DeadlineHeight = 1000
	order.Deadline = 1000
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	if _, err := c.refreshChainHeight(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.reconcileTask(sessionID, taskID, 0, "test", nil)
	if _, ok := c.getFSM(sessionID, taskID); ok {
		t.Fatal("expired Pending task remains active")
	}
	if _, terminal := c.terminalTasks[taskKey(sessionID, taskID)]; terminal {
		t.Fatal("pre-chain timeout wrote a terminal marker")
	}
	if _, ok := c.kv.Get(kv.NSTask, taskKey(sessionID, taskID)); ok {
		t.Fatal("pre-chain timeout retained the task snapshot")
	}
	events := c.journalFor(taskKey(sessionID, taskID)).snapshot()
	if len(events) == 0 || events[len(events)-1].EventCode != EvAssignTimeout {
		t.Fatalf("last event = %+v, want %s", events, EvAssignTimeout)
	}
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("resubmit after assign timeout: %v", err)
	}
	if _, ok := c.getFSM(sessionID, taskID); !ok {
		t.Fatal("same session sequence could not be resubmitted after timeout")
	}
}

func TestPendingDeadlineBoundaryRequestsReconciliationAfterExpiry(t *testing.T) {
	fsm := &taskFSM{
		state: types.Pending,
		order: types.Order{TaskHash: testPlaceholderTaskHash, DeadlineHeight: 100},
	}
	if fsm.lifecycleBoundaryDue(100) {
		t.Fatal("deadline height is still valid on Node")
	}
	if !fsm.lifecycleBoundaryDue(101) {
		t.Fatal("first expired height did not request reconciliation")
	}
}

// A settled task is next due at its finality height; challenge_close_height is not a boundary.
func TestSettledBoundaryIsFinalityNotChallengeClose(t *testing.T) {
	fsm := &taskFSM{
		state:      types.Settled,
		settlement: chaincli.TaskSettlementState{ChallengeCloseHeight: 100, TaskFinalityHeight: 120},
	}
	if fsm.lifecycleBoundaryDue(100) {
		t.Fatal("challenge close height requested reconciliation")
	}
	if !fsm.lifecycleBoundaryDue(120) {
		t.Fatal("finality height did not request reconciliation")
	}
}

func TestPendingTaskNotFoundBeforeDeadlineIsDebugNoise(t *testing.T) {
	const sessionID, taskID = "session-pending", "task-pending"
	facts := &chainFactsFake{height: 100, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	var logs bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := c.OnOrder(context.Background(), testCurrentOrder(sessionID, taskID, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.refreshChainHeight(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.reconcileTask(sessionID, taskID, 0, "test", nil)
	output := logs.String()
	if strings.Contains(output, "level=WARN") {
		t.Fatalf("expected Pending not-found reconciliation without WARN, logs:\n%s", output)
	}
	if !strings.Contains(output, "pending task not on chain yet") {
		t.Fatalf("missing DEBUG reconciliation context, logs:\n%s", output)
	}
}

type chainStateFailStore struct{ kv.Store }

func (s chainStateFailStore) Set(namespace kv.Namespace, key string, value []byte) error {
	if namespace == kv.NSChainState {
		return errors.New("chain state write failed")
	}
	return s.Store.Set(namespace, key, value)
}

func TestHeightPersistenceFailureNeverBecomesAuthoritative(t *testing.T) {
	facts := &chainFactsFake{height: 10, tasks: map[string]chaincli.OnChainTask{}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts))
	c.kv = chainStateFailStore{Store: kv.NewMemStore()}
	if _, err := c.refreshChainHeight(context.Background()); err == nil {
		t.Fatal("height refresh succeeded after persistence failure")
	}
	if _, authoritative := c.currentChainHeight(); authoritative {
		t.Fatal("failed height persistence became authoritative")
	}
}

// releasableSettlement is what the chain actually reports for a settled task: TaskCoreState's
// finality status and task_finality_height, plus the settlement event's heights. It carries no
// challenge_close_height, evidence_cleanup_height or optimistic finality status: no chain
// query or event provides them.
func releasableSettlement() chaincli.TaskSettlementState {
	return chaincli.TaskSettlementState{
		SettlementStatus: "FINALIZED", SettlementHeight: 90,
		FinalityStatus: "FINAL", TaskFinalityHeight: 110,
		ClaimableAfterHeight: 115,
	}
}

func TestSettlementCustodyReleaseBoundaries(t *testing.T) {
	base := releasableSettlement()
	tests := []struct {
		name   string
		height uint64
		mutate func(*chaincli.TaskSettlementState)
		want   bool
	}{
		{name: "before finality", height: 109, want: false},
		{name: "claim immature", height: 114, want: false},
		{name: "at claimable", height: 115, want: true},
		{name: "no claimable gate at finality", height: 110, mutate: func(s *chaincli.TaskSettlementState) { s.ClaimableAfterHeight = 0 }, want: true},
		{name: "pending", height: 120, mutate: func(s *chaincli.TaskSettlementState) { s.FinalityStatus = "PENDING" }, want: false},
		{name: "finality unknown", height: 120, mutate: func(s *chaincli.TaskSettlementState) { s.FinalityStatus = "" }, want: false},
		{name: "finality height missing", height: 120, mutate: func(s *chaincli.TaskSettlementState) { s.TaskFinalityHeight = 0 }, want: false},
		{name: "challenge unresolved", height: 120, mutate: func(s *chaincli.TaskSettlementState) { s.MaxChallengeResolveDeadlineHeight = 121 }, want: false},
		{name: "height unknown", height: 0, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settlement := base
			if test.mutate != nil {
				test.mutate(&settlement)
			}
			if got := settlementAllowsCustodyRelease(settlement, test.height); got != test.want {
				t.Fatalf("release=%v want=%v settlement=%+v", got, test.want, settlement)
			}
		})
	}
}

type selectionFactsFake struct {
	mu        sync.Mutex
	selection chaincli.TaskBuilderSelectionState
	err       error
	grace     uint64
	graceErr  error
	calls     int
}

type blockingSelectionFacts struct {
	selection chaincli.TaskBuilderSelectionState
	started   chan struct{}
	release   chan struct{}
}

func (f *blockingSelectionFacts) QueryTaskBuilders(context.Context, chaincli.TaskKey) (chaincli.TaskBuilderSelectionState, error) {
	close(f.started)
	<-f.release
	return f.selection, nil
}

func (f *blockingSelectionFacts) QueryEVMChainID(context.Context) (uint64, error) { return 31337, nil }

func (f *blockingSelectionFacts) QuerySettlementBuilderGraceBlocks(context.Context) (uint64, error) {
	return 2, nil
}

func (f *selectionFactsFake) QueryTaskBuilders(_ context.Context, _ chaincli.TaskKey) (chaincli.TaskBuilderSelectionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.selection, f.err
}

func (f *selectionFactsFake) QueryEVMChainID(context.Context) (uint64, error) { return 31337, nil }

func (f *selectionFactsFake) QuerySettlementBuilderGraceBlocks(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.graceErr != nil {
		return 0, f.graceErr
	}
	if f.grace == 0 {
		return 2, nil
	}
	return f.grace, nil
}

func taskBuilders(task string, builders ...string) chaincli.TaskBuilderSelectionState {
	return chaincli.TaskBuilderSelectionState{
		TaskID: task, SelectedBuilders: builders, SelectedCount: uint32(len(builders)), CreatedHeight: 200, BodyStatus: "ACTIVE",
	}
}

// Settlement ordering comes from the frozen TaskBuilders: self ranks first -> submit immediately; ordering and grace blocks land in the FSM together.
func TestReconcileSettleSelectionAppliesFrozenOrder(t *testing.T) {
	reconTask := testTaskID("reconcile-selection")
	facts := &selectionFactsFake{selection: taskBuilders(reconTask, testBuilderSelf, "builder-b"), grace: 5}
	c, _ := newTestCoordinator(t, WithBuilderSelectionQuerier(facts))
	driveToSettleReady(t, c, "session-1", reconTask, nil)
	fsm, ok := c.getFSM("session-1", reconTask)
	if !ok {
		t.Fatal("fsm not found")
	}
	c.reconcileSettleSelection(fsm)
	sub := c.submit.(*fakeSubmitter)
	if settleCount(sub) != 0 {
		t.Fatalf("settle must wait for the window, submissions=%d", settleCount(sub))
	}
	c.onNewBlock(rankRevealDeadline + 1)
	if settleCount(sub) != 1 {
		t.Fatalf("settle submissions=%d", settleCount(sub))
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if fsm.settleSelection.Stage != prepareStageSettle || fsm.settleSelection.SelectedHeight != 200 ||
		len(fsm.settleSelection.SelectedBuilders) != 2 || fsm.settleSelection.SelectedBuilders[0] != testBuilderSelf {
		t.Fatalf("selection=%+v", fsm.settleSelection)
	}
	if fsm.settleGraceBlocks != 5 {
		t.Fatalf("grace=%d", fsm.settleGraceBlocks)
	}
}

func TestReconcileSettleSelectionFailsClosed(t *testing.T) {
	failClosedTask := testTaskID("fail-closed-selection")
	tests := []struct {
		name      string
		selection chaincli.TaskBuilderSelectionState
		err       error
		graceErr  error
	}{
		{name: "query error", err: errors.New("node unavailable")},
		{name: "empty builders", selection: taskBuilders(failClosedTask)},
		{name: "invalid duplicate", selection: taskBuilders(failClosedTask, testBuilderSelf, testBuilderSelf)},
		{name: "grace params error", selection: taskBuilders(failClosedTask, testBuilderSelf), graceErr: errors.New("hub params unavailable")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := &selectionFactsFake{selection: test.selection, err: test.err, graceErr: test.graceErr}
			c, _ := newTestCoordinator(t, WithBuilderSelectionQuerier(facts))
			driveToSettleReady(t, c, "session-1", failClosedTask, nil)
			fsm, ok := c.getFSM("session-1", failClosedTask)
			if !ok {
				t.Fatal("fsm not found")
			}
			c.reconcileSettleSelection(fsm)
			if got := settleCount(c.submit.(*fakeSubmitter)); got != 0 {
				t.Fatalf("settle submissions=%d", got)
			}
			fsm.mu.Lock()
			defer fsm.mu.Unlock()
			if fsm.settleSelection.SessionID != "" {
				t.Fatalf("selection=%+v", fsm.settleSelection)
			}
		})
	}
}

func TestReconcileSettleSelectionDoesNotSubmitAfterTaskTerminates(t *testing.T) {
	terminateTask := testTaskID("terminate-selection")
	facts := &blockingSelectionFacts{
		selection: taskBuilders(terminateTask, testBuilderSelf),
		started:   make(chan struct{}), release: make(chan struct{}),
	}
	c, _ := newTestCoordinator(t, WithBuilderSelectionQuerier(facts))
	driveToSettleReady(t, c, "session-1", terminateTask, nil)
	fsm, ok := c.getFSM("session-1", terminateTask)
	if !ok {
		t.Fatal("fsm not found")
	}
	done := make(chan struct{})
	go func() {
		c.reconcileSettleSelection(fsm)
		close(done)
	}()
	<-facts.started
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: "session-1", TaskID: terminateTask, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 400,
	})
	close(facts.release)
	<-done
	if got := settleCount(c.submit.(*fakeSubmitter)); got != 0 {
		t.Fatalf("terminal task submitted settle %d times", got)
	}
	if _, exists := c.kv.Get(kv.NSTask, taskKey("session-1", "task-1")); exists {
		t.Fatal("terminal task snapshot was recreated")
	}
}
