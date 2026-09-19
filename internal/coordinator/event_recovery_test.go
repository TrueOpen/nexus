package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

type recordTaskEventTracker struct {
	chaincli.Client

	mu        sync.Mutex
	tracked   []chaincli.TaskKey
	untracked []chaincli.TaskKey
}

func (t *recordTaskEventTracker) TrackTaskEvents(key chaincli.TaskKey) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked = append(t.tracked, key)
	return nil
}

func (t *recordTaskEventTracker) UntrackTaskEvents(key chaincli.TaskKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.untracked = append(t.untracked, key)
}

func (t *recordTaskEventTracker) counts() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tracked), len(t.untracked)
}

func newTaskTrackingCoordinator(t *testing.T, store kv.Store) (*Coordinator, *recordTaskEventTracker) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := &recordTaskEventTracker{Client: chaincli.NewStub(log, config.ChainConfig{})}
	c := New(log, msgbus.NewStub(log, nil), tracker, relay.NewMem(log), store, "", testChainID)
	c.submit = &fakeSubmitter{}
	return c, tracker
}

func TestTaskEventTrackingLifecycle(t *testing.T) {
	c, tracker := newTaskTrackingCoordinator(t, kv.NewMemStore())
	first := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnOrder(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := c.OnOrder(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if tracked, untracked := tracker.counts(); tracked != 1 || untracked != 0 {
		t.Fatalf("after duplicate order: tracked=%d untracked=%d", tracked, untracked)
	}
	c.removeTask(taskKey(first.SessionID, first.TaskID))
	if tracked, untracked := tracker.counts(); tracked != 1 || untracked != 1 {
		t.Fatalf("after terminal removal: tracked=%d untracked=%d", tracked, untracked)
	}

	second := testPlaceholderOrder("session-1", "task-2")
	if err := c.OnOrder(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(second.SessionID, second.TaskID)
	if !ok {
		t.Fatal("second task was not published")
	}
	c.abandonTask(taskKey(second.SessionID, second.TaskID), fsm)
	if tracked, untracked := tracker.counts(); tracked != 2 || untracked != 2 {
		t.Fatalf("after abandonment: tracked=%d untracked=%d", tracked, untracked)
	}
}

func TestIncompleteChainEventReconcilesFromQueryTask(t *testing.T) {
	querier := &recordTaskQuerier{height: 55, task: chaincli.OnChainTask{
		SessionID: "session-1", TaskID: "task-1", State: types.Verifying,
		Winner: "worker-1", Verifiers: []string{"verifier-1", "verifier-2", "verifier-3"},
		Deadlines: types.Deadlines{Commit: 60, WorkerReveal: 70, Reveal: 80, Verify: 90},
	}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventOpenVerifyAccepted, SessionID: "session-1", TaskID: "task-1", Height: 55,
	})

	fsm, _ := c.getFSM("session-1", "task-1")
	eventually(t, func() bool {
		calls, key := querier.snapshot()
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return calls == 1 && key.SessionID == "session-1" && key.TaskID == "task-1" &&
			fsm.state == types.Verifying && fsm.winner == "worker-1" && len(fsm.verifiers) == 3 && fsm.deadlines.Verify == 90
	})
}

func TestNewBlockHeightGapReconcilesActiveTasks(t *testing.T) {
	querier := &recordTaskQuerier{height: 103, task: chaincli.OnChainTask{
		SessionID: "session-1", TaskID: "task-1", State: types.Assigned, Winner: "worker-1",
	}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 101})
	if calls, _ := querier.snapshot(); calls != 0 {
		t.Fatalf("first heartbeat queries=%d", calls)
	}
	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 103})
	fsm, _ := c.getFSM("session-1", "task-1")
	eventually(t, func() bool {
		calls, _ := querier.snapshot()
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return calls == 1 && fsm.state == types.Assigned && fsm.winner == "worker-1"
	})
}

func TestApplicationEventWithoutTaskKeyReconcilesAllActiveTasks(t *testing.T) {
	settlement := chaincli.TaskSettlementState{
		SettlementID: "settlement-1", SettlementMode: "OPTIMISTIC",
		SettlementStatus: "SETTLED_PASS", SettlementHeight: 390,
		ChallengeCloseHeight: 500, EvidenceCleanupHeight: 600,
		OptimisticFinalityStatus: "PENDING", TaskFinalityHeight: 600,
	}
	querier := &recordTaskQuerier{height: 400, task: chaincli.OnChainTask{
		SessionID: "session-1", TaskID: "task-1", State: types.Settled,
		TaskVerdict: types.VerdictPass, Settlement: settlement,
	}}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventSettleAccepted, Height: 400})
	fsm, _ := c.getFSM("session-1", "task-1")
	eventually(t, func() bool {
		calls, _ := querier.snapshot()
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return calls == 1 && fsm.state == types.Settled && fsm.verdict == types.VerdictPass && fsm.settlement == settlement
	})
}

type scopedTaskQuerier struct {
	mu                 sync.Mutex
	calls              []chaincli.TaskKey
	started            chan chaincli.TaskKey
	release            <-chan struct{}
	height             uint64
	heightErr          error
	task               chaincli.OnChainTask
	tasks              []chaincli.OnChainTask
	failures           int
	queryErrs          []error
	settlementFacts    chaincli.SettlementBuildFacts
	settlementFailures int
	settlementCalls    int
}

func (q *scopedTaskQuerier) LatestHeight(context.Context) (uint64, error) {
	return q.height, q.heightErr
}

func (q *scopedTaskQuerier) QueryTask(ctx context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	q.mu.Lock()
	q.calls = append(q.calls, key)
	if len(q.queryErrs) > 0 {
		err := q.queryErrs[0]
		q.queryErrs = q.queryErrs[1:]
		q.mu.Unlock()
		return chaincli.OnChainTask{}, err
	}
	if q.failures > 0 {
		q.failures--
		q.mu.Unlock()
		return chaincli.OnChainTask{}, errors.New("temporary task query failure")
	}
	if len(q.tasks) > 0 {
		task := q.tasks[0]
		q.tasks = q.tasks[1:]
		q.mu.Unlock()
		return task, nil
	}
	q.mu.Unlock()
	select {
	case q.started <- key:
	default:
	}
	if q.release != nil {
		select {
		case <-q.release:
		case <-ctx.Done():
			return chaincli.OnChainTask{}, ctx.Err()
		}
	}
	if q.task.SessionID != "" {
		return q.task, nil
	}
	return chaincli.OnChainTask{SessionID: key.SessionID, TaskID: key.TaskID, State: types.Verifying}, nil
}

func (q *scopedTaskQuerier) snapshotCalls() []chaincli.TaskKey {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]chaincli.TaskKey(nil), q.calls...)
}

func (q *scopedTaskQuerier) QuerySettlementBuildFacts(_ context.Context, key chaincli.TaskKey) (chaincli.SettlementBuildFacts, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.settlementCalls++
	if q.settlementFailures > 0 {
		q.settlementFailures--
		return chaincli.SettlementBuildFacts{}, errors.New("temporary settlement facts failure")
	}
	facts := q.settlementFacts
	if facts.SnapshotHeight == 0 {
		facts.SnapshotHeight = q.height
	}
	return facts, nil
}

func TestTaskNotificationQueriesAuthoritativeState(t *testing.T) {
	release := make(chan struct{})
	querier := &scopedTaskQuerier{
		height: 88, started: make(chan chaincli.TaskKey, 4), release: release,
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight: 88, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 87,
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	for _, taskID := range []string{"task-1", "task-2"} {
		if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", taskID)); err != nil {
			t.Fatal(err)
		}
	}
	target, _ := c.getFSM("session-1", "task-1")
	target.mu.Lock()
	target.state = types.Verifying
	target.phase = types.PhaseOpenVerify
	target.workerRevealed = false
	target.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventWorkerRevealAccepted, SessionID: "session-1", TaskID: "task-1",
		Height: 88, TaskNotification: true,
	})
	select {
	case key := <-querier.started:
		if key.SessionID != "session-1" || key.TaskID != "task-1" {
			t.Fatalf("first query key = %+v", key)
		}
	case <-time.After(time.Second):
		t.Fatal("task notification did not query authoritative task state")
	}
	target.mu.Lock()
	workerRevealed := target.workerRevealed
	target.mu.Unlock()
	if workerRevealed {
		t.Fatal("task notification mutated the FSM before QueryTask completed")
	}
	close(release)
	eventually(t, func() bool {
		target.mu.Lock()
		defer target.mu.Unlock()
		return target.workerRevealed
	})
	if calls := querier.snapshotCalls(); len(calls) != 1 || calls[0].TaskID != "task-1" {
		t.Fatalf("task notification queries = %+v", calls)
	}
	events := c.journalFor(taskKey("session-1", "task-1")).snapshot()
	last := events[len(events)-1]
	if last.EventCode != EvWorkerRevealAccepted || last.ChainHeight != 87 {
		t.Fatalf("last event = %+v, want authoritative worker reveal at height 87", last)
	}
}

func TestTaskNotificationAppliesFullResultRevealAfterQuery(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 91, started: make(chan chaincli.TaskKey, 1),
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight:    91,
			FullResultReveals: []chaincli.FullResultRevealFact{{Verifier: "verifier-3", AcceptedHeight: 90}},
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.phase = types.PhaseOpenVerify
	fsm.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventFullResultRevealAccepted, SessionID: "session-1", TaskID: "task-1",
		Height: 91, Attrs: map[string]string{"verifier_operator_address": "verifier-3"}, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return fsm.fullReveals["verifier-3"]
	})
	events := c.journalFor(taskKey("session-1", "task-1")).snapshot()
	last := events[len(events)-1]
	if last.EventCode != EvFullResultRevealAccepted || last.ChainHeight != 90 {
		t.Fatalf("last event = %+v, want authoritative full reveal at height 90", last)
	}
}

func TestSessionResyncRestoresRevealFactsWithoutOriginalEvent(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 95,
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight: 95, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 92,
			FullResultReveals: []chaincli.FullResultRevealFact{{Verifier: "verifier-2", AcceptedHeight: 93}},
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.phase = types.PhaseOpenVerify
	fsm.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired, SessionID: "session-1"})
	eventually(t, func() bool {
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return fsm.workerRevealed && fsm.fullReveals["verifier-2"]
	})
}

func TestSettlementFactsApplyInAcceptedHeightOrder(t *testing.T) {
	c, _ := newTestCoordinator(t)
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.winner = "worker-1"
	fsm.verifiers = []string{"verifier-1", "verifier-2", "verifier-3"}
	fsm.mu.Unlock()

	err := fsm.reconcileSettlementFacts(chaincli.SettlementBuildFacts{
		SnapshotHeight: 95, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 94,
		FullResultReveals: []chaincli.FullResultRevealFact{{Verifier: "verifier-2", AcceptedHeight: 93}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	fsm.mu.Lock()
	phase := fsm.phase
	fsm.mu.Unlock()
	if phase != types.PhaseWorkerReveal {
		t.Fatalf("phase = %v, want worker reveal from latest accepted fact", phase)
	}
	events := c.journalFor(taskKey("session-1", "task-1")).snapshot()
	if len(events) < 2 || events[len(events)-2].ChainHeight != 93 || events[len(events)-1].ChainHeight != 94 {
		t.Fatalf("reveal events are not ordered by accepted height: %+v", events)
	}
}

func TestSettlementFactsValidationIsAtomic(t *testing.T) {
	c, _ := newTestCoordinator(t)
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.winner = "worker-1"
	fsm.verifiers = []string{"verifier-1", "verifier-2", "verifier-3"}
	fsm.mu.Unlock()
	before := len(c.journalFor(taskKey("session-1", "task-1")).snapshot())

	err := fsm.reconcileSettlementFacts(chaincli.SettlementBuildFacts{
		SnapshotHeight: 95, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 92,
		FullResultReveals: []chaincli.FullResultRevealFact{{Verifier: "unknown-verifier", AcceptedHeight: 93}},
	}, false)
	if err == nil {
		t.Fatal("expected invalid verifier fact to fail")
	}
	fsm.mu.Lock()
	workerRevealed := fsm.workerRevealed
	fsm.mu.Unlock()
	after := len(c.journalFor(taskKey("session-1", "task-1")).snapshot())
	if workerRevealed || after != before {
		t.Fatalf("invalid facts partially applied: worker_revealed=%v events=%d->%d", workerRevealed, before, after)
	}
}

func TestTaskReconciliationUsesAuthoritativeStageHeights(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 99,
		task: chaincli.OnChainTask{
			SessionID: "session-1", TaskID: "task-1", State: types.Verifying, Winner: "worker-1",
			SampleSeed: []byte("sample-seed"), Verifiers: []string{"verifier-1", "verifier-2", "verifier-3"},
			Assignment: chaincli.TaskAssignmentState{
				AssignAcceptHeight: 10, AssignmentRandomnessHeight: 11, WinnerConfirmHeight: 11,
			},
			VerifierAssignment: chaincli.VerifierAssignmentState{OpenVerifyHeight: 12, SampleSeedReadyHeight: 13},
		},
		settlementFacts: chaincli.SettlementBuildFacts{SnapshotHeight: 99},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventTaskStateChanged, EventCode: "FUTURE_TASK_STATE_CHANGED",
		SessionID: "session-1", TaskID: "task-1", Height: 99, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm, ok := c.getFSM("session-1", "task-1")
		if !ok {
			return false
		}
		fsm.mu.Lock()
		ready := fsm.state == types.Verifying && len(fsm.sampleSeed) > 0
		fsm.mu.Unlock()
		return ready
	})
	wantHeights := map[string]int64{
		EvAssignAccepted: 10, EvAssignmentFinalized: 11, EvOpenVerifyAccepted: 12, EvSampleReady: 13,
	}
	for _, event := range c.journalFor(taskKey("session-1", "task-1")).snapshot() {
		if want, ok := wantHeights[event.EventCode]; ok {
			if event.ChainHeight != want {
				t.Fatalf("%s height = %d, want %d", event.EventCode, event.ChainHeight, want)
			}
			delete(wantHeights, event.EventCode)
		}
	}
	if len(wantHeights) != 0 {
		t.Fatalf("missing stage events: %+v", wantHeights)
	}
}

func TestTaskNotificationRetriesTransientQueryFailure(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 88, failures: 1,
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight: 88, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 88,
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventWorkerRevealAccepted, SessionID: "session-1", TaskID: "task-1",
		Height: 88, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm.mu.Lock()
		revealed := fsm.workerRevealed
		fsm.mu.Unlock()
		return revealed && len(querier.snapshotCalls()) == 2
	})
}

func TestTaskNotificationRetriesSettlementFactsFailure(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 88, settlementFailures: 1,
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight: 88, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 88,
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM("session-1", "task-1")
	fsm.mu.Lock()
	fsm.state = types.Verifying
	fsm.mu.Unlock()
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventWorkerRevealAccepted, SessionID: "session-1", TaskID: "task-1",
		Height: 88, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm.mu.Lock()
		revealed := fsm.workerRevealed
		fsm.mu.Unlock()
		querier.mu.Lock()
		settlementCalls := querier.settlementCalls
		querier.mu.Unlock()
		return revealed && settlementCalls == 2
	})
}

func TestTaskNotificationRetriesTemporaryNotFound(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 88, queryErrs: []error{chaincli.ErrNotFound},
		task: chaincli.OnChainTask{
			SessionID: "session-1", TaskID: "task-1", State: types.Assigned, Winner: "worker-1",
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventAssignAccepted, SessionID: "session-1", TaskID: "task-1",
		Height: 88, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm, ok := c.getFSM("session-1", "task-1")
		if !ok {
			return false
		}
		fsm.mu.Lock()
		assigned := fsm.state == types.Assigned && fsm.winner == "worker-1"
		fsm.mu.Unlock()
		return assigned && len(querier.snapshotCalls()) == 2
	})
}

func TestTaskNotificationRetriesStaleSnapshot(t *testing.T) {
	querier := &scopedTaskQuerier{
		height: 88,
		tasks: []chaincli.OnChainTask{
			{SessionID: "session-1", TaskID: "task-1", State: types.Pending},
			{SessionID: "session-1", TaskID: "task-1", State: types.Assigned, Winner: "worker-1"},
		},
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventAssignmentFinalized, EventCode: "ASSIGNMENT_FINALIZED",
		SessionID: "session-1", TaskID: "task-1", Height: 88, TaskNotification: true,
	})
	eventually(t, func() bool {
		fsm, ok := c.getFSM("session-1", "task-1")
		if !ok {
			return false
		}
		fsm.mu.Lock()
		assigned := fsm.state == types.Assigned && fsm.winner == "worker-1"
		fsm.mu.Unlock()
		return assigned && len(querier.snapshotCalls()) == 2
	})
}

func TestAuthoritativeFailedTaskIsClosedAndUntracked(t *testing.T) {
	store := kv.NewMemStore()
	c, tracker := newTaskTrackingCoordinator(t, store)
	querier := &scopedTaskQuerier{
		height: 102,
		task: chaincli.OnChainTask{
			SessionID: "session-1", TaskID: "task-1", State: types.Failed,
			TaskVerdict: types.VerdictWorkerTimeout, FailureClass: "WORKER_TIMEOUT",
		},
	}
	c.query = querier
	c.height = querier
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventTaskStateChanged, EventCode: "WORKER_TIMEOUT",
		SessionID: "session-1", TaskID: "task-1", Height: 102, TaskNotification: true,
	})
	eventually(t, func() bool {
		_, active := c.getFSM("session-1", "task-1")
		c.mu.RLock()
		_, terminal := c.terminalTasks[taskKey("session-1", "task-1")]
		c.mu.RUnlock()
		_, untracked := tracker.counts()
		return !active && terminal && untracked == 1
	})
}

type flakyBuilderRegistry struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (r *flakyBuilderRegistry) QueryBuilder(context.Context, string) (chaincli.BuilderState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failures > 0 {
		r.failures--
		return chaincli.BuilderState{}, errors.New("temporary builder query failure")
	}
	return chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "ACTIVE"}, nil
}

func (r *flakyBuilderRegistry) LatestHeight(context.Context) (uint64, error) { return 77, nil }

func (r *flakyBuilderRegistry) QueryBuilderSetAtHeight(context.Context, uint64) (chaincli.BuilderSet, error) {
	return chaincli.BuilderSet{Epoch: 7, BuilderSetID: "7", BodyStatus: "ACTIVE", ActiveBuilderCount: 1,
		SetHash: strings.Repeat("ab", 32),
		Members: []types.BuilderRef{{Address: testBuilderSelf, Rank: 1}}}, nil
}

func (r *flakyBuilderRegistry) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestBuilderSetNotificationRetriesTransientQueryFailure(t *testing.T) {
	registry := &flakyBuilderRegistry{failures: 1}
	c, _ := newTestCoordinator(t, WithBuilderRegistry(registry))
	c.reconcileRetryBase = time.Millisecond
	c.reconcileRetryMax = 5 * time.Millisecond
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)

	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderSetUpdated, Height: 77})
	eventually(t, func() bool { return registry.callCount() == 2 && c.active.Epoch() == 7 })
}

func TestTaskNotificationQueriesWhenHeightUnavailable(t *testing.T) {
	querier := &scopedTaskQuerier{
		heightErr: errors.New("latest height unavailable"),
		started:   make(chan chaincli.TaskKey, 1),
	}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)
	c.OnChainEvent(chaincli.ChainEvent{
		Type: chaincli.EventTaskStateChanged, SessionID: "session-1", TaskID: "task-1",
		Height: 88, TaskNotification: true,
	})
	select {
	case key := <-querier.started:
		if key.SessionID != "session-1" || key.TaskID != "task-1" {
			t.Fatalf("query key = %+v", key)
		}
	case <-time.After(time.Second):
		t.Fatal("height failure suppressed authoritative task query")
	}
}

func TestSessionResyncIsScoped(t *testing.T) {
	querier := &scopedTaskQuerier{height: 99, started: make(chan chaincli.TaskKey, 4)}
	c, _ := newTestCoordinator(t, WithHeightQuerier(querier), WithTaskQuerier(querier))
	orders := []types.Order{
		testPlaceholderOrder("session-1", "task-1"),
		testPlaceholderOrder("session-1", "task-2"),
		testPlaceholderOrder("session-2", "task-3"),
	}
	for _, order := range orders {
		if err := c.OnOrder(context.Background(), order); err != nil {
			t.Fatal(err)
		}
	}
	c.startReconcileWorker()
	t.Cleanup(c.stopReconcileWorker)
	c.OnChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired, SessionID: "session-1"})

	eventually(t, func() bool { return len(querier.snapshotCalls()) >= 2 })
	time.Sleep(100 * time.Millisecond)
	calls := querier.snapshotCalls()
	if len(calls) != 2 {
		t.Fatalf("session resync queries = %+v", calls)
	}
	for _, key := range calls {
		if key.SessionID != "session-1" {
			t.Fatalf("session resync queried out-of-scope task %+v", key)
		}
	}
}

func TestProtocolEventSource(t *testing.T) {
	protocolEvents := make(chan chaincli.ChainEvent, 1)
	registry := &fakeBuilderRegistry{
		builder: chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "ACTIVE"},
		height:  77,
		set: chaincli.BuilderSet{Epoch: 7, BuilderSetID: "7", BodyStatus: "ACTIVE", ActiveBuilderCount: 1,
			SetHash: strings.Repeat("ab", 32), Members: []types.BuilderRef{
				{Address: testBuilderSelf, Rank: 1},
			}},
	}
	c, _ := newTestCoordinator(t,
		WithBuilderRegistry(registry),
		WithProtocolEventSource(protocolEvents),
	)
	c.startReconcileWorker()
	done := make(chan struct{})
	go func() {
		c.eventLoop()
		close(done)
	}()
	protocolEvents <- chaincli.ChainEvent{Type: chaincli.EventBuilderSetUpdated, Height: 77}
	eventually(t, func() bool { return c.active.Epoch() == 7 })
	close(protocolEvents)

	select {
	case <-done:
		t.Fatal("event loop stopped when only the protocol source closed")
	case <-time.After(50 * time.Millisecond):
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event loop did not stop with the coordinator")
	}
}

type recordTaskQuerier struct {
	mu     sync.Mutex
	calls  int
	key    chaincli.TaskKey
	task   chaincli.OnChainTask
	err    error
	height uint64
}

func (q *recordTaskQuerier) LatestHeight(context.Context) (uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.height, nil
}

func (q *recordTaskQuerier) QueryTask(_ context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls++
	q.key = key
	return q.task, q.err
}

func (q *recordTaskQuerier) QuerySettlementBuildFacts(context.Context, chaincli.TaskKey) (chaincli.SettlementBuildFacts, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return chaincli.SettlementBuildFacts{SnapshotHeight: q.height}, nil
}

func (q *recordTaskQuerier) snapshot() (int, chaincli.TaskKey) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.calls, q.key
}
