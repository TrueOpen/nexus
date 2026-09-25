package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

func newOutputTestCoordinator(t *testing.T) (*Coordinator, outputdelivery.Manager, kv.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newOutputTestCoordinatorWithLogger(t, log)
}

func newOutputTestCoordinatorWithLogger(t *testing.T, log *slog.Logger) (*Coordinator, outputdelivery.Manager, kv.Store) {
	t.Helper()
	store := kv.NewMemStore()
	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	c := New(
		log,
		msgbus.NewStub(log, nil),
		chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log),
		store,
		testBuilderSelf,
		testChainID,
		WithOutputDelivery(outputs),
	)
	c.submit = &fakeSubmitter{}
	outputs.SetPreparedResolver(c.HasAcceptedOutput)
	outputs.SetTaskTerminal(c.IsTaskTerminal)
	if err := outputs.Start(context.Background()); err != nil {
		t.Fatalf("output delivery Start: %v", err)
	}
	if err := c.CompleteOutputRecovery(); err != nil {
		t.Fatalf("complete output recovery: %v", err)
	}
	t.Cleanup(func() { _ = outputs.Stop(context.Background()) })
	return c, outputs, store
}

func driveOutputTestToAssigned(t *testing.T, c *Coordinator, session, task, user string) {
	t.Helper()
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, user)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
		SessionID: session, TaskID: task, Winner: "worker-1", Height: 101,
	})
}

// deliverPlaintext drives the internal "plaintext delivery + accept receipt" flow.
//
// The Worker no longer hands plaintext to the Builder: OUTPUT goes over the streaming data plane,
// and the legacy whole-plaintext path (used only when task_data.output_stream is disabled) has no
// production caller of Prepare. This helper stands in via the internal seam of outputdelivery +
// FSM, to keep coverage of that path's semantics: terminal-state advance, recovery and snapshot
// isolation.
func deliverPlaintext(t *testing.T, c *Coordinator, session, task, user, text string) (types.InferReceiptSubmission, error) {
	t.Helper()
	receipt := plaintextReceipt(session, task, text)
	outputID, prepared, err := c.outputs.Prepare(outputdelivery.Submission{
		SessionID: session, TaskID: task, Recipient: user,
		OutputText: &text, OutputHash: receipt.OutputHash,
	})
	if err != nil {
		return receipt, err
	}
	if err := c.OnInferReceipt(context.Background(), receipt); err != nil {
		return receipt, err
	}
	if prepared {
		if err := c.outputs.Commit(session, task, outputID); err != nil {
			return receipt, err
		}
	}
	return receipt, nil
}

func plaintextReceipt(session, task, text string) types.InferReceiptSubmission {
	hash := sha256.Sum256([]byte(text))
	return testInferReceipt(session, task, "worker-1", hash[:])
}

type coordinatorSubscribeResult struct {
	output types.PlaintextOutput
	err    error
}

func subscribeCoordinator(ctx context.Context, c *Coordinator, session, task, requester string) <-chan coordinatorSubscribeResult {
	result := make(chan coordinatorSubscribeResult, 1)
	go func() {
		output, err := c.SubscribeOutput(ctx, session, task, requester)
		result <- coordinatorSubscribeResult{output: output, err: err}
	}()
	return result
}

// TestCoordinatorSubscribeWithoutPreparedOutputFailsFast a task that was never Prepared:
// SubscribeOutput returns OUTPUT_UNAVAILABLE immediately instead of blocking: production code has
// no caller of Prepare (interface RESERVED), so the wait would never end.
func TestCoordinatorSubscribeWithoutPreparedOutputFailsFast(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user = "session-nowait", "task-nowait", testUserAddress
	driveOutputTestToAssigned(t, c, session, task, user)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err := c.SubscribeOutput(ctx, session, task, user)
	if !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("SubscribeOutput without prepared output error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("SubscribeOutput waited %s instead of failing fast", time.Since(started))
	}
	if _, err := c.SubscribeOutput(ctx, session, task, "trueopen1other"); !errors.Is(err, outputdelivery.ErrUnauthorized) {
		t.Fatalf("non-owner error = %v", err)
	}
}

func TestCoordinatorOutputDeliveryHappyPath(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user, text = "session-output", "task-output", testUserAddress, "hello"
	driveOutputTestToAssigned(t, c, session, task, user)

	// Prepare first (so a record exists); only then does the subscription wait for Commit.
	receipt := plaintextReceipt(session, task, text)
	body := text
	outputID, prepared, err := c.outputs.Prepare(outputdelivery.Submission{
		SessionID: session, TaskID: task, Recipient: user,
		OutputText: &body, OutputHash: receipt.OutputHash,
	})
	if err != nil || !prepared {
		t.Fatalf("prepare plaintext: prepared=%v err=%v", prepared, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := subscribeCoordinator(ctx, c, session, task, user)
	if err := c.OnInferReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("infer receipt: %v", err)
	}
	if err := c.outputs.Commit(session, task, outputID); err != nil {
		t.Fatalf("commit plaintext: %v", err)
	}
	ref := receipt
	delivered := <-result
	if delivered.err != nil || delivered.output.Text != text || !bytes.Equal(delivered.output.Hash, ref.OutputHash) {
		t.Fatalf("delivered = %+v/%v", delivered.output, delivered.err)
	}
	ack, err := c.AckOutput(ctx, session, task, delivered.output.OutputID, user)
	if err != nil || !ack.Acked || ack.AlreadyAcked {
		t.Fatalf("AckOutput = %+v/%v", ack, err)
	}
	_, err = c.SubscribeOutput(ctx, session, task, user)
	if !errors.Is(err, outputdelivery.ErrAlreadyAcked) {
		t.Fatalf("Subscribe after ACK error = %v", err)
	}
}

func TestCoordinatorOutputDeliveryWithoutAndWithEmptyPlaintext(t *testing.T) {
	t.Run("receipt without plaintext", func(t *testing.T) {
		c, _, _ := newOutputTestCoordinator(t)
		const session, task, user = "session-legacy", "task-legacy", testUserAddress
		driveOutputTestToAssigned(t, c, session, task, user)
		ref := testInferReceipt(session, task, "worker-1", []byte("legacy-hash"))
		if err := c.OnInferReceipt(context.Background(), ref); err != nil {
			t.Fatalf("receipt without plaintext: %v", err)
		}
		if !c.HasAcceptedOutput(session, task, ref.OutputHash) {
			t.Fatal("infer receipt was not accepted")
		}
	})

	t.Run("explicit empty plaintext", func(t *testing.T) {
		c, _, _ := newOutputTestCoordinator(t)
		const session, task, user = "session-empty", "task-empty", testUserAddress
		driveOutputTestToAssigned(t, c, session, task, user)
		ref, err := deliverPlaintext(t, c, session, task, user, "")
		if err != nil {
			t.Fatalf("empty plaintext delivery: %v", err)
		}
		output, err := c.SubscribeOutput(context.Background(), session, task, user)
		if err != nil || output.OutputID == "" || output.Text != "" || !bytes.Equal(output.Hash, ref.OutputHash) {
			t.Fatalf("empty output = %+v/%v", output, err)
		}
	})
}

func TestCoordinatorOutputDeliveryRejectsNonOwnerSubscription(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user, text = "session-private", "task-private", testUserAddress, "private"
	driveOutputTestToAssigned(t, c, session, task, user)
	if _, err := deliverPlaintext(t, c, session, task, user, text); err != nil {
		t.Fatalf("deliver plaintext: %v", err)
	}
	if _, err := c.SubscribeOutput(context.Background(), session, task, "trueopen1other"); !errors.Is(err, outputdelivery.ErrUnauthorized) {
		t.Fatalf("non-owner error = %v", err)
	}
}

func TestCoordinatorOutputDeliveryRejectsNonOwnerAckBeforeReady(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user = "session-ack-private", "task-ack-private", testUserAddress
	driveOutputTestToAssigned(t, c, session, task, user)
	if _, err := c.AckOutput(context.Background(), session, task, "missing", "trueopen1other"); !errors.Is(err, outputdelivery.ErrUnauthorized) {
		t.Fatalf("non-owner AckOutput error = %v", err)
	}
	if _, err := c.AckOutput(context.Background(), session, task, "missing", user); !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("owner AckOutput before ready error = %v", err)
	}
}

func TestCoordinatorOutputDeliveryUnknownTaskIsNotFound(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	if _, err := c.SubscribeOutput(context.Background(), "unknown-session", "unknown-task", testUserAddress); !errors.Is(err, types.ErrTaskNotFound) {
		t.Fatalf("unknown SubscribeOutput error = %v", err)
	}
	if _, err := c.AckOutput(context.Background(), "unknown-session", "unknown-task", "output", testUserAddress); !errors.Is(err, types.ErrTaskNotFound) {
		t.Fatalf("unknown AckOutput error = %v", err)
	}
}

type failFirstCommitManager struct {
	outputdelivery.Manager
	mu     sync.Mutex
	failed bool
}

type blockingCommitManager struct {
	outputdelivery.Manager
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type readyWriteFaultStore struct {
	kv.Store
	failReady bool
}

func (s *readyWriteFaultStore) Set(ns kv.Namespace, key string, value []byte) error {
	if ns == kv.NSOutputDelivery && s.failReady {
		var record struct {
			State string `json:"state"`
		}
		if json.Unmarshal(value, &record) == nil && record.State == "READY" {
			return errors.New("injected ready write failure")
		}
	}
	return s.Store.Set(ns, key, value)
}

func (m *blockingCommitManager) Commit(sessionID, taskID, outputID string) error {
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return m.Manager.Commit(sessionID, taskID, outputID)
}

func (m *failFirstCommitManager) Commit(sessionID, taskID, outputID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.failed {
		m.failed = true
		return outputdelivery.ErrDeliveryFailure
	}
	return m.Manager.Commit(sessionID, taskID, outputID)
}

func TestCoordinatorOutputDeliveryRetriesCommitWithoutDuplicateEvent(t *testing.T) {
	c, outputs, _ := newOutputTestCoordinator(t)
	failing := &failFirstCommitManager{Manager: outputs}
	c.outputs = failing
	const session, task, user, text = "session-retry", "task-retry", testUserAddress, "retry"
	driveOutputTestToAssigned(t, c, session, task, user)
	if _, err := deliverPlaintext(t, c, session, task, user, text); !errors.Is(err, outputdelivery.ErrDeliveryFailure) {
		t.Fatalf("first delivery error = %v", err)
	}
	if _, err := deliverPlaintext(t, c, session, task, user, text); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	replay, _, cancel, err := c.TaskEvents(context.Background(), session, task, 0)
	if err != nil {
		t.Fatalf("TaskEvents: %v", err)
	}
	cancel()
	count := 0
	for _, event := range replay {
		if event.EventCode == EvInferReceiptReceived {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("OUTPUT_REF_RECEIVED count = %d", count)
	}
	delivered, err := c.SubscribeOutput(context.Background(), session, task, user)
	if err != nil || delivered.Text != text {
		t.Fatalf("SubscribeOutput = %+v/%v", delivered, err)
	}
}

func TestCoordinatorTerminalizationPreservesAcceptedPreparedOutput(t *testing.T) {
	c, outputs, _ := newOutputTestCoordinator(t)
	blocking := &blockingCommitManager{
		Manager: outputs, entered: make(chan struct{}), release: make(chan struct{}),
	}
	c.outputs = blocking
	const session, task, user, text = "session-terminal-race", "task-terminal-race", testUserAddress, "accepted before terminal"
	driveOutputTestToAssigned(t, c, session, task, user)
	result := make(chan error, 1)
	go func() {
		_, err := deliverPlaintext(t, c, session, task, user, text)
		result <- err
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("Commit was not reached")
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	close(blocking.release)
	if err := <-result; err != nil {
		t.Fatalf("deliver plaintext: %v", err)
	}
	if _, ok := c.getFSM(session, task); ok {
		t.Fatal("terminal task remains active")
	}
	delivered, err := c.SubscribeOutput(context.Background(), session, task, user)
	if err != nil || delivered.Text != text {
		t.Fatalf("SubscribeOutput = %+v/%v", delivered, err)
	}
}

func TestCoordinatorConflictingOutputRetryDoesNotReplaceCustody(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user, text = "session-conflict", "task-conflict", testUserAddress, "same plaintext"
	driveOutputTestToAssigned(t, c, session, task, user)
	first, err := deliverPlaintext(t, c, session, task, user, text)
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	// Contract §6 I3: the receipt material digest of the same Task must not be replaced by a second, different receipt.
	conflict := first
	conflict.InferReceiptHash = []byte("infer-receipt-conflict")
	if err := c.OnInferReceipt(context.Background(), conflict); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("conflicting receipt error = %v", err)
	}
	served, err := c.relay.Serve(session, task, types.AccessSealedKey)
	if err != nil {
		t.Fatalf("custody serve: %v", err)
	}
	if string(served.InferReceiptHash) != string(first.InferReceiptHash) {
		t.Fatalf("custody replaced by rejected conflict: %+v", served)
	}
}

func TestCoordinatorTerminalWithoutOutputWakesSubscriber(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user = "session-terminal", "task-terminal", testUserAddress
	driveOutputTestToAssigned(t, c, session, task, user)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := subscribeCoordinator(ctx, c, session, task, user)
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	if got := (<-result).err; !errors.Is(got, outputdelivery.ErrUnavailable) {
		t.Fatalf("terminal subscription error = %v", got)
	}
}

func TestCoordinatorTerminalTaskRemainsKnownAfterTombstoneGC(t *testing.T) {
	c1, _, store := newOutputTestCoordinator(t)
	const session, task, user = "session-terminal-known", "task-terminal-known", testUserAddress
	driveOutputTestToAssigned(t, c1, session, task, user)
	c1.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	if _, ok := store.Get(kv.NSTerminalTask, taskKey(session, task)); !ok {
		t.Fatal("durable terminal task marker missing")
	}
	if err := store.Delete(kv.NSOutputTombstone, taskKey(session, task)); err != nil {
		t.Fatalf("delete tombstone: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	replacement, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	c2 := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(replacement),
	)
	c2.query = nil
	if err := c2.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	replacement.SetPreparedResolver(c2.HasAcceptedOutput)
	replacement.SetTaskTerminal(c2.IsTaskTerminal)
	if err := replacement.Start(context.Background()); err != nil {
		t.Fatalf("replacement Start: %v", err)
	}
	t.Cleanup(func() { _ = replacement.Stop(context.Background()) })
	if err := c2.CompleteOutputRecovery(); err != nil {
		t.Fatalf("CompleteOutputRecovery: %v", err)
	}
	if _, err := c2.SubscribeOutput(context.Background(), session, task, user); !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("SubscribeOutput after tombstone GC error = %v", err)
	}
	if _, err := c2.AckOutput(context.Background(), session, task, "missing", user); !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("AckOutput after tombstone GC error = %v", err)
	}
	if _, err := c2.SubscribeOutput(context.Background(), session, task, "trueopen1other"); !errors.Is(err, outputdelivery.ErrUnauthorized) {
		t.Fatalf("non-owner SubscribeOutput after tombstone GC error = %v", err)
	}
	if _, err := c2.AckOutput(context.Background(), session, task, "missing", "trueopen1other"); !errors.Is(err, outputdelivery.ErrUnauthorized) {
		t.Fatalf("non-owner AckOutput after tombstone GC error = %v", err)
	}
}

func TestCoordinatorTerminalTaskCannotBeRecreatedByOrderReplay(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user = "session-terminal-replay", "task-terminal-replay", testUserAddress
	driveOutputTestToAssigned(t, c, session, task, user)
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, user)); err != nil {
		t.Fatalf("replayed OnOrder: %v", err)
	}
	if _, err := c.TaskStatus(context.Background(), session, task); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("TaskStatus after replay = %v", err)
	}
}

func TestCoordinatorStopWaitsForInFlightTerminalCallback(t *testing.T) {
	c, _, _ := newOutputTestCoordinator(t)
	const session, task, user = "session-stop-terminal", "task-stop-terminal", testUserAddress
	fsm := c.newFSM(testCurrentOrder(session, task, user))
	fsm.state = types.Settled
	fsm.settlement = releasableSettlement()
	entered := make(chan struct{})
	release := make(chan struct{})
	fsm.onClose = func() {
		c.removeTask(taskKey(session, task))
		close(entered)
		<-release
	}
	c.mu.Lock()
	c.tasks[taskKey(session, task)] = fsm
	c.mu.Unlock()
	fsm.mu.Lock()
	fsm.timer = fsm.afterFunc(0, func() { fsm.closeSettledAtHeight(120) })
	fsm.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("terminal callback did not start")
	}
	stopped := make(chan struct{})
	go func() {
		_ = c.Stop(context.Background())
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Coordinator.Stop returned before terminal callback completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Coordinator.Stop did not finish after terminal callback completed")
	}
}

func TestCoordinatorTerminalMarkerDominatesStaleSnapshot(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	const session, task, user = "session-terminal-stale", "task-terminal-stale", testUserAddress
	order := testCurrentOrder(session, task, user)
	raw, err := json.Marshal(taskSnapshot{
		Order: order, SessionID: session, TaskID: task, ModelID: order.ModelID,
		User: user, State: types.Assigned, Phase: types.PhaseAssignmentFinalized,
	})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := store.Set(kv.NSTask, taskKey(session, task), raw); err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}
	marker, err := json.Marshal(terminalTaskRecord{Version: 1, Recipient: user})
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}
	if err := store.Set(kv.NSTerminalTask, taskKey(session, task), marker); err != nil {
		t.Fatalf("persist marker: %v", err)
	}
	c := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID,
	)
	c.query = nil
	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if _, err := c.TaskStatus(context.Background(), session, task); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("TaskStatus error = %v", err)
	}
}

func TestCoordinatorTerminalSnapshotDominatesCoarseState(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	const session, task, user = "session-terminal-snapshot", "task-terminal-snapshot", testUserAddress
	order := testCurrentOrder(session, task, user)
	raw, err := json.Marshal(taskSnapshot{
		Order: order, SessionID: session, TaskID: task, ModelID: order.ModelID,
		User: user, State: types.Settled, Phase: types.PhaseSweepObserved, Terminal: true,
	})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := store.Set(kv.NSTask, taskKey(session, task), raw); err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}
	c := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID,
	)
	c.query = nil
	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if _, err := c.TaskStatus(context.Background(), session, task); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("TaskStatus error = %v", err)
	}
	if _, ok := store.Get(kv.NSTerminalTask, taskKey(session, task)); !ok {
		t.Fatal("terminal marker was not rebuilt from terminal snapshot")
	}
}

func TestCoordinatorDoesNotPutPlaintextInSnapshotOrEvent(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	c, _, store := newOutputTestCoordinatorWithLogger(t, log)
	const session, task, user, text = "session-no-leak", "task-no-leak", testUserAddress, "unique-plaintext-secret"
	driveOutputTestToAssigned(t, c, session, task, user)
	if _, err := deliverPlaintext(t, c, session, task, user, text); err != nil {
		t.Fatalf("deliver plaintext: %v", err)
	}
	raw, ok := store.Get(kv.NSTask, taskKey(session, task))
	if !ok {
		t.Fatal("task snapshot missing")
	}
	if bytes.Contains(raw, []byte(text)) || bytes.Contains(raw, []byte("output_text")) {
		t.Fatalf("snapshot contains plaintext: %s", raw)
	}
	replay, _, cancel, err := c.TaskEvents(context.Background(), session, task, 0)
	if err != nil {
		t.Fatalf("TaskEvents: %v", err)
	}
	cancel()
	eventsJSON, err := json.Marshal(replay)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	if bytes.Contains(eventsJSON, []byte(text)) || bytes.Contains(eventsJSON, []byte("output_text")) {
		t.Fatalf("events contain plaintext: %s", eventsJSON)
	}
	if bytes.Contains(logs.Bytes(), []byte(text)) {
		t.Fatalf("logs contain plaintext: %s", logs.Bytes())
	}
}

func TestCoordinatorRecoveryPromotesTerminalAcceptedPreparedOutputAcrossCrashBoundary(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	const session, task, user, text = "session-terminal-recovery", "task-terminal-recovery", testUserAddress, "recover me"
	ref := plaintextReceipt(session, task, text)
	id, prepared, err := outputs.Prepare(outputdelivery.Submission{
		SessionID: session, TaskID: task, Recipient: user, OutputText: &[]string{text}[0], OutputHash: ref.OutputHash,
	})
	if err != nil || !prepared {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}
	order := testCurrentOrder(session, task, user)
	snapshot := taskSnapshot{
		Order: order, InferReceipt: ref,
		SessionID: session, TaskID: task, ModelID: order.ModelID, User: user,
		State: types.Closed, OutputHash: ref.OutputHash,
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := store.Set(kv.NSTask, taskKey(session, task), raw); err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}

	c1 := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs),
	)
	c1.query = nil
	if err := c1.recoverTasks(context.Background()); err != nil {
		t.Fatalf("first recoverTasks: %v", err)
	}
	if _, ok := store.Get(kv.NSTask, taskKey(session, task)); !ok {
		t.Fatal("terminal snapshot deleted before output recovery completed")
	}

	// Simulate a second crash before outputdelivery.Start and recover again.
	outputs2, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("second outputdelivery.New: %v", err)
	}
	c2 := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs2),
	)
	c2.query = nil
	if err := c2.recoverTasks(context.Background()); err != nil {
		t.Fatalf("second recoverTasks: %v", err)
	}
	outputs2.SetPreparedResolver(c2.HasAcceptedOutput)
	outputs2.SetTaskTerminal(c2.IsTaskTerminal)
	if err := outputs2.Start(context.Background()); err != nil {
		t.Fatalf("outputs Start: %v", err)
	}
	t.Cleanup(func() { _ = outputs2.Stop(context.Background()) })
	if err := c2.CompleteOutputRecovery(); err != nil {
		t.Fatalf("CompleteOutputRecovery: %v", err)
	}
	if _, ok := store.Get(kv.NSTask, taskKey(session, task)); ok {
		t.Fatal("terminal snapshot remains after output recovery completed")
	}
	delivered, err := c2.SubscribeOutput(context.Background(), session, task, user)
	if err != nil || delivered.OutputID != id || delivered.Text != text {
		t.Fatalf("SubscribeOutput = %+v/%v", delivered, err)
	}
}

func TestCoordinatorRecoveryFailsClosedForCorruptTerminalSnapshot(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	const session, task, user, text = "session-corrupt-terminal", "task-corrupt-terminal", testUserAddress, "must survive"
	ref := plaintextReceipt(session, task, text)
	if _, prepared, err := outputs.Prepare(outputdelivery.Submission{
		SessionID: session, TaskID: task, Recipient: user,
		OutputText: &[]string{text}[0], OutputHash: ref.OutputHash,
	}); err != nil || !prepared {
		t.Fatalf("Prepare = %v/%v", prepared, err)
	}
	key := taskKey(session, task)
	marker, err := json.Marshal(terminalTaskRecord{Version: terminalTaskVersion, Recipient: user})
	if err != nil {
		t.Fatalf("marshal terminal marker: %v", err)
	}
	if err := store.Set(kv.NSTerminalTask, key, marker); err != nil {
		t.Fatalf("persist terminal marker: %v", err)
	}
	corrupt := []byte("{not-json")
	if err := store.Set(kv.NSTask, key, corrupt); err != nil {
		t.Fatalf("persist corrupt snapshot: %v", err)
	}

	c := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs),
	)
	if err := c.recoverTasks(context.Background()); err == nil {
		t.Fatal("recoverTasks succeeded with corrupt terminal snapshot")
	}
	if raw, ok := store.Get(kv.NSTask, key); !ok || !bytes.Equal(raw, corrupt) {
		t.Fatalf("corrupt terminal snapshot was modified: %q, exists=%v", raw, ok)
	}
	if _, ok := store.Get(kv.NSOutputDelivery, key); !ok {
		t.Fatal("PREPARED plaintext was deleted after failed recovery")
	}
}

func TestCoordinatorRecoveryFailsClosedForMismatchedTerminalSnapshotKey(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	const session, task, user, text = "session-mismatched-terminal", "task-mismatched-terminal", testUserAddress, "must survive mismatch"
	ref := plaintextReceipt(session, task, text)
	if _, prepared, err := outputs.Prepare(outputdelivery.Submission{
		SessionID: session, TaskID: task, Recipient: user,
		OutputText: &[]string{text}[0], OutputHash: ref.OutputHash,
	}); err != nil || !prepared {
		t.Fatalf("Prepare = %v/%v", prepared, err)
	}
	key := taskKey(session, task)
	marker, err := json.Marshal(terminalTaskRecord{Version: terminalTaskVersion, Recipient: user})
	if err != nil {
		t.Fatalf("marshal terminal marker: %v", err)
	}
	if err := store.Set(kv.NSTerminalTask, key, marker); err != nil {
		t.Fatalf("persist terminal marker: %v", err)
	}
	snapshotRaw, err := json.Marshal(taskSnapshot{
		SessionID: session, TaskID: task + "-corrupt", User: user,
		State: types.Closed, OutputHash: ref.OutputHash,
	})
	if err != nil {
		t.Fatalf("marshal mismatched snapshot: %v", err)
	}
	if err := store.Set(kv.NSTask, key, snapshotRaw); err != nil {
		t.Fatalf("persist mismatched snapshot: %v", err)
	}

	c := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs),
	)
	if err := c.recoverTasks(context.Background()); err == nil {
		t.Fatal("recoverTasks succeeded with mismatched terminal snapshot key")
	}
	if raw, ok := store.Get(kv.NSTask, key); !ok || !bytes.Equal(raw, snapshotRaw) {
		t.Fatalf("mismatched terminal snapshot was modified: %q, exists=%v", raw, ok)
	}
	if _, ok := store.Get(kv.NSOutputDelivery, key); !ok {
		t.Fatal("PREPARED plaintext was deleted after mismatched recovery")
	}
}

func TestCoordinatorRetainsSnapshotWhenTerminalPromotionFails(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := kv.NewMemStore()
	store := &readyWriteFaultStore{Store: base, failReady: true}
	newOutputs := func() outputdelivery.Manager {
		outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
			MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
			TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
		})
		if err != nil {
			t.Fatalf("outputdelivery.New: %v", err)
		}
		return outputs
	}
	outputs1 := newOutputs()
	c1 := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, testBuilderSelf, testChainID, WithOutputDelivery(outputs1),
	)
	c1.submit = &fakeSubmitter{}
	outputs1.SetPreparedResolver(c1.HasAcceptedOutput)
	outputs1.SetTaskTerminal(c1.IsTaskTerminal)
	if err := outputs1.Start(context.Background()); err != nil {
		t.Fatalf("outputs1 Start: %v", err)
	}
	if err := c1.CompleteOutputRecovery(); err != nil {
		t.Fatalf("c1 CompleteOutputRecovery: %v", err)
	}
	t.Cleanup(func() { _ = outputs1.Stop(context.Background()) })

	const session, task, user, text = "session-failed-promotion", "task-failed-promotion", testUserAddress, "survive failed promotion"
	driveOutputTestToAssigned(t, c1, session, task, user)
	if _, err := deliverPlaintext(t, c1, session, task, user, text); !errors.Is(err, outputdelivery.ErrDeliveryFailure) {
		t.Fatalf("delivery error = %v", err)
	}
	c1.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	if _, ok := base.Get(kv.NSTask, taskKey(session, task)); !ok {
		t.Fatal("snapshot deleted before output finalization succeeded")
	}

	store.failReady = false
	outputs2 := newOutputs()
	c2 := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs2),
	)
	c2.query = nil
	outputs2.SetPreparedResolver(c2.HasAcceptedOutput)
	outputs2.SetTaskTerminal(c2.IsTaskTerminal)
	if err := c2.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if err := outputs2.Start(context.Background()); err != nil {
		t.Fatalf("outputs2 Start: %v", err)
	}
	t.Cleanup(func() { _ = outputs2.Stop(context.Background()) })
	if err := c2.CompleteOutputRecovery(); err != nil {
		t.Fatalf("c2 CompleteOutputRecovery: %v", err)
	}
	delivered, err := c2.SubscribeOutput(context.Background(), session, task, user)
	if err != nil || delivered.Text != text {
		t.Fatalf("SubscribeOutput = %+v/%v", delivered, err)
	}
}

func TestCoordinatorRecoveryMarksTerminalTaskWithoutOutputUnavailable(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := kv.NewMemStore()
	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		MaxBytes: 1 << 20, PlaintextTTL: 4 * time.Hour,
		TombstoneTTL: 24 * time.Hour, SweepInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("outputdelivery.New: %v", err)
	}
	const session, task, user = "session-terminal-empty", "task-terminal-empty", testUserAddress
	order := testCurrentOrder(session, task, user)
	raw, err := json.Marshal(taskSnapshot{
		Order: order, SessionID: session, TaskID: task, ModelID: order.ModelID,
		User: user, State: types.Failed, Phase: types.PhaseSweepObserved,
	})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := store.Set(kv.NSTask, taskKey(session, task), raw); err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}
	c := New(
		log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
		relay.NewMem(log), store, "", testChainID, WithOutputDelivery(outputs),
	)
	c.query = nil
	outputs.SetPreparedResolver(c.HasAcceptedOutput)
	outputs.SetTaskTerminal(c.IsTaskTerminal)
	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if err := outputs.Start(context.Background()); err != nil {
		t.Fatalf("outputs Start: %v", err)
	}
	t.Cleanup(func() { _ = outputs.Stop(context.Background()) })
	if err := c.CompleteOutputRecovery(); err != nil {
		t.Fatalf("CompleteOutputRecovery: %v", err)
	}
	if _, err := c.SubscribeOutput(context.Background(), session, task, user); !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("SubscribeOutput error = %v", err)
	}
	if _, err := c.AckOutput(context.Background(), session, task, "missing", user); !errors.Is(err, outputdelivery.ErrUnavailable) {
		t.Fatalf("AckOutput error = %v", err)
	}
}

// Closing a task writes the terminal marker before output delivery reports the output
// finalized, so the snapshot is deleted on the first attempt instead of logging a missing marker.
func TestCoordinatorCloseWritesTerminalMarkerBeforeOutputTerminate(t *testing.T) {
	c, _, store := newOutputTestCoordinator(t)
	const session, task, user = "session-marker-order", "task-marker-order", testUserAddress
	driveOutputTestToAssigned(t, c, session, task, user)
	var logs bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 200,
	})
	if strings.Contains(logs.String(), "terminal task marker missing") {
		t.Fatalf("snapshot delete ran before the terminal marker was written:\n%s", logs.String())
	}
	if _, ok := store.Get(kv.NSTerminalTask, taskKey(session, task)); !ok {
		t.Fatal("durable terminal task marker missing")
	}
	if _, ok := store.Get(kv.NSTask, taskKey(session, task)); ok {
		t.Fatal("task snapshot retained after close")
	}
}
