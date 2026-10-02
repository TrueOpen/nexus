package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

func TestHasAcceptedOrderUsesDurableSnapshot(t *testing.T) {
	c, _ := newTestCoordinator(t)
	key := taskdata.ObjectKey{SessionID: "session-accepted", TaskID: "task-accepted", Kind: taskdata.ObjectKindInput}
	accepted, err := c.HasAcceptedOrder(context.Background(), key)
	if err != nil || accepted {
		t.Fatalf("before OnOrder = %t, %v", accepted, err)
	}
	if err := c.OnOrder(context.Background(), testCurrentOrder(key.SessionID, key.TaskID, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	accepted, err = c.HasAcceptedOrder(context.Background(), key)
	if err != nil || !accepted {
		t.Fatalf("after OnOrder = %t, %v", accepted, err)
	}
}

func TestHasTerminatedOrderRequiresDurableTerminalMarker(t *testing.T) {
	c, _ := newTestCoordinator(t)
	key := taskdata.ObjectKey{SessionID: "session-terminal", TaskID: "task-terminal", Kind: taskdata.ObjectKindInput}
	terminated, err := c.HasTerminatedOrder(context.Background(), key)
	if err != nil || terminated {
		t.Fatalf("without marker = %t, %v", terminated, err)
	}
	if err := c.kv.Set(kv.NSTerminalTask, taskKey(key.SessionID, key.TaskID), []byte(`{"terminal":true}`)); err != nil {
		t.Fatal(err)
	}
	terminated, err = c.HasTerminatedOrder(context.Background(), key)
	if err != nil || !terminated {
		t.Fatalf("with marker = %t, %v", terminated, err)
	}
}

func TestOnOrderStage1AdmissionFailureIsObserveOnly(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		code    string
		errText string
	}{
		{name: "builder not selected", err: ErrNotSelectedBuilder, code: ErrNotSelectedBuilder.Error(), errText: ErrNotSelectedBuilder.Error()},
		{name: "authority unavailable", err: ErrAdmissionUnavailable, code: ErrAdmissionUnavailable.Error(), errText: ErrAdmissionUnavailable.Error()},
		{name: "unknown validation failure", err: errors.New("unexpected validation failure"), code: "NEXUS_INGRESS_STAGE1_VALIDATION_FAILED", errText: "unexpected validation failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &fakeOrderAdmission{err: tt.err}
			c, _ := newTestCoordinator(t, WithOrderAdmission(policy))
			var logs bytes.Buffer
			c.log = slog.New(slog.NewTextHandler(&logs, nil))
			order := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("encrypted input"), 100)

			if err := c.OnOrder(context.Background(), order); err != nil {
				t.Fatalf("OnOrder: %v", err)
			}
			if policy.calls != 1 {
				t.Fatalf("admission calls=%d want=1", policy.calls)
			}
			fsm, exists := c.getFSM(order.SessionID, order.TaskID)
			if !exists {
				t.Fatal("task was not created after observed admission failure")
			}
			if fsm.order.Stage1BuilderRank != 0 || fsm.order.Stage1SelectionProof != "" {
				t.Fatalf("unverified selection was retained: rank=%d proof=%q", fsm.order.Stage1BuilderRank, fsm.order.Stage1SelectionProof)
			}
			if _, exists := c.kv.Get(kv.NSTask, taskKey(order.SessionID, order.TaskID)); !exists {
				t.Fatal("task snapshot was not written after observed admission failure")
			}
			for _, want := range []string{"stage1 order admission failed", "session_id=" + order.SessionID, "task_id=" + order.TaskID, "code=" + tt.code, tt.errText} {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("warning log %q does not contain %q", logs.String(), want)
				}
			}
		})
	}
}

func TestOnOrderStage1AdmissionAllowsNormalPath(t *testing.T) {
	policy := &fakeOrderAdmission{result: OrderAdmissionResult{TermID: 7, Rank: 2, Proof: strings.Repeat("ab", 32)}}
	c, _ := newTestCoordinator(t, WithOrderAdmission(policy))
	order := testPlaceholderOrder("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b")

	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	if policy.calls != 1 {
		t.Fatalf("admission calls=%d want=1", policy.calls)
	}
	fsm, exists := c.getFSM(order.SessionID, order.TaskID)
	if !exists {
		t.Fatal("task was not created after admission accepted")
	}
	if fsm.order.Stage1BuilderRank != 2 || fsm.order.Stage1SelectionProof != policy.result.Proof {
		t.Fatalf("admitted selection was not retained: rank=%d proof=%q", fsm.order.Stage1BuilderRank, fsm.order.Stage1SelectionProof)
	}
}

func TestOnOrderCarriesStage1SelectionIntoAssign(t *testing.T) {
	proof := strings.Repeat("ab", 32)
	policy := &fakeOrderAdmission{result: OrderAdmissionResult{TermID: 7, Rank: 2, Proof: proof}}
	c, _ := newTestCoordinator(t, WithOrderAdmission(policy))
	order := testCurrentOrder("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", testTaskID("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"), testUserAddress)

	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	fsm, ok := c.getFSM(order.SessionID, order.TaskID)
	if !ok {
		t.Fatal("task was not created")
	}
	for _, worker := range []string{"worker-1", "worker-2", "worker-3"} {
		fsm.onWorkerHandraise(testWorkerHandraise(order.SessionID, order.TaskID, worker))
	}
	sub := c.submit.(*fakeSubmitter)
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.assign) != 1 {
		t.Fatalf("assign submissions=%d want=1", len(sub.assign))
	}
	if sub.assign[0].BuilderRank != 2 || sub.assign[0].BuilderSelectionProof != proof {
		t.Fatalf("assign selection rank/proof=%d/%q want=2/%q", sub.assign[0].BuilderRank, sub.assign[0].BuilderSelectionProof, proof)
	}
}

// A task's INPUT is removed by the version its order names, even when the INPUT index points at
// another version of the same task.
func TestTerminalTaskRemovesItsInputVersion(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore, payloads := newCoordinatorTaskData(t, backend)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("tracked input"), 100)
	tracked := stageOrderInput(t, taskStore, order, []byte("tracked input"), true)
	other := order
	other.TaskHash = strings.Repeat("6f", 32)
	other = withPayload(t, other, []byte("other input"))
	otherKey := stageOrderInput(t, taskStore, other, []byte("other input"), false)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}

	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: order.SessionID, TaskID: order.TaskID, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_ASSIGNMENT_FAILED, Height: 50,
	})
	if !inputDeleted(t, taskStore, tracked) {
		t.Fatal("tracked input survived task termination")
	}
	if inputDeleted(t, taskStore, otherKey) {
		t.Fatal("termination removed another version of the input")
	}
}

func TestRecoveryRemovesInputForTerminalSnapshot(t *testing.T) {
	c, _ := newTestCoordinator(t)
	taskStore, payloads := newCoordinatorTaskData(t, c.kv)
	c.payloads = payloads
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("encrypted input"), 100)
	input := stageOrderInput(t, taskStore, order, []byte("encrypted input"), true)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}

	fsm, _ := c.getFSM(order.SessionID, order.TaskID)
	fsm.mu.Lock()
	fsm.state = types.Closed
	fsm.terminal = true
	if err := fsm.save(); err != nil {
		fsm.mu.Unlock()
		t.Fatalf("save terminal snapshot: %v", err)
	}
	fsm.mu.Unlock()
	c.mu.Lock()
	delete(c.tasks, taskKey(order.SessionID, order.TaskID))
	c.mu.Unlock()

	restarted, _ := newTestCoordinator(t)
	restarted.kv = c.kv
	restarted.payloads = payloads
	if err := restarted.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if !inputDeleted(t, taskStore, input) {
		t.Fatal("input survived terminal recovery")
	}
}

func TestTerminalPayloadDeleteFailureIsRetriedFromCleanupIntent(t *testing.T) {
	base := kv.NewMemStore()
	faults := &payloadDeleteFaultStore{Store: base, remaining: 1}
	c, _ := newTestCoordinator(t)
	c.kv = faults
	_, payloads := newCoordinatorTaskData(t, faults)
	c.payloads = payloads
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("encrypted input"), 100)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: order.SessionID, TaskID: order.TaskID, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_ASSIGNMENT_FAILED, Height: 50,
	})
	raw, ok := base.Get(kv.NSPayloadCleanup, taskKey(order.SessionID, order.TaskID))
	if !ok {
		t.Fatal("payload cleanup intent was not persisted")
	}
	var intent payloadCleanupRecord
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.TaskHash != order.TaskHash || intent.ContentHash != order.PayloadHash {
		t.Fatalf("cleanup intent = %+v, want the order's task_hash and input hash", intent)
	}

	restarted, _ := newTestCoordinator(t)
	restarted.kv = faults
	restarted.payloads = payloads
	if err := restarted.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if _, ok := base.Get(kv.NSPayloadCleanup, taskKey(order.SessionID, order.TaskID)); ok {
		t.Fatal("payload cleanup intent remained after successful retry")
	}
}

// An intent queued by an older release names no version: the retry removes what the INPUT index
// points at.
func TestCleanupIntentWithoutVersionUsesInputIndex(t *testing.T) {
	c, _ := newTestCoordinator(t)
	taskStore, payloads := newCoordinatorTaskData(t, c.kv)
	c.payloads = payloads
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("encrypted input"), 100)
	input := stageOrderInput(t, taskStore, order, []byte("encrypted input"), true)
	legacy, err := json.Marshal(map[string]any{
		"version": payloadCleanupVersion, "session_id": order.SessionID, "task_id": order.TaskID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.kv.Set(kv.NSPayloadCleanup, taskKey(order.SessionID, order.TaskID), legacy); err != nil {
		t.Fatal(err)
	}
	if err := c.retryPayloadCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !inputDeleted(t, taskStore, input) {
		t.Fatal("legacy cleanup intent did not remove the indexed input")
	}
}

const (
	testPayloadSession = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	testPayloadTask    = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
)

func newCoordinatorTaskData(t *testing.T, backend kv.Store) (*taskdata.Store, payloadstore.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	taskStore, err := taskdata.NewStore(log, t.TempDir(), backend, taskdata.Config{
		InlineMaxBytes: 1024, ChunkSizeBytes: 1024, MaxRangeBytes: 1024, MaxBlobBytes: 1024,
		SpoolReservationBytes: 4096, DiskAcceptWatermarkPercent: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := payloadstore.New(log, backend, payloadstore.Config{MaxBytes: 1024}, payloadstore.WithTaskData(taskStore))
	if err != nil {
		t.Fatal(err)
	}
	return taskStore, payloads
}

// stageOrderInput stores the order's INPUT version the way OpenTask does: prepared, and READY
// once the order is accepted.
func stageOrderInput(t *testing.T, taskStore *taskdata.Store, order types.Order, payload []byte, ready bool) taskdata.ObjectKey {
	t.Helper()
	ctx := context.Background()
	key := taskdata.ObjectKey{
		TaskHash: order.TaskHash, SessionID: order.SessionID, TaskID: order.TaskID,
		Kind: taskdata.ObjectKindInput, ContentHash: order.PayloadHash,
	}
	upload, err := taskStore.Begin(ctx, taskdata.UploadHeader{
		Key: key, SizeBytes: uint64(len(payload)), SemanticHash: key.ContentHash,
		MediaType: "application/octet-stream", RetainUntilHeight: order.DeadlineHeight,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Abort()
	if err := upload.WriteChunk(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if ready {
		if _, err := taskStore.MarkReady(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

// inputDeleted reports whether the object is gone: taskdata answers a deleted key with its tombstone.
func inputDeleted(t *testing.T, taskStore *taskdata.Store, key taskdata.ObjectKey) bool {
	t.Helper()
	metadata, err := taskStore.Metadata(context.Background(), key)
	if errors.Is(err, taskdata.ErrNotFound) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	return metadata.RetentionStatus == taskdata.RetentionDeleted
}

type fakeOrderAdmission struct {
	calls  int
	result OrderAdmissionResult
	err    error
}

func (a *fakeOrderAdmission) AdmitOrder(context.Context, types.Order) (OrderAdmissionResult, error) {
	a.calls++
	return a.result, a.err
}

func taskPayloadOrder(t *testing.T, sessionID, taskID, user string, payload []byte, deadline uint64) types.Order {
	t.Helper()
	order := testCurrentOrder(sessionID, taskID, user)
	envelope, err := nodecontract.ParseAssignmentOrderEnvelope(order.OrderEnvelope)
	if err != nil {
		t.Fatalf("parse test order envelope: %v", err)
	}
	sum := sha256.Sum256(payload)
	envelope.PayloadHash = hex.EncodeToString(sum[:])
	envelope.DeadlineHeight = deadline
	raw, err := nodecontract.CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		t.Fatalf("canonical test order envelope: %v", err)
	}
	// Here we **no longer** recompute the order digest alongside: task_hash is derived from TaskOrderV2
	// and is independent of the order_envelope bytes; changing the envelope does not change identity.
	order.OrderEnvelope = raw
	order.PayloadHash = envelope.PayloadHash
	order.PayloadCID = payloadstore.RefFor(payload)
	order.Deadline = int64(deadline)
	order.DeadlineHeight = deadline
	return order
}

// withPayload points the order at another input: its envelope payload hash, payload hash and ref.
func withPayload(t *testing.T, order types.Order, payload []byte) types.Order {
	t.Helper()
	envelope, err := nodecontract.ParseAssignmentOrderEnvelope(order.OrderEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	envelope.PayloadHash = hex.EncodeToString(sum[:])
	raw, err := nodecontract.CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	order.OrderEnvelope = raw
	order.PayloadHash = envelope.PayloadHash
	order.PayloadCID = payloadstore.RefFor(payload)
	return order
}

type payloadDeleteFaultStore struct {
	kv.Store
	remaining int
}

func (s *payloadDeleteFaultStore) Delete(ns kv.Namespace, key string) error {
	if ns == kv.NSPayload && s.remaining > 0 {
		s.remaining--
		return errors.New("injected payload delete failure")
	}
	return s.Store.Delete(ns, key)
}
