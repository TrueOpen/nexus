package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestOnOrderPersistsPayloadBeforeCreatingTask(t *testing.T) {
	payloads := newCoordinatorPayloadStore(t, kv.NewMemStore(), 4)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	order := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("oversized"), 100)

	err := c.OnOrder(context.Background(), order)
	if !errors.Is(err, payloadstore.ErrTooLarge) {
		t.Fatalf("OnOrder error = %v, want ErrTooLarge", err)
	}
	if _, exists := c.getFSM(order.SessionID, order.TaskID); exists {
		t.Fatal("task was created after payload persistence failed")
	}
}

func TestLegacyPayloadAdapterMarksReadyOnlyAfterOrderAccepted(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore, err := taskdata.NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir(), backend, taskdata.Config{
		InlineMaxBytes: 1024, ChunkSizeBytes: 1024, MaxRangeBytes: 1024, MaxBlobBytes: 1024,
		SpoolReservationBytes: 4096, DiskAcceptWatermarkPercent: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := payloadstore.New(slog.New(slog.NewTextHandler(io.Discard, nil)), backend, payloadstore.Config{MaxBytes: 1024}, payloadstore.WithTaskData(taskStore))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	order := taskPayloadOrder(t, "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b", "9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c", testUserAddress, []byte("encrypted input"), 100)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	// The object is located by the full ref and resolved by index, same source as the production path.
	inputKey, err := taskStore.ResolveObject(context.Background(), order.SessionID, order.TaskID, taskdata.ObjectKindInput)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := taskStore.Metadata(context.Background(), inputKey)
	if err != nil || metadata.State != taskdata.StateReady {
		t.Fatalf("metadata = %#v, %v", metadata, err)
	}
	if _, ok := backend.Get(kv.NSPayload, order.SessionID+"|"+order.TaskID); ok {
		t.Fatal("Coordinator adapter left an NSPayload copy")
	}
}

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
			backend := kv.NewMemStore()
			payloads := newCoordinatorPayloadStore(t, backend, 1024)
			policy := &fakeOrderAdmission{err: tt.err}
			c, _ := newTestCoordinator(t, WithPayloadStore(payloads), WithOrderAdmission(policy))
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
			if _, err := payloads.Fetch(context.Background(), order.SessionID, order.TaskID, 0); err != nil {
				t.Fatalf("payload was not written after observed admission failure: %v", err)
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
	policy := &fakeOrderAdmission{result: OrderAdmissionResult{TermID: 7, Rank: 2, Proof: nodecontract.BuilderSelectionProofVersion + ":00"}}
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
	const proof = nodecontract.BuilderSelectionProofVersion + ":00"
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

func TestFetchPayloadAuthorizesTaskParticipants(t *testing.T) {
	backend := kv.NewMemStore()
	payloads := newCoordinatorPayloadStore(t, backend, 1024)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	const session, task = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	order := taskPayloadOrder(t, session, task, testUserAddress, []byte("encrypted inference input"), 100)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}

	if _, _, err := c.FetchPayload(context.Background(), session, task, "worker-1", "WORKER_INFERENCE"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pre-handraise FetchPayload error = %v, want ErrUnauthorized", err)
	}
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.workerHR["worker-1"] = &taskv1.WorkerHandraiseV1{
		Member: &taskv1.CandidateMemberRefV1{OperatorAddress: "worker-1"},
	}
	fsm.mu.Unlock()
	if _, _, err := c.FetchPayload(context.Background(), session, task, "worker-1", "WORKER_INFERENCE"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("handraiser FetchPayload error = %v, want ErrUnauthorized", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 10})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "winner-1", Height: 11})
	got, cred, err := c.FetchPayload(context.Background(), session, task, "winner-1", "WORKER_INFERENCE")
	if err != nil {
		t.Fatalf("winner FetchPayload: %v", err)
	}
	if got.Ref != order.PayloadCID || got.Hash != order.PayloadHash || string(got.Payload) != string(order.Payload) ||
		cred.Recipient != "winner-1" || cred.Usage != "WORKER_INFERENCE" {
		t.Fatalf("winner payload/credential = %+v / %+v", got, cred)
	}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: []string{"verifier-1", "verifier-2", "verifier-3"}, Height: 12,
	})
	if _, _, err := c.FetchPayload(context.Background(), session, task, "verifier-2", "VERIFIER_RECOMPUTE"); err != nil {
		t.Fatalf("verifier FetchPayload: %v", err)
	}
	if _, _, err := c.FetchPayload(context.Background(), session, task, order.User, "CHALLENGE_EVIDENCE"); err != nil {
		t.Fatalf("order user challenge FetchPayload: %v", err)
	}
	if _, _, err := c.FetchPayload(context.Background(), session, task, "verifier-2", "CHALLENGE_EVIDENCE"); err != nil {
		t.Fatalf("formal verifier challenge FetchPayload: %v", err)
	}
	if _, _, err := c.FetchPayload(context.Background(), session, task, order.User, "WORKER_INFERENCE"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("order user worker FetchPayload error = %v, want ErrUnauthorized", err)
	}
	if _, _, err := c.FetchPayload(context.Background(), session, task, "stranger", "WORKER_INFERENCE"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stranger FetchPayload error = %v, want ErrUnauthorized", err)
	}
}

func TestPayloadRemovedAtDeadlineAndTaskTerminal(t *testing.T) {
	backend := kv.NewMemStore()
	payloads := newCoordinatorPayloadStore(t, backend, 1024)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	first := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("first encrypted input"), 100)
	if err := c.OnOrder(context.Background(), first); err != nil {
		t.Fatalf("first OnOrder: %v", err)
	}
	c.onNewBlock(100)
	if _, err := payloads.Fetch(context.Background(), first.SessionID, first.TaskID, 0); !errors.Is(err, payloadstore.ErrNotFound) {
		t.Fatalf("payload after deadline error = %v, want ErrNotFound", err)
	}

	second := taskPayloadOrder(t, "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f", "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a", testUserAddress, []byte("second encrypted input"), 200)
	if err := c.OnOrder(context.Background(), second); err != nil {
		t.Fatalf("second OnOrder: %v", err)
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: second.SessionID, TaskID: second.TaskID, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_ASSIGNMENT_FAILED, Height: 150,
	})
	if _, err := payloads.Fetch(context.Background(), second.SessionID, second.TaskID, 0); !errors.Is(err, payloadstore.ErrNotFound) {
		t.Fatalf("payload after terminal error = %v, want ErrNotFound", err)
	}
}

func TestFetchPayloadHonorsLastKnownHeightWhenChainRefreshIsUnavailable(t *testing.T) {
	payloads := newCoordinatorPayloadStore(t, kv.NewMemStore(), 1024)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	order := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("encrypted input"), 100)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	fsm, _ := c.getFSM(order.SessionID, order.TaskID)
	fsm.mu.Lock()
	fsm.winner = "worker-1"
	fsm.mu.Unlock()
	c.chainStateMu.Lock()
	c.chainState.LastObservedHeight = 101
	c.heightAuthoritative = false
	c.chainStateMu.Unlock()

	if _, _, err := c.FetchPayload(context.Background(), order.SessionID, order.TaskID, "worker-1", "WORKER_INFERENCE"); !errors.Is(err, payloadstore.ErrExpired) {
		t.Fatalf("FetchPayload at persisted expired height error = %v, want ErrExpired", err)
	}
}

func TestRecoveryRemovesPayloadForTerminalSnapshot(t *testing.T) {
	c, _ := newTestCoordinator(t)
	payloads := newCoordinatorPayloadStore(t, c.kv, 1024)
	c.payloads = payloads
	order := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("encrypted input"), 100)
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
	if _, err := payloads.Fetch(context.Background(), order.SessionID, order.TaskID, 0); !errors.Is(err, payloadstore.ErrNotFound) {
		t.Fatalf("payload after terminal recovery error = %v, want ErrNotFound", err)
	}
}

func TestTerminalPayloadDeleteFailureIsRetriedFromCleanupIntent(t *testing.T) {
	base := kv.NewMemStore()
	faults := &payloadDeleteFaultStore{Store: base, remaining: 1}
	c, _ := newTestCoordinator(t)
	c.kv = faults
	payloads := newCoordinatorPayloadStore(t, faults, 1024)
	c.payloads = payloads
	order := taskPayloadOrder(t, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b", testUserAddress, []byte("encrypted input"), 100)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
		SessionID: order.SessionID, TaskID: order.TaskID, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_ASSIGNMENT_FAILED, Height: 50,
	})
	if _, err := payloads.Fetch(context.Background(), order.SessionID, order.TaskID, 0); err != nil {
		t.Fatalf("payload should remain after injected Delete failure: %v", err)
	}
	if _, ok := base.Get(kv.NSPayloadCleanup, taskKey(order.SessionID, order.TaskID)); !ok {
		t.Fatal("payload cleanup intent was not persisted")
	}

	restarted, _ := newTestCoordinator(t)
	restarted.kv = faults
	restarted.payloads = payloads
	if err := restarted.recoverTasks(context.Background()); err != nil {
		t.Fatalf("recoverTasks: %v", err)
	}
	if _, err := payloads.Fetch(context.Background(), order.SessionID, order.TaskID, 0); !errors.Is(err, payloadstore.ErrNotFound) {
		t.Fatalf("payload after cleanup retry error = %v, want ErrNotFound", err)
	}
	if _, ok := base.Get(kv.NSPayloadCleanup, taskKey(order.SessionID, order.TaskID)); ok {
		t.Fatal("payload cleanup intent remained after successful retry")
	}
}

func newCoordinatorPayloadStore(t *testing.T, backend kv.Store, maxBytes int) payloadstore.Store {
	t.Helper()
	store, err := payloadstore.New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), backend, payloadstore.Config{MaxBytes: maxBytes},
	)
	if err != nil {
		t.Fatalf("payloadstore.New: %v", err)
	}
	return store
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
	// and is independent of the order_envelope bytes; changing the envelope does not change identity (gh #42).
	order.OrderEnvelope = raw
	order.PayloadHash = envelope.PayloadHash
	order.PayloadCID = payloadstore.RefFor(payload)
	order.Payload = append([]byte(nil), payload...)
	order.Deadline = int64(deadline)
	order.DeadlineHeight = deadline
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
