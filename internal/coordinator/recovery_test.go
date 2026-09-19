package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"testing"

	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

type taskScanFailStore struct{ kv.Store }

func (s taskScanFailStore) Scan(ns kv.Namespace, fn func(string, []byte) bool) error {
	if ns == kv.NSTask {
		return errors.New("injected task scan failure")
	}
	return s.Store.Scan(ns, fn)
}

// newRecoveryCoordinator builds a coordinator + KV escrow on a shared pebble store (simulating the same data directory).
func newRecoveryCoordinator(t *testing.T, store kv.Store, opts ...Option) (*Coordinator, *fakeSubmitter, relay.Custodian) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewKV(log, store)
	if err := rl.Start(context.Background()); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	t.Cleanup(func() { _ = rl.Stop(context.Background()) })
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), rl, store, testBuilderSelf, testChainID, opts...)
	sub := &fakeSubmitter{}
	c.submit = sub
	return c, sub, rl
}

func TestCoordinatorStartFailsWhenTaskScanFails(t *testing.T) {
	store := taskScanFailStore{Store: kv.NewMemStore()}
	c, _, _ := newRecoveryCoordinator(t, store)
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded after task snapshot scan failure")
	}
}

func TestRecoveryTracksActiveTaskEvents(t *testing.T) {
	store := kv.NewMemStore()
	snapshot := taskSnapshot{
		Version: 2, SessionID: "session-recovered", TaskID: "task-recovered",
		ModelID: "model", PayloadCID: "cid", State: types.Pending,
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSTask, taskKey(snapshot.SessionID, snapshot.TaskID), raw); err != nil {
		t.Fatal(err)
	}
	c, tracker := newTaskTrackingCoordinator(t, store)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if tracked, untracked := tracker.counts(); tracked != 1 || untracked != 0 {
		t.Fatalf("recovered tracking: tracked=%d untracked=%d", tracked, untracked)
	}
}

func TestRecoveryRestoresAuthoritativeRevealFacts(t *testing.T) {
	store := kv.NewMemStore()
	snapshot := taskSnapshot{
		Version: 2, SessionID: "session-recovered", TaskID: "task-recovered",
		ModelID: "model", PayloadCID: "cid", State: types.Verifying, Phase: types.PhaseOpenVerify,
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSTask, taskKey(snapshot.SessionID, snapshot.TaskID), raw); err != nil {
		t.Fatal(err)
	}
	querier := &scopedTaskQuerier{
		height: 95,
		task: chaincli.OnChainTask{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, State: types.Verifying,
		},
		settlementFacts: chaincli.SettlementBuildFacts{
			SnapshotHeight: 95, HasWorkerRevealReceipt: true, Worker: "worker-1", WorkerRevealAcceptedHeight: 92,
			FullResultReveals: []chaincli.FullResultRevealFact{{Verifier: "verifier-2", AcceptedHeight: 93}},
		},
	}
	c, _, _ := newRecoveryCoordinator(t, store, WithTaskQuerier(querier))

	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatal(err)
	}
	fsm, ok := c.getFSM(snapshot.SessionID, snapshot.TaskID)
	if !ok {
		t.Fatal("recovered FSM missing")
	}
	fsm.mu.Lock()
	workerRevealed := fsm.workerRevealed
	fullRevealed := fsm.fullReveals["verifier-2"]
	fsm.mu.Unlock()
	if !workerRevealed || !fullRevealed {
		t.Fatalf("authoritative reveals not restored: worker=%v full=%v", workerRevealed, fullRevealed)
	}
}

// TestRecoveryResumesInFlightTask after crash-restart: state/event history restored, escrow retrievable, can advance to settlement.
func TestRecoveryResumesInFlightTask(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	session, task, user := "sess-rec", testTaskID("task-rec"), testUserAddress
	ctx := context.Background()

	// First process: advance to Verifying, then "crash" (no graceful shutdown, close the store directly).
	store1, err := kv.NewPebble(dir, log)
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	c1, _, _ := newRecoveryCoordinator(t, store1)
	driveToVerifying(t, c1, session, task, user, []string{"verifier-1", "verifier-2", "verifier-3"})
	fsm1, ok := c1.getFSM(session, task)
	if !ok {
		t.Fatal("first coordinator fsm missing")
	}
	fsm1.mu.Lock()
	fsm1.settleSelection = settleSelection(session, task, testBuilderSelf)
	fsm1.settleGraceBlocks = rankGraceBlocks
	if err := fsm1.save(); err != nil {
		fsm1.mu.Unlock()
		t.Fatalf("persist settle selection: %v", err)
	}
	fsm1.mu.Unlock()
	if err := store1.Close(); err != nil {
		t.Fatalf("close store1: %v", err)
	}

	// Second process: restart on the same data directory.
	store2, err := kv.NewPebble(dir, log)
	if err != nil {
		t.Fatalf("reopen pebble: %v", err)
	}
	t.Cleanup(func() { _ = store2.Close() })
	c2, sub2, _ := newRecoveryCoordinator(t, store2)
	if err := c2.Start(ctx); err != nil {
		t.Fatalf("c2 start: %v", err)
	}
	t.Cleanup(func() { _ = c2.Stop(ctx) })

	// State and sub-state restored.
	st, err := c2.TaskStatus(ctx, session, task)
	if err != nil || st.State != "VERIFYING" || st.TaskPhase != "OPEN_VERIFY" {
		t.Fatalf("recovered status = %+v (%v), want VERIFYING/OPEN_VERIFY", st, err)
	}

	// Event history restored with continuous cursor semantics: original 5 entries + TASK_RECOVERED at seq 6.
	replay, _, cancel, err := c2.TaskEvents(ctx, session, task, 0)
	if err != nil {
		t.Fatalf("TaskEvents: %v", err)
	}
	defer cancel()
	if len(replay) != 6 || replay[4].EventCode != EvOpenVerifyAccepted ||
		replay[5].EventCode != EvTaskRecovered || replay[5].Seq != 6 {
		t.Fatalf("recovered events = %+v", replay)
	}

	// Escrow restored: the selected Verifier can still fetch the binding credential (the contract dropped OutputRef, so no reference is returned).
	cred, err := c2.FetchOutputRef(ctx, session, task, "verifier-1", types.AccessSealedKey, "VERIFIER_FETCH")
	if err != nil || cred.ID == "" {
		t.Fatalf("custody not restored: cred=%+v err=%v", cred, err)
	}

	// Keep advancing: W_i reveal + two consistent V_i -> the new process submits SettleTx.
	c2.OnWorkerRevealAccepted(chaincli.WorkerRevealAccepted{SessionID: session, TaskID: task, Height: 300})
	c2.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("sample-seed"), Height: 210})
	fsm, _ := c2.getFSM(session, task)
	vals := [][]byte{[]byte("v")}
	if err := fsm.onVerifyResult(testVerifyResult(task, "verifier-1", vals)); err != nil {
		t.Fatalf("onVerifyResult verifier-1: %v", err)
	}
	if err := fsm.onVerifyResult(testVerifyResult(task, "verifier-2", vals)); err != nil {
		t.Fatalf("onVerifyResult verifier-2: %v", err)
	}
	// Settlement ordering and grace blocks are both restored from the snapshot; timing still follows chain height (§10.10a).
	if settleCount(sub2) != 0 {
		t.Fatalf("settle must wait for the window, got %d submissions", settleCount(sub2))
	}
	c2.onNewBlock(rankRevealDeadline + 1)
	if settleCount(sub2) != 1 {
		t.Fatalf("recovered task must continue to settle, got %d submissions", settleCount(sub2))
	}
}

func TestRecoverySettledTaskUsesChainHeight(t *testing.T) {
	tests := []struct {
		name        string
		height      uint64
		settlement  chaincli.TaskSettlementState
		queryErr    error
		legacyUntil int64
		wantPresent bool
	}{
		{name: "equal close retained", height: 100, settlement: chaincli.TaskSettlementState{
			SettlementID: "settlement-1", SettlementMode: "OPTIMISTIC",
			SettlementStatus: "SETTLED_PASS", SettlementHeight: 90,
			ChallengeCloseHeight: 100, EvidenceCleanupHeight: 120,
			OptimisticFinalityStatus: "PENDING", TaskFinalityHeight: 100,
			ClaimableAfterHeight: 100,
		}, wantPresent: true},
		{name: "cleanup and finality release", height: 120, settlement: releasableSettlement(), wantPresent: false},
		{name: "query failure retains legacy snapshot", height: 120,
			settlement: releasableSettlement(), queryErr: errors.New("query unavailable"),
			legacyUntil: 1, wantPresent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := kv.NewMemStore()
			snapshot := taskSnapshot{
				Version: 2, SessionID: "session-1", TaskID: "task-1",
				ModelID: "model", PayloadCID: "cid", State: types.Settled,
				Phase: types.PhaseSettle, Settlement: test.settlement,
				LegacyChallengeUntil: test.legacyUntil,
			}
			raw, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Set(kv.NSTask, taskKey("session-1", "task-1"), raw); err != nil {
				t.Fatal(err)
			}
			facts := &chainFactsFake{
				height: test.height, taskErr: test.queryErr,
				tasks: map[string]chaincli.OnChainTask{
					taskKey("session-1", "task-1"): {
						SessionID: "session-1", TaskID: "task-1",
						State: types.Settled, TaskVerdict: types.VerdictPass,
						Settlement: test.settlement,
					},
				},
			}
			c, _, _ := newRecoveryCoordinator(t, store,
				WithHeightQuerier(facts), WithTaskQuerier(facts))
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Stop(context.Background()) }()
			_, err = c.TaskStatus(context.Background(), "session-1", "task-1")
			if test.wantPresent && err != nil {
				t.Fatalf("task was removed: %v", err)
			}
			if !test.wantPresent && !errors.Is(err, ErrTaskNotFound) {
				t.Fatalf("task remained: %v", err)
			}
		})
	}
}

// TestRecoveryDropsTerminalAndCorruptSnapshots terminal and corrupt snapshots are purged on recovery and not loaded into the task table.
func TestRecoveryDropsTerminalAndCorruptSnapshots(t *testing.T) {
	store := kv.NewMemStore()
	ctx := context.Background()

	sn := taskSnapshot{SessionID: "s-done", TaskID: "t-done", State: types.Closed, Phase: types.PhaseSettle}
	b, _ := json.Marshal(sn)
	store.Set(kv.NSTask, taskKey("s-done", "t-done"), b)
	store.Set(kv.NSTask, taskKey("s-bad", "t-bad"), []byte("{not json"))

	c, _, _ := newRecoveryCoordinator(t, store)
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop(ctx) })

	if _, err := c.TaskStatus(ctx, "s-done", "t-done"); err != ErrTaskNotFound {
		t.Fatalf("terminal task must not be recovered, got %v", err)
	}
	if _, ok := store.Get(kv.NSTask, taskKey("s-done", "t-done")); ok {
		t.Fatal("terminal snapshot must be deleted")
	}
	if _, ok := store.Get(kv.NSTask, taskKey("s-bad", "t-bad")); ok {
		t.Fatal("corrupt snapshot must be deleted")
	}
}

func TestSnapshotRetainsCanonicalOrderHandraiseAndReceiptInputs(t *testing.T) {
	store := kv.NewMemStore()
	c, _, _ := newRecoveryCoordinator(t, store)
	order := types.Order{
		SessionID: "session-canonical", TaskID: testTaskID("task-canonical"), OrderSequence: 7,
		ModelID: "model", ProfileVersion: math.MaxUint32, PayloadCID: "cid", User: "user",
		OrderEnvelope: `{"schema_version":"trueopen-order-envelope-v1"}`, TaskHash: testCanonicalTaskHash(testUserAddress),
		SignatureScheme: "secp256k1", UserSignature: "user-signature", MaxFee: 1000,
		InferTimeoutBlocks: 20,
		Stage1BuilderRank:  2, Stage1SelectionProof: nodecontract.BuilderSelectionProofVersion + ":00",
		SignedOrder: testSignedOrderBytes(testUserAddress),
	}
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM(order.SessionID, order.TaskID)
	fsm.onWorkerHandraise(testWorkerHandraise(order.SessionID, order.TaskID, "worker-1"))
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: order.SessionID, TaskID: order.TaskID, Height: 10})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: order.SessionID, TaskID: order.TaskID, Winner: "worker-1", Height: 11})
	if err := c.OnInferReceipt(context.Background(), testInferReceipt(order.SessionID, order.TaskID, "worker-1", []byte("output"))); err != nil {
		t.Fatal(err)
	}

	raw, ok := store.Get(kv.NSTask, taskKey(order.SessionID, order.TaskID))
	if !ok {
		t.Fatal("snapshot not found")
	}
	var snapshot taskSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Order.OrderEnvelope != order.OrderEnvelope || snapshot.Order.UserSignature != order.UserSignature || snapshot.Order.MaxFee != 1000 {
		t.Fatalf("order=%+v", snapshot.Order)
	}
	if snapshot.Order.Stage1BuilderRank != order.Stage1BuilderRank || snapshot.Order.Stage1SelectionProof != order.Stage1SelectionProof {
		t.Fatalf("stage1 selection was not persisted: rank=%d proof=%q", snapshot.Order.Stage1BuilderRank, snapshot.Order.Stage1SelectionProof)
	}
	if snapshot.ProfileVersion != order.ProfileVersion || bytes.Contains(raw, []byte(`"profile_version":"`)) {
		t.Fatalf("profile version was not persisted as an integer: snapshot=%d raw=%s", snapshot.ProfileVersion, raw)
	}
	if len(snapshot.WorkerHandraises) != 1 || len(snapshot.WorkerHandraises[0]) == 0 {
		t.Fatalf("worker handraises=%+v", snapshot.WorkerHandraises)
	}
	if string(snapshot.InferReceipt.InferReceiptHash) != "infer-receipt" || len(snapshot.InferReceipt.WorkerServiceSignature) == 0 {
		t.Fatalf("infer receipt=%+v", snapshot.InferReceipt)
	}
}

// TestRestoreDropsLegacySnapshotMaterial pins the version gate on the upgrade path: from v4 on,
// hand-raise / verification-result data is frozen-wire proto bytes; those sections of pre-v4 snapshots
// (old msgbus JSON payloads) are dropped wholesale; undecodable proto entries are dropped one by
// one. The data can be re-collected, so correctness wins over cache preservation.
func TestRestoreDropsLegacySnapshotMaterial(t *testing.T) {
	task := testTaskID("restore-legacy")
	fresh := testVerifyResult(task, "fresh", [][]byte{[]byte("v0"), []byte("v1")})
	freshRaw, err := proto.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}

	newFSM := func() *taskFSM {
		return &taskFSM{
			log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
			taskID:        task,
			workerHR:      make(map[string]*taskv1.WorkerHandraiseV1),
			verifierHR:    make(map[string]*taskv1.VerifierHandraiseV1),
			verifyResults: make(map[string]*taskv1.ResultReceiptV2),
			fullReveals:   make(map[string]bool),
		}
	}

	t.Run("pre-v4 snapshot payloads are dropped wholesale", func(t *testing.T) {
		fsm := newFSM()
		fsm.restoreFrom(taskSnapshot{
			Version: snapshotVersionProtoPayloadV4 - 1, SessionID: "session-1", TaskID: task,
			VerifyResults: [][]byte{freshRaw},
		})
		if len(fsm.verifyResults) != 0 {
			t.Fatalf("pre-v4 payloads survived: %+v", fsm.verifyResults)
		}
	})

	t.Run("v4 snapshot drops undecodable entries and keeps valid ones", func(t *testing.T) {
		fsm := newFSM()
		fsm.restoreFrom(taskSnapshot{
			Version: snapshotVersionProtoPayloadV4, SessionID: "session-1", TaskID: task,
			VerifyResults: [][]byte{[]byte("not-a-proto-result-receipt"), freshRaw},
		})
		if _, ok := fsm.verifyResults["fresh"]; !ok {
			t.Fatalf("valid verify result was dropped: %+v", fsm.verifyResults)
		}
		if len(fsm.verifyResults) != 1 {
			t.Fatalf("undecodable verify result survived: %+v", fsm.verifyResults)
		}
	})
}

// TestSaveWritesCurrentSnapshotVersion pins save() in sync with the version gate: if it still
// wrote the old version number, every restart would drop its own just-saved payload as pre-v3,
// and no test would go red.
func TestSaveWritesCurrentSnapshotVersion(t *testing.T) {
	var got taskSnapshot
	task := testTaskID("save-version")
	fsm := &taskFSM{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessionID:     "session-1",
		taskID:        task,
		workerHR:      make(map[string]*taskv1.WorkerHandraiseV1),
		verifierHR:    make(map[string]*taskv1.VerifierHandraiseV1),
		verifyResults: make(map[string]*taskv1.ResultReceiptV2),
		fullReveals:   make(map[string]bool),
		persist:       func(sn taskSnapshot) error { got = sn; return nil },
	}
	fsm.verifyResults["fresh"] = testVerifyResult(task, "fresh", [][]byte{[]byte("v0")})
	if err := fsm.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got.Version != snapshotVersionProtoPayloadV4 {
		t.Fatalf("save() wrote snapshot version %d, want %d", got.Version, snapshotVersionProtoPayloadV4)
	}

	// What is stored must read back verbatim: the version number save writes must pass its own version gate.
	restored := &taskFSM{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		taskID:        task,
		workerHR:      make(map[string]*taskv1.WorkerHandraiseV1),
		verifierHR:    make(map[string]*taskv1.VerifierHandraiseV1),
		verifyResults: make(map[string]*taskv1.ResultReceiptV2),
		fullReveals:   make(map[string]bool),
	}
	restored.restoreFrom(got)
	if _, ok := restored.verifyResults["fresh"]; !ok {
		t.Fatalf("save→restore round trip lost the verify result: %+v", restored.verifyResults)
	}
}

// Assignment finalized while offline: recovery on restart must re-send the start notification once,
// otherwise the winner never learns its winner identity and infer deadline, and the task never
// starts on the Worker side.
func TestRecoveryPublishesMissedAssignmentNotify(t *testing.T) {
	store := kv.NewMemStore()
	session, task := "sess-missed-assign", testTaskID("missed-assign")
	snapshot := taskSnapshot{
		Version: snapshotVersionProtoPayloadV4, SessionID: session, TaskID: task,
		ModelID: "model", PayloadCID: "cid", State: types.Pending, Phase: types.PhaseUnspecified,
		Order: types.Order{SessionID: session, TaskID: task, TaskHash: task},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(kv.NSTask, taskKey(session, task), raw); err != nil {
		t.Fatal(err)
	}
	querier := &scopedTaskQuerier{
		height: 15_300,
		task: chaincli.OnChainTask{
			SessionID: session, TaskID: task, State: types.Assigned,
			Winner: testOperator("missed-winner"),
			Assignment: chaincli.TaskAssignmentState{
				WinnerConfirmHeight: 15_201, InferDeadlineHeight: 15_260,
			},
		},
	}
	c, _, _ := newRecoveryCoordinator(t, store, WithTaskQuerier(querier))
	enableTestBusEnvelopes(c)
	sent := &captured{}
	mustSub(t, c.bus, msgbus.SubjectWorkerAssignment(task), sent)

	if err := c.recoverTasks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent.count() != 1 {
		t.Fatalf("recovery published %d assignment notifications, want 1", sent.count())
	}
	notify := decodeTestPayload[busv1.WorkerAssignmentNotifyV1](t, sent.last())
	if notify.GetWinnerOperatorAddress() != testOperator("missed-winner") ||
		notify.GetFinalizedHeight() != 15_201 || notify.GetInferDeadlineHeight() != 15_260 {
		t.Fatalf("recovered notification mismatch: %+v", notify)
	}
}
