package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

var (
	testAcceptedTaskHash  = strings.Repeat("6f", 32)
	testAcceptedInputHash = strings.Repeat("7a", 32)
)

// The chain accepted another version than this Builder's order: the FSM switches to the accepted
// task_hash, keeps only hand-raises for it, removes its own input and remembers all of it.
func TestAcceptedOtherVersionSwitchesToTheAcceptedVersion(t *testing.T) {
	c, _ := newTestCoordinator(t)
	taskStore, payloads := newCoordinatorTaskData(t, c.kv)
	c.payloads = payloads
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("local input"), 100)
	local := stageOrderInput(t, taskStore, order, []byte("local input"), true)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM(order.SessionID, order.TaskID)
	fsm.onWorkerHandraise(testWorkerHandraise(order.SessionID, order.TaskID, testOperator("before")))

	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: order.SessionID, TaskID: order.TaskID, State: types.Pending,
		Assignment: chaincli.TaskAssignmentState{AcceptedTaskHash: testAcceptedTaskHash, AcceptedInputHash: testAcceptedInputHash},
	}, 120)

	fsm.mu.Lock()
	mismatch, collected := fsm.versionMismatch, len(fsm.workerHR)
	taskHash := hex.EncodeToString(fsm.taskHashBytes())
	fsm.mu.Unlock()
	if !mismatch {
		t.Fatal("version mismatch was not recorded")
	}
	if collected != 0 {
		t.Fatalf("hand-raises for the local version were kept: %d", collected)
	}
	if taskHash != testAcceptedTaskHash {
		t.Fatalf("task identified by %s, want the accepted task_hash", taskHash)
	}
	if !inputDeleted(t, taskStore, local) {
		t.Fatal("local input of the other version was not removed")
	}

	// Later hand-raises are checked against the accepted version.
	stale := testWorkerHandraise(order.SessionID, order.TaskID, testOperator("stale"))
	fresh := testWorkerHandraise(order.SessionID, order.TaskID, testOperator("fresh"))
	fresh.TaskHash = mustHex32(testAcceptedTaskHash)
	fsm.onWorkerHandraise(stale)
	fsm.onWorkerHandraise(fresh)
	fsm.mu.Lock()
	_, staleKept := fsm.workerHR[testOperator("stale")]
	_, freshKept := fsm.workerHR[testOperator("fresh")]
	fsm.mu.Unlock()
	if staleKept || !freshKept {
		t.Fatalf("hand-raise filter after mismatch: stale kept=%t fresh kept=%t", staleKept, freshKept)
	}

	// Detected once; the snapshot keeps it for a restart.
	if fsm.rememberAcceptedVersion(testAcceptedTaskHash, testAcceptedInputHash) {
		t.Fatal("mismatch reported twice")
	}
	raw, ok := c.kv.Get(kv.NSTask, taskKey(order.SessionID, order.TaskID))
	if !ok {
		t.Fatal("snapshot missing")
	}
	var sn taskSnapshot
	if err := json.Unmarshal(raw, &sn); err != nil {
		t.Fatal(err)
	}
	if !sn.VersionMismatch || sn.AcceptedInputHash != testAcceptedInputHash {
		t.Fatalf("snapshot version_mismatch=%t accepted_input_hash=%q", sn.VersionMismatch, sn.AcceptedInputHash)
	}
	restored := c.newFSM(order)
	restored.restoreFrom(sn)
	if !restored.versionMismatch || restored.acceptedInputHash != testAcceptedInputHash {
		t.Fatal("restored FSM lost the mismatch")
	}
}

// The chain accepting this Builder's own version is not a mismatch, and the local input stays.
func TestAcceptedOwnVersionKeepsLocalInput(t *testing.T) {
	c, _ := newTestCoordinator(t)
	taskStore, payloads := newCoordinatorTaskData(t, c.kv)
	c.payloads = payloads
	order := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("local input"), 100)
	local := stageOrderInput(t, taskStore, order, []byte("local input"), true)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM(order.SessionID, order.TaskID)
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: order.SessionID, TaskID: order.TaskID, State: types.Pending,
		Assignment: chaincli.TaskAssignmentState{AcceptedTaskHash: order.TaskHash, AcceptedInputHash: order.PayloadHash},
	}, 120)
	fsm.mu.Lock()
	mismatch := fsm.versionMismatch
	fsm.mu.Unlock()
	if mismatch {
		t.Fatal("own version reported as a mismatch")
	}
	if inputDeleted(t, taskStore, local) {
		t.Fatal("own input was removed")
	}
}

// A Builder holding another input version must not claim data-ready: no OPEN_VERIFY and no
// Verifier proposal, even once the Worker result is complete here.
func TestAcceptedOtherVersionIsNeverDataReady(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "mismatch-not-ready")
	fx.c.applyAuthoritativeTask(fx.fsm, chaincli.OnChainTask{
		SessionID: fx.session, TaskID: fx.task, State: types.Verifying, Winner: fx.fsm.winner,
		Assignment: chaincli.TaskAssignmentState{
			WinnerConfirmHeight: 101, AcceptedTaskHash: testAcceptedTaskHash, AcceptedInputHash: testAcceptedInputHash,
		},
		ReceiptAccepted: true,
	}, 150)
	waitDataReadyIdle(t, fx.fsm)
	readiness.set(true)
	fx.resultFinalized(t)
	fx.deliver(testOperator("verifier-1"))
	waitDataReadyIdle(t, fx.fsm)
	if openVerify.count() != 0 || len(fx.proposed()) != 0 {
		t.Fatalf("mismatched Builder: OPEN_VERIFY=%d proposals=%d, want 0/0", openVerify.count(), len(fx.proposed()))
	}
	fx.fsm.mu.Lock()
	ready := fx.fsm.dataReady
	payload := fx.fsm.openVerifyPayload()
	fx.fsm.mu.Unlock()
	if ready {
		t.Fatal("mismatched Builder became data-ready")
	}
	if payload == nil || hex.EncodeToString(payload.GetTaskHash()) != testAcceptedTaskHash {
		t.Fatalf("OPEN_VERIFY payload task_hash = %x, want the accepted one", payload.GetTaskHash())
	}
}

// The data-ready check asks for the accepted INPUT by the chain's accepted input_hash.
func TestDataReadyQueryNamesTheAcceptedInput(t *testing.T) {
	fx, readiness, _ := newDataReadyFixture(t, "data-ready-input")
	fx.fsm.mu.Lock()
	own := fx.fsm.order.TaskHash
	fx.fsm.mu.Unlock()
	fx.c.applyAuthoritativeTask(fx.fsm, chaincli.OnChainTask{
		SessionID: fx.session, TaskID: fx.task, State: types.Verifying, Winner: fx.fsm.winner,
		Assignment: chaincli.TaskAssignmentState{
			WinnerConfirmHeight: 101, AcceptedTaskHash: own, AcceptedInputHash: fx.fsm.order.PayloadHash,
		},
		ReceiptAccepted: true,
	}, 150)
	waitDataReadyIdle(t, fx.fsm)
	fx.resultFinalized(t)
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	if len(readiness.queries) == 0 {
		t.Fatal("no data-ready query")
	}
	if got := readiness.queries[len(readiness.queries)-1].InputHash; got != fx.fsm.order.PayloadHash || got == "" {
		t.Fatalf("data-ready query input_hash = %q, want %q", got, fx.fsm.order.PayloadHash)
	}
}
