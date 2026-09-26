package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// fakeResultReadiness stands in for the task data plane. With receiptHash set it is ready only for
// that receipt, like taskdata.Service.ResultReady.
type fakeResultReadiness struct {
	mu          sync.Mutex
	ready       bool
	receiptHash string
	err         error
	queries     []taskdata.ResultReadyQuery
}

func (f *fakeResultReadiness) ResultReady(_ context.Context, q taskdata.ResultReadyQuery) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return false, f.err
	}
	return f.ready && (f.receiptHash == "" || f.receiptHash == q.InferReceiptHash), nil
}

func (f *fakeResultReadiness) set(ready bool) {
	f.mu.Lock()
	f.ready = ready
	f.mu.Unlock()
}

// newDataReadyFixture is a verifier proposal fixture whose data plane answers "not ready" until the
// test says otherwise, with OPEN_VERIFY captured.
func newDataReadyFixture(t *testing.T, name string) (*verifierProposalFixture, *fakeResultReadiness, *captured) {
	t.Helper()
	fx := newVerifierProposalFixture(t, name)
	readiness := &fakeResultReadiness{receiptHash: hex.EncodeToString(fx.receipt)}
	fx.c.SetResultReadiness(readiness)
	fx.fsm.mu.Lock()
	fx.fsm.resultReadiness = readiness
	fx.fsm.dataReady = false
	fx.fsm.mu.Unlock()
	openVerify := &captured{}
	mustSub(t, fx.bus, msgbus.SubjectVerifyOpen(fx.task), openVerify)
	return fx, readiness, openVerify
}

func (fx *verifierProposalFixture) chainAcceptsReceipt(t *testing.T, height int64) {
	t.Helper()
	fx.c.applyAuthoritativeTask(fx.fsm, chaincli.OnChainTask{
		SessionID: fx.session, TaskID: fx.task, State: types.Verifying, Winner: fx.fsm.winner,
		Assignment:      chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		ReceiptAccepted: true,
	}, height)
	waitDataReadyIdle(t, fx.fsm)
}

func (fx *verifierProposalFixture) resultFinalized(t *testing.T) {
	t.Helper()
	fx.c.OnResultFinalized(fx.session, fx.task)
	waitDataReadyIdle(t, fx.fsm)
}

// waitDataReadyIdle waits for a background data-ready check to finish.
func waitDataReadyIdle(t *testing.T, f *taskFSM) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		busy := f.dataReadyChecking
		f.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("data-ready check did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

// Receipt accepted locally and on chain, but the Worker has not finalized its result on this
// Builder: no OPEN_VERIFY and no proposal (04 §326). Finalize then sends both.
func TestOpenVerifyAndProposalWaitForLocalDataReady(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-wait")
	fx.chainAcceptsReceipt(t, 150)
	fx.deliver(testOperator("verifier-1"))
	waitDataReadyIdle(t, fx.fsm)
	if openVerify.count() != 0 || len(fx.proposed()) != 0 {
		t.Fatalf("before Finalize: OPEN_VERIFY=%d proposals=%d, want 0/0", openVerify.count(), len(fx.proposed()))
	}
	fx.fsm.mu.Lock()
	buffered := len(fx.fsm.verifierHR)
	fx.fsm.mu.Unlock()
	if buffered != 1 {
		t.Fatalf("hand-raise was not kept while waiting for data-ready: %d", buffered)
	}

	// Reconcile alone does not help while the data is missing.
	fx.chainAcceptsReceipt(t, 151)
	if openVerify.count() != 0 || len(fx.proposed()) != 0 {
		t.Fatal("a reconcile sent OPEN_VERIFY or a proposal before data-ready")
	}

	readiness.set(true)
	fx.resultFinalized(t)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY after Finalize = %d, want 1", openVerify.count())
	}
	if ops := proposalOperators(t, fx.proposed()); len(ops) != 1 || ops[0] != testOperator("verifier-1") {
		t.Fatalf("buffered hand-raise was not proposed after Finalize: %v", ops)
	}

	// The query names the result this FSM holds.
	readiness.mu.Lock()
	last := readiness.queries[len(readiness.queries)-1]
	readiness.mu.Unlock()
	if last.SessionID != fx.session || last.TaskID != fx.task ||
		last.OutputHash != hex.EncodeToString(fx.output) || last.InferReceiptHash != hex.EncodeToString(fx.receipt) {
		t.Fatalf("data-ready query = %+v", last)
	}

	fx.chainAcceptsReceipt(t, 152)
	fx.resultFinalized(t)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY was resent: %d", openVerify.count())
	}
}

// A result finalized with a different receipt does not make this FSM data-ready.
func TestDataReadyIsBoundToTheSameReceipt(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-other-receipt")
	readiness.mu.Lock()
	readiness.ready, readiness.receiptHash = true, hex.EncodeToString(make([]byte, 32))
	readiness.mu.Unlock()
	fx.chainAcceptsReceipt(t, 150)
	fx.resultFinalized(t)
	fx.deliver(testOperator("verifier-1"))
	waitDataReadyIdle(t, fx.fsm)
	if openVerify.count() != 0 || len(fx.proposed()) != 0 {
		t.Fatalf("OPEN_VERIFY=%d proposals=%d for another receipt's result, want 0/0", openVerify.count(), len(fx.proposed()))
	}
}

// Finalize before the chain accepts the receipt: nothing is sent until the chain does.
func TestDataReadyBeforeChainAcceptance(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-first")
	readiness.set(true)
	fx.resultFinalized(t)
	if openVerify.count() != 0 {
		t.Fatal("OPEN_VERIFY was sent before the chain accepted the receipt")
	}
	fx.chainAcceptsReceipt(t, 150)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY after chain acceptance = %d, want 1", openVerify.count())
	}
}

// A failing data-ready check is not an answer: retried at the next trigger.
func TestDataReadyCheckErrorIsRetried(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-error")
	readiness.mu.Lock()
	readiness.ready, readiness.err = true, errors.New("storage unavailable")
	readiness.mu.Unlock()
	fx.chainAcceptsReceipt(t, 150)
	if openVerify.count() != 0 {
		t.Fatal("OPEN_VERIFY was sent although the data-ready check failed")
	}
	readiness.mu.Lock()
	readiness.err = nil
	readiness.mu.Unlock()
	fx.chainAcceptsReceipt(t, 151)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY after the check recovered = %d, want 1", openVerify.count())
	}
}

// After a restart the first reconcile re-sends OPEN_VERIFY once if the stored result is ready (the
// sent flag is not persisted), later reconciles do not, and nothing is sent when it is not ready.
func TestOpenVerifyAfterRestartFollowsStoredDataReady(t *testing.T) {
	for _, ready := range []bool{true, false} {
		fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-restart-"+map[bool]string{true: "ready", false: "missing"}[ready])
		fx.chainAcceptsReceipt(t, 150)

		raw, ok := fx.c.kv.Get(kv.NSTask, taskKey(fx.session, fx.task))
		if !ok {
			t.Fatal("task snapshot was not persisted")
		}
		var snapshot taskSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		if !snapshot.ReceiptOnChain {
			t.Fatal("snapshot lost receipt_on_chain")
		}
		readiness.set(ready)
		restored := fx.c.newFSM(snapshot.Order)
		restored.restoreFrom(snapshot)
		restored.resultReadiness = readiness

		restored.onInferReceiptAccepted()
		waitDataReadyIdle(t, restored)
		restored.onInferReceiptAccepted()
		waitDataReadyIdle(t, restored)
		want := 0
		if ready {
			want = 1
		}
		if openVerify.count() != want {
			t.Fatalf("ready=%v: OPEN_VERIFY after restart = %d, want %d", ready, openVerify.count(), want)
		}
	}
}

// Once Verifiers are selected the FSM leaves Assigned and a late Finalize sends nothing.
func TestNoOpenVerifyAfterLeavingAssigned(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-late")
	fx.chainAcceptsReceipt(t, 150)
	fx.fsm.mu.Lock()
	fx.fsm.state = types.Verifying
	fx.fsm.mu.Unlock()
	readiness.set(true)
	fx.resultFinalized(t)
	if openVerify.count() != 0 {
		t.Fatalf("OPEN_VERIFY after leaving Assigned = %d, want 0", openVerify.count())
	}
}

// A Finalize that lands while a check is in flight is not lost: the check runs once more.
func TestFinalizeDuringDataReadyCheckIsNotLost(t *testing.T) {
	fx, readiness, openVerify := newDataReadyFixture(t, "data-ready-during-check")
	gate := &gatedResultReadiness{inner: readiness, release: make(chan struct{}), entered: make(chan struct{})}
	fx.fsm.mu.Lock()
	fx.fsm.resultReadiness = gate
	fx.fsm.mu.Unlock()

	// The reconcile starts a check that will answer "not ready"; Finalize lands meanwhile.
	fx.c.applyAuthoritativeTask(fx.fsm, chaincli.OnChainTask{
		SessionID: fx.session, TaskID: fx.task, State: types.Verifying, Winner: fx.fsm.winner,
		Assignment:      chaincli.TaskAssignmentState{WinnerConfirmHeight: 101},
		ReceiptAccepted: true,
	}, 150)
	<-gate.entered
	readiness.set(true)
	fx.c.OnResultFinalized(fx.session, fx.task)
	close(gate.release)
	waitDataReadyIdle(t, fx.fsm)
	if openVerify.count() != 1 {
		t.Fatalf("OPEN_VERIFY after a Finalize during a check = %d, want 1", openVerify.count())
	}
}

// gatedResultReadiness holds its first answer until released, answering as of when it was asked.
type gatedResultReadiness struct {
	inner   *fakeResultReadiness
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (g *gatedResultReadiness) ResultReady(ctx context.Context, q taskdata.ResultReadyQuery) (bool, error) {
	first := false
	g.once.Do(func() { first = true })
	ready, err := g.inner.ResultReady(ctx, q)
	if first {
		g.entered <- struct{}{}
		<-g.release
	}
	return ready, err
}
