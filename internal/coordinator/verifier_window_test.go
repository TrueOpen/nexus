package coordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// setWindow puts a verifier window and a chain height into the FSM, as reconciliation and new
// blocks would.
func (fx *verifierProposalFixture) setWindow(window chaincli.VerifierWindow, height uint64) {
	fx.fsm.mu.Lock()
	fx.fsm.verifierWindow = window
	fx.fsm.verifierWindowKnown = true
	fx.fsm.observedHeight = height
	fx.fsm.mu.Unlock()
}

func (fx *verifierProposalFixture) setHeight(height uint64) {
	fx.fsm.mu.Lock()
	fx.fsm.observedHeight = height
	fx.fsm.mu.Unlock()
}

func (fx *verifierProposalFixture) setSubmitErr(err error) {
	fx.fake.mu.Lock()
	fx.fake.verifierHandraisesErr = err
	fx.fake.mu.Unlock()
}

func (fx *verifierProposalFixture) attempts() int {
	fx.fake.mu.Lock()
	defer fx.fake.mu.Unlock()
	return fx.fake.verifierHandraiseAttempts
}

func (fx *verifierProposalFixture) closed() bool {
	fx.fsm.mu.Lock()
	defer fx.fsm.mu.Unlock()
	return fx.fsm.verifierProposalClosed
}

var readyWindow = chaincli.VerifierWindow{
	WindowRandomnessHeight: 105, GeneratedHeight: 106,
	BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230, Ready: true,
}

// A proposal that would execute at BuilderProposalCloseHeight still goes out; once the next block
// is past it, this Builder stops submitting, keeps late hand-raises, and does not retry.
func TestVerifierProposalStopsAfterBuilderWindowCloses(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-close")
	fx.fsm.onInferReceiptAccepted()
	fx.setWindow(readyWindow, 199) // executes at 200 == close at the earliest

	v1, v2 := testOperator("verifier-1"), testOperator("verifier-2")
	fx.deliver(v1)
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 || got[0] != v1 {
		t.Fatalf("proposal executing at the close height must still go out, got %v", got)
	}

	fx.fsm.onHeight(200) // a proposal sent now executes at 201 > close
	fx.deliver(v2)
	fx.fsm.onInferReceiptAccepted() // reconciliation
	fx.fsm.onInferReceiptAccepted()
	if n := fx.attempts(); n != 1 {
		t.Fatalf("submissions after the Builder window closed = %d, want none (1 in total)", n-1)
	}
	if !fx.closed() {
		t.Fatal("the FSM must record that this Builder's proposal window is closed")
	}
	fx.fsm.mu.Lock()
	_, kept := fx.fsm.verifierHR[v2]
	fx.fsm.mu.Unlock()
	if !kept {
		t.Fatal("a hand-raise that arrives after the close must still be kept")
	}
}

// A refusal after the close height stops the retries; the decision is by height, not by the
// chain's error text.
func TestVerifierProposalDoesNotRetryAfterCloseOnFailure(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-close-failure")
	fx.fsm.onInferReceiptAccepted()
	fx.setWindow(readyWindow, 199)
	fx.setSubmitErr(errors.New("verifier handraise window is unavailable"))
	fx.deliver(testOperator("verifier-1"))
	if n := fx.attempts(); n != 1 {
		t.Fatalf("attempts = %d, want 1", n)
	}
	if fx.closed() {
		t.Fatal("a refusal before the close height must not close the window")
	}

	fx.setHeight(200)
	fx.fsm.onInferReceiptAccepted()
	fx.fsm.onInferReceiptAccepted()
	if n := fx.attempts(); n != 1 {
		t.Fatalf("attempts after the close = %d, want no new ones", n-1)
	}
	if !fx.closed() {
		t.Fatal("the window must be closed once the height is past it")
	}
}

// Before the window randomness height the beacon cannot have arrived: nothing is submitted.
// After it a stale SOURCE_FROZEN status does not hold the proposal back.
func TestVerifierProposalWaitsForWindowRandomness(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-randomness")
	fx.fsm.onInferReceiptAccepted()
	frozen := chaincli.VerifierWindow{WindowRandomnessHeight: 150, BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230}
	fx.setWindow(frozen, 140)
	fx.deliver(testOperator("verifier-1"))
	fx.fsm.onInferReceiptAccepted()
	if n := fx.attempts(); n != 0 {
		t.Fatalf("%d submissions before the window randomness height, want 0", n)
	}

	// The block whose successor is past the randomness height triggers the attempt on its own,
	// although the status is still cached as SOURCE_FROZEN.
	fx.fsm.onHeight(150)
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 {
		t.Fatalf("after the randomness height the proposal must be tried, got %d hand-raises on chain", len(got))
	}
}

// The height poll can skip blocks: jumping from before the randomness height to past it still
// triggers the attempt, and only once.
func TestVerifierProposalRandomnessTriggerSurvivesSkippedBlocks(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-randomness-skip")
	fx.fsm.onInferReceiptAccepted()
	frozen := chaincli.VerifierWindow{WindowRandomnessHeight: 150, BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230}
	fx.setWindow(frozen, 149)
	fx.setSubmitErr(errors.New("verifier handraise window is unavailable"))
	fx.deliver(testOperator("verifier-1"))
	if n := fx.attempts(); n != 0 {
		t.Fatalf("%d submissions before the randomness height, want 0", n)
	}
	fx.fsm.onHeight(153) // 149 -> 153 skips the block right after the randomness height
	if n := fx.attempts(); n != 1 {
		t.Fatalf("attempts after a skipped randomness block = %d, want 1", n)
	}
	fx.fsm.onHeight(154)
	fx.fsm.onHeight(155)
	if n := fx.attempts(); n != 1 {
		t.Fatalf("new blocks repeated the randomness attempt: %d attempts, want 1", n)
	}
}

// Between the window randomness height and the block where the window turns READY, a refusal is
// expected; it must not close the window, and the proposal goes through once READY.
func TestVerifierProposalRetriesInBeaconGap(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-beacon-gap")
	fx.fsm.onInferReceiptAccepted()
	frozen := chaincli.VerifierWindow{WindowRandomnessHeight: 150, BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230}
	fx.setWindow(frozen, 151)
	fx.setSubmitErr(errors.New("verifier handraise window is unavailable"))
	fx.deliver(testOperator("verifier-1"))
	if n := fx.attempts(); n != 1 {
		t.Fatalf("attempts in the beacon gap = %d, want 1", n)
	}
	if fx.closed() {
		t.Fatal("a refusal in the beacon gap must not close the window")
	}

	fx.setSubmitErr(nil)
	fx.fsm.setVerifierWindow(chaincli.VerifierWindow{
		WindowRandomnessHeight: 150, GeneratedHeight: 153, BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230, Ready: true,
	})
	fx.setHeight(153)
	fx.fsm.onInferReceiptAccepted()
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 {
		t.Fatalf("once READY the proposal must go through, got %d hand-raises on chain", len(got))
	}
}

// READY but the chain's generated height is still ahead: wait instead of sending a proposal the
// chain would refuse.
func TestVerifierProposalWaitsForGeneratedHeight(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-generated")
	fx.fsm.onInferReceiptAccepted()
	window := readyWindow
	window.GeneratedHeight = 160
	fx.setWindow(window, 150)
	fx.deliver(testOperator("verifier-1"))
	if n := fx.attempts(); n != 0 {
		t.Fatalf("%d submissions before the generated height, want 0", n)
	}
	fx.setHeight(159)
	fx.fsm.onInferReceiptAccepted()
	if n := fx.attempts(); n != 1 {
		t.Fatalf("attempts once the next block reaches the generated height = %d, want 1", n)
	}
}

// Batched hand-raises are flushed when the next block is the last one in which this Builder's
// proposal can execute, rather than waiting out the batching delay.
func TestVerifierProposalFlushesBatchAtClose(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-flush")
	fx.fsm.mu.Lock()
	fx.fsm.verifierProposalDelay = time.Hour
	fx.fsm.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()
	fx.setWindow(readyWindow, 150)
	fx.deliver(testOperator("verifier-1"))
	if n := fx.attempts(); n != 0 {
		t.Fatalf("%d submissions while batching, want 0", n)
	}
	fx.fsm.onHeight(197) // the next block, 198, is within the lead (2) of the close height 200
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 {
		t.Fatalf("the batch must be flushed before the close, got %d hand-raises on chain", len(got))
	}
}

// The height poll can skip blocks: jumping from well before the close to the last block before it
// still flushes the batch in time.
func TestVerifierProposalFlushSurvivesSkippedBlocks(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-flush-skip")
	fx.fsm.mu.Lock()
	fx.fsm.verifierProposalDelay = time.Hour
	fx.fsm.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()
	fx.setWindow(readyWindow, 150)
	fx.deliver(testOperator("verifier-1"))
	fx.fsm.onHeight(195) // next 196: not yet within the lead
	if n := fx.attempts(); n != 0 {
		t.Fatalf("%d submissions outside the lead, want 0", n)
	}
	fx.fsm.onHeight(199) // 195 -> 199 skips every block of the lead; next 200 is still legal
	if got := proposalOperators(t, fx.proposed()); len(got) != 1 {
		t.Fatalf("the batch must be flushed after skipped blocks, got %d hand-raises on chain", len(got))
	}
}

// A Builder that cannot submit (it does not hold the signed receipt) never closes the window or
// logs it, even when its batching timer is running as the height passes the close.
func TestVerifierProposalCloseIgnoredWithoutData(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-no-data")
	fx.fsm.mu.Lock()
	fx.fsm.verifierProposalDelay = time.Hour
	// Knows the receipt only from the chain, like a Builder the Worker did not upload to.
	fx.fsm.outputHash = nil
	fx.fsm.acceptedOutputHash = fx.output
	fx.fsm.acceptedReceiptHash = fx.receipt
	fx.fsm.mu.Unlock()
	fx.fsm.onInferReceiptAccepted()
	fx.setWindow(readyWindow, 150)
	v1 := testOperator("verifier-1")
	fx.deliver(v1)
	fx.fsm.mu.Lock()
	_, kept := fx.fsm.verifierHR[v1]
	batching := fx.fsm.verifierProposalTimer != nil
	fx.fsm.mu.Unlock()
	if !kept || !batching {
		t.Fatalf("setup: hand-raise kept=%v, batching timer running=%v; both must hold for this case", kept, batching)
	}
	// The height poll skips past the close while the batching timer runs, as on the devlocal run.
	fx.fsm.onHeight(201)
	if n := fx.attempts(); n != 0 {
		t.Fatalf("attempts = %d, want 0", n)
	}
	if fx.closed() {
		t.Fatal("a Builder that could not submit must not record the window as closed")
	}
}

type fakeWindowQuerier struct {
	window chaincli.VerifierWindow
	err    error
	calls  int
}

func (q *fakeWindowQuerier) QueryVerifierCandidateWindow(_ context.Context, _ string, round uint32) (chaincli.VerifierWindow, error) {
	q.calls++
	if round != 1 {
		return chaincli.VerifierWindow{}, errors.New("unexpected round")
	}
	return q.window, q.err
}

// Reconciliation reads the window until it is READY, then stops; a failed read changes nothing.
func TestCoordinatorReadsVerifierWindowUntilReady(t *testing.T) {
	fx := newVerifierProposalFixture(t, "verifier-window-read")
	q := &fakeWindowQuerier{err: errors.New("query failed")}
	fx.c.verifierWindows = q
	fx.c.fillVerifierWindow(fx.fsm)
	if fx.fsm.verifierWindowKnown {
		t.Fatal("a failed read must leave the window unknown")
	}

	q.err = nil
	q.window = chaincli.VerifierWindow{WindowRandomnessHeight: 150, BuilderProposalCloseHeight: 200, HandraiseCloseHeight: 230}
	fx.c.fillVerifierWindow(fx.fsm)
	if !fx.fsm.verifierWindowKnown || !fx.fsm.needsVerifierWindow() {
		t.Fatal("a window that is not READY must be recorded and read again")
	}
	q.window = readyWindow
	fx.c.fillVerifierWindow(fx.fsm)
	calls := q.calls
	fx.c.fillVerifierWindow(fx.fsm)
	if q.calls != calls {
		t.Fatal("a READY window must not be read again")
	}
}
