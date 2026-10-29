package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

const testChainID = "trueopen-test-chain"

// newTestCoordinator starts an in-process coordinator (fake CortexLink + fake submitter), optionally
// with an identity signer.
func newTestCoordinator(t *testing.T, opts ...Option) (*Coordinator, *relay.Custodian) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID, opts...)
	enableTestBuilderMessages(c)
	c.submit = &fakeSubmitter{}
	return c, &rl
}

// driveToVerifying advances to Verifying (including user / verifiers / held receipt).
func driveToVerifying(t *testing.T, c *Coordinator, session, task, user string, verifiers []string) {
	t.Helper()
	ctx := context.Background()
	if err := trackTestOrder(c, testCurrentOrder(session, task, user)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, "worker-1", 101)
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
}

// TestTaskEventsReplayAndLive the event stream: event codes ordered throughout, replay from a
// cursor checkpoint, and live push.
func TestTaskEventsReplayAndLive(t *testing.T) {
	c, _ := newTestCoordinator(t)
	const session, task = "sess-ev", "task-ev"
	driveToVerifying(t, c, session, task, testUserAddress, []string{"verifier-1", "verifier-2"})
	ctx := context.Background()

	replay, live, cancel, err := c.TaskEvents(ctx, session, task, 0)
	if err != nil {
		t.Fatalf("TaskEvents: %v", err)
	}
	defer cancel()
	wantCodes := []string{EvOrderReceived, EvAssignmentFinalized, EvInferReceiptReceived, EvOpenVerifyAccepted}
	if len(replay) != len(wantCodes) {
		t.Fatalf("replay = %d events, want %d: %+v", len(replay), len(wantCodes), replay)
	}
	for i, ev := range replay {
		if ev.EventCode != wantCodes[i] || ev.Seq != uint64(i+1) {
			t.Fatalf("replay[%d] = %+v, want code %s seq %d", i, ev, wantCodes[i], i+1)
		}
	}
	if replay[3].ChainHeight != 200 || replay[3].TaskPhase != "OPEN_VERIFY" {
		t.Fatalf("OpenVerify event fields: %+v", replay[3])
	}

	// Live: advance SampleReady, the subscription channel must receive it.
	c.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("s"), ReadyHeight: 210, Height: 211})
	select {
	case ev := <-live:
		if ev.EventCode != EvSampleReady || ev.Seq != 5 {
			t.Fatalf("live event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live event not delivered")
	}

	// Checkpoint replay: cursor=3 replays only the events after it.
	replay2, _, cancel2, err := c.TaskEvents(ctx, session, task, 3)
	if err != nil {
		t.Fatalf("TaskEvents resume: %v", err)
	}
	defer cancel2()
	if len(replay2) != 2 || replay2[0].EventCode != EvOpenVerifyAccepted || replay2[1].EventCode != EvSampleReady {
		t.Fatalf("resume replay mismatch: %+v", replay2)
	}

	// Unknown task -> NotFound.
	if _, _, _, err := c.TaskEvents(ctx, "no", "no", 0); err != ErrTaskNotFound {
		t.Fatalf("unknown task: want ErrTaskNotFound, got %v", err)
	}
}

func TestPrepareChallengeUsesInclusiveChainHeightBoundary(t *testing.T) {
	tests := []struct {
		name     string
		height   uint64
		status   string
		wantOpen bool
	}{
		{name: "before", height: 99, status: "PENDING", wantOpen: true},
		{name: "equal", height: 100, status: "PENDING", wantOpen: true},
		{name: "after", height: 101, status: "PENDING", wantOpen: false},
		{name: "final", height: 99, status: "FINAL", wantOpen: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := newChallengeFacts(test.height, test.status)
			c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
			if err := trackTestOrder(c, testPlaceholderOrder("session-1", "task-1")); err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", "VERDICT_FRAUD_PROOF")
			if err != nil {
				t.Fatal(err)
			}
			if plan.ChallengeOpen != test.wantOpen || plan.ChallengeCloseHeight != 100 {
				t.Fatalf("plan=%+v", plan)
			}
		})
	}
}

// The opener of a challenge round holds no evidence, whatever kind the SDK names.
func TestPrepareChallengeListsNoRequiredEvidence(t *testing.T) {
	facts := newChallengeFacts(95, "PENDING")
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := trackTestOrder(c, testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"", "RESULT", "VERDICT_FRAUD_PROOF"} {
		plan, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.RequiredEvidence) != 0 {
			t.Fatalf("kind %q: required evidence = %v", kind, plan.RequiredEvidence)
		}
	}
}

// The window is open only while TaskStage reports the challenge window close as the next
// deadline: not before round 1 closes, not while a round is open or the task is settling, and not
// when the round limit allows no second round.
func TestPrepareChallengeFollowsChainTaskStage(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*chainFactsFake)
	}{
		{name: "no deadline", configure: func(f *chainFactsFake) { f.stage = chaincli.TaskStage{FinalityStatus: "PENDING"} }},
		{name: "round deadline", configure: func(f *chainFactsFake) {
			f.stage = chaincli.TaskStage{FinalityStatus: "PENDING", NextDeadlineKind: "VERIFY_COMMIT", NextDeadlineHeight: 100}
		}},
		{name: "settling", configure: func(f *chainFactsFake) {
			f.stage = chaincli.TaskStage{FinalityStatus: "PENDING", NextDeadlineKind: "TASK_SETTLEMENT", NextDeadlineHeight: 100}
		}},
		{name: "round limit", configure: func(f *chainFactsFake) { f.maxVerifyRound = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := newChallengeFacts(95, "PENDING")
			test.configure(facts)
			c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
			if err := trackTestOrder(c, testPlaceholderOrder("session-1", "task-1")); err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", "VERDICT_FRAUD_PROOF")
			if err != nil {
				t.Fatal(err)
			}
			if plan.ChallengeOpen {
				t.Fatalf("challenge reported open: %+v", plan)
			}
		})
	}
}

func TestPrepareChallengeNeverReopensBelowObservedHeight(t *testing.T) {
	facts := newChallengeFacts(99, "PENDING")
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := trackTestOrder(c, testPlaceholderOrder("session-1", "task-1")); err != nil {
		t.Fatal(err)
	}
	c.onNewBlock(101)

	plan, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", "VERDICT_FRAUD_PROOF")
	if err != nil {
		t.Fatal(err)
	}
	if plan.ChallengeOpen {
		t.Fatalf("challenge reopened from stale height: %+v", plan)
	}
}

// newChallengeFacts is a task whose round 1 has closed with a challenge window up to 100, as the
// chain reports it: finality from QueryTask, the window from TaskStage.
func newChallengeFacts(height uint64, status string) *chainFactsFake {
	return &chainFactsFake{
		height:         height,
		maxVerifyRound: 2,
		stage: chaincli.TaskStage{
			FinalityStatus: status, NextDeadlineKind: "CHALLENGE_WINDOW_CLOSE", NextDeadlineHeight: 100,
		},
		tasks: map[string]chaincli.OnChainTask{
			taskKey("session-1", "task-1"): {
				SessionID: "session-1", TaskID: "task-1",
				State: types.Settled, TaskVerdict: types.VerdictPass,
				Settlement: chaincli.TaskSettlementState{FinalityStatus: status},
			},
		},
	}
}

func TestPrepareChallengeFailsClosedWhenChainFactsUnavailable(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*chainFactsFake)
	}{
		{name: "height", configure: func(f *chainFactsFake) { f.heightErr = errors.New("height unavailable") }},
		{name: "task", configure: func(f *chainFactsFake) { f.taskErr = errors.New("task unavailable") }},
		{name: "unknown finality", configure: func(f *chainFactsFake) {
			task := f.tasks[taskKey("session-1", "task-1")]
			task.Settlement.FinalityStatus = ""
			f.tasks[taskKey("session-1", "task-1")] = task
		}},
		{name: "challenge params", configure: func(f *chainFactsFake) { f.paramsErr = errors.New("params unavailable") }},
		{name: "task stage", configure: func(f *chainFactsFake) { f.stageErr = errors.New("stage unavailable") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := newChallengeFacts(99, "PENDING")
			test.configure(facts)
			c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
			if err := trackTestOrder(c, testPlaceholderOrder("session-1", "task-1")); err != nil {
				t.Fatal(err)
			}
			_, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", "VERDICT_FRAUD_PROOF")
			if !errors.Is(err, types.ErrChainStateUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
