package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/credential"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

const testChainID = "trueopen-test-chain"

// newTestCoordinator starts an in-process coordinator (stub bus + fake submitter), optionally with
// an identity signer.
func newTestCoordinator(t *testing.T, opts ...Option) (*Coordinator, *relay.Custodian) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rl := relay.NewMem(log)
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testBuilderSelf, testChainID, opts...)
	enableTestBusEnvelopes(c)
	c.submit = &fakeSubmitter{}
	return c, &rl
}

// driveToVerifying advances to Verifying (including user / verifiers / held credential).
func driveToVerifying(t *testing.T, c *Coordinator, session, task, user string, verifiers []string) {
	t.Helper()
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, user)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1", Height: 101})
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline}, Height: 200,
	})
}

// TestFetchOutputRefAuthorization the strict SEALED_KEY authorization surface: a stranger is
// refused, a selected Verifier and the order user are admitted; PACKAGE is lenient. The contract's
// target-state baseline removed the OutputRef object and the sealed key, so this method only issues
// a bound credential.
func TestFetchOutputRefAuthorization(t *testing.T) {
	c, _ := newTestCoordinator(t)
	const session, task, user = "sess-au", "task-au", testUserAddress
	driveToVerifying(t, c, session, task, user, []string{"verifier-1", "verifier-2"})
	ctx := context.Background()

	// A stranger asks for the key -> refuse.
	if _, err := c.FetchOutputRef(ctx, session, task, "trueopen1stranger", types.AccessSealedKey, "VERIFIER_FETCH"); err != ErrUnauthorized {
		t.Fatalf("stranger sealed-key: want ErrUnauthorized, got %v", err)
	}
	// A selected Verifier -> admitted, gets a bound credential.
	cred, err := c.FetchOutputRef(ctx, session, task, "verifier-1", types.AccessSealedKey, "VERIFIER_FETCH")
	if err != nil {
		t.Fatalf("verifier sealed-key: %v", err)
	}
	if cred.ID == "" || cred.Recipient != "verifier-1" || cred.AccessLevel != types.AccessSealedKey {
		t.Fatalf("credential not bound: %+v", cred)
	}
	// The order user asks for the key -> admitted.
	if _, err := c.FetchOutputRef(ctx, session, task, user, types.AccessSealedKey, "SDK_DELIVERY"); err != nil {
		t.Fatalf("order user sealed-key: %v", err)
	}
	// A candidate asks for PACKAGE -> admitted (contract §2.2: a candidate may only see metadata; the
	// actual content is still authorized by FetchTaskData against the on-chain duty).
	pkgCred, err := c.FetchOutputRef(ctx, session, task, "trueopen1candidate", types.AccessPackage, "VERIFIER_FETCH")
	if err != nil {
		t.Fatalf("candidate package: %v", err)
	}
	if pkgCred.AccessLevel != types.AccessPackage {
		t.Fatalf("package fetch mismatch: %+v", pkgCred)
	}
	// Unknown task -> NotFound.
	if _, err := c.FetchOutputRef(ctx, "no", "no", user, types.AccessPackage, "SDK_DELIVERY"); err != ErrTaskNotFound {
		t.Fatalf("unknown task: want ErrTaskNotFound, got %v", err)
	}
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
	wantCodes := []string{EvOrderReceived, EvAssignAccepted, EvAssignmentFinalized, EvInferReceiptReceived, EvOpenVerifyAccepted}
	if len(replay) != len(wantCodes) {
		t.Fatalf("replay = %d events, want %d: %+v", len(replay), len(wantCodes), replay)
	}
	for i, ev := range replay {
		if ev.EventCode != wantCodes[i] || ev.Seq != uint64(i+1) {
			t.Fatalf("replay[%d] = %+v, want code %s seq %d", i, ev, wantCodes[i], i+1)
		}
	}
	if replay[4].ChainHeight != 200 || replay[4].TaskPhase != "OPEN_VERIFY" {
		t.Fatalf("OpenVerify event fields: %+v", replay[4])
	}

	// Live: advance SampleReady, the subscription channel must receive it.
	c.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("s"), ReadyHeight: 210, Height: 211})
	select {
	case ev := <-live:
		if ev.EventCode != EvSampleReady || ev.Seq != 6 {
			t.Fatalf("live event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live event not delivered")
	}

	// Checkpoint replay: cursor=4 replays only the events after it.
	replay2, _, cancel2, err := c.TaskEvents(ctx, session, task, 4)
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

// TestRefreshCredential credential refresh: a signed credential round trip, refusal on a wrong
// recipient/usage, and refusal after the held credential is released.
func TestRefreshCredential(t *testing.T) {
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	c, _ := newTestCoordinator(t, WithIdentitySigner(sg))
	const session, task, user = "sess-rc", "task-rc", testUserAddress
	driveToVerifying(t, c, session, task, user, []string{"verifier-1", "verifier-2"})
	ctx := context.Background()

	cred, err := c.FetchOutputRef(ctx, session, task, user, types.AccessSealedKey, "SDK_DELIVERY")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(cred.IssuerSig) != 64 || cred.Issuer != sg.Address() {
		t.Fatalf("credential must be signed: %+v", cred)
	}

	// A normal refresh: the old credential must still be valid and must still be held.
	// Pass an explicitly shorter requested_valid_until so the new credential is distinguishable from
	// the old one (the same parameters within the same millisecond yield the same deterministic ID).
	wantUntil := cred.ValidUntil - 60_000
	newCred, err := c.RefreshCredential(ctx, cred, user, "SDK_DELIVERY", wantUntil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if newCred.ID == cred.ID || newCred.ValidUntil != wantUntil {
		t.Fatalf("refresh result: old=%+v new=%+v", cred, newCred)
	}
	if len(newCred.IssuerSig) != 64 {
		t.Fatal("refreshed credential must be re-signed")
	}
	// Wrong recipient -> refuse.
	if _, err := c.RefreshCredential(ctx, cred, "trueopen1other", "SDK_DELIVERY", 0); err != credential.ErrWrongRecipient {
		t.Fatalf("want ErrWrongRecipient, got %v", err)
	}
	// Wrong usage -> refuse.
	if _, err := c.RefreshCredential(ctx, cred, user, "WATCHER_AUDIT", 0); err != credential.ErrWrongUsage {
		t.Fatalf("want ErrWrongUsage, got %v", err)
	}
	// A tampered credential -> refuse.
	forged := cred
	forged.AccessLevel = types.AccessSealedKey
	forged.ValidUntil += 1000
	if _, err := c.RefreshCredential(ctx, forged, user, "SDK_DELIVERY", 0); err != credential.ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
	expired, err := credential.Issue(sg, types.Credential{
		SessionID:   session,
		TaskID:      task,
		Recipient:   user,
		Usage:       "SDK_DELIVERY",
		AccessLevel: types.AccessSealedKey,
		ValidUntil:  nowMS() - 1,
	})
	if err != nil {
		t.Fatalf("issue expired credential: %v", err)
	}
	if _, err := c.RefreshCredential(ctx, expired, user, "SDK_DELIVERY", 0); err != credential.ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	// After the held credential is released -> refuse (the sweep triggers the release).
	c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{SessionID: session, TaskID: task, TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_VERIFY_OPEN_TIMEOUT, Height: 900})
	if _, err := c.RefreshCredential(ctx, cred, user, "SDK_DELIVERY", 0); err == nil {
		t.Fatal("refresh must be denied after custody released")
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
			if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
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

func TestPrepareChallengeNeverReopensBelowObservedHeight(t *testing.T) {
	facts := newChallengeFacts(99, "PENDING")
	c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
	if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
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

func newChallengeFacts(height uint64, status string) *chainFactsFake {
	return &chainFactsFake{
		height: height,
		tasks: map[string]chaincli.OnChainTask{
			taskKey("session-1", "task-1"): {
				SessionID: "session-1", TaskID: "task-1",
				State: types.Settled, TaskVerdict: types.VerdictPass,
				Settlement: chaincli.TaskSettlementState{
					SettlementID:             "settlement-1",
					SettlementMode:           "OPTIMISTIC",
					SettlementStatus:         "SETTLED_PASS",
					SettlementHeight:         90,
					ChallengeCloseHeight:     100,
					EvidenceCleanupHeight:    150,
					OptimisticFinalityStatus: status,
					TaskFinalityHeight:       100,
					ClaimableAfterHeight:     100,
				},
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
			task.Settlement.OptimisticFinalityStatus = "UNKNOWN"
			f.tasks[taskKey("session-1", "task-1")] = task
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := newChallengeFacts(99, "PENDING")
			test.configure(facts)
			c, _ := newTestCoordinator(t, WithHeightQuerier(facts), WithTaskQuerier(facts))
			if err := c.OnOrder(context.Background(), testPlaceholderOrder("session-1", "task-1")); err != nil {
				t.Fatal(err)
			}
			_, err := c.PrepareChallenge(context.Background(), "session-1", "task-1", "VERDICT_FRAUD_PROOF")
			if !errors.Is(err, types.ErrChainStateUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
