package taskdata

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type recoveryOrderState struct {
	accepted bool
	terminal bool
	live     bool
	err      error
	liveErr  error
}

func (s recoveryOrderState) HasAcceptedOrder(context.Context, ObjectKey) (bool, error) {
	return s.accepted, s.err
}

func (s recoveryOrderState) HasTerminatedOrder(context.Context, ObjectKey) (bool, error) {
	return s.terminal, s.err
}

func (s recoveryOrderState) HasLiveTask(context.Context, ObjectKey) (bool, error) {
	return s.live, s.liveErr
}

func TestRecoveryPolicyRevalidatesPreparedUploaderAndAcceptedReceipt(t *testing.T) {
	fx := newAuthorizerFixture(t)
	policy, err := NewRecoveryPolicy(fx.authority, &fakeCleanup{err: chaincli.ErrNotFound}, fx.authorizer, recoveryOrderState{accepted: true})
	if err != nil {
		t.Fatal(err)
	}

	evidence := readyMetadata(ObjectKindEvidenceManifest)
	evidence.State = StatePrepared
	evidence.Uploader = fx.verifier.Address()
	evidence.Key.EvidenceProducerKind = EvidenceProducerVerifier
	evidence.Key.EvidenceKind = EvidenceKindVerifierValueOpening
	evidence.Key.ProducerOperator = fx.verifier.Address()
	if ok, err := policy.RevalidatePrepared(context.Background(), evidence); err != nil || !ok {
		t.Fatalf("revalidate evidence = %t, %v", ok, err)
	}
	rounds := fx.authority.task.VerifierRounds
	fx.authority.task.VerifierRounds = nil
	if ok, err := policy.RevalidatePrepared(context.Background(), evidence); !errors.Is(err, ErrUnauthorized) || ok {
		t.Fatalf("revalidate removed verifier = %t, %v", ok, err)
	}

	fx.authority.task.VerifierRounds = rounds
	output := readyMetadata(ObjectKindOutput)
	output.State = StatePrepared
	output.Uploader = fx.worker.Address()
	receipt := validReceipt(t, fx, output)
	output.Receipt = &receipt
	fx.authority.task.InferReceipt = chaincli.InferReceiptState{
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, OutputHash: receipt.OutputHash,
		ServiceSignature: receipt.ServiceSignature, AcceptedItemHash: "accepted-receipt",
	}
	output.AcceptedReceiptHash = "accepted-receipt"
	if ok, err := policy.RevalidatePrepared(context.Background(), output); err != nil || !ok {
		t.Fatalf("revalidate output = %t, %v", ok, err)
	}
}

// fakeCleanup answers QueryEvidenceCleanup with one status for every task and counts calls.
type fakeCleanup struct {
	status chaincli.EvidenceCleanupStatus
	err    error
	calls  int
}

func (f *fakeCleanup) QueryEvidenceCleanup(context.Context, string) (chaincli.EvidenceCleanupStatus, error) {
	f.calls++
	return f.status, f.err
}

// A task on chain is kept with its signed lease until the chain starts compacting it, and deleted
// once it has (RUNNING or COMPACTED). An INPUT whose order never reached the chain follows the
// pre-chain lease and the local order termination.
func TestRecoveryPolicyRetentionFollowsChainCleanup(t *testing.T) {
	fx := newAuthorizerFixture(t)
	cleanup := &fakeCleanup{status: chaincli.EvidenceCleanupNotScheduled}
	policy, err := NewRecoveryPolicy(fx.authority, cleanup, fx.authorizer, recoveryOrderState{accepted: true, terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := readyMetadata(ObjectKindOutput)
	metadata.RetainUntilHeight = 186

	decision, err := policy.Retention(context.Background(), metadata, 120)
	if err != nil || decision.Status != RetentionActive || decision.Delete || decision.RetainUntilHeight != 186 {
		t.Fatalf("not scheduled decision = %+v, %v (want active, keeping the lease 186)", decision, err)
	}
	for _, status := range []chaincli.EvidenceCleanupStatus{chaincli.EvidenceCleanupRunning, chaincli.EvidenceCleanupCompacted} {
		fresh, err := NewRecoveryPolicy(fx.authority, &fakeCleanup{status: status}, fx.authorizer, recoveryOrderState{})
		if err != nil {
			t.Fatal(err)
		}
		decision, err := fresh.Retention(context.Background(), metadata, 121)
		if err != nil || decision.Status != RetentionEligibleForCleanup || !decision.Delete || decision.RetainUntilHeight != 121 {
			t.Fatalf("%s decision = %+v, %v", status, decision, err)
		}
		if !validRetentionDecision(decision, 121) {
			t.Fatalf("%s decision is rejected by the sweep: %+v", status, decision)
		}
	}

	cleanup.err = chaincli.ErrNotFound
	input := readyMetadata(ObjectKindInput)
	input.RetainUntilHeight = 130
	decision, err = policy.Retention(context.Background(), input, 130)
	if err != nil || decision.Status != RetentionEligibleForCleanup || !decision.Delete {
		t.Fatalf("terminated pre-chain input decision = %+v, %v", decision, err)
	}
}

// One sweep asks the chain once per task, not once per object; a started cleanup is never asked
// again; an outage is not cached.
func TestRecoveryPolicyRetentionCachesCleanupQueries(t *testing.T) {
	fx := newAuthorizerFixture(t)
	cleanup := &fakeCleanup{status: chaincli.EvidenceCleanupNotScheduled}
	policy, err := NewRecoveryPolicy(fx.authority, cleanup, fx.authorizer, recoveryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	objects := []Metadata{readyMetadata(ObjectKindInput), readyMetadata(ObjectKindOutput), readyMetadata(ObjectKindEvidenceManifest)}
	sweep := func(height uint64) {
		t.Helper()
		for _, metadata := range objects {
			if _, err := policy.Retention(context.Background(), metadata, height); err != nil {
				t.Fatal(err)
			}
		}
	}
	sweep(150)
	if cleanup.calls != 1 {
		t.Fatalf("one sweep made %d cleanup queries, want 1", cleanup.calls)
	}
	sweep(151)
	if cleanup.calls != 2 {
		t.Fatalf("a not-scheduled task must be asked again at a new height: %d calls", cleanup.calls)
	}
	cleanup.status = chaincli.EvidenceCleanupCompacted
	sweep(152)
	sweep(153)
	if cleanup.calls != 3 {
		t.Fatalf("a compacted task must not be asked again: %d calls", cleanup.calls)
	}

	outage := &fakeCleanup{err: errors.New("node offline")}
	policy, err = NewRecoveryPolicy(fx.authority, outage, fx.authorizer, recoveryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := policy.Retention(context.Background(), readyMetadata(ObjectKindOutput), 150); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatalf("outage error = %v", err)
		}
	}
	if outage.calls != 2 {
		t.Fatalf("an outage must not be cached: %d calls", outage.calls)
	}
}

func TestRecoveryPolicyRetentionFailsClosedForMissingNonInputAndQueryOutage(t *testing.T) {
	fx := newAuthorizerFixture(t)
	cleanup := &fakeCleanup{err: chaincli.ErrNotFound}
	policy, err := NewRecoveryPolicy(fx.authority, cleanup, fx.authorizer, recoveryOrderState{terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Retention(context.Background(), readyMetadata(ObjectKindEvidenceManifest), 200); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("missing evidence error = %v", err)
	}
	cleanup.err = errors.New("node offline")
	if _, err := policy.Retention(context.Background(), readyMetadata(ObjectKindInput), 200); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("query outage error = %v", err)
	}
}

// An INPUT the chain does not know, with no local end of its order (stored by a release that
// marked no dropped order, a marker that was not written, or a group member's copy), is released
// once the chain is unmarkedInputReleaseMarginBlocks past its retention height and this Builder
// tracks no task for it; never while it does, nor while the chain holds the task.
func TestRecoveryPolicyReleasesUnmarkedPreChainInputPastItsRetention(t *testing.T) {
	fx := newAuthorizerFixture(t)
	input := readyMetadata(ObjectKindInput)
	input.RetainUntilHeight = 130
	release := input.RetainUntilHeight + unmarkedInputReleaseMarginBlocks
	decide := func(cleanup *fakeCleanup, orders recoveryOrderState, metadata Metadata, height uint64) (RetentionDecision, error) {
		t.Helper()
		policy, err := NewRecoveryPolicy(fx.authority, cleanup, fx.authorizer, orders)
		if err != nil {
			t.Fatal(err)
		}
		return policy.Retention(context.Background(), metadata, height)
	}
	notOnChain := func() *fakeCleanup { return &fakeCleanup{err: chaincli.ErrNotFound} }

	for _, height := range []uint64{input.RetainUntilHeight - 1, input.RetainUntilHeight, release - 1} {
		decision, err := decide(notOnChain(), recoveryOrderState{}, input, height)
		if err != nil || decision.Status != RetentionActive || decision.Delete {
			t.Fatalf("unmarked input at %d = %+v, %v; want kept until %d", height, decision, err, release)
		}
	}
	decision, err := decide(notOnChain(), recoveryOrderState{}, input, release)
	if err != nil || decision.Status != RetentionEligibleForCleanup || !decision.Delete || decision.RetainUntilHeight != input.RetainUntilHeight {
		t.Fatalf("unmarked input at %d = %+v, %v; want released", release, decision, err)
	}
	if !validRetentionDecision(decision, release) {
		t.Fatalf("release decision is rejected by the sweep: %+v", decision)
	}

	// A task still tracked here keeps it, however late; an unreadable local state fails closed.
	decision, err = decide(notOnChain(), recoveryOrderState{live: true}, input, release+100000)
	if err != nil || decision.Delete {
		t.Fatalf("input of a tracked task = %+v, %v; want kept", decision, err)
	}
	if _, err := decide(notOnChain(), recoveryOrderState{liveErr: errors.New("disk")}, input, release); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("unreadable local task state error = %v", err)
	}
	// A task the chain holds follows the chain's cleanup only.
	decision, err = decide(&fakeCleanup{status: chaincli.EvidenceCleanupNotScheduled}, recoveryOrderState{}, input, release+100000)
	if err != nil || decision.Delete {
		t.Fatalf("input of a task on chain = %+v, %v; want kept", decision, err)
	}
	// A retention height whose margin overflows is never released by the fallback.
	far := input
	far.RetainUntilHeight = math.MaxUint64 - unmarkedInputReleaseMarginBlocks/2
	decision, err = decide(notOnChain(), recoveryOrderState{}, far, math.MaxUint64)
	if err != nil || decision.Delete {
		t.Fatalf("input with an overflowing release height = %+v, %v; want kept", decision, err)
	}
	// An input without a retention height is never released by it either.
	unleased := input
	unleased.RetainUntilHeight = 0
	decision, err = decide(notOnChain(), recoveryOrderState{}, unleased, release)
	if err != nil || decision.Delete {
		t.Fatalf("input without a retention height = %+v, %v; want kept", decision, err)
	}
}
