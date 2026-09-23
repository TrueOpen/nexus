package taskdata

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type recoveryOrderState struct {
	accepted bool
	terminal bool
	err      error
}

func (s recoveryOrderState) HasAcceptedOrder(context.Context, ObjectKey) (bool, error) {
	return s.accepted, s.err
}

func (s recoveryOrderState) HasTerminatedOrder(context.Context, ObjectKey) (bool, error) {
	return s.terminal, s.err
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
