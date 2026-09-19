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
	policy, err := NewRecoveryPolicy(fx.authority, fx.authorizer, recoveryOrderState{accepted: true})
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
	fx.authority.task.Verifiers = nil
	if ok, err := policy.RevalidatePrepared(context.Background(), evidence); !errors.Is(err, ErrUnauthorized) || ok {
		t.Fatalf("revalidate removed verifier = %t, %v", ok, err)
	}

	fx.authority.task.Verifiers = []string{fx.verifier.Address()}
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

func TestRecoveryPolicyRetentionUsesTaskCleanupAndDurableTermination(t *testing.T) {
	fx := newAuthorizerFixture(t)
	policy, err := NewRecoveryPolicy(fx.authority, fx.authorizer, recoveryOrderState{accepted: true, terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := readyMetadata(ObjectKindOutput)
	fx.authority.task.Settlement.EvidenceCleanupHeight = 140

	decision, err := policy.Retention(context.Background(), metadata, 120)
	if err != nil || decision.Status != RetentionRetainedForChallenge || decision.RetainUntilHeight != 140 || decision.Delete {
		t.Fatalf("retained decision = %+v, %v", decision, err)
	}
	decision, err = policy.Retention(context.Background(), metadata, 140)
	if err != nil || decision.Status != RetentionEligibleForCleanup || !decision.Delete {
		t.Fatalf("cleanup decision = %+v, %v", decision, err)
	}

	fx.authority.err = chaincli.ErrNotFound
	input := readyMetadata(ObjectKindInput)
	input.RetainUntilHeight = 130
	decision, err = policy.Retention(context.Background(), input, 130)
	if err != nil || decision.Status != RetentionEligibleForCleanup || !decision.Delete {
		t.Fatalf("terminated input decision = %+v, %v", decision, err)
	}
}

func TestRecoveryPolicyRetentionFailsClosedForMissingNonInputAndQueryOutage(t *testing.T) {
	fx := newAuthorizerFixture(t)
	policy, err := NewRecoveryPolicy(fx.authority, fx.authorizer, recoveryOrderState{terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	fx.authority.err = chaincli.ErrNotFound
	if _, err := policy.Retention(context.Background(), readyMetadata(ObjectKindEvidenceManifest), 200); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("missing evidence error = %v", err)
	}
	fx.authority.err = errors.New("node offline")
	if _, err := policy.Retention(context.Background(), readyMetadata(ObjectKindInput), 200); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("query outage error = %v", err)
	}
}

// While the task is unsettled, the retention decision must keep the object's existing
// retention height (the one signed in the storage confirmation) and must not return 0:
// otherwise the periodic sweep would erase a signed commitment.
func TestRecoveryPolicyRetentionKeepsLeaseWhileTaskUnsettled(t *testing.T) {
	fx := newAuthorizerFixture(t)
	policy, err := NewRecoveryPolicy(fx.authority, fx.authorizer, recoveryOrderState{accepted: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := readyMetadata(ObjectKindOutput)
	metadata.RetainUntilHeight = 186
	fx.authority.task.Settlement.EvidenceCleanupHeight = 0

	decision, err := policy.Retention(context.Background(), metadata, 150)
	if err != nil || decision.Status != RetentionActive || decision.Delete {
		t.Fatalf("unsettled decision = %+v, %v", decision, err)
	}
	if decision.RetainUntilHeight != 186 {
		t.Fatalf("unsettled decision retain_until_height = %d, want 186 (keep the object's existing lease)", decision.RetainUntilHeight)
	}
}
