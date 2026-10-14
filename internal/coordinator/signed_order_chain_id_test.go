package coordinator

import (
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/types"
)

// The SignedOrderV2 the SDK sent is decoded and re-encoded into the first proposal scope;
// signature_chain_id (field 4), the domain chainId the user signed under, must survive that, or the
// Keeper would rebuild the order digest under another domain. An order that does not carry it is
// refused before submission.
func TestSignedOrderSignatureChainIDSurvivesProposalScope(t *testing.T) {
	signed := testSignedOrder(testUserAddress)
	signed.SignatureChainId = 1
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	scope, existing, err := workerHandraiseScope(types.Order{SignedOrder: raw}, nil)
	if err != nil || existing != nil {
		t.Fatalf("scope = %v, existing = %v, err = %v", scope, existing, err)
	}
	if err := validateSignedOrder(scope); err != nil {
		t.Fatalf("validateSignedOrder: %v", err)
	}
	msg := &taskv1.MsgSubmitWorkerHandraises{Scope: &taskv1.WorkerHandraiseScopeV1{
		Scope: &taskv1.WorkerHandraiseScopeV1_SignedOrder{SignedOrder: scope},
	}}
	encoded, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded taskv1.MsgSubmitWorkerHandraises
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.GetScope().GetSignedOrder(); got.GetSignatureChainId() != 1 || !proto.Equal(got, signed) {
		t.Fatalf("signed order in the proposal = %v, want the SDK's order with signature_chain_id 1", got)
	}

	scope.SignatureChainId = 0
	if err := validateSignedOrder(scope); err == nil {
		t.Fatal("a signed order without signature_chain_id must be refused")
	}
}
