package nodecontract

import (
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/eip712"
)

// The order domain a SignedOrderV2 is signed in. The domain chainId is the signer's
// signature_chain_id; the typed chainId string is the order's own chain_id.
const (
	TaskOrderDomainName    = "TrueOpen Task Order"
	TaskOrderDomainVersion = "3"

	taskOrderType = "TaskOrder(string chainId,string user,bytes32 sessionId,uint64 orderSequence," +
		"bytes32 modelId,uint32 profileVersion,string maxFee,string feeDenom,uint64 earliestSubmitHeight," +
		"uint64 orderExpireHeight,bytes32 taskHash)"
)

// TaskOrderDigestV3 is the EIP-712 digest a SignedOrderV2 signs over order. feeDenom is not an
// order field: it is the chain's business_denom (hub Params phase0.business_denom). taskHash is
// recomputed from the order, never taken from the caller. The user's wallet and a key registered
// on the session sign this same digest; the recovered address tells them apart.
func TaskOrderDigestV3(order *taskv1.TaskOrderV3, feeDenom string, signatureChainID uint64) ([32]byte, error) {
	if order == nil {
		return [32]byte{}, fmt.Errorf("task order is required")
	}
	if !eip712.ValidSignatureChainID(signatureChainID) {
		return [32]byte{}, fmt.Errorf("signature_chain_id must be in 1..MaxInt64")
	}
	if feeDenom == "" {
		return [32]byte{}, fmt.Errorf("fee denom is required")
	}
	if len(order.GetSessionId()) != 32 || len(order.GetModelId()) != 32 {
		return [32]byte{}, fmt.Errorf("task order session_id and model_id must be 32 bytes")
	}
	taskHash, err := TaskOrderHashV3(order)
	if err != nil {
		return [32]byte{}, err
	}
	hash := eip712.HashStruct(taskOrderType,
		eip712.String(order.GetChainId()), eip712.String(order.GetUserAddress()),
		order.GetSessionId(), eip712.Uint(order.GetOrderSequence()),
		order.GetModelId(), eip712.Uint(uint64(order.GetProfileVersion())),
		eip712.String(order.GetMaxFee().GetAtomicUnits()), eip712.String(feeDenom),
		eip712.Uint(order.GetEarliestSubmitHeight()), eip712.Uint(order.GetOrderExpireHeight()),
		taskHash[:])
	separator := eip712.DomainSeparator(TaskOrderDomainName, TaskOrderDomainVersion, signatureChainID)
	return eip712.Digest(separator, hash), nil
}
