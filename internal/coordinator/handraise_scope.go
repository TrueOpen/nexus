// This file is the admission layer from NATS hand-raises to MsgSubmitWorkerHandraises (Keeper Interface Contract
// §4.1 / §4.2.1, Implementation Design §4.2).
//
// After the bus format migration (TRUEOPEN_BUS_ENVELOPE_V2) the hand-raise payload is the frozen contract's
// task.v1.WorkerHandraiseV1 proto itself; the old msgbus JSON -> proto translation layer is gone:
// whatever bytes Cortex signed are the bytes the Builder submits. Only field validation, slot ordering
// and scope selection remain here.
//
// Boundary: service_signature is always passed through as opaque bytes. Signature verification belongs to the
// Keeper; this layer never invents framing or recomputes digests.
package coordinator

import (
	"fmt"
	"sort"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
)

// workerHandraisesV1 validates, sorts and deduplicates NATS hand-raises (already the frozen contract's
// WorkerHandraiseV1 proto: whatever bytes Cortex signed are the bytes submitted here,
// no translation).
//
// §4.2.2 requires handraises within one proposal to be strictly ascending by member.slot with unique slots -- the
// chain ORs legal bits into the stage union in this order and rejects out-of-order or duplicate slots outright.
// Hand-raises are deduplicated in the map by candidate address, so sorting must be done explicitly by slot, not address order.
func workerHandraisesV1(chainID string, input map[string]*taskv1.WorkerHandraiseV1) ([]*taskv1.WorkerHandraiseV1, error) {
	if chainID == "" {
		return nil, fmt.Errorf("worker handraise chain_id is required")
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("worker handraise set must not be empty")
	}
	handraises := make([]*taskv1.WorkerHandraiseV1, 0, len(input))
	for address, hr := range input {
		if address != hr.GetMember().GetOperatorAddress() {
			return nil, fmt.Errorf("worker handraise map identity mismatch")
		}
		if err := validateWorkerHandraiseV1(chainID, hr); err != nil {
			return nil, err
		}
		handraises = append(handraises, hr)
	}
	sort.Slice(handraises, func(i, j int) bool {
		return handraises[i].GetMember().GetSlot() < handraises[j].GetMember().GetSlot()
	})
	for i := 1; i < len(handraises); i++ {
		if handraises[i].GetMember().GetSlot() == handraises[i-1].GetMember().GetSlot() {
			return nil, fmt.Errorf("worker handraises must have unique candidate slots, slot %d is duplicated",
				handraises[i].GetMember().GetSlot())
		}
	}
	return handraises, nil
}

// validateWorkerHandraiseV1 validates one frozen-wire hand-raise field by field. service_signature is
// passed through after a length check only: verification belongs to the Keeper; Nexus does not recompute digests.
func validateWorkerHandraiseV1(chainID string, hr *taskv1.WorkerHandraiseV1) error {
	worker := hr.GetMember().GetOperatorAddress()
	if hr.GetDuty() != sharedv1.Duty_DUTY_WORKER {
		return fmt.Errorf("worker handraise %q duty must be DUTY_WORKER", worker)
	}
	if hr.GetSchemaVersion() != 1 {
		return fmt.Errorf("worker handraise %q schema_version must be 1", worker)
	}
	// chain_id is the target chain declared by the sender. It can only be accepted by the Keeper if it equals
	// the local chain, so instead of overwriting it with the local value we compare byte for byte first -- otherwise
	// a cross-chain replayed frame would be silently rewritten into a legitimate frame for this chain.
	if hr.GetChainId() != chainID {
		return fmt.Errorf("worker handraise %q chain_id %q does not match the local Task Chain %q",
			worker, hr.GetChainId(), chainID)
	}
	if len(hr.GetTaskId()) != 32 || len(hr.GetTaskHash()) != 32 {
		return fmt.Errorf("worker handraise %q task identity must be 32 raw bytes", worker)
	}
	if len(hr.GetMember().GetCandidatePoolSnapshotId()) != 32 {
		return fmt.Errorf("worker handraise %q candidate_pool_snapshot_id must be 32 raw bytes", worker)
	}
	if len(hr.GetServiceSignature()) != 64 {
		return fmt.Errorf("worker handraise %q service_signature must be 64 raw bytes", worker)
	}
	if worker == "" {
		return fmt.Errorf("worker handraise member.operator_address is required")
	}
	if hr.GetMember().GetSlotVersion() == 0 {
		return fmt.Errorf("worker handraise %q member.slot_version is required", worker)
	}
	if hr.GetModelId() == "" || hr.GetProfileVersion() == 0 {
		return fmt.Errorf("worker handraise %q model_id and profile_version are required", worker)
	}
	// service_authorization_nonce is the nonce of the operator's current service binding, not a per-message
	// counter (§4.1); 0 means Cortex did not fill it and the chain will reject.
	if hr.GetServiceAuthorizationNonce() == 0 {
		return fmt.Errorf("worker handraise %q service_authorization_nonce is required", worker)
	}
	if hr.GetExpiryHeight() == 0 {
		return fmt.Errorf("worker handraise %q expiry_height is required", worker)
	}
	return nil
}

// workerHandraiseScope selects the single proposal scope per §4.2.1.
//
// The first proposal must carry signed_order: the task does not exist on-chain yet and the Keeper admits the
// order from the user-signed SignedOrderV2. Later proposals must carry existing_task instead; both set or
// both empty is rejected. The criterion is "does the chain already have an authoritative task_hash" -- it can
// only come from on-chain query/event (Nexus creates no consensus fact), so acceptedTaskHash present = later proposal.
//
// signed_order can only come from the SDK: the user signed the frozen TaskOrderV2, and Nexus has neither that
// signature nor the right to rebuild the order. While the SDK still sends the old JSON envelope, order.SignedOrder
// is empty and a first proposal cannot be validly assembled; we return an error rather than forge one.
func workerHandraiseScope(order types.Order, acceptedTaskHash []byte) (*taskv1.SignedOrderV2, *taskv1.ExistingTaskRefV1, error) {
	if len(acceptedTaskHash) > 0 {
		taskID, err := nodecontract.Hash32Bytes("task_id", order.TaskID)
		if err != nil {
			return nil, nil, err
		}
		if len(acceptedTaskHash) != 32 {
			return nil, nil, fmt.Errorf("accepted task_hash must be 32 raw bytes, got %d", len(acceptedTaskHash))
		}
		return nil, &taskv1.ExistingTaskRefV1{
			TaskId:   taskID,
			TaskHash: append([]byte(nil), acceptedTaskHash...),
		}, nil
	}
	if len(order.SignedOrder) == 0 {
		return nil, nil, fmt.Errorf("first proposal requires a SDK-provided SignedOrderV2 " +
			"(order_envelope still carries the legacy json envelope)")
	}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(order.SignedOrder, &signed); err != nil {
		return nil, nil, fmt.Errorf("decode SignedOrderV2: %w", err)
	}
	return &signed, nil, nil
}
