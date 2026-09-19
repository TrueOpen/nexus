package chaincli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The frozen contract unified the event model into "envelope + numeric
// hub.v1.ProtocolEventCodeV1 code + typed payload oneof partitioned by code": the
// local TaskEventCode / ProtocolEventCode enums were removed, session_id / task_id / all
// hashes are bytes, and the payload oneof member's field number equals the code itself
// (the old contract used code+19).
//
// The nexus-side ChainEvent contract is unchanged: IDs still propagate upward as
// lowercase hex strings, and when Attrs are missing the coordinator falls back to Query
// reconciliation (taskEventNeedsQuery), so leaving facts that do not exist on the new
// wire empty is a safe degradation; nothing needs to be fabricated here.
const protocolEventCodePrefix = "PROTOCOL_EVENT_CODE_V1_"

func taskEventToChainEvent(event *taskv1.TaskEvent) (ChainEvent, error) {
	if event == nil {
		return ChainEvent{}, fmt.Errorf("task event is required")
	}
	if strings.TrimSpace(event.GetCursor()) == "" {
		return ChainEvent{}, fmt.Errorf("task event cursor is required")
	}
	sessionID := hex.EncodeToString(event.GetSessionId())
	taskID := hex.EncodeToString(event.GetTaskId())
	if sessionID == "" {
		return ChainEvent{}, fmt.Errorf("task event session_id is required")
	}
	if taskID == "" {
		if taskEventIsSessionScoped(event) {
			return ChainEvent{}, errSessionScopedTaskEvent
		}
		return ChainEvent{}, fmt.Errorf("task event compound key is required")
	}
	if event.GetChainHeight() == 0 || event.GetChainHeight() > math.MaxInt64 {
		return ChainEvent{}, fmt.Errorf("task event chain height is invalid")
	}
	if event.GetCode() == sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_UNSPECIFIED {
		return ChainEvent{}, fmt.Errorf("task event code is required")
	}
	if err := validateTaskEventPayload(event, sessionID, taskID); err != nil {
		return ChainEvent{}, err
	}
	code := protocolEventCodeName(event.GetCode())
	return ChainEvent{
		Type:             taskEventType(code),
		EventCode:        code,
		SessionID:        sessionID,
		TaskID:           taskID,
		Height:           int64(event.GetChainHeight()),
		Attrs:            taskEventAttributes(event),
		TaskNotification: true,
	}, nil
}

// errSessionScopedTaskEvent marks a valid session-level event the coordinator has no use
// for (currently only §5.11 code 1 SESSION_CREATED): the wire payload has no task_id by
// design, and node still pushes it on the task stream for session subscriptions. The
// subscription loop must advance the cursor past it and keep receiving, not treat it as a
// bad envelope and drop the stream; otherwise a reconnect receives the same event from the
// same position and backs off forever.
var errSessionScopedTaskEvent = errors.New("task event is session-scoped")

// taskEventIsSessionScoped reports whether the typed payload for the envelope's code has
// no task_id field at all. Only codes known to this mirror count: unknown codes must not
// be admitted by guessing.
func taskEventIsSessionScoped(event *taskv1.TaskEvent) bool {
	code := protoreflect.FieldNumber(int32(event.GetCode()))
	field := (&taskv1.TaskProtocolEventPayloadV1{}).ProtoReflect().Descriptor().Fields().ByNumber(code)
	if field == nil || field.Message() == nil {
		return false
	}
	return field.Message().Fields().ByName("task_id") == nil
}

// validateTaskEventPayload asserts that the payload oneof field number equals the
// envelope's code and that the session/task identity in the payload matches the envelope
// (Keeper Interface Contract §5.11).
//
// This validation only applies to codes known to this mirror: if the typed_event oneof of
// TaskProtocolEventPayloadV1 has no such field number, the code is either not a Task-domain
// payload or not yet known here, and it goes through Query reconciliation as an unknown
// code instead of being rejected as an invalid envelope.
func validateTaskEventPayload(event *taskv1.TaskEvent, sessionID, taskID string) error {
	code := int32(event.GetCode())
	descriptor := (&taskv1.TaskProtocolEventPayloadV1{}).ProtoReflect().Descriptor()
	if descriptor.Fields().ByNumber(protoreflect.FieldNumber(code)) == nil {
		return nil
	}
	payload := event.GetPayload()
	if payload == nil {
		return fmt.Errorf("task event %s payload is required", protocolEventCodeName(event.GetCode()))
	}
	message := payload.ProtoReflect()
	field := message.WhichOneof(message.Descriptor().Oneofs().ByName("typed_event"))
	if field == nil {
		return fmt.Errorf("task event %s payload is required", protocolEventCodeName(event.GetCode()))
	}
	if int32(field.Number()) != code {
		return fmt.Errorf("task event code %s does not match payload %s", protocolEventCodeName(event.GetCode()), field.Name())
	}
	if err := validateTaskEventPayloadIdentity(message.Get(field).Message(), sessionID, taskID); err != nil {
		return fmt.Errorf("task event %s payload: %w", protocolEventCodeName(event.GetCode()), err)
	}
	return nil
}

func validateTaskEventPayloadIdentity(payload protoreflect.Message, sessionID, taskID string) error {
	fields := payload.Descriptor().Fields()
	if field := fields.ByName("session_id"); field != nil && payload.Has(field) &&
		hex.EncodeToString(payload.Get(field).Bytes()) != sessionID {
		return fmt.Errorf("session_id does not match envelope")
	}
	if field := fields.ByName("task_id"); field != nil && payload.Has(field) &&
		hex.EncodeToString(payload.Get(field).Bytes()) != taskID {
		return fmt.Errorf("task_id does not match envelope")
	}
	return nil
}

// taskEventType maps only codes whose semantics correspond one-to-one to a local event
// constant; everything else degrades to EventTaskStateChanged so the coordinator goes
// through Query reconciliation.
//
// Two local constants are deliberately unmapped: EventSampleReady and
// EventWorkerRevealAccepted. The frozen contract has neither a sample seed event nor a
// Worker reveal event (§9.4 registers no Worker reveal Msg); forcing a code would treat a
// wrong fact as a consensus fact.
func taskEventType(code string) string {
	switch code {
	case "WORKER_HANDRAISES_ACCEPTED":
		return EventAssignAccepted
	case "WORKER_ASSIGNMENT_FINALIZED":
		return EventAssignmentFinalized
	case "VERIFIER_ASSIGNMENT_FINALIZED":
		return EventOpenVerifyAccepted
	case "COMMIT_ACCEPTED":
		return EventVerifyCommitAccepted
	case "FULL_RESULT_REVEAL_ACCEPTED":
		return EventFullResultRevealAccepted
	case "TASK_SETTLED":
		return EventSettleAccepted
	case "DEADLINE_SWEPT":
		return EventSweepDeadlineAccepted
	default:
		return EventTaskStateChanged
	}
}

func protocolEventCodeName(code sharedv1.ProtocolEventCodeV1) string {
	return enumShortName(protocolEventCodePrefix, code)
}

// taskEventAttributes exports only fields that actually exist on the new payload.
//
// The old Attrs formal_verifier_set, worker_reveal_deadline_height,
// verification_sample_seed_hash, sample_seed_ready_height and swept_stage have no
// corresponding fields on the frozen contract's payload (the formal Verifier set is now
// only selected_verifiers_hash, and deadline sweep gives DeadlineKindV1), so they are no
// longer populated.
func taskEventAttributes(event *taskv1.TaskEvent) map[string]string {
	attrs := make(map[string]string)
	switch payload := event.GetPayload().GetTypedEvent().(type) {
	case *taskv1.TaskProtocolEventPayloadV1_WorkerAssignmentFinalized:
		finalized := payload.WorkerAssignmentFinalized
		attrs["winner_worker"] = finalized.GetWinnerWorker()
		attrs["worker_operator_address"] = finalized.GetWinnerWorker()
		attrs["infer_deadline_height"] = strconv.FormatUint(finalized.GetInferDeadline(), 10)
	case *taskv1.TaskProtocolEventPayloadV1_VerifierAssignmentFinalized:
		finalized := payload.VerifierAssignmentFinalized
		attrs["selected_verifiers_hash"] = hex.EncodeToString(finalized.GetSelectedVerifiersHash())
		attrs["commit_deadline_height"] = strconv.FormatUint(finalized.GetCommitDeadline(), 10)
		attrs["verify_deadline_height"] = strconv.FormatUint(finalized.GetVerifyDeadline(), 10)
	case *taskv1.TaskProtocolEventPayloadV1_RevealPhaseStarted:
		attrs["reveal_deadline_height"] = strconv.FormatUint(payload.RevealPhaseStarted.GetRevealDeadlineHeight(), 10)
	case *taskv1.TaskProtocolEventPayloadV1_InferReceiptAccepted:
		accepted := payload.InferReceiptAccepted
		attrs["worker_operator_address"] = accepted.GetWorker()
		attrs["infer_receipt_hash"] = hex.EncodeToString(accepted.GetInferReceiptHash())
		attrs["output_hash"] = hex.EncodeToString(accepted.GetOutputHash())
	case *taskv1.TaskProtocolEventPayloadV1_CommitAccepted:
		accepted := payload.CommitAccepted
		attrs["verifier"] = accepted.GetVerifier()
		attrs["verifier_operator_address"] = accepted.GetVerifier()
	case *taskv1.TaskProtocolEventPayloadV1_ResultAccepted:
		// wire v0.4.1: the Verifier result on-chain event is RESULT_ACCEPTED (ResultReceiptV2);
		// the old FULL_RESULT_REVEAL_ACCEPTED was removed together with MsgSubmitFullResultReveal.
		accepted := payload.ResultAccepted
		attrs["verifier"] = accepted.GetVerifier()
		attrs["verifier_operator_address"] = accepted.GetVerifier()
		attrs["verify_round"] = strconv.FormatUint(uint64(accepted.GetVerifyRound()), 10)
		attrs["result_payload_hash"] = hex.EncodeToString(accepted.GetResultPayloadHash())
	case *taskv1.TaskProtocolEventPayloadV1_TaskSettled:
		settled := payload.TaskSettled
		attrs["task_verdict"] = enumShortName("TASK_VERDICT_", settled.GetVerdict())
		// The challenge window is no longer published with the event (EventTaskSettled has
		// only settlement_height / task_finality_height); task_finality_height is the Task's
		// terminal height, and the challenge window is taken from QueryTask's settlement state.
		attrs["settlement_height"] = strconv.FormatUint(settled.GetSettlementHeight(), 10)
		attrs["task_finality_height"] = strconv.FormatUint(settled.GetTaskFinalityHeight(), 10)
	case *taskv1.TaskProtocolEventPayloadV1_DeadlineSwept:
		swept := payload.DeadlineSwept
		attrs["deadline_kind"] = enumShortName("DEADLINE_KIND_V1_", swept.GetDeadlineKind())
		attrs["transition_code"] = enumShortName("DEADLINE_TRANSITION_CODE_", swept.GetTransitionCode())
	}
	return attrs
}
