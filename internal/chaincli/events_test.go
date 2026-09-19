package chaincli

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
)

// The frozen contract carries session_id / task_id as bytes; tests use canonical 32-byte values throughout.
var (
	testSessionIDBytes = mustHash32("11")
	testTaskIDBytes    = mustHash32("22")
	testOtherIDBytes   = mustHash32("33")
	testSessionIDHex   = hex.EncodeToString(testSessionIDBytes)
	testTaskIDHex      = hex.EncodeToString(testTaskIDBytes)
	testOtherIDHex     = hex.EncodeToString(testOtherIDBytes)
)

func mustHash32(seed string) []byte {
	raw, err := hex.DecodeString(strings.Repeat(seed, 32))
	if err != nil {
		panic(err)
	}
	return raw
}

func TestTaskEventServiceProcedureMatchesNode(t *testing.T) {
	if got, want := taskv1connect.TaskEventServiceSubscribeTaskEventsProcedure,
		"/task.v1.TaskEventService/SubscribeTaskEvents"; got != want {
		t.Fatalf("procedure = %q, want %q", got, want)
	}
}

// The frozen contract deregistered the whole SettlementBuildFacts RPC; this procedure
// constant must no longer appear in the mirror. QueryTask remains.
func TestSettlementBuildFactsProcedureIsGone(t *testing.T) {
	if got, want := taskv1connect.QueryTaskProcedure, "/task.v1.Query/Task"; got != want {
		t.Fatalf("query task procedure = %q, want %q", got, want)
	}
	// Since wire v0.4.1 the FullResultReveal Queries were removed together with
	// MsgSubmitFullResultReveal; Verifier results are carried by ResultReceipt.
	for _, procedure := range []string{
		taskv1connect.QueryInferReceiptProcedure,
		taskv1connect.QueryResultReceiptProcedure,
	} {
		if strings.Contains(procedure, "SettlementBuildFacts") {
			t.Fatalf("procedure %q still references SettlementBuildFacts", procedure)
		}
	}
}

func TestTaskEventToChainEventMapsStableEnvelope(t *testing.T) {
	event, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "v1:42:0:3:1", ChainHeight: 42, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 3, EventIndex: 1,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code:    sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_COMMIT_ACCEPTED,
		Targets: []*sharedv1.EventTarget{{Role: sharedv1.EventRole_EVENT_ROLE_VERIFIER, Address: "trueopen1verifier"}},
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_CommitAccepted{
				CommitAccepted: &taskv1.EventCommitAccepted{
					SessionId: testSessionIDBytes, TaskId: testTaskIDBytes, Verifier: "trueopen1verifier",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventVerifyCommitAccepted || event.EventCode != "COMMIT_ACCEPTED" || !event.TaskNotification {
		t.Fatalf("event = %+v", event)
	}
	if event.SessionID != testSessionIDHex || event.TaskID != testTaskIDHex || event.Height != 42 {
		t.Fatalf("event identity = %+v", event)
	}
	if got := event.Attrs["verifier_operator_address"]; got != "trueopen1verifier" {
		t.Fatalf("verifier_operator_address = %q", got)
	}
}

// Since wire v0.4.1 the Verifier result on-chain event is RESULT_ACCEPTED
// (ResultReceiptV2); the old FULL_RESULT_REVEAL_ACCEPTED was removed together with
// MsgSubmitFullResultReveal. verifier / verify_round / result_payload_hash on the payload
// must all be exported; this code has no dedicated local event type yet, so it degrades
// to TaskStateChanged like an unregistered code and goes through Query reconciliation.
func TestTaskEventToChainEventExportsResultAcceptedAttrs(t *testing.T) {
	payloadHash := mustHash32("44")
	event, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "v1:43:0:3:1", ChainHeight: 43, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 3, EventIndex: 1,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code:    sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_RESULT_ACCEPTED,
		Targets: []*sharedv1.EventTarget{{Role: sharedv1.EventRole_EVENT_ROLE_VERIFIER, Address: "trueopen1verifier"}},
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_ResultAccepted{
				ResultAccepted: &taskv1.EventResultAccepted{
					SessionId: testSessionIDBytes, TaskId: testTaskIDBytes, VerifyRound: 1,
					Verifier: "trueopen1verifier", ResultPayloadHash: payloadHash,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventTaskStateChanged || event.EventCode != "RESULT_ACCEPTED" || !event.TaskNotification {
		t.Fatalf("event = %+v", event)
	}
	if event.SessionID != testSessionIDHex || event.TaskID != testTaskIDHex || event.Height != 43 {
		t.Fatalf("event identity = %+v", event)
	}
	if got := event.Attrs["verifier"]; got != "trueopen1verifier" {
		t.Fatalf("verifier = %q", got)
	}
	if got := event.Attrs["verifier_operator_address"]; got != "trueopen1verifier" {
		t.Fatalf("verifier_operator_address = %q", got)
	}
	if got := event.Attrs["verify_round"]; got != "1" {
		t.Fatalf("verify_round = %q", got)
	}
	if got := event.Attrs["result_payload_hash"]; got != hex.EncodeToString(payloadHash) {
		t.Fatalf("result_payload_hash = %q", got)
	}
}

// DEADLINE_SWEPT is the inclusion confirmation event of MsgSweepDeadline. Both
// deadline_kind and transition_code must be exported: only the latter tells whether the
// task really converged to a terminal state; without it the coordinator must fall back
// to Query reconciliation instead of guessing locally.
func TestTaskEventToChainEventExportsDeadlineSweepTransition(t *testing.T) {
	event, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "v1:77:0:1:0", ChainHeight: 77, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 1,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DEADLINE_SWEPT,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DeadlineSwept{
				DeadlineSwept: &taskv1.EventDeadlineSwept{
					SessionId:      testSessionIDBytes,
					TaskId:         testTaskIDBytes,
					DeadlineKind:   taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT,
					TransitionCode: taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_COMMIT_CLOSED,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventSweepDeadlineAccepted || event.EventCode != "DEADLINE_SWEPT" {
		t.Fatalf("event = %+v", event)
	}
	if got := event.Attrs["deadline_kind"]; got != "VERIFY_COMMIT" {
		t.Fatalf("deadline_kind = %q", got)
	}
	if got := event.Attrs["transition_code"]; got != "COMMIT_CLOSED" {
		t.Fatalf("transition_code = %q", got)
	}
}

// An unregistered code must degrade to TaskStateChanged so the coordinator goes through
// Query reconciliation, rather than being treated as some known event.
func TestTaskEventToChainEventKeepsUnknownCodeQueryFirst(t *testing.T) {
	event, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "opaque", ChainHeight: 99, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 1, EventIndex: 2,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1(200),
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventTaskStateChanged || !event.TaskNotification || event.EventCode != "200" {
		t.Fatalf("event = %+v", event)
	}
}

// The payload oneof field number must equal the envelope's code (frozen contract §5.11);
// the old code+19 offset no longer holds.
func TestTaskEventToChainEventRejectsCodePayloadMismatch(t *testing.T) {
	_, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "opaque", ChainHeight: 1, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_CommitAccepted{
				CommitAccepted: &taskv1.EventCommitAccepted{SessionId: testSessionIDBytes, TaskId: testTaskIDBytes},
			},
		},
	})
	if err == nil {
		t.Fatal("code/payload mismatch must fail")
	}
}

func TestTaskEventToChainEventRejectsPayloadIdentityMismatch(t *testing.T) {
	_, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "opaque", ChainHeight: 1, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_WorkerAssignmentFinalized{
				WorkerAssignmentFinalized: &taskv1.EventWorkerAssignmentFinalized{
					SessionId: testOtherIDBytes, TaskId: testTaskIDBytes,
				},
			},
		},
	})
	if err == nil {
		t.Fatal("payload identity mismatch must fail")
	}
}

// Since wire v0.4.1 BuilderSet rotation has its own event code BUILDER_SET_UPDATED
// (code 60), which the protocol event side uses for local mapping; the short name strips
// the PROTOCOL_EVENT_CODE_V1_ prefix.
func TestProtocolEventCodeNameStripsPrefix(t *testing.T) {
	if got := protocolEventCodeName(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED); got != "SERVICE_KEY_ROTATED" {
		t.Fatalf("code name = %q", got)
	}
	if got := protocolEventCodeName(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED); got != "BUILDER_SET_UPDATED" {
		t.Fatalf("builder set code name = %q", got)
	}
	if code, ok := sharedv1.ProtocolEventCodeV1_value["PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED"]; !ok || code != 60 {
		t.Fatalf("BUILDER_SET_UPDATED code = %d, ok = %v; want 60", code, ok)
	}
}

// SESSION_CREATED (§5.11 code 1) is a session-level event: the wire EventSessionCreated
// has no task_id field, yet node still pushes it on the task stream for session
// subscriptions. It is not an invalid envelope, just useless to the coordinator; the
// mapping layer must use a sentinel error to tell the subscription loop "skip and advance
// the cursor" rather than killing the whole subscription.
func TestTaskEventToChainEventSkipsSessionScopedEvent(t *testing.T) {
	_, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "opaque", ChainHeight: 1, SessionId: testSessionIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_CREATED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionCreated{
				SessionCreated: &taskv1.EventSessionCreated{SessionId: testSessionIDBytes, Owner: "trueopen1owner", Nonce: 1},
			},
		},
	})
	if !errors.Is(err, errSessionScopedTaskEvent) {
		t.Fatalf("err = %v, want errSessionScopedTaskEvent", err)
	}
}

// A task-level event code missing task_id is still an invalid envelope: admitting
// session-level events must not turn every empty task_id into something skippable.
func TestTaskEventToChainEventStillRejectsMissingTaskIDOnTaskScopedEvent(t *testing.T) {
	_, err := taskEventToChainEvent(&taskv1.TaskEvent{
		Cursor: "opaque", ChainHeight: 1, SessionId: testSessionIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_WorkerAssignmentFinalized{
				WorkerAssignmentFinalized: &taskv1.EventWorkerAssignmentFinalized{SessionId: testSessionIDBytes},
			},
		},
	})
	if err == nil || errors.Is(err, errSessionScopedTaskEvent) {
		t.Fatalf("err = %v, want a hard compound-key error", err)
	}
}
