package chaincli

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

func amount(units string) *sharedv1.Amount { return &sharedv1.Amount{AtomicUnits: units} }

// sessionEvent wraps a payload in a session stream envelope without task_id.
func sessionEvent(code sharedv1.ProtocolEventCodeV1, payload *taskv1.TaskProtocolEventPayloadV1) *taskv1.TaskEvent {
	return &taskv1.TaskEvent{
		Cursor: "c1", ChainHeight: 88, SessionId: testSessionIDBytes, Code: code, Payload: payload,
	}
}

// Session-level Phase 1 events used to be skipped like SESSION_CREATED; they now reach the
// consumer as typed events, outside task notifications.
func TestSessionScopedPhase1EventsAreTyped(t *testing.T) {
	old := "trueopen1old"
	cases := []struct {
		code    sharedv1.ProtocolEventCodeV1
		payload *taskv1.TaskProtocolEventPayloadV1
		want    TypedEvent
	}{
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_DEPOSITED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionDeposited{
				SessionDeposited: &taskv1.EventSessionDeposited{SessionId: testSessionIDBytes, Owner: "trueopen1owner", Amount: amount("10"), Balance: amount("30")},
			}},
			SessionDeposited{SessionID: testSessionIDHex, Owner: "trueopen1owner", Amount: "10", Balance: "30"},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_WITHDRAW_REQUESTED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionWithdrawRequested{
				SessionWithdrawRequested: &taskv1.EventSessionWithdrawRequested{
					SessionId: testSessionIDBytes, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE, Amount: amount("30"), EffectiveHeight: 99,
				},
			}},
			SessionWithdrawRequested{SessionID: testSessionIDHex, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_CLOSE, Amount: "30", EffectiveHeight: 99},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_WITHDRAW_EFFECTIVE,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionWithdrawEffective{
				SessionWithdrawEffective: &taskv1.EventSessionWithdrawEffective{
					SessionId: testSessionIDBytes, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT, PaidAmount: amount("5"), RemainingBalance: amount("25"),
				},
			}},
			SessionWithdrawEffective{SessionID: testSessionIDHex, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT, PaidAmount: "5", RemainingBalance: "25"},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_KEY_CHANGE_REQUESTED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionKeyChangeRequested{
				SessionKeyChangeRequested: &taskv1.EventSessionKeyChangeRequested{
					SessionId: testSessionIDBytes, Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR, EffectiveHeight: 120,
				},
			}},
			SessionKeyChangeRequested{SessionID: testSessionIDHex, Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR, EffectiveHeight: 120},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_ORDER_CANCEL_REQUESTED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_OrderCancelRequested{
				OrderCancelRequested: &taskv1.EventOrderCancelRequested{SessionId: testSessionIDBytes, OrderSequence: 6, CancelEffectiveHeight: 130},
			}},
			OrderCancelRequested{SessionID: testSessionIDHex, OrderSequence: 6, CancelEffectiveHeight: 130},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_BUILDER_BOUND,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionBuilderBound{
				SessionBuilderBound: &taskv1.EventSessionBuilderBound{
					SessionId: testSessionIDBytes, OldBuilderOrEmpty: &old, NewBuilder: "trueopen1new",
					Trigger: taskv1.SessionBuilderBoundTriggerV1_SESSION_BUILDER_BOUND_TRIGGER_V1_TAKEOVER, BoundChangeHeight: 140,
				},
			}},
			SessionBuilderBound{SessionID: testSessionIDHex, OldBuilder: old, NewBuilder: "trueopen1new",
				Trigger: taskv1.SessionBuilderBoundTriggerV1_SESSION_BUILDER_BOUND_TRIGGER_V1_TAKEOVER, BoundChangeHeight: 140},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_TAKEOVER_REGISTERED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionTakeoverRegistered{
				SessionTakeoverRegistered: &taskv1.EventSessionTakeoverRegistered{
					SessionId: testSessionIDBytes, BoundBuilder: "trueopen1old", CandidateBuilder: "trueopen1new",
					OrderSequence: 7, RegisteredHeight: 135, ActivationHeight: 140,
				},
			}},
			SessionTakeoverRegistered{SessionID: testSessionIDHex, BoundBuilder: "trueopen1old", CandidateBuilder: "trueopen1new",
				OrderSequence: 7, RegisteredHeight: 135, ActivationHeight: 140},
		},
		{
			sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_TAKEOVER_VOIDED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionTakeoverVoided{
				SessionTakeoverVoided: &taskv1.EventSessionTakeoverVoided{
					SessionId: testSessionIDBytes, CandidateBuilder: "trueopen1new", OrderSequence: 7,
					Reason: taskv1.SessionTakeoverVoidReasonV1_SESSION_TAKEOVER_VOID_REASON_V1_ORDER_RECORDED,
				},
			}},
			SessionTakeoverVoided{SessionID: testSessionIDHex, CandidateBuilder: "trueopen1new", OrderSequence: 7,
				Reason: taskv1.SessionTakeoverVoidReasonV1_SESSION_TAKEOVER_VOID_REASON_V1_ORDER_RECORDED},
		},
	}
	for _, tc := range cases {
		event, err := taskEventToChainEvent(sessionEvent(tc.code, tc.payload))
		if err != nil {
			t.Fatalf("%s: %v", tc.code, err)
		}
		if event.Type != EventSessionScoped || event.TaskNotification || event.SessionID != testSessionIDHex ||
			event.TaskID != "" || event.Height != 88 || event.EventCode != protocolEventCodeName(tc.code) {
			t.Fatalf("%s: envelope = %+v", tc.code, event)
		}
		if !reflect.DeepEqual(event.Typed, tc.want) {
			t.Fatalf("%s: typed = %#v, want %#v", tc.code, event.Typed, tc.want)
		}
	}
}

// A session-level payload naming another session is a bad envelope, as for task events.
func TestSessionScopedEventRejectsAnotherSessionsPayload(t *testing.T) {
	event := sessionEvent(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_DEPOSITED,
		&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionDeposited{
			SessionDeposited: &taskv1.EventSessionDeposited{SessionId: mustHash32("99"), Amount: amount("1")},
		}})
	if _, err := taskEventToChainEvent(event); err == nil || errors.Is(err, errSessionScopedTaskEvent) {
		t.Fatalf("err = %v, want a payload identity error", err)
	}
	event.Code = sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_WITHDRAW_EFFECTIVE
	if _, err := taskEventToChainEvent(event); err == nil {
		t.Fatal("a payload for another code was accepted")
	}
}

// dispatch_recorded keeps its task notification (the coordinator reconciles the task on it) and
// now also carries the decoded record facts.
func TestDispatchRecordedStaysATaskNotificationWithTypedFacts(t *testing.T) {
	recorded := &taskv1.EventDispatchRecorded{
		SessionId: testSessionIDBytes, TaskId: testTaskIDBytes, OrderSequence: 7, Builder: "trueopen1builder",
		WinnerWorker: "trueopen1worker", DispatchRecordHash: mustHash32("a1"), DispatchTicketHash: mustHash32("a2"),
		ReferenceHeight: 100, ReservedAmount: amount("400"), InferDeadline: 160,
	}
	envelope := &taskv1.TaskEvent{
		Cursor: "c2", ChainHeight: 120, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_RECORDED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchRecorded{
			DispatchRecorded: recorded,
		}},
	}
	event, err := taskEventToChainEvent(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventTaskStateChanged || event.EventCode != "DISPATCH_RECORDED" || !event.TaskNotification ||
		event.TaskID != testTaskIDHex || event.Height != 120 {
		t.Fatalf("envelope = %+v", event)
	}
	want := DispatchRecorded{
		SessionID: testSessionIDHex, TaskID: testTaskIDHex, OrderSequence: 7, Builder: "trueopen1builder",
		WinnerWorker: "trueopen1worker", RecordHash: mustHash32("a1"), TicketHash: mustHash32("a2"),
		ReferenceHeight: 100, ReservedAmount: "400", InferDeadline: 160,
	}
	if !reflect.DeepEqual(event.Typed, want) {
		t.Fatalf("typed = %#v", event.Typed)
	}

	bad := proto.Clone(envelope).(*taskv1.TaskEvent)
	bad.GetPayload().GetDispatchRecorded().DispatchTicketHash = []byte{1}
	if _, err := taskEventToChainEvent(bad); err == nil {
		t.Fatal("a short ticket hash was accepted")
	}
}

// order_cancelled is a task event when the cancelled sequence has a task, and a session event
// when it does not; without a task it used to stop the stream as a broken envelope.
func TestOrderCancelledWithAndWithoutTask(t *testing.T) {
	payload := func(taskID []byte) *taskv1.TaskProtocolEventPayloadV1 {
		return &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_OrderCancelled{
			OrderCancelled: &taskv1.EventOrderCancelled{SessionId: testSessionIDBytes, OrderSequence: 6, TaskId: taskID},
		}}
	}
	code := sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_ORDER_CANCELLED

	withTask := sessionEvent(code, payload(testTaskIDBytes))
	withTask.TaskId = testTaskIDBytes
	event, err := taskEventToChainEvent(withTask)
	if err != nil || !event.TaskNotification || event.Type != EventTaskStateChanged ||
		!reflect.DeepEqual(event.Typed, OrderCancelled{SessionID: testSessionIDHex, OrderSequence: 6, TaskID: testTaskIDHex}) {
		t.Fatalf("with task = %+v, %v", event, err)
	}

	event, err = taskEventToChainEvent(sessionEvent(code, payload(nil)))
	if err != nil || event.TaskNotification || event.Type != EventSessionScoped ||
		!reflect.DeepEqual(event.Typed, OrderCancelled{SessionID: testSessionIDHex, OrderSequence: 6}) {
		t.Fatalf("without task = %+v, %v", event, err)
	}
}

// Session events without a Phase 1 meaning keep their old treatment.
func TestSessionCreatedIsStillSkipped(t *testing.T) {
	_, err := taskEventToChainEvent(sessionEvent(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_CREATED,
		&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionCreated{
			SessionCreated: &taskv1.EventSessionCreated{SessionId: testSessionIDBytes, Owner: "trueopen1owner"},
		}}))
	if !errors.Is(err, errSessionScopedTaskEvent) {
		t.Fatalf("err = %v", err)
	}
}

// A session can be followed for its session-level events without any tracked task, and its
// stream stays while either a task or the session watch needs it.
func TestTrackSessionEventsKeepsTheStreamUntilBothUsesEnd(t *testing.T) {
	c := &client{sessions: make(map[string]*sessionSubscription)}
	if err := c.TrackSessionEvents(testSessionIDHex); err != nil {
		t.Fatal(err)
	}
	if c.sessions[testSessionIDHex] == nil {
		t.Fatal("session not tracked")
	}
	key := TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}
	if err := c.TrackTaskEvents(key); err != nil {
		t.Fatal(err)
	}
	c.UntrackSessionEvents(testSessionIDHex)
	if c.sessions[testSessionIDHex] == nil {
		t.Fatal("untracking the session dropped the stream a task still needs")
	}
	c.UntrackTaskEvents(key)
	if c.sessions[testSessionIDHex] != nil {
		t.Fatal("stream kept after both uses ended")
	}

	if err := c.TrackTaskEvents(key); err != nil {
		t.Fatal(err)
	}
	if err := c.TrackSessionEvents(testSessionIDHex); err != nil {
		t.Fatal(err)
	}
	c.UntrackTaskEvents(key)
	if c.sessions[testSessionIDHex] == nil {
		t.Fatal("untracking the last task dropped a watched session")
	}
	c.UntrackSessionEvents(testSessionIDHex)
	if c.sessions[testSessionIDHex] != nil {
		t.Fatal("stream kept after the watch ended")
	}

	if err := c.TrackSessionEvents("not-hex"); err == nil {
		t.Fatal("a malformed session id was tracked")
	}
}
