package chaincli

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
)

const testBuilder = "trueopen1builder"

// fakeRoleStream replays role stream items without a server.
type fakeRoleStream struct {
	items []*taskv1.SubscribeRoleEventsResponse
	next  *taskv1.SubscribeRoleEventsResponse
	err   error
}

func (s *fakeRoleStream) Receive() bool {
	if len(s.items) == 0 {
		return false
	}
	s.next, s.items = s.items[0], s.items[1:]
	return true
}

func (s *fakeRoleStream) Msg() *taskv1.SubscribeRoleEventsResponse { return s.next }
func (s *fakeRoleStream) Err() error                               { return s.err }

func claimedEvent(cursor string, height uint64) *taskv1.TaskEvent {
	return &taskv1.TaskEvent{
		Cursor: cursor, ChainHeight: height, TaskId: testTaskIDBytes,
		Code:    sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_CLAIMED,
		Targets: []*sharedv1.EventTarget{{Role: sharedv1.EventRole_EVENT_ROLE_BUILDER, Address: testBuilder}},
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchCompensationClaimed{
			DispatchCompensationClaimed: &taskv1.EventDispatchCompensationClaimed{
				DispatchTicketHash: mustHash32("a2"), TaskId: testTaskIDBytes, Builder: testBuilder, Worker: "trueopen1worker",
				Amount: amount("70"), RebuttalDeadlineHeight: 260,
			},
		}},
	}
}

func challengeOpenedEvent(cursor string, height uint64) *taskv1.TaskEvent {
	return &taskv1.TaskEvent{
		Cursor: cursor, ChainHeight: height, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_OPENED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchChallengeOpened{
			DispatchChallengeOpened: &taskv1.EventDispatchChallengeOpened{
				ChallengeId: mustHash32("c1"), TaskId: testTaskIDBytes, Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP,
				Challenger: "trueopen1worker", ProofDeadlineHeightOrZero: 300,
			},
		}},
	}
}

func TestRoleEventToChainEventDecodesClaimsAndChallenges(t *testing.T) {
	event, err := roleEventToChainEvent(claimedEvent("r1", 200))
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventBuilderRole || event.EventCode != "DISPATCH_COMPENSATION_CLAIMED" || event.TaskNotification ||
		event.TaskID != testTaskIDHex || event.SessionID != "" || event.Height != 200 {
		t.Fatalf("envelope = %+v", event)
	}
	if want := (DispatchCompensationClaimed{
		TicketHash: mustHash32("a2"), TaskID: testTaskIDHex, Builder: testBuilder, Worker: "trueopen1worker",
		Amount: "70", RebuttalDeadlineHeight: 260,
	}); !reflect.DeepEqual(event.Typed, want) {
		t.Fatalf("typed = %#v", event.Typed)
	}

	event, err = roleEventToChainEvent(challengeOpenedEvent("r2", 201))
	if err != nil {
		t.Fatal(err)
	}
	if want := (DispatchChallengeOpened{
		ChallengeID: mustHash32("c1"), TaskID: testTaskIDHex, Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP,
		Challenger: "trueopen1worker", ProofDeadlineHeight: 300,
	}); !reflect.DeepEqual(event.Typed, want) {
		t.Fatalf("typed = %#v", event.Typed)
	}

	// The envelope may leave task_id to the payload.
	noTask := claimedEvent("r3", 202)
	noTask.TaskId = nil
	if event, err := roleEventToChainEvent(noTask); err != nil || event.TaskID != testTaskIDHex {
		t.Fatalf("payload task id = %+v, %v", event, err)
	}

	for name, edit := range map[string]func(*taskv1.TaskEvent){
		"no cursor": func(e *taskv1.TaskEvent) { e.Cursor = "" },
		"no height": func(e *taskv1.TaskEvent) { e.ChainHeight = 0 },
		"other code": func(e *taskv1.TaskEvent) {
			e.Code = sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_OPENED
		},
		"no payload": func(e *taskv1.TaskEvent) { e.Payload = nil },
		"other task": func(e *taskv1.TaskEvent) { e.TaskId = mustHash32("99") },
		"short ticket": func(e *taskv1.TaskEvent) {
			e.GetPayload().GetDispatchCompensationClaimed().DispatchTicketHash = []byte{1}
		},
		"unset code":    func(e *taskv1.TaskEvent) { e.Code = sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_UNSPECIFIED },
		"short task id": func(e *taskv1.TaskEvent) { e.TaskId = []byte{1} },
	} {
		bad := claimedEvent("r4", 203)
		edit(bad)
		if _, err := roleEventToChainEvent(bad); err == nil || errors.Is(err, errUnmappedRoleEvent) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}

	settled := &taskv1.TaskEvent{
		Cursor: "r5", ChainHeight: 204, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_TASK_SETTLED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_TaskSettled{
			TaskSettled: &taskv1.EventTaskSettled{TaskId: testTaskIDBytes},
		}},
	}
	if _, err := roleEventToChainEvent(settled); !errors.Is(err, errUnmappedRoleEvent) {
		t.Fatalf("unmapped code: err = %v", err)
	}
}

func TestBuilderRoleRequestNamesTheBuilderAndItsCodes(t *testing.T) {
	request := builderRoleRequest(testBuilder, "", 500)
	if request.GetOperatorAddress() != testBuilder || request.GetTargetRole() != sharedv1.EventRole_EVENT_ROLE_BUILDER ||
		request.GetFromHeight() != 500 || request.GetAfterCursor() != "" {
		t.Fatalf("request = %v", request)
	}
	want := []sharedv1.ProtocolEventCodeV1{
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_CLAIMED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_PAID,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_REBUTTED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_OPENED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_RESOLVED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_DISPATCH_FAULT_RECORDED,
	}
	if !reflect.DeepEqual(request.GetCodes(), want) {
		t.Fatalf("codes = %v", request.GetCodes())
	}
	resumed := builderRoleRequest(testBuilder, "saved", 500)
	if resumed.GetAfterCursor() != "saved" || resumed.GetFromHeight() != 0 {
		t.Fatalf("resumed request = %v", resumed)
	}
}

func newRoleTestClient(store kv.Store) *client {
	return &client{
		log:          slog.New(slog.DiscardHandler),
		cfg:          config.ChainConfig{ChainID: "trueopen-localnet-1"},
		events:       make(chan ChainEvent, 16),
		stopCh:       make(chan struct{}),
		cursorStore:  eventCursorStore{store: store},
		roleOperator: testBuilder,
	}
}

func savedRoleCursor(t *testing.T, store kv.Store) string {
	t.Helper()
	cursor, err := eventCursorStore{store: store}.Load("trueopen-localnet-1", eventCursorKindBuilderRole, testBuilder)
	if err != nil {
		t.Fatal(err)
	}
	return cursor
}

// The role stream keeps the existing cursor rule: the cursor moves past an item only after it was
// delivered (or deliberately skipped), and checkpoints move it without an event.
func TestConsumeRoleEventsDeliversThenPersistsTheCursor(t *testing.T) {
	store := kv.NewMemStore()
	c := newRoleTestClient(store)
	unmapped := &taskv1.TaskEvent{
		Cursor: "r3", ChainHeight: 203, TaskId: testTaskIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_TASK_SETTLED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_TaskSettled{
			TaskSettled: &taskv1.EventTaskSettled{TaskId: testTaskIDBytes},
		}},
	}
	stream := &fakeRoleStream{items: []*taskv1.SubscribeRoleEventsResponse{
		{Item: &taskv1.SubscribeRoleEventsResponse_Event{Event: claimedEvent("r1", 201)}},
		{Item: &taskv1.SubscribeRoleEventsResponse_Checkpoint{Checkpoint: &sharedv1.StreamCheckpoint{Cursor: "cp1", ChainHeight: 202}}},
		{Item: &taskv1.SubscribeRoleEventsResponse_Event{Event: unmapped}},
		{Item: &taskv1.SubscribeRoleEventsResponse_Event{Event: challengeOpenedEvent("r4", 204)}},
	}}
	delivered, err := c.consumeRoleEvents(context.Background(), stream)
	if !delivered || err == nil {
		t.Fatalf("delivered %v, err %v; an ended stream must report an error so it is reopened", delivered, err)
	}
	if got := savedRoleCursor(t, store); got != "r4" {
		t.Fatalf("cursor = %q, want r4", got)
	}
	var codes []string
	for len(c.events) > 0 {
		codes = append(codes, (<-c.events).EventCode)
	}
	if !reflect.DeepEqual(codes, []string{"DISPATCH_COMPENSATION_CLAIMED", "DISPATCH_CHALLENGE_OPENED"}) {
		t.Fatalf("events = %v", codes)
	}

	broken := claimedEvent("r5", 205)
	broken.Payload = nil
	stream = &fakeRoleStream{items: []*taskv1.SubscribeRoleEventsResponse{
		{Item: &taskv1.SubscribeRoleEventsResponse_Event{Event: broken}},
	}}
	if _, err := c.consumeRoleEvents(context.Background(), stream); err == nil {
		t.Fatal("a broken envelope was skipped")
	}
	if got := savedRoleCursor(t, store); got != "r4" {
		t.Fatalf("cursor moved past a broken envelope to %q", got)
	}
}

func TestProtocolEventToChainEventMapsHubOperationalEvents(t *testing.T) {
	rotated := &hubv1.ProtocolEvent{
		Cursor: "p1", ChainHeight: 300, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		Payload: &hubv1.ProtocolEventPayloadV1{TypedEvent: &hubv1.ProtocolEventPayloadV1_ServiceKeyRotated{
			ServiceKeyRotated: &hubv1.EventServiceKeyRotated{
				ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, Operator: "trueopen1worker",
				OldServiceAddress: "trueopen1old", NewServiceAddress: "trueopen1new", AuthorizationNonce: 4,
			},
		}},
	}
	event, ok, err := protocolEventToChainEvent(rotated)
	if err != nil || !ok {
		t.Fatalf("rotated: ok %v, err %v", ok, err)
	}
	if event.Type != EventHubOperational || event.EventCode != "SERVICE_KEY_ROTATED" || event.Height != 300 {
		t.Fatalf("envelope = %+v", event)
	}
	if want := (ServiceKeyRotated{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, Operator: "trueopen1worker",
		OldServiceAddress: "trueopen1old", NewServiceAddress: "trueopen1new", AuthorizationNonce: 4,
	}); !reflect.DeepEqual(event.Typed, want) {
		t.Fatalf("typed = %#v", event.Typed)
	}

	funded := &hubv1.ProtocolEvent{
		Cursor: "p2", ChainHeight: 301, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_COMPENSATION_FUNDED,
		Payload: &hubv1.ProtocolEventPayloadV1{TypedEvent: &hubv1.ProtocolEventPayloadV1_BuilderCompensationFunded{
			BuilderCompensationFunded: &hubv1.EventBuilderCompensationFunded{Builder: testBuilder, Amount: amount("100"), Balance: amount("900")},
		}},
	}
	event, ok, err = protocolEventToChainEvent(funded)
	if err != nil || !ok || !reflect.DeepEqual(event.Typed, BuilderCompensationFunded{Builder: testBuilder, Amount: "100", Balance: "900"}) {
		t.Fatalf("funded = %+v, %v, %v", event, ok, err)
	}

	setUpdated := &hubv1.ProtocolEvent{Cursor: "p3", ChainHeight: 302, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED}
	event, ok, err = protocolEventToChainEvent(setUpdated)
	if err != nil || !ok || event.Type != EventBuilderSetUpdated || event.Height != 302 || event.Typed != nil {
		t.Fatalf("builder set = %+v, %v, %v", event, ok, err)
	}

	other := &hubv1.ProtocolEvent{Cursor: "p4", ChainHeight: 303, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_REGISTERED}
	if _, ok, err := protocolEventToChainEvent(other); ok || err != nil {
		t.Fatalf("unmapped code: ok %v, err %v", ok, err)
	}

	mismatched := &hubv1.ProtocolEvent{
		Cursor: "p5", ChainHeight: 304, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		Payload: funded.GetPayload(),
	}
	if _, _, err := protocolEventToChainEvent(mismatched); err == nil {
		t.Fatal("a payload for another code was accepted")
	}
	noPayload := &hubv1.ProtocolEvent{Cursor: "p6", ChainHeight: 305, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_COMPENSATION_FUNDED}
	if _, _, err := protocolEventToChainEvent(noPayload); err == nil {
		t.Fatal("a missing payload was accepted")
	}
}

func TestProtocolEventCodesIncludeHubOperationalEvents(t *testing.T) {
	want := []sharedv1.ProtocolEventCodeV1{
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_COMPENSATION_FUNDED,
	}
	if !reflect.DeepEqual(protocolEventCodes(), want) {
		t.Fatalf("codes = %v", protocolEventCodes())
	}
}

func TestBuilderRoleCursorKeyIsScopedToTheOperator(t *testing.T) {
	key, err := eventCursorKey("chain-a", eventCursorKindBuilderRole, testBuilder)
	if err != nil || key != "chain-a|builder_role|"+testBuilder {
		t.Fatalf("key = %q, %v", key, err)
	}
	if _, err := eventCursorKey("chain-a", eventCursorKindBuilderRole, ""); err == nil {
		t.Fatal("an empty operator scope was accepted")
	}
}

// The outcomes of claims and challenges reach the Builder as typed role events.
func TestRoleEventToChainEventDecodesOutcomes(t *testing.T) {
	envelope := func(code sharedv1.ProtocolEventCodeV1, payload *taskv1.TaskProtocolEventPayloadV1) *taskv1.TaskEvent {
		return &taskv1.TaskEvent{Cursor: "o1", ChainHeight: 400, Code: code, Payload: payload}
	}
	cases := []struct {
		event *taskv1.TaskEvent
		want  TypedEvent
	}{
		{envelope(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_PAID,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchCompensationPaid{
				DispatchCompensationPaid: &taskv1.EventDispatchCompensationPaid{DispatchTicketHash: mustHash32("a2"), TaskId: testTaskIDBytes,
					Builder: testBuilder, Worker: "trueopen1worker", Amount: amount("70"), PaidAmount: amount("60"), UnfilledAmount: amount("10")},
			}}),
			DispatchCompensationPaid{TicketHash: mustHash32("a2"), TaskID: testTaskIDHex, Builder: testBuilder, Worker: "trueopen1worker",
				Amount: "70", PaidAmount: "60", UnfilledAmount: "10"}},
		{envelope(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_REBUTTED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchCompensationRebutted{
				DispatchCompensationRebutted: &taskv1.EventDispatchCompensationRebutted{DispatchTicketHash: mustHash32("a2"), TaskId: testTaskIDBytes,
					Builder: testBuilder, Worker: "trueopen1worker", Responder: testBuilder},
			}}),
			DispatchCompensationRebutted{TicketHash: mustHash32("a2"), TaskID: testTaskIDHex, Builder: testBuilder, Worker: "trueopen1worker", Responder: testBuilder}},
		{envelope(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_RESOLVED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchChallengeResolved{
				DispatchChallengeResolved: &taskv1.EventDispatchChallengeResolved{ChallengeId: mustHash32("c1"), TaskId: testTaskIDBytes},
			}}),
			DispatchChallengeResolved{ChallengeID: mustHash32("c1"), TaskID: testTaskIDHex}},
		{envelope(sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_DISPATCH_FAULT_RECORDED,
			&taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_BuilderDispatchFaultRecorded{
				BuilderDispatchFaultRecorded: &taskv1.EventBuilderDispatchFaultRecorded{Builder: testBuilder, FaultId: mustHash32("f1"), TaskId: testTaskIDBytes,
					PenaltyAmount: amount("5"), UnfilledAmount: amount("0")},
			}}),
			BuilderDispatchFaultRecorded{Builder: testBuilder, FaultID: mustHash32("f1"), TaskID: testTaskIDHex, PenaltyAmount: "5", UnfilledAmount: "0"}},
	}
	for _, tc := range cases {
		event, err := roleEventToChainEvent(tc.event)
		if err != nil || event.TaskID != testTaskIDHex || !reflect.DeepEqual(event.Typed, tc.want) {
			t.Fatalf("%s = %+v, %v", tc.event.GetCode(), event, err)
		}
	}
}
