package chaincli

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

type fakeTaskStream struct {
	items []*taskv1.SubscribeTaskEventsResponse
	next  *taskv1.SubscribeTaskEventsResponse
}

func (s *fakeTaskStream) Receive() bool {
	if len(s.items) == 0 {
		return false
	}
	s.next, s.items = s.items[0], s.items[1:]
	return true
}
func (s *fakeTaskStream) Msg() *taskv1.SubscribeTaskEventsResponse { return s.next }
func (s *fakeTaskStream) Err() error                               { return nil }

type fakeProtocolStream struct {
	items []*hubv1.SubscribeProtocolEventsResponse
	next  *hubv1.SubscribeProtocolEventsResponse
}

func (s *fakeProtocolStream) Receive() bool {
	if len(s.items) == 0 {
		return false
	}
	s.next, s.items = s.items[0], s.items[1:]
	return true
}
func (s *fakeProtocolStream) Msg() *hubv1.SubscribeProtocolEventsResponse { return s.next }
func (s *fakeProtocolStream) Err() error                                  { return nil }

func savedCursor(t *testing.T, store kv.Store, kind, scope string) string {
	t.Helper()
	cursor, err := eventCursorStore{store: store}.Load("trueopen-localnet-1", kind, scope)
	if err != nil {
		t.Fatal(err)
	}
	return cursor
}

func drainEvents(c *client) []ChainEvent {
	var out []ChainEvent
	for len(c.events) > 0 {
		out = append(out, <-c.events)
	}
	return out
}

func recordedEvent(cursor string, envelopeTask bool) *taskv1.TaskEvent {
	event := &taskv1.TaskEvent{
		Cursor: cursor, ChainHeight: 120, SessionId: testSessionIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_RECORDED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{TypedEvent: &taskv1.TaskProtocolEventPayloadV1_DispatchRecorded{
			DispatchRecorded: &taskv1.EventDispatchRecorded{
				SessionId: testSessionIDBytes, TaskId: testTaskIDBytes, OrderSequence: 7, Builder: testBuilder,
				DispatchRecordHash: mustHash32("a1"), DispatchTicketHash: mustHash32("a2"),
			},
		}},
	}
	if envelopeTask {
		event.TaskId = testTaskIDBytes
	}
	return event
}

// A bad business field is delivered without its typed payload and the cursor moves past it; a
// task_id left to the payload is taken from it; a broken envelope still stops the stream.
func TestSessionStreamDeliversBusinessFieldProblems(t *testing.T) {
	store := kv.NewMemStore()
	c := newRoleTestClient(store)
	short := recordedEvent("s1", true)
	short.GetPayload().GetDispatchRecorded().DispatchTicketHash = []byte{1}
	stream := &fakeTaskStream{items: []*taskv1.SubscribeTaskEventsResponse{
		{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: short}},
		{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: recordedEvent("s2", false)}},
	}}
	if _, err := c.consumeTaskEvents(context.Background(), testSessionIDHex, stream); err == nil {
		t.Fatal("an ended stream reported no error")
	}
	if got := savedCursor(t, store, eventCursorKindTask, testSessionIDHex); got != "s2" {
		t.Fatalf("cursor = %q, want s2", got)
	}
	events := drainEvents(c)
	if len(events) != 2 || events[0].Typed != nil || events[0].TaskID != testTaskIDHex ||
		events[1].TaskID != testTaskIDHex || !events[1].TaskNotification {
		t.Fatalf("events = %+v", events)
	}
	if typed, ok := events[1].Typed.(DispatchRecorded); !ok || typed.OrderSequence != 7 {
		t.Fatalf("payload task event typed = %#v", events[1].Typed)
	}

	broken := recordedEvent("s3", true)
	broken.Payload = nil
	stream = &fakeTaskStream{items: []*taskv1.SubscribeTaskEventsResponse{{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: broken}}}}
	if _, err := c.consumeTaskEvents(context.Background(), testSessionIDHex, stream); err == nil {
		t.Fatal("a broken envelope was skipped")
	}
	if got := savedCursor(t, store, eventCursorKindTask, testSessionIDHex); got != "s2" {
		t.Fatalf("cursor moved past a broken envelope to %q", got)
	}
	other := recordedEvent("s4", true)
	other.GetPayload().GetDispatchRecorded().TaskId = mustHash32("99")
	if _, err := taskEventToChainEvent(other); err == nil {
		t.Fatal("a payload task_id that contradicts the envelope was accepted")
	}
}

func TestRoleStreamDeliversBusinessFieldProblems(t *testing.T) {
	store := kv.NewMemStore()
	c := newRoleTestClient(store)
	short := claimedEvent("r1", 201)
	short.GetPayload().GetDispatchCompensationClaimed().DispatchTicketHash = []byte{1}
	stream := &fakeRoleStream{items: []*taskv1.SubscribeRoleEventsResponse{
		{Item: &taskv1.SubscribeRoleEventsResponse_Event{Event: short}},
	}}
	_, _ = c.consumeRoleEvents(context.Background(), stream)
	if got := savedRoleCursor(t, store); got != "r1" {
		t.Fatalf("cursor = %q, want r1", got)
	}
	events := drainEvents(c)
	if len(events) != 1 || events[0].Type != EventBuilderRole || events[0].Typed != nil ||
		events[0].EventCode != "DISPATCH_COMPENSATION_CLAIMED" || events[0].TaskID != testTaskIDHex {
		t.Fatalf("events = %+v", events)
	}
}

func rotatedEvent(cursor string, height uint64, operator string) *hubv1.ProtocolEvent {
	return &hubv1.ProtocolEvent{
		Cursor: cursor, ChainHeight: height, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		Payload: &hubv1.ProtocolEventPayloadV1{TypedEvent: &hubv1.ProtocolEventPayloadV1_ServiceKeyRotated{
			ServiceKeyRotated: &hubv1.EventServiceKeyRotated{
				ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, Operator: operator, AuthorizationNonce: 2,
			},
		}},
	}
}

func TestProtocolStreamDeliversBusinessFieldProblems(t *testing.T) {
	store := kv.NewMemStore()
	c := newRoleTestClient(store)
	stream := &fakeProtocolStream{items: []*hubv1.SubscribeProtocolEventsResponse{
		{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: rotatedEvent("p1", 300, "")}},
		{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: rotatedEvent("p2", 301, "trueopen1worker")}},
	}}
	_, _ = c.consumeProtocolEvents(context.Background(), stream)
	if got := savedCursor(t, store, eventCursorKindProtocol, ""); got != "p2" {
		t.Fatalf("cursor = %q, want p2", got)
	}
	events := drainEvents(c)
	if len(events) != 2 || events[0].Type != EventHubOperational || events[0].EventCode != "SERVICE_KEY_ROTATED" ||
		events[0].Typed != nil {
		t.Fatalf("events = %+v", events)
	}
	if typed, ok := events[1].Typed.(ServiceKeyRotated); !ok || typed.Operator != "trueopen1worker" {
		t.Fatalf("typed = %#v", events[1].Typed)
	}

	for name, edit := range map[string]func(*hubv1.ProtocolEvent){
		"no cursor":  func(e *hubv1.ProtocolEvent) { e.Cursor = "" },
		"no height":  func(e *hubv1.ProtocolEvent) { e.ChainHeight = 0 },
		"no payload": func(e *hubv1.ProtocolEvent) { e.Payload = nil },
	} {
		bad := proto.Clone(rotatedEvent("p3", 302, "trueopen1worker")).(*hubv1.ProtocolEvent)
		edit(bad)
		stream := &fakeProtocolStream{items: []*hubv1.SubscribeProtocolEventsResponse{
			{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: bad}},
		}}
		if _, err := c.consumeProtocolEvents(context.Background(), stream); err == nil {
			t.Fatalf("%s: stream went on", name)
		}
		if got := savedCursor(t, store, eventCursorKindProtocol, ""); got != "p2" {
			t.Fatalf("%s: cursor moved to %q", name, got)
		}
		if events := drainEvents(c); len(events) != 0 {
			t.Fatalf("%s: delivered %+v", name, events)
		}
	}
}
