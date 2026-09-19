package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	tmtypes "cosmossdk.io/api/tendermint/types"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
)

func TestTaskEventTrackingSharesSessionStream(t *testing.T) {
	c := &client{
		events:   make(chan ChainEvent, 1),
		stopCh:   make(chan struct{}),
		sessions: make(map[string]*sessionSubscription),
	}
	first := TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}
	second := TaskKey{SessionID: testSessionIDHex, TaskID: testOtherIDHex}
	if err := c.TrackTaskEvents(first); err != nil {
		t.Fatal(err)
	}
	if err := c.TrackTaskEvents(first); err != nil {
		t.Fatal(err)
	}
	if err := c.TrackTaskEvents(second); err != nil {
		t.Fatal(err)
	}
	c.sessionMu.Lock()
	if len(c.sessions) != 1 || len(c.sessions[testSessionIDHex].tasks) != 2 {
		t.Fatalf("sessions = %+v", c.sessions)
	}
	c.sessionMu.Unlock()

	c.UntrackTaskEvents(first)
	c.sessionMu.Lock()
	if len(c.sessions) != 1 || len(c.sessions[testSessionIDHex].tasks) != 1 {
		t.Fatalf("sessions after first untrack = %+v", c.sessions)
	}
	c.sessionMu.Unlock()

	c.UntrackTaskEvents(second)
	c.sessionMu.Lock()
	if len(c.sessions) != 0 {
		t.Fatalf("sessions after final untrack = %+v", c.sessions)
	}
	c.sessionMu.Unlock()
}

type taskEventCall struct {
	request *taskv1.SubscribeTaskEventsRequest
	stream  *connect.ServerStream[taskv1.SubscribeTaskEventsResponse]
}

type taskEventTestService struct {
	taskv1connect.UnimplementedTaskEventServiceHandler

	mu       sync.Mutex
	requests []*taskv1.SubscribeTaskEventsRequest
	calls    chan taskEventCall
}

func (s *taskEventTestService) SubscribeTaskEvents(
	ctx context.Context,
	req *connect.Request[taskv1.SubscribeTaskEventsRequest],
	stream *connect.ServerStream[taskv1.SubscribeTaskEventsResponse],
) error {
	cloned := cloneTaskEventRequest(req.Msg)
	s.mu.Lock()
	s.requests = append(s.requests, cloned)
	s.mu.Unlock()
	select {
	case s.calls <- taskEventCall{request: cloned, stream: stream}:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return ctx.Err()
}

func cloneTaskEventRequest(req *taskv1.SubscribeTaskEventsRequest) *taskv1.SubscribeTaskEventsRequest {
	if req == nil {
		return nil
	}
	return &taskv1.SubscribeTaskEventsRequest{
		SessionId: req.GetSessionId(), TaskId: req.GetTaskId(), AfterCursor: req.GetAfterCursor(),
		FromHeight: req.GetFromHeight(), Codes: append([]sharedv1.ProtocolEventCodeV1(nil), req.GetCodes()...),
	}
}

func newTaskEventTestClient(t *testing.T, service taskv1connect.TaskEventServiceHandler, store kv.Store, latest uint64) *client {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(taskv1connect.NewTaskEventServiceHandler(service))
	server := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	server.Start()
	t.Cleanup(server.Close)

	realClient := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.ChainConfig{
		GRPCAddr: server.Listener.Addr().String(),
		ChainID:  "stream-test",
	}).(*client)
	realClient.latestBlock = &recordLatestBlock{response: &cmtv1beta1.GetLatestBlockResponse{
		Block: &tmtypes.Block{Header: &tmtypes.Header{ChainId: "stream-test", Height: int64(latest)}},
	}}
	realClient.cursorStore = eventCursorStore{store: store}
	return realClient
}

func completeTaskEvent(cursor string, height uint64) *taskv1.TaskEvent {
	return &taskv1.TaskEvent{
		Cursor: cursor, ChainHeight: height, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 1, EventIndex: 2,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
		Code:    sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED,
		Targets: []*sharedv1.EventTarget{{Role: sharedv1.EventRole_EVENT_ROLE_WORKER, Address: "trueopen1worker"}},
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_WorkerAssignmentFinalized{
				WorkerAssignmentFinalized: &taskv1.EventWorkerAssignmentFinalized{
					SessionId: testSessionIDBytes, TaskId: testTaskIDBytes,
					WinnerWorker: "trueopen1worker", InferDeadline: height,
				},
			},
		},
	}
}

func TestTaskEventStreamUsesHeightAndPersistsCursor(t *testing.T) {
	service := &taskEventTestService{calls: make(chan taskEventCall, 2)}
	store := kv.NewMemStore()
	c := newTaskEventTestClient(t, service, store, 41)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if err := c.TrackTaskEvents(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err != nil {
		t.Fatal(err)
	}

	call := receiveTaskEventCall(t, service.calls)
	if hex.EncodeToString(call.request.GetSessionId()) != testSessionIDHex || call.request.GetAfterCursor() != "" || call.request.GetFromHeight() != 41 {
		t.Fatalf("request = %+v", call.request)
	}
	if err := call.stream.Send(&taskv1.SubscribeTaskEventsResponse{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: completeTaskEvent("v1:42:0:1:2", 42)}}); err != nil {
		t.Fatal(err)
	}

	resync := receiveChainEvent(t, c.Events())
	if resync.Type != EventResyncRequired || resync.SessionID != testSessionIDHex {
		t.Fatalf("resync = %+v", resync)
	}
	notification := receiveChainEvent(t, c.Events())
	if notification.Type != EventAssignmentFinalized || !notification.TaskNotification {
		t.Fatalf("notification = %+v", notification)
	}
	eventuallyChainCLI(t, func() bool {
		cursor, err := c.cursorStore.Load("stream-test", eventCursorKindTask, testSessionIDHex)
		return err == nil && cursor == "v1:42:0:1:2"
	})
}

func TestTaskEventCheckpointPersistsCursorWithoutBusinessEvent(t *testing.T) {
	service := &taskEventTestService{calls: make(chan taskEventCall, 1)}
	store := kv.NewMemStore()
	c := newTaskEventTestClient(t, service, store, 41)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if err := c.TrackTaskEvents(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err != nil {
		t.Fatal(err)
	}

	call := receiveTaskEventCall(t, service.calls)
	if err := call.stream.Send(&taskv1.SubscribeTaskEventsResponse{
		Item: &taskv1.SubscribeTaskEventsResponse_Checkpoint{Checkpoint: &sharedv1.StreamCheckpoint{
			Cursor: "checkpoint-cursor", ChainHeight: 42,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	resync := receiveChainEvent(t, c.Events())
	if resync.Type != EventResyncRequired {
		t.Fatalf("resync = %+v", resync)
	}
	eventuallyChainCLI(t, func() bool {
		cursor, err := c.cursorStore.Load("stream-test", eventCursorKindTask, testSessionIDHex)
		return err == nil && cursor == "checkpoint-cursor"
	})
	select {
	case event := <-c.Events():
		t.Fatalf("checkpoint emitted business event: %+v", event)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTaskEventMissingItemStopsWithoutCursorAdvance(t *testing.T) {
	service := &taskEventTestService{calls: make(chan taskEventCall, 1)}
	c := newTaskEventTestClient(t, service, kv.NewMemStore(), 41)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type result struct {
		delivered bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		delivered, err := c.subscribeTaskEventsOnce(ctx, testSessionIDHex)
		done <- result{delivered: delivered, err: err}
	}()

	call := receiveTaskEventCall(t, service.calls)
	if err := call.stream.Send(&taskv1.SubscribeTaskEventsResponse{}); err != nil {
		t.Fatal(err)
	}
	resync := receiveChainEvent(t, c.Events())
	if resync.Type != EventResyncRequired {
		t.Fatalf("resync = %+v", resync)
	}
	select {
	case got := <-done:
		if got.delivered || got.err == nil || !strings.Contains(got.err.Error(), "response item is required") {
			t.Fatalf("subscribe result = %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for malformed stream to stop")
	}
	if cursor, err := c.cursorStore.Load("stream-test", eventCursorKindTask, testSessionIDHex); err != nil || cursor != "" {
		t.Fatalf("cursor after missing item = %q, err = %v", cursor, err)
	}
}

type reconnectingTaskEventService struct {
	taskv1connect.UnimplementedTaskEventServiceHandler

	mu       sync.Mutex
	calls    int
	requests chan *taskv1.SubscribeTaskEventsRequest
}

func (s *reconnectingTaskEventService) SubscribeTaskEvents(
	ctx context.Context,
	req *connect.Request[taskv1.SubscribeTaskEventsRequest],
	stream *connect.ServerStream[taskv1.SubscribeTaskEventsResponse],
) error {
	cloned := cloneTaskEventRequest(req.Msg)
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	select {
	case s.requests <- cloned:
	case <-ctx.Done():
		return ctx.Err()
	}
	if call == 1 {
		return stream.Send(&taskv1.SubscribeTaskEventsResponse{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: completeTaskEvent("reconnect-cursor", 100)}})
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestTaskEventResumeUsesSavedCursor(t *testing.T) {
	service := &reconnectingTaskEventService{requests: make(chan *taskv1.SubscribeTaskEventsRequest, 2)}
	c := newTaskEventTestClient(t, service, kv.NewMemStore(), 99)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if err := c.TrackTaskEvents(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err != nil {
		t.Fatal(err)
	}
	first := receiveTaskEventRequest(t, service.requests)
	if first.GetAfterCursor() != "" || first.GetFromHeight() != 99 {
		t.Fatalf("first request = %+v", first)
	}
	second := receiveTaskEventRequest(t, service.requests)
	if second.GetAfterCursor() != "reconnect-cursor" || second.GetFromHeight() != 0 {
		t.Fatalf("second request = %+v", second)
	}
}

type outOfRangeTaskEventService struct {
	taskv1connect.UnimplementedTaskEventServiceHandler

	mu       sync.Mutex
	calls    int
	requests chan *taskv1.SubscribeTaskEventsRequest
}

func (s *outOfRangeTaskEventService) SubscribeTaskEvents(
	ctx context.Context,
	req *connect.Request[taskv1.SubscribeTaskEventsRequest],
	_ *connect.ServerStream[taskv1.SubscribeTaskEventsResponse],
) error {
	cloned := cloneTaskEventRequest(req.Msg)
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	select {
	case s.requests <- cloned:
	case <-ctx.Done():
		return ctx.Err()
	}
	if call == 1 {
		return connect.NewError(connect.CodeOutOfRange, errors.New("cursor expired"))
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestTaskEventOutOfRangeDropsCursorAndUsesLatestHeight(t *testing.T) {
	service := &outOfRangeTaskEventService{requests: make(chan *taskv1.SubscribeTaskEventsRequest, 2)}
	store := kv.NewMemStore()
	cursors := eventCursorStore{store: store}
	if err := cursors.Save("stream-test", eventCursorKindTask, testSessionIDHex, "stale-cursor"); err != nil {
		t.Fatal(err)
	}
	c := newTaskEventTestClient(t, service, store, 77)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if err := c.TrackTaskEvents(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err != nil {
		t.Fatal(err)
	}

	first := receiveTaskEventRequest(t, service.requests)
	if first.GetAfterCursor() != "stale-cursor" {
		t.Fatalf("first request = %+v", first)
	}
	second := receiveTaskEventRequest(t, service.requests)
	if second.GetAfterCursor() != "" || second.GetFromHeight() != 77 {
		t.Fatalf("second request = %+v", second)
	}
	if cursor, err := cursors.Load("stream-test", eventCursorKindTask, testSessionIDHex); err != nil || cursor != "" {
		t.Fatalf("cursor after OUT_OF_RANGE = %q, err = %v", cursor, err)
	}
}

func TestTaskEventRetryPolicy(t *testing.T) {
	unimplemented := connect.NewError(connect.CodeUnimplemented, errors.New("disabled"))
	delay, next := taskEventRetryPolicy(unimplemented, false, time.Second, 2*time.Second)
	if delay != eventLoopMaxBackoff || next != eventLoopMaxBackoff {
		t.Fatalf("unimplemented retry = (%s, %s)", delay, next)
	}

	delay, next = taskEventRetryPolicy(errors.New("dropped"), false, 30*time.Second, 8*time.Second)
	if delay != eventLoopMinBackoff || next != 2*eventLoopMinBackoff {
		t.Fatalf("healthy stream retry = (%s, %s)", delay, next)
	}

	delay, next = taskEventRetryPolicy(errors.New("dropped"), true, time.Second, 8*time.Second)
	if delay != eventLoopMinBackoff || next != 2*eventLoopMinBackoff {
		t.Fatalf("delivered stream retry = (%s, %s)", delay, next)
	}
}

// protocolEventTestService simulates hub.v1.HubEventService, which carries the
// protocol event stream since wire v0.4.1 (ADR-0013: SubscribeProtocolEvents moved from
// TaskEventService to Hub); the Task event stream is still served by TaskEventService.
type protocolEventTestService struct {
	hubv1connect.UnimplementedHubEventServiceHandler

	mu       sync.Mutex
	calls    int
	requests chan *hubv1.SubscribeProtocolEventsRequest
}

func (s *protocolEventTestService) SubscribeProtocolEvents(
	ctx context.Context,
	req *connect.Request[hubv1.SubscribeProtocolEventsRequest],
	stream *connect.ServerStream[hubv1.SubscribeProtocolEventsResponse],
) error {
	cloned := &hubv1.SubscribeProtocolEventsRequest{
		TargetAddress: req.Msg.GetTargetAddress(), AfterCursor: req.Msg.GetAfterCursor(),
		FromHeight: req.Msg.GetFromHeight(), Codes: append([]sharedv1.ProtocolEventCodeV1(nil), req.Msg.GetCodes()...),
	}
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	select {
	case s.requests <- cloned:
	case <-ctx.Done():
		return ctx.Err()
	}
	if call == 1 {
		// First send a Hub-domain event outside the subscription filter (SERVICE_KEY_ROTATED)
		// to verify "no local mapping still advances the cursor and is not passed upward
		// disguised as BuilderSetUpdated"; then send BUILDER_SET_UPDATED to verify it maps to
		// a BuilderSetUpdated carrying the event code.
		if err := stream.Send(&hubv1.SubscribeProtocolEventsResponse{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: &hubv1.ProtocolEvent{
			Cursor: "protocol-cursor", ChainHeight: 51, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"),
			Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX,
			Code:   sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
			Payload: &hubv1.ProtocolEventPayloadV1{
				TypedEvent: &hubv1.ProtocolEventPayloadV1_ServiceKeyRotated{
					ServiceKeyRotated: &hubv1.EventServiceKeyRotated{AuthorizationNonce: 7},
				},
			},
		}}}); err != nil {
			return err
		}
		return stream.Send(&hubv1.SubscribeProtocolEventsResponse{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: &hubv1.ProtocolEvent{
			Cursor: "builder-set-cursor", ChainHeight: 52, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"),
			Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX,
			Code:   sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED,
			Payload: &hubv1.ProtocolEventPayloadV1{
				TypedEvent: &hubv1.ProtocolEventPayloadV1_BuilderSetUpdated{
					BuilderSetUpdated: &hubv1.EventBuilderSetUpdated{OldVersion: 1, NewVersion: 2, BuilderSetId: "bs-2", EffectiveHeight: 52},
				},
			},
		}}})
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestProtocolEventStream(t *testing.T) {
	service := &protocolEventTestService{requests: make(chan *hubv1.SubscribeProtocolEventsRequest, 2)}
	mux := http.NewServeMux()
	mux.Handle(hubv1connect.NewHubEventServiceHandler(service))
	server := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	server.Start()
	t.Cleanup(server.Close)
	store := kv.NewMemStore()
	cursors := eventCursorStore{store: store}
	if err := cursors.Save("protocol-test", eventCursorKindTask, testSessionIDHex, "task-cursor"); err != nil {
		t.Fatal(err)
	}
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.ChainConfig{
		GRPCAddr: server.Listener.Addr().String(), ChainID: "protocol-test",
	}, WithEventStore(store), WithProtocolEvents()).(*client)
	c.latestBlock = &recordLatestBlock{response: &cmtv1beta1.GetLatestBlockResponse{
		Block: &tmtypes.Block{Header: &tmtypes.Header{ChainId: "protocol-test", Height: 50}},
	}}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	first := receiveProtocolEventRequest(t, service.requests)
	// Subscribe only to the BuilderSet rotation code: other Hub events have no local mapping in nexus.
	if first.GetTargetAddress() != "" || first.GetAfterCursor() != "" || first.GetFromHeight() != 50 ||
		len(first.GetCodes()) != 1 || first.GetCodes()[0] != sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED {
		t.Fatalf("first protocol request = %+v", first)
	}
	// The one BuilderSetUpdated emitted on stream setup is the rotation reconcile trigger and carries no event code.
	refresh := receiveChainEvent(t, c.Events())
	if refresh.Type != EventBuilderSetUpdated || refresh.EventCode != "" {
		t.Fatalf("protocol connection refresh = %+v", refresh)
	}
	// SERVICE_KEY_ROTATED produces no local event; the next one received must be the mapping of the on-chain BUILDER_SET_UPDATED.
	updated := receiveChainEvent(t, c.Events())
	if updated.Type != EventBuilderSetUpdated || updated.EventCode != "BUILDER_SET_UPDATED" {
		t.Fatalf("builder set updated event = %+v", updated)
	}
	second := receiveProtocolEventRequest(t, service.requests)
	if second.GetAfterCursor() != "builder-set-cursor" || second.GetFromHeight() != 0 {
		t.Fatalf("second protocol request = %+v", second)
	}
	if cursor, err := cursors.Load("protocol-test", eventCursorKindProtocol, ""); err != nil || cursor != "builder-set-cursor" {
		t.Fatalf("protocol cursor = %q, err = %v", cursor, err)
	}
	if cursor, err := cursors.Load("protocol-test", eventCursorKindTask, testSessionIDHex); err != nil || cursor != "task-cursor" {
		t.Fatalf("task cursor changed = %q, err = %v", cursor, err)
	}
}

func receiveTaskEventCall(t *testing.T, calls <-chan taskEventCall) taskEventCall {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for task event subscription")
		return taskEventCall{}
	}
}

func receiveTaskEventRequest(t *testing.T, requests <-chan *taskv1.SubscribeTaskEventsRequest) *taskv1.SubscribeTaskEventsRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for task event subscription request")
		return nil
	}
}

func receiveProtocolEventRequest(t *testing.T, requests <-chan *hubv1.SubscribeProtocolEventsRequest) *hubv1.SubscribeProtocolEventsRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for protocol event subscription request")
		return nil
	}
}

func receiveChainEvent(t *testing.T, events <-chan ChainEvent) ChainEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for chain event")
		return ChainEvent{}
	}
}

func eventuallyChainCLI(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}

func TestSendEventBackpressuresUntilCancellation(t *testing.T) {
	c := &client{events: make(chan ChainEvent, 1), stopCh: make(chan struct{})}
	c.events <- ChainEvent{Type: EventNewBlock, Height: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.sendEvent(ctx, ChainEvent{Type: EventNewBlock, Height: 2})
	}()
	select {
	case err := <-done:
		t.Fatalf("send returned before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("send error = %v, want context cancellation", err)
	}
}

// When the subscription start falls before the block that created the session, the first
// item on the stream is SESSION_CREATED. It has no task_id; the subscription loop must
// skip it, advance the cursor, and keep receiving the following task events. It must not
// drop and reconnect as with a bad envelope, which would back off forever on the same event.
func TestTaskEventSessionCreatedIsSkippedAndAdvancesCursor(t *testing.T) {
	service := &taskEventTestService{calls: make(chan taskEventCall, 1)}
	store := kv.NewMemStore()
	c := newTaskEventTestClient(t, service, store, 41)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if err := c.TrackTaskEvents(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err != nil {
		t.Fatal(err)
	}

	call := receiveTaskEventCall(t, service.calls)
	if err := call.stream.Send(&taskv1.SubscribeTaskEventsResponse{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: &taskv1.TaskEvent{
		Cursor: "session-created-cursor", ChainHeight: 42, BlockHash: []byte("BLOCK"), TxHash: []byte("TX"), TxIndex: 1, EventIndex: 0,
		Source: sharedv1.TaskEventSource_TASK_EVENT_SOURCE_TX, SessionId: testSessionIDBytes,
		Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_CREATED,
		Payload: &taskv1.TaskProtocolEventPayloadV1{
			TypedEvent: &taskv1.TaskProtocolEventPayloadV1_SessionCreated{
				SessionCreated: &taskv1.EventSessionCreated{SessionId: testSessionIDBytes, Owner: "trueopen1owner", Nonce: 1},
			},
		},
	}}}); err != nil {
		t.Fatal(err)
	}
	resync := receiveChainEvent(t, c.Events())
	if resync.Type != EventResyncRequired {
		t.Fatalf("resync = %+v", resync)
	}
	eventuallyChainCLI(t, func() bool {
		cursor, err := c.cursorStore.Load("stream-test", eventCursorKindTask, testSessionIDHex)
		return err == nil && cursor == "session-created-cursor"
	})
	select {
	case event := <-c.Events():
		t.Fatalf("session-scoped event emitted business event: %+v", event)
	case <-time.After(100 * time.Millisecond):
	}

	// The same stream was not dropped: the following task event is delivered as usual.
	if err := call.stream.Send(&taskv1.SubscribeTaskEventsResponse{Item: &taskv1.SubscribeTaskEventsResponse_Event{Event: completeTaskEvent("task-cursor", 43)}}); err != nil {
		t.Fatal(err)
	}
	event := receiveChainEvent(t, c.Events())
	if event.Type != EventAssignmentFinalized || event.TaskID != testTaskIDHex {
		t.Fatalf("event = %+v", event)
	}
	eventuallyChainCLI(t, func() bool {
		cursor, err := c.cursorStore.Load("stream-test", eventCursorKindTask, testSessionIDHex)
		return err == nil && cursor == "task-cursor"
	})
}
