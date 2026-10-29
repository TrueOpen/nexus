package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// WithBuilderRoleEvents subscribes to the Task events addressed to operator in its Builder role
// (task.v1.TaskEventService/SubscribeRoleEvents): compensation claims and dispatch challenges
// against the Builder's records. They reach Events() as EventBuilderRole.
func WithBuilderRoleEvents(operator string) Option {
	return func(c *client) {
		c.roleOperator = operator
	}
}

// builderRoleCodes are the role events addressed to a Builder: a claim it may rebut and a
// challenge it may respond to within a window, and how claims and challenges ended (payments,
// rebuttals, resolutions and recorded faults move its compensation account balance).
func builderRoleCodes() []sharedv1.ProtocolEventCodeV1 {
	return []sharedv1.ProtocolEventCodeV1{
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_CLAIMED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_PAID,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_COMPENSATION_REBUTTED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_OPENED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_DISPATCH_CHALLENGE_RESOLVED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_DISPATCH_FAULT_RECORDED,
	}
}

// builderRoleRequest resumes after cursor, or starts at fromHeight when there is none.
func builderRoleRequest(operator, cursor string, fromHeight uint64) *taskv1.SubscribeRoleEventsRequest {
	request := &taskv1.SubscribeRoleEventsRequest{
		OperatorAddress: operator,
		TargetRole:      sharedv1.EventRole_EVENT_ROLE_BUILDER,
		Codes:           builderRoleCodes(),
	}
	if cursor != "" {
		request.AfterCursor = cursor
	} else {
		request.FromHeight = fromHeight
	}
	return request
}

func (c *client) startRoleEventsLocked() {
	if c.roleOperator == "" || c.roleCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.roleCancel = cancel
	c.wg.Add(1)
	go c.roleEventLoop(ctx)
}

// roleEventLoop keeps the Builder role stream open with the same retry and expired-cursor rules
// as the session streams.
func (c *client) roleEventLoop(ctx context.Context) {
	defer c.wg.Done()

	backoff := eventLoopMinBackoff
	for {
		startedAt := time.Now()
		delivered, err := c.subscribeRoleEventsOnce(ctx)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		if connect.CodeOf(err) == connect.CodeOutOfRange {
			if deleteErr := c.cursorStore.Delete(c.cfg.ChainID, eventCursorKindBuilderRole, c.roleOperator); deleteErr != nil {
				c.log.Warn("chaincli: failed to discard expired builder role event cursor",
					"err", redactSensitiveText(deleteErr.Error()))
			} else {
				if sendErr := c.sendEvent(ctx, ChainEvent{Type: EventBuilderRoleResync}); sendErr != nil {
					return
				}
				backoff = eventLoopMinBackoff
				continue
			}
		}
		delay, nextBackoff := taskEventRetryPolicy(err, delivered, time.Since(startedAt), backoff)
		if err != nil {
			c.log.Warn("chaincli: builder role event subscription dropped, will retry",
				"grpc", configuredLabel(c.cfg.GRPCAddr),
				"backoff", delay,
				"err", redactSensitiveText(err.Error()))
		}
		if !waitTaskEventRetry(ctx, delay) {
			return
		}
		backoff = nextBackoff
	}
}

func (c *client) subscribeRoleEventsOnce(ctx context.Context) (bool, error) {
	if c.taskEvents == nil {
		return false, fmt.Errorf("task event gRPC client is not configured")
	}
	cursor, err := c.cursorStore.Load(c.cfg.ChainID, eventCursorKindBuilderRole, c.roleOperator)
	if err != nil {
		return false, err
	}
	var fromHeight uint64
	if cursor == "" {
		if fromHeight, err = c.LatestHeight(ctx); err != nil {
			return false, err
		}
	}
	stream, err := c.taskEvents.SubscribeRoleEvents(ctx, connect.NewRequest(builderRoleRequest(c.roleOperator, cursor, fromHeight)))
	if err != nil {
		return false, fmt.Errorf("subscribe builder role events: %w", err)
	}
	defer func() { _ = stream.Close() }()
	// Claims and challenges of the gap may have been missed: the consumer re-reads its open ones.
	if err := c.sendEvent(ctx, ChainEvent{Type: EventBuilderRoleResync}); err != nil {
		return false, err
	}
	return c.consumeRoleEvents(ctx, stream)
}

// roleEventStream is the receiving half of a SubscribeRoleEvents stream.
type roleEventStream interface {
	Receive() bool
	Msg() *taskv1.SubscribeRoleEventsResponse
	Err() error
}

// consumeRoleEvents delivers each role event, then saves its cursor; checkpoints and events
// without a mapping only move the cursor. A broken envelope stops the stream before its cursor.
func (c *client) consumeRoleEvents(ctx context.Context, stream roleEventStream) (bool, error) {
	delivered := false
	for stream.Receive() {
		response := stream.Msg()
		if response == nil {
			return delivered, fmt.Errorf("receive builder role events: response item is required")
		}
		if checkpoint := response.GetCheckpoint(); checkpoint != nil {
			if err := saveStreamCheckpoint(c.cursorStore, c.cfg.ChainID, eventCursorKindBuilderRole, c.roleOperator, checkpoint); err != nil {
				return delivered, fmt.Errorf("receive builder role events: %w", err)
			}
			delivered = true
			continue
		}
		event := response.GetEvent()
		if event == nil {
			return delivered, fmt.Errorf("receive builder role events: response item is required")
		}
		mapped, err := roleEventToChainEvent(event)
		switch {
		case errors.Is(err, errUnmappedRoleEvent):
			c.log.Debug("chaincli: builder role event has no local mapping",
				"code", protocolEventCodeName(event.GetCode()), "chain_height", event.GetChainHeight())
		case errors.Is(err, errEventBusinessField):
			c.log.Warn("chaincli: delivering a builder role event without its typed payload",
				"cursor", event.GetCursor(), "err", redactSensitiveText(err.Error()))
			if err := c.sendEvent(ctx, mapped); err != nil {
				return delivered, err
			}
		case err != nil:
			return delivered, fmt.Errorf("receive builder role events: %w", err)
		default:
			if err := c.sendEvent(ctx, mapped); err != nil {
				return delivered, err
			}
		}
		if err := c.cursorStore.Save(c.cfg.ChainID, eventCursorKindBuilderRole, c.roleOperator, event.GetCursor()); err != nil {
			return delivered, err
		}
		delivered = true
	}
	if err := stream.Err(); err != nil {
		return delivered, fmt.Errorf("receive builder role events: %w", err)
	}
	return delivered, errors.New("builder role event stream ended")
}

// errUnmappedRoleEvent marks a well-formed role event this Builder has no typed mapping for; the
// stream skips it and moves on.
var errUnmappedRoleEvent = errors.New("builder role event has no typed mapping")

// roleEventToChainEvent maps one role event. Role events are found by operator, not session: the
// envelope may carry no session, and its task_id may be left to the payload.
func roleEventToChainEvent(event *taskv1.TaskEvent) (ChainEvent, error) {
	if event.GetCursor() == "" {
		return ChainEvent{}, fmt.Errorf("role event cursor is required")
	}
	if event.GetChainHeight() == 0 || event.GetChainHeight() > math.MaxInt64 {
		return ChainEvent{}, fmt.Errorf("role event chain height is invalid")
	}
	if event.GetCode() == sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_UNSPECIFIED {
		return ChainEvent{}, fmt.Errorf("role event code is required")
	}
	code := protocolEventCodeName(event.GetCode())
	if err := payloadMatchesCode(event.GetPayload(), int32(event.GetCode())); err != nil {
		return ChainEvent{}, fmt.Errorf("role event %s: %w", code, err)
	}
	taskID := hex.EncodeToString(event.GetTaskId())
	if payloadTask := payloadTaskID(event); taskID == "" {
		taskID = payloadTask
	} else if payloadTask != "" && payloadTask != taskID {
		return ChainEvent{}, fmt.Errorf("role event %s: payload task_id does not match envelope", code)
	}
	mapped := ChainEvent{
		Type:      EventBuilderRole,
		EventCode: code,
		SessionID: hex.EncodeToString(event.GetSessionId()),
		TaskID:    taskID,
		Height:    int64(event.GetChainHeight()),
	}
	typed, err := typedTaskEvent(event.GetPayload())
	if err != nil {
		return mapped, businessFieldError(fmt.Sprintf("role event %s", code), err)
	}
	if typed == nil {
		return ChainEvent{}, errUnmappedRoleEvent
	}
	mapped.Typed = typed
	return mapped, nil
}

// payloadMatchesCode checks that exactly the payload oneof member numbered code is set: every
// typed payload oneof numbers its members by event code.
func payloadMatchesCode(payload proto.Message, code int32) error {
	message := payload.ProtoReflect()
	if !message.IsValid() {
		return fmt.Errorf("payload is required")
	}
	field := message.WhichOneof(message.Descriptor().Oneofs().ByName("typed_event"))
	if field == nil {
		return fmt.Errorf("payload is required")
	}
	if field.Number() != protoreflect.FieldNumber(code) {
		return fmt.Errorf("payload %s does not match the event code", field.Name())
	}
	return nil
}

// protocolEventCodes are the Hub events the protocol stream asks for: BuilderSet rotation, current
// service key rotation (keys cached for the operator are stale) and compensation account funding.
func protocolEventCodes() []sharedv1.ProtocolEventCodeV1 {
	return []sharedv1.ProtocolEventCodeV1{
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_COMPENSATION_FUNDED,
	}
}

// protocolEventToChainEvent maps one Hub protocol event; false for a code without a local mapping.
// A business-field problem in the typed payload returns the event with Typed nil and an error
// wrapping errEventBusinessField; it is still delivered.
func protocolEventToChainEvent(event *hubv1.ProtocolEvent) (ChainEvent, bool, error) {
	if event.GetCursor() == "" {
		return ChainEvent{}, false, fmt.Errorf("protocol event cursor is required")
	}
	if event.GetChainHeight() == 0 {
		return ChainEvent{}, false, fmt.Errorf("protocol event chain height is required")
	}
	height, err := uint64ToInt64("protocol event chain height", event.GetChainHeight())
	if err != nil {
		return ChainEvent{}, false, err
	}
	code := protocolEventCodeName(event.GetCode())
	switch event.GetCode() {
	case sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED:
		return ChainEvent{Type: EventBuilderSetUpdated, EventCode: code, Height: height}, true, nil
	case sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SERVICE_KEY_ROTATED,
		sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_COMPENSATION_FUNDED:
		if err := payloadMatchesCode(event.GetPayload(), int32(event.GetCode())); err != nil {
			return ChainEvent{}, false, fmt.Errorf("protocol event %s: %w", code, err)
		}
		mapped := ChainEvent{Type: EventHubOperational, EventCode: code, Height: height}
		typed, err := typedHubEvent(event.GetPayload())
		if err != nil {
			return mapped, true, businessFieldError(fmt.Sprintf("protocol event %s", code), err)
		}
		mapped.Typed = typed
		return mapped, true, nil
	}
	return ChainEvent{}, false, nil
}
