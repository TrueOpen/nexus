package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

const taskEventHealthyStreamTime = 30 * time.Second

func WithEventStore(store kv.Store) Option {
	return func(c *client) {
		c.cursorStore = eventCursorStore{store: store}
	}
}

func WithProtocolEvents() Option {
	return func(c *client) {
		c.protocolEvents = true
	}
}

type sessionSubscription struct {
	tasks  map[string]struct{}
	cancel context.CancelFunc
}

func (c *client) TrackTaskEvents(key TaskKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.sessions == nil {
		c.sessions = make(map[string]*sessionSubscription)
	}
	session := c.sessions[key.SessionID]
	if session == nil {
		session = &sessionSubscription{tasks: make(map[string]struct{})}
		c.sessions[key.SessionID] = session
		if c.started {
			c.startTaskSessionLocked(key.SessionID, session)
		}
	}
	session.tasks[key.TaskID] = struct{}{}
	return nil
}

func (c *client) UntrackTaskEvents(key TaskKey) {
	if key.Validate() != nil {
		return
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	session := c.sessions[key.SessionID]
	if session == nil {
		return
	}
	delete(session.tasks, key.TaskID)
	if len(session.tasks) != 0 {
		return
	}
	delete(c.sessions, key.SessionID)
	if session.cancel != nil {
		session.cancel()
	}
}

func (c *client) startTaskSessionLocked(sessionID string, session *sessionSubscription) {
	if session.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	c.wg.Add(1)
	go c.taskEventLoop(ctx, sessionID)
}

func (c *client) taskEventLoop(ctx context.Context, sessionID string) {
	defer c.wg.Done()

	backoff := eventLoopMinBackoff
	for {
		startedAt := time.Now()
		delivered, err := c.subscribeTaskEventsOnce(ctx, sessionID)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		if connect.CodeOf(err) == connect.CodeOutOfRange {
			if deleteErr := c.cursorStore.Delete(c.cfg.ChainID, eventCursorKindTask, sessionID); deleteErr != nil {
				c.log.Warn("chaincli: failed to discard expired task event cursor",
					"session_id", sessionID,
					"err", redactSensitiveText(deleteErr.Error()))
			} else {
				if sendErr := c.sendEvent(ctx, ChainEvent{Type: EventResyncRequired, SessionID: sessionID}); sendErr != nil {
					return
				}
				backoff = eventLoopMinBackoff
				continue
			}
		}
		delay, nextBackoff := taskEventRetryPolicy(err, delivered, time.Since(startedAt), backoff)
		if err != nil {
			c.log.Warn("chaincli: task event subscription dropped, will retry",
				"session_id", sessionID,
				"grpc", configuredLabel(c.cfg.GRPCAddr),
				"backoff", delay,
				"err", redactSensitiveText(err.Error()))
		}
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			c.log.Error("chaincli: TaskEventService is disabled; task notifications are unavailable",
				"session_id", sessionID,
				"required_node_flag", "NODED_TASK_EVENT_GRPC_ENABLED=true")
		}
		if !waitTaskEventRetry(ctx, delay) {
			return
		}
		backoff = nextBackoff
	}
}

func taskEventRetryPolicy(err error, delivered bool, streamLifetime, backoff time.Duration) (time.Duration, time.Duration) {
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		return eventLoopMaxBackoff, eventLoopMaxBackoff
	}
	if delivered || streamLifetime >= taskEventHealthyStreamTime {
		backoff = eventLoopMinBackoff
	}
	if backoff < eventLoopMinBackoff {
		backoff = eventLoopMinBackoff
	}
	delay := backoff
	next := backoff * 2
	if next > eventLoopMaxBackoff {
		next = eventLoopMaxBackoff
	}
	return delay, next
}

func (c *client) subscribeTaskEventsOnce(ctx context.Context, sessionID string) (bool, error) {
	if c.taskEvents == nil {
		return false, fmt.Errorf("task event gRPC client is not configured")
	}
	cursor, err := c.cursorStore.Load(c.cfg.ChainID, eventCursorKindTask, sessionID)
	if err != nil {
		return false, err
	}
	// The frozen contract's SubscribeTaskEventsRequest carries session_id / task_id as bytes.
	sessionKey, err := nodecontract.Hash32Bytes("session_id", sessionID)
	if err != nil {
		return false, fmt.Errorf("subscribe task events: %w", err)
	}
	request := &taskv1.SubscribeTaskEventsRequest{SessionId: sessionKey}
	if cursor != "" {
		request.AfterCursor = cursor
	} else {
		height, err := c.LatestHeight(ctx)
		if err != nil {
			return false, err
		}
		request.FromHeight = height
	}

	stream, err := c.taskEvents.SubscribeTaskEvents(ctx, connect.NewRequest(request))
	if err != nil {
		return false, fmt.Errorf("subscribe task events: %w", err)
	}
	defer func() { _ = stream.Close() }()
	if err := c.sendEvent(ctx, ChainEvent{Type: EventResyncRequired, SessionID: sessionID}); err != nil {
		return false, err
	}

	delivered := false
	for stream.Receive() {
		response := stream.Msg()
		if response == nil {
			return delivered, fmt.Errorf("receive task events: response item is required")
		}
		if checkpoint := response.GetCheckpoint(); checkpoint != nil {
			if err := saveStreamCheckpoint(c.cursorStore, c.cfg.ChainID, eventCursorKindTask, sessionID, checkpoint); err != nil {
				return delivered, fmt.Errorf("receive task events: %w", err)
			}
			delivered = true
			continue
		}
		if response.GetEvent() == nil {
			return delivered, fmt.Errorf("receive task events: response item is required")
		}
		event := response.GetEvent()
		if eventSession := hex.EncodeToString(event.GetSessionId()); eventSession != sessionID {
			return delivered, fmt.Errorf("receive task events: session %q does not match subscription %q", eventSession, sessionID)
		}
		mapped, err := taskEventToChainEvent(event)
		if errors.Is(err, errSessionScopedTaskEvent) {
			// Session-level events produce no application event, but the cursor must advance past them or a reconnect gets stuck here.
			if err := c.cursorStore.Save(c.cfg.ChainID, eventCursorKindTask, sessionID, event.GetCursor()); err != nil {
				return delivered, err
			}
			delivered = true
			continue
		}
		if err != nil {
			return delivered, fmt.Errorf("receive task events: %w", err)
		}
		if err := c.sendEvent(ctx, mapped); err != nil {
			return delivered, err
		}
		if err := c.cursorStore.Save(c.cfg.ChainID, eventCursorKindTask, sessionID, event.GetCursor()); err != nil {
			return delivered, err
		}
		delivered = true
	}
	if err := stream.Err(); err != nil {
		return delivered, fmt.Errorf("receive task events: %w", err)
	}
	return delivered, errors.New("task event stream ended")
}

func waitTaskEventRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *client) startProtocolEventsLocked() {
	if !c.protocolEvents || c.protocolCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.protocolCancel = cancel
	c.wg.Add(1)
	go c.protocolEventLoop(ctx)
}

func (c *client) protocolEventLoop(ctx context.Context) {
	defer c.wg.Done()

	backoff := eventLoopMinBackoff
	for {
		startedAt := time.Now()
		delivered, err := c.subscribeProtocolEventsOnce(ctx)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		if connect.CodeOf(err) == connect.CodeOutOfRange {
			if deleteErr := c.cursorStore.Delete(c.cfg.ChainID, eventCursorKindProtocol, ""); deleteErr != nil {
				c.log.Warn("chaincli: failed to discard expired protocol event cursor",
					"err", redactSensitiveText(deleteErr.Error()))
			} else {
				if sendErr := c.sendEvent(ctx, ChainEvent{Type: EventBuilderSetUpdated}); sendErr != nil {
					return
				}
				backoff = eventLoopMinBackoff
				continue
			}
		}
		delay, nextBackoff := taskEventRetryPolicy(err, delivered, time.Since(startedAt), backoff)
		if err != nil {
			c.log.Warn("chaincli: protocol event subscription dropped, will retry",
				"grpc", configuredLabel(c.cfg.GRPCAddr),
				"backoff", delay,
				"err", redactSensitiveText(err.Error()))
		}
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			c.log.Error("chaincli: HubEventService is disabled; BuilderSet notifications are unavailable",
				"required_node_flags", "NODED_TASK_EVENT_GRPC_ENABLED=true,NODED_TASK_EVENT_GRPC_PROTOCOL_EVENTS_ENABLED=true")
		}
		if !waitTaskEventRetry(ctx, delay) {
			return
		}
		backoff = nextBackoff
	}
}

func (c *client) subscribeProtocolEventsOnce(ctx context.Context) (bool, error) {
	if c.hubEvents == nil {
		return false, fmt.Errorf("hub event gRPC client is not configured")
	}
	cursor, err := c.cursorStore.Load(c.cfg.ChainID, eventCursorKindProtocol, "")
	if err != nil {
		return false, err
	}
	// Since wire v0.4.1 BuilderSet rotation has its own event code BUILDER_SET_UPDATED; subscribe only to it.
	// Each new stream still emits one BuilderSetUpdated first: a rotation may have been missed
	// while the stream was down, and having the coordinator reconcile via Query once is the safest.
	request := &hubv1.SubscribeProtocolEventsRequest{
		Codes: []sharedv1.ProtocolEventCodeV1{sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED},
	}
	if cursor != "" {
		request.AfterCursor = cursor
	} else {
		height, err := c.LatestHeight(ctx)
		if err != nil {
			return false, err
		}
		request.FromHeight = height
	}

	stream, err := c.hubEvents.SubscribeProtocolEvents(ctx, connect.NewRequest(request))
	if err != nil {
		return false, fmt.Errorf("subscribe protocol events: %w", err)
	}
	defer func() { _ = stream.Close() }()
	if err := c.sendEvent(ctx, ChainEvent{Type: EventBuilderSetUpdated}); err != nil {
		return false, err
	}

	delivered := false
	for stream.Receive() {
		response := stream.Msg()
		if response == nil {
			return delivered, fmt.Errorf("receive protocol events: response item is required")
		}
		if checkpoint := response.GetCheckpoint(); checkpoint != nil {
			if err := saveStreamCheckpoint(c.cursorStore, c.cfg.ChainID, eventCursorKindProtocol, "", checkpoint); err != nil {
				return delivered, fmt.Errorf("receive protocol events: %w", err)
			}
			delivered = true
			continue
		}
		event := response.GetEvent()
		if event == nil {
			return delivered, fmt.Errorf("receive protocol events: response item is required")
		}
		if event.GetCode() == sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_BUILDER_SET_UPDATED {
			height, err := uint64ToInt64("protocol event chain height", event.GetChainHeight())
			if err != nil {
				return delivered, fmt.Errorf("receive protocol events: %w", err)
			}
			if err := c.sendEvent(ctx, ChainEvent{Type: EventBuilderSetUpdated, EventCode: protocolEventCodeName(event.GetCode()), Height: height}); err != nil {
				return delivered, err
			}
		} else {
			// The subscription filters by code; any other code arriving here means the chain-side filter semantics changed: only advance the cursor and log.
			c.log.Debug("chaincli: protocol event has no local mapping",
				"code", protocolEventCodeName(event.GetCode()), "chain_height", event.GetChainHeight())
		}
		if err := c.cursorStore.Save(c.cfg.ChainID, eventCursorKindProtocol, "", event.GetCursor()); err != nil {
			return delivered, err
		}
		delivered = true
	}
	if err := stream.Err(); err != nil {
		return delivered, fmt.Errorf("receive protocol events: %w", err)
	}
	return delivered, errors.New("protocol event stream ended")
}

func saveStreamCheckpoint(store eventCursorStore, chainID, kind, scope string, checkpoint *sharedv1.StreamCheckpoint) error {
	if checkpoint.GetCursor() == "" || checkpoint.GetChainHeight() == 0 {
		return fmt.Errorf("stream checkpoint cursor and chain height are required")
	}
	return store.Save(chainID, kind, scope, checkpoint.GetCursor())
}
