package chaincli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// SessionState is the part of a session's StreamState that governs its registered signing key.
type SessionState struct {
	SessionID string // lowercase hex, no 0x
	Owner     string // canonical bech32 owner_user_address
	Closed    bool
	// Key is the registered 20-byte key address; nil when none is registered.
	Key          []byte
	ExpiryHeight uint64
	SetHeight    uint64
	SpendCap     string // decimal atomic units; "0" is unlimited
	Spent        string // decimal atomic units
}

// SessionStreamObserver hears about the task event streams of tracked sessions, so that cached
// session state can follow them: a key update arrives on the session's stream, and while a
// stream is down its updates are missed.
type SessionStreamObserver interface {
	// SessionStreamUp: the session's stream is (re)connected; updates from the gap were missed.
	SessionStreamUp(sessionID string)
	// SessionStreamDown: the stream dropped and will reconnect.
	SessionStreamDown(sessionID string)
	// SessionStreamClosed: the session is no longer tracked; its stream is gone on purpose.
	SessionStreamClosed(sessionID string)
	// SessionKeyUpdated: the session's registered key changed (event session_key_updated).
	SessionKeyUpdated(sessionID string)
}

// WithSessionStreamObserver reports tracked sessions' stream state and key updates to observer.
func WithSessionStreamObserver(observer SessionStreamObserver) Option {
	return func(c *client) {
		c.sessionObserver = observer
	}
}

// QuerySession reads one session's StreamState (task.v1.Query/Session). A session the chain does
// not know, including one compacted after it closed, is ErrNotFound.
func (c *client) QuerySession(ctx context.Context, sessionID string) (SessionState, error) {
	id, err := nodecontract.Hash32Bytes("session_id", sessionID)
	if err != nil {
		return SessionState{}, fmt.Errorf("query session %q: %w", sessionID, err)
	}
	resp, err := c.taskQuery.Session(ctx, connect.NewRequest(&taskv1.QuerySessionRequest{SessionId: id}))
	if err != nil {
		return SessionState{}, applicationQueryError("session", err)
	}
	return sessionStateFromPB(id, resp.Msg.GetSession())
}

func sessionStateFromPB(id []byte, s *taskv1.StreamState) (SessionState, error) {
	if s == nil || !bytes.Equal(s.GetSessionId(), id) {
		return SessionState{}, fmt.Errorf("query session: response session does not match request")
	}
	if s.GetStatus() == taskv1.SessionStatus_SESSION_STATUS_UNSPECIFIED || s.GetOwnerUserAddress() == "" {
		return SessionState{}, fmt.Errorf("query session: response has no status or owner")
	}
	state := SessionState{
		SessionID:    hex.EncodeToString(id),
		Owner:        s.GetOwnerUserAddress(),
		Closed:       s.GetStatus() == taskv1.SessionStatus_SESSION_STATUS_CLOSED,
		ExpiryHeight: s.GetSessionKeyExpiryHeight(),
		SetHeight:    s.GetSessionKeySetHeight(),
		SpendCap:     s.GetSessionKeySpendCap().GetAtomicUnits(),
		Spent:        s.GetSessionKeySpent().GetAtomicUnits(),
	}
	if s.SessionKey != nil {
		if len(s.GetSessionKey()) != 20 {
			return SessionState{}, fmt.Errorf("query session: session_key is %d bytes, want 20", len(s.GetSessionKey()))
		}
		state.Key = append([]byte(nil), s.GetSessionKey()...)
	}
	return state, nil
}

// QueryBusinessDenom reads hub params phase0.business_denom, the feeDenom of the order signing
// domain.
func (c *client) QueryBusinessDenom(ctx context.Context) (string, error) {
	resp, err := c.hubQuery.Params(ctx, connect.NewRequest(&hubv1.QueryHubParamsRequest{}))
	if err != nil {
		return "", applicationQueryError("hub params", err)
	}
	denom := resp.Msg.GetParams().GetPhase0().GetBusinessDenom()
	if denom == "" {
		return "", fmt.Errorf("query hub params: phase0.business_denom is empty")
	}
	return denom, nil
}

func isSessionKeyUpdated(event *taskv1.TaskEvent) bool {
	return event.GetCode() == sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_SESSION_KEY_UPDATED
}

// QuerySession has no chain to ask in stub mode; callers fail closed.
func (c *stubClient) QuerySession(context.Context, string) (SessionState, error) {
	return SessionState{}, ErrNotSupportedOnChain
}

// QueryBusinessDenom has no chain to ask in stub mode; callers fail closed.
func (c *stubClient) QueryBusinessDenom(context.Context) (string, error) {
	return "", ErrNotSupportedOnChain
}
