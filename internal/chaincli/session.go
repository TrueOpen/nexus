package chaincli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// SessionState is a session's StreamState: its registered signing key, its prefunded balance and
// pending withdrawal, the Builder it is bound to, and the sticky dispatch context.
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

	// NextExpectedSequence is the only authority for the next acceptable order sequence.
	NextExpectedSequence uint64
	OpenPendingCount     uint32
	// Balance and FrozenTotal are decimal atomic units. Admission freezes max_fee from
	// Balance - FrozenTotal; a pending withdrawal is not subtracted on chain.
	Balance                        string
	FrozenTotal                    string
	PendingWithdrawKind            taskv1.SessionWithdrawKindV1
	PendingWithdrawAmount          string // decimal atomic units
	PendingWithdrawEffectiveHeight uint64
	// BoundBuilder is the only Builder whose dispatch records the chain admits for the session;
	// BoundChangeHeight changes on every binding and is signed into each ticket and record.
	BoundBuilder      string
	BoundChangeHeight uint64
	LastRecordHeight  uint64
	// LastRecordWinner is empty when the session has no recorded winner yet.
	LastRecordWinner     string
	StickyAnchorSequence uint64
	StickyAnchorHeight   uint64
	StickyRunCount       uint32
	// PendingKeyChange and PendingTakeover are nil when nothing is pending.
	PendingKeyChange *PendingSessionKeyChange
	PendingTakeover  *PendingTakeover
	// FrozenDispatch is the dispatch half of the parameter body the session froze, at
	// ParamsVersion: the record deadline, order lifetime and compensation and challenge windows of
	// its orders. Governance changes to the current params do not move it, and current params never
	// stand in for it. Shared, read only.
	FrozenDispatch *taskv1.DispatchParamsV1
	ParamsVersion  uint64
}

// PendingSessionKeyChange is a delayed SET or CLEAR of the session key.
type PendingSessionKeyChange struct {
	Kind taskv1.SessionKeyChangeKindV1
	// Key, ExpiryHeight and SpendCap are the grant a SET installs; empty for CLEAR.
	Key             []byte
	ExpiryHeight    uint64
	SpendCap        string // decimal atomic units; "0" is unlimited
	EffectiveHeight uint64
}

// PendingTakeover is a registered takeover candidate that EndBlock binds at ActivationHeight
// while OrderSequence stays unconsumed.
type PendingTakeover struct {
	CandidateBuilder string
	OrderSequence    uint64
	OrderTaskHash    []byte // 32 bytes
	RegisteredHeight uint64
	ActivationHeight uint64
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
	state, err := sessionStateFromPB(id, resp.Msg.GetSession())
	if err != nil {
		return SessionState{}, err
	}
	if state.FrozenDispatch, err = frozenDispatchFromPB(resp.Msg.GetParams()); err != nil {
		return SessionState{}, err
	}
	state.ParamsVersion = resp.Msg.GetParamsVersion()
	return state, nil
}

// frozenDispatchFromPB reads the dispatch params a session froze. A body without a record deadline
// or with an order lifetime outside 1..dispatch.MaxOrderLifetimeBlocksV1 is refused: the session's
// orders could not be judged with it.
func frozenDispatchFromPB(params *taskv1.TaskParamsV1) (*taskv1.DispatchParamsV1, error) {
	d := params.GetDispatch()
	switch {
	case d == nil:
		return nil, fmt.Errorf("query session: response has no frozen dispatch params")
	case d.GetRecordDeadlineBlocks() == 0:
		return nil, fmt.Errorf("query session: frozen dispatch.record_deadline_blocks is zero")
	case d.GetMaxOrderLifetimeBlocks() == 0 || d.GetMaxOrderLifetimeBlocks() > dispatch.MaxOrderLifetimeBlocksV1:
		return nil, fmt.Errorf("query session: frozen dispatch.max_order_lifetime_blocks %d is not in 1..%d",
			d.GetMaxOrderLifetimeBlocks(), dispatch.MaxOrderLifetimeBlocksV1)
	}
	return d, nil
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
	state.NextExpectedSequence = s.GetNextExpectedSequence()
	state.OpenPendingCount = s.GetOpenPendingCount()
	state.Balance = s.GetBalance().GetAtomicUnits()
	state.FrozenTotal = s.GetFrozenTotal().GetAtomicUnits()
	state.PendingWithdrawKind = s.GetPendingWithdrawKind()
	state.PendingWithdrawAmount = s.GetPendingWithdrawAmount().GetAtomicUnits()
	state.PendingWithdrawEffectiveHeight = s.GetPendingWithdrawEffectiveHeight()
	state.BoundBuilder = s.GetBoundBuilder()
	state.BoundChangeHeight = s.GetBoundChangeHeight()
	state.LastRecordHeight = s.GetLastRecordHeight()
	state.LastRecordWinner = s.GetLastRecordWinner()
	state.StickyAnchorSequence = s.GetStickyAnchorSequence()
	state.StickyAnchorHeight = s.GetStickyAnchorHeight()
	state.StickyRunCount = s.GetStickyRunCount()
	if change := s.GetPendingSessionKeyChange(); change != nil {
		pending, err := pendingKeyChangeFromPB(change)
		if err != nil {
			return SessionState{}, err
		}
		state.PendingKeyChange = pending
	}
	if takeover := s.GetPendingTakeover(); takeover != nil {
		if takeover.GetCandidateBuilder() == "" || len(takeover.GetOrderTaskHash()) != 32 {
			return SessionState{}, fmt.Errorf("query session: pending_takeover needs a candidate and a 32-byte order_task_hash")
		}
		state.PendingTakeover = &PendingTakeover{
			CandidateBuilder: takeover.GetCandidateBuilder(), OrderSequence: takeover.GetOrderSequence(),
			OrderTaskHash:    bytes.Clone(takeover.GetOrderTaskHash()),
			RegisteredHeight: takeover.GetRegisteredHeight(), ActivationHeight: takeover.GetActivationHeight(),
		}
	}
	return state, nil
}

// pendingKeyChangeFromPB reads a delayed key change: a SET carries the grant it installs, a CLEAR
// carries none.
func pendingKeyChangeFromPB(change *taskv1.PendingSessionKeyChangeV1) (*PendingSessionKeyChange, error) {
	pending := &PendingSessionKeyChange{Kind: change.GetKind(), EffectiveHeight: change.GetEffectiveHeight()}
	switch change.GetKind() {
	case taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET:
		grant := change.GetGrant()
		if grant == nil || len(grant.GetSessionKey()) != 20 {
			return nil, fmt.Errorf("query session: pending SET needs a grant with a 20-byte session_key")
		}
		pending.Key = bytes.Clone(grant.GetSessionKey())
		pending.ExpiryHeight = grant.GetExpiryHeight()
		pending.SpendCap = grant.GetSpendCap().GetAtomicUnits()
	case taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR:
		if change.Grant != nil {
			return nil, fmt.Errorf("query session: pending CLEAR carries a grant")
		}
	default:
		return nil, fmt.Errorf("query session: pending key change has kind %s", change.GetKind())
	}
	return pending, nil
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
