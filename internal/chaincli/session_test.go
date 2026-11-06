package chaincli

import (
	"bytes"
	"context"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"google.golang.org/protobuf/proto"
)

func TestSessionStateFromPB(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 32)
	key := bytes.Repeat([]byte{0x33}, 20)
	pb := &taskv1.StreamState{
		SessionId: id, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_IDLE,
		SessionKey: key, SessionKeyExpiryHeight: 1100, SessionKeySetHeight: 980,
		SessionKeySpendCap: &sharedv1.Amount{AtomicUnits: "1150000"}, SessionKeySpent: &sharedv1.Amount{AtomicUnits: "1000000"},
	}
	got, err := sessionStateFromPB(id, pb)
	if err != nil {
		t.Fatal(err)
	}
	if got.Closed || got.Owner != "trueopen1owner" || !bytes.Equal(got.Key, key) || got.ExpiryHeight != 1100 ||
		got.SetHeight != 980 || got.SpendCap != "1150000" || got.Spent != "1000000" {
		t.Fatalf("state = %+v", got)
	}

	pb.Status = taskv1.SessionStatus_SESSION_STATUS_CLOSED
	pb.SessionKey = nil
	got, err = sessionStateFromPB(id, pb)
	if err != nil || !got.Closed || got.Key != nil {
		t.Fatalf("closed, no key: %+v, %v", got, err)
	}

	for name, edit := range map[string]func(*taskv1.StreamState){
		"other session": func(s *taskv1.StreamState) { s.SessionId = bytes.Repeat([]byte{0x22}, 32) },
		"no status":     func(s *taskv1.StreamState) { s.Status = taskv1.SessionStatus_SESSION_STATUS_UNSPECIFIED },
		"no owner":      func(s *taskv1.StreamState) { s.OwnerUserAddress = "" },
		"short key":     func(s *taskv1.StreamState) { s.SessionKey = key[:19] },
		"empty key":     func(s *taskv1.StreamState) { s.SessionKey = []byte{} },
	} {
		bad := proto.Clone(pb).(*taskv1.StreamState)
		bad.Status = taskv1.SessionStatus_SESSION_STATUS_ACTIVE
		bad.SessionKey = key
		edit(bad)
		if _, err := sessionStateFromPB(id, bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A Builder's preflight, takeover and sticky draw read the Phase 1 half of StreamState.
func TestSessionStateFromPBReadsPhase1Fields(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 32)
	winner := "trueopen1winner"
	pb := &taskv1.StreamState{
		SessionId: id, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_ACTIVE,
		NextExpectedSequence: 12, OpenPendingCount: 2,
		Balance: &sharedv1.Amount{AtomicUnits: "9000"}, FrozenTotal: &sharedv1.Amount{AtomicUnits: "3000"},
		PendingWithdrawKind:            taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT,
		PendingWithdrawAmount:          &sharedv1.Amount{AtomicUnits: "1000"},
		PendingWithdrawEffectiveHeight: 400,
		BoundBuilder:                   "trueopen1builder", BoundChangeHeight: 77,
		LastRecordHeight: 390, LastRecordWinner: &winner,
		StickyAnchorSequence: 9, StickyAnchorHeight: 380, StickyRunCount: 3,
		PendingSessionKeyChange: &taskv1.PendingSessionKeyChangeV1{
			Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET,
			Grant: &taskv1.SessionKeyGrantV1{
				SessionKey: bytes.Repeat([]byte{0x44}, 20), ExpiryHeight: 900, SpendCap: &sharedv1.Amount{AtomicUnits: "50"},
			},
			EffectiveHeight: 410,
		},
		PendingTakeover: &taskv1.PendingTakeoverV1{
			CandidateBuilder: "trueopen1candidate", OrderSequence: 12, OrderTaskHash: bytes.Repeat([]byte{0x55}, 32),
			RegisteredHeight: 395, ActivationHeight: 405,
		},
	}
	got, err := sessionStateFromPB(id, pb)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextExpectedSequence != 12 || got.OpenPendingCount != 2 || got.Balance != "9000" || got.FrozenTotal != "3000" ||
		got.PendingWithdrawKind != taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT ||
		got.PendingWithdrawAmount != "1000" || got.PendingWithdrawEffectiveHeight != 400 ||
		got.BoundBuilder != "trueopen1builder" || got.BoundChangeHeight != 77 ||
		got.LastRecordHeight != 390 || got.LastRecordWinner != winner ||
		got.StickyAnchorSequence != 9 || got.StickyAnchorHeight != 380 || got.StickyRunCount != 3 {
		t.Fatalf("state = %+v", got)
	}
	change := got.PendingKeyChange
	if change == nil || change.Kind != taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET ||
		!bytes.Equal(change.Key, bytes.Repeat([]byte{0x44}, 20)) || change.ExpiryHeight != 900 || change.SpendCap != "50" ||
		change.EffectiveHeight != 410 {
		t.Fatalf("pending key change = %+v", change)
	}
	takeover := got.PendingTakeover
	if takeover == nil || takeover.CandidateBuilder != "trueopen1candidate" || takeover.OrderSequence != 12 ||
		!bytes.Equal(takeover.OrderTaskHash, bytes.Repeat([]byte{0x55}, 32)) || takeover.RegisteredHeight != 395 ||
		takeover.ActivationHeight != 405 {
		t.Fatalf("pending takeover = %+v", takeover)
	}

	pb.LastRecordWinner, pb.PendingSessionKeyChange, pb.PendingTakeover = nil, nil, nil
	got, err = sessionStateFromPB(id, pb)
	if err != nil || got.LastRecordWinner != "" || got.PendingKeyChange != nil || got.PendingTakeover != nil {
		t.Fatalf("no pending changes: %+v, %v", got, err)
	}

	for name, edit := range map[string]func(*taskv1.StreamState){
		"short takeover task hash": func(s *taskv1.StreamState) {
			s.PendingTakeover = &taskv1.PendingTakeoverV1{CandidateBuilder: "trueopen1candidate", OrderTaskHash: []byte{1}}
		},
		"takeover without candidate": func(s *taskv1.StreamState) {
			s.PendingTakeover = &taskv1.PendingTakeoverV1{OrderTaskHash: bytes.Repeat([]byte{0x55}, 32)}
		},
		"short pending key": func(s *taskv1.StreamState) {
			s.PendingSessionKeyChange = &taskv1.PendingSessionKeyChangeV1{
				Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET, Grant: &taskv1.SessionKeyGrantV1{SessionKey: []byte{1}},
			}
		},
		"SET without grant": func(s *taskv1.StreamState) {
			s.PendingSessionKeyChange = &taskv1.PendingSessionKeyChangeV1{Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET}
		},
		"CLEAR with grant": func(s *taskv1.StreamState) {
			s.PendingSessionKeyChange = &taskv1.PendingSessionKeyChangeV1{
				Kind:  taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR,
				Grant: &taskv1.SessionKeyGrantV1{SessionKey: bytes.Repeat([]byte{0x44}, 20)},
			}
		},
	} {
		bad := proto.Clone(pb).(*taskv1.StreamState)
		edit(bad)
		if _, err := sessionStateFromPB(id, bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A session read carries the parameter body the session froze, with its version: the record
// deadline and order lifetime of its orders, whatever the current params say. A response without a
// usable body is an error, never filled in from current params.
func TestQuerySessionReadsTheFrozenPolicy(t *testing.T) {
	frozen := &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 30, MaxOrderLifetimeBlocks: 120, DispatchCompensationRebuttalBlocks: 12}
	state := &taskv1.StreamState{SessionId: testSessionIDBytes, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_ACTIVE}
	query := &dispatchTaskQuery{session: &taskv1.QuerySessionResponse{Session: state, Params: &taskv1.TaskParamsV1{Dispatch: frozen}, ParamsVersion: 0}}
	c := &client{taskQuery: query}
	got, err := c.QuerySession(context.Background(), testSessionIDHex)
	if err != nil || got.ParamsVersion != 0 || !proto.Equal(got.FrozenDispatch, frozen) {
		t.Fatalf("session = %+v, %v", got, err)
	}
	query.session.ParamsVersion = 4
	if got, err := c.QuerySession(context.Background(), testSessionIDHex); err != nil || got.ParamsVersion != 4 {
		t.Fatalf("session at version 4 = %+v, %v", got, err)
	}

	for name, params := range map[string]*taskv1.TaskParamsV1{
		"no body":                nil,
		"no dispatch":            {},
		"no record deadline":     {Dispatch: &taskv1.DispatchParamsV1{MaxOrderLifetimeBlocks: 120}},
		"no order lifetime":      {Dispatch: &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 30}},
		"order lifetime of 7201": {Dispatch: &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 30, MaxOrderLifetimeBlocks: 7201}},
	} {
		c := &client{taskQuery: &dispatchTaskQuery{session: &taskv1.QuerySessionResponse{Session: state, Params: params}}}
		if _, err := c.QuerySession(context.Background(), testSessionIDHex); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Any frozen order lifetime in 1..7200 is a usable session policy: the protocol ceiling and a
// shorter policy a session froze earlier alike.
func TestQuerySessionAcceptsFrozenLifetimesUpToTheProtocolCeiling(t *testing.T) {
	state := &taskv1.StreamState{SessionId: testSessionIDBytes, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_ACTIVE}
	for _, lifetime := range []uint64{1, 240, 7200} {
		frozen := &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 1, MaxOrderLifetimeBlocks: lifetime}
		c := &client{taskQuery: &dispatchTaskQuery{session: &taskv1.QuerySessionResponse{Session: state, Params: &taskv1.TaskParamsV1{Dispatch: frozen}}}}
		if got, err := c.QuerySession(context.Background(), testSessionIDHex); err != nil || got.FrozenDispatch.GetMaxOrderLifetimeBlocks() != lifetime {
			t.Fatalf("lifetime %d: session = %+v, %v", lifetime, got, err)
		}
	}
}
