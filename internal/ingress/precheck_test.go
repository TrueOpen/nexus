package ingress

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/types"
)

// These tests open no listener: validateOpenTaskHeader is called directly, OpenTask through the
// in-memory transport of newTaskDataClientWithHandler.

type fakePrechecker struct {
	orders   []inflight.Order
	result   inflight.Result
	err      error
	released []*inflight.Reservation
}

func (p *fakePrechecker) Reserve(_ context.Context, o inflight.Order) (inflight.Result, error) {
	p.orders = append(p.orders, o)
	if p.err != nil {
		return inflight.Result{}, p.err
	}
	result := p.result
	if result.Binding == 0 {
		result.Binding = inflight.BoundHere
	}
	return result, nil
}

func (p *fakePrechecker) Release(r *inflight.Reservation) error {
	p.released = append(p.released, r)
	return nil
}

// The vector OpenTask (sequence 7, earliest_submit_height 1000, order_expire_height 2000, anchor
// 990, max_fee 150000, signed by the registered key) reaches the precheck with those facts, and
// the registered-key precheck of the order is not run a second time.
func TestOpenTaskHeaderRunsThePrecheck(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	p := &fakePrechecker{}
	h.svc.auth.Precheck = p
	if err := h.validate(); err != nil {
		t.Fatalf("validateOpenTaskHeader: %v", err)
	}
	if len(p.orders) != 1 {
		t.Fatalf("precheck ran %d times", len(p.orders))
	}
	o := p.orders[0]
	var key [20]byte
	copy(key[:], mustHexBytes(t, h.file.SessionKey.AddressBytes))
	if o.SessionID != h.header.GetSessionId()[2:] || o.Sequence != 7 || o.User != h.file.Account.Bech32 || o.MaxFee != 150000 ||
		o.EarliestSubmitHeight != 1000 || o.ExpireHeight != 2000 || o.SessionAnchorHeight != 990 ||
		o.SessionKey == nil || *o.SessionKey != key || o.TaskHash == "" || o.TaskID == "" {
		t.Fatalf("precheck order = %+v", o)
	}
	// One lookup: the registered-key envelope; the order is judged by the precheck alone.
	if len(h.keys.heights) != 1 {
		t.Fatalf("session key lookups = %d, want 1", len(h.keys.heights))
	}

	h.setOrderSignature(t, mustHexBytes(t, h.file.WalletOrder.Signature))
	h.signEnvelopeWithWallet(t)
	if err := h.validate(); err != nil {
		t.Fatalf("wallet order: %v", err)
	}
	if p.orders[1].SessionKey != nil {
		t.Fatal("a wallet order reached the precheck as a session key order")
	}
}

func TestOpenTaskHeaderPrecheckErrors(t *testing.T) {
	cases := []struct {
		err  error
		code connect.Code
		text string
	}{
		{inflight.ErrOrderExpired, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_EXPIRED"},
		{inflight.ErrOrderStale, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_STALE"},
		{inflight.ErrOrderFuture, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_FUTURE"},
		{&inflight.TakeoverPendingError{Candidate: "trueopen1candidate", ActivationHeight: 1030}, connect.CodeFailedPrecondition, "NEXUS_INGRESS_TAKEOVER_PENDING"},
		{inflight.ErrOrderReplacementUnsupported, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_REPLACEMENT_UNSUPPORTED"},
		{inflight.ErrOrderLocked, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_LOCKED"},
		{inflight.ErrTaskTerminal, connect.CodeFailedPrecondition, "NEXUS_INGRESS_TASK_TERMINAL"},
		{inflight.ErrSessionSuspended, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_SUSPENDED"},
		{inflight.ErrOrderSequenceConflict, connect.CodeFailedPrecondition, "NEXUS_INGRESS_ORDER_SEQUENCE_CONFLICT"},
		{inflight.ErrInflightLimit, connect.CodeFailedPrecondition, "NEXUS_INGRESS_INFLIGHT_LIMIT"},
		{inflight.ErrSessionClosing, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_CLOSING"},
		{inflight.ErrSessionBalanceInsufficient, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_BALANCE_INSUFFICIENT"},
		{inflight.ErrUnavailable, connect.CodeUnavailable, "NEXUS_SDKAUTH_CHAIN_UNAVAILABLE"},
		{registeredkey.ErrKeyInvalid, connect.CodeUnauthenticated, "SDK_AUTH_INVALID_SIGNATURE"},
		{registeredkey.ErrKeyExpired, connect.CodeDeadlineExceeded, "SDK_AUTH_SESSION_GRANT_EXPIRED"},
		{registeredkey.ErrSpendCapExceeded, connect.CodeFailedPrecondition, "SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED"},
	}
	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			h := newRegisteredKeyHeader(t)
			h.svc.auth.Precheck = &fakePrechecker{err: c.err}
			wantConnectErr(t, h.validate(), c.code, c.text)
		})
	}
}

func TestOpenTaskHeaderSessionBoundElsewhere(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.svc.auth.Precheck = &fakePrechecker{result: inflight.Result{
		Binding: inflight.BoundElsewhere, Session: inflight.Session{SessionState: chaincli.SessionState{BoundBuilder: "trueopen1other"}},
	}}
	err := h.validate()
	wantConnectErr(t, err, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE")
	wantConnectErr(t, err, connect.CodeFailedPrecondition, "trueopen1other")
}

// An exact retry of an order this Builder already dispatches is answered with its state; nothing
// is stored and the coordinator is not asked.
func TestOpenTaskAnswersAnExistingOrder(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	auth := h.svc.auth
	auth.Precheck = &fakePrechecker{result: inflight.Result{Existing: &inflight.Entry{Sequence: 7, State: inflight.StateAccepted}}}
	api := &fakeTaskDataAPI{chunkSize: 4096}
	handler := &fakeHandler{}
	client := newTaskDataClientWithHandler(t, handler, api, auth)
	stream := client.OpenTask(context.Background())
	if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: h.header}}); err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: make([]byte, 4096)}})
	response, err := stream.CloseAndReceive()
	if err != nil {
		t.Fatalf("OpenTask: %v", err)
	}
	if !response.Msg.GetAccepted() || response.Msg.GetStatus() != nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_DISPATCHED ||
		response.Msg.GetTaskId() != h.header.GetRequestEnvelope().GetTaskId() {
		t.Fatalf("response = %+v", response.Msg)
	}
	if api.openTaskNonce == nil {
		t.Fatal("the request nonce was not checked")
	}
	if api.inputUpload != nil || handler.lastOrder.TaskID != "" {
		t.Fatal("an existing order reached storage or the coordinator")
	}
}

// The real precheck behind the header: a session key order must fit the spend cap together with
// the key's in-flight orders.
func TestOpenTaskHeaderPrecheckCountsInFlightKeyOrders(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	sessionID := h.header.GetSessionId()[2:]
	key := *h.keys.state.Key
	state := chaincli.SessionState{
		Owner: h.file.Account.Bech32, Key: key[:], ExpiryHeight: 1100, SetHeight: 980, SpendCap: "1150000", Spent: "1000000",
		NextExpectedSequence: 6, Balance: "100000000", FrozenTotal: "0", BoundBuilder: "trueopen1builder", BoundChangeHeight: 1,
	}
	p, ledger := newPrechecker(t, state)
	h.svc.auth.Precheck = p
	// Sequence 6 in flight, signed by the key with max_fee 1: 1000000 + 1 + 150000 > 1150000.
	if _, err := p.Reserve(context.Background(), inflight.Order{
		SessionID: sessionID, Sequence: 6, TaskID: "t6", TaskHash: hex.EncodeToString([]byte{6}), User: h.file.Account.Bech32,
		MaxFee: 1, EarliestSubmitHeight: 1000, ExpireHeight: 2000, SessionAnchorHeight: 990, SessionKey: &key,
	}); err != nil {
		t.Fatal(err)
	}
	wantConnectErr(t, h.validate(), connect.CodeFailedPrecondition, "SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED")
	if err := ledger.MarkFailed(sessionID, 6); err != nil {
		t.Fatal(err)
	}
	// 6 failed: the next order is 6 again, so 7 is out of sequence.
	if err := h.validate(); !errors.Is(err, inflight.ErrOrderSequenceConflict) {
		t.Fatalf("order 7 after 6 failed = %v", err)
	}
}

// newPrechecker is the real precheck over a session in the given state, at head 1000, for
// Builder trueopen1builder.
func newPrechecker(t *testing.T, state chaincli.SessionState) (*inflight.Prechecker, *inflight.Ledger) {
	t.Helper()
	ledger, err := inflight.NewLedger(kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := inflight.NewSessionCache(inflight.SessionCacheConfig{
		Read:         func(context.Context, string) (chaincli.SessionState, error) { return state, nil },
		LatestHeight: func(context.Context) (uint64, error) { return 1000, nil },
		Ledger:       ledger,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := inflight.NewPrechecker(inflight.PrecheckConfig{
		Builder: "trueopen1builder", Sessions: cache, Ledger: ledger,
		Params: inflight.Params{RecordDeadlineBlocks: 50, OrderFreshnessMarginBlocks: 10, BuilderMaxInflightPerSession: 4, MaxPendingPerSession: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, ledger
}

// The precheck reserves the order's sequence and funds in the in-flight ledger before the input
// is uploaded, so a concurrent order of the session is judged with it; any failure before the
// coordinator takes the order releases the reservation, and a dispatched order keeps it.
func TestOpenTaskReservesThenReleasesOnFailure(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(*fakeTaskDataAPI, *fakeHandler)
		released bool
	}{
		{name: "request nonce refused", setup: func(api *fakeTaskDataAPI, _ *fakeHandler) {
			api.openTaskErr = errors.New("replayed")
		}, released: true},
		{name: "input not stored", setup: func(api *fakeTaskDataAPI, _ *fakeHandler) {
			api.chunkSize = 1 // the chunk below is too large
		}, released: true},
		{name: "coordinator refuses", setup: func(_ *fakeTaskDataAPI, handler *fakeHandler) {
			handler.orderErr = errors.New("NEXUS_INGRESS_DISPATCH_NOT_IMPLEMENTED")
		}, released: true},
		{name: "dispatched", released: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newRegisteredKeyHeader(t)
			h.signEnvelopeWithWallet(t)
			sessionID := h.header.GetSessionId()[2:]
			key := *h.keys.state.Key
			p, ledger := newPrechecker(t, chaincli.SessionState{
				Owner: h.file.Account.Bech32, Key: key[:], ExpiryHeight: 1100, SetHeight: 980, SpendCap: "0", Spent: "0",
				NextExpectedSequence: 7, Balance: "100000000", FrozenTotal: "0", BoundBuilder: "trueopen1builder", BoundChangeHeight: 1,
			})
			auth := h.svc.auth
			auth.Precheck = p
			api := &fakeTaskDataAPI{chunkSize: 4096}
			handler := &fakeHandler{}
			if c.setup != nil {
				c.setup(api, handler)
			}
			orderErr := handler.orderErr
			handler.onOrder = func(context.Context, types.Order) error {
				if e, ok := ledger.Get(sessionID, 7); !ok || e.State != inflight.StateDispatching {
					t.Errorf("ledger entry during OnOrder = %+v, %v", e, ok)
				}
				return orderErr
			}
			client := newTaskDataClientWithHandler(t, handler, api, auth)
			stream := client.OpenTask(context.Background())
			if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: h.header}}); err != nil {
				t.Fatal(err)
			}
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: make([]byte, 16)}})
			_, err := stream.CloseAndReceive()
			if (err != nil) != c.released {
				t.Fatalf("OpenTask = %v", err)
			}
			e, held := ledger.Get(sessionID, 7)
			if held == c.released {
				t.Fatalf("ledger entry after OpenTask = %+v, %v, want released %v", e, held, c.released)
			}
		})
	}
}

// The ingress side of a reservation with the fake: released once on failure, never on success.
func TestOpenTaskReleasesTheReservationItGot(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	reservation := &inflight.Reservation{SessionID: h.header.GetSessionId()[2:], Sequence: 7}
	fake := &fakePrechecker{result: inflight.Result{Reservation: reservation}}
	auth := h.svc.auth
	auth.Precheck = fake
	api := &fakeTaskDataAPI{chunkSize: 4096, openTaskErr: errors.New("replayed")}
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, auth)
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: h.header}})
	if _, err := stream.CloseAndReceive(); err == nil {
		t.Fatal("OpenTask with a refused nonce succeeded")
	}
	if len(fake.released) != 1 || fake.released[0] != reservation {
		t.Fatalf("released = %v", fake.released)
	}
}
