package ingress

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/takeover"
	"github.com/TrueOpen/nexus/internal/types"
)

// These tests open no listener: validateOpenTaskHeader is called directly, OpenTask through the
// in-memory transport of newTaskDataClientWithHandler.

const testSelf = "trueopen1self"

type fakeTakeovers struct {
	held      *takeover.Admission
	admission takeover.Admission
	admitErr  error
	submitErr error
	admitted  []inflight.Order
	submitted []types.Order
	released  []string
}

func (f *fakeTakeovers) Held(string, uint64, string) (takeover.Admission, bool) {
	if f.held == nil {
		return takeover.Admission{}, false
	}
	return *f.held, true
}

func (f *fakeTakeovers) Admit(_ context.Context, _ types.Order, pre inflight.Order) (takeover.Admission, error) {
	f.admitted = append(f.admitted, pre)
	return f.admission, f.admitErr
}

func (f *fakeTakeovers) Submit(_ context.Context, o types.Order) error {
	f.submitted = append(f.submitted, o)
	return f.submitErr
}

func (f *fakeTakeovers) Release(_, taskHash string) { f.released = append(f.released, taskHash) }

// boundElsewhere is a precheck that finds the session bound to "trueopen1bound".
func boundElsewhere() *fakePrechecker {
	return &fakePrechecker{result: inflight.Result{
		Binding: inflight.BoundElsewhere, Session: inflight.Session{SessionState: chaincli.SessionState{BoundBuilder: "trueopen1bound"}},
	}}
}

// openTaskDetail returns the OpenTaskResponse detail of a refusal.
func openTaskDetail(t *testing.T, err error) *nexusv1.OpenTaskResponse {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	for _, d := range ce.Details() {
		msg, derr := d.Value()
		if derr != nil {
			t.Fatal(derr)
		}
		if r, ok := msg.(*nexusv1.OpenTaskResponse); ok {
			return r
		}
	}
	t.Fatalf("no OpenTaskResponse detail in %v", err)
	return nil
}

// Without takeovers a session bound elsewhere is refused naming the bound Builder, also as an
// OpenTaskResponse detail.
func TestOpenTaskHeaderBoundElsewhereDetail(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.svc.auth.Precheck = boundElsewhere()
	err := h.validate()
	wantConnectErr(t, err, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE")
	if d := openTaskDetail(t, err); d.GetBoundBuilder() != "trueopen1bound" {
		t.Fatalf("detail = %v", d)
	}
}

// With takeovers the order goes to Admit, judged as the precheck judged it; its refusals name the
// Builder that recorded the order with its task, or the takeover candidate with the activation
// height.
func TestOpenTaskHeaderTakeoverRefusals(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.svc.auth.Precheck = boundElsewhere()
	tk := &fakeTakeovers{admitErr: &inflight.SessionBoundElsewhereError{Builder: "trueopen1bound", TaskID: "0707070707070707070707070707070707070707070707070707070707070707"}}
	h.svc.auth.Takeovers = tk
	err := h.validate()
	wantConnectErr(t, err, connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE")
	d := openTaskDetail(t, err)
	if d.GetBoundBuilder() != "trueopen1bound" || d.GetTaskId() != "0x0707070707070707070707070707070707070707070707070707070707070707" {
		t.Fatalf("detail = %v", d)
	}
	if len(tk.admitted) != 1 || tk.admitted[0].Sequence != 7 || tk.admitted[0].MaxFee != 150000 {
		t.Fatalf("admitted %+v", tk.admitted)
	}

	tk.admitErr = &inflight.TakeoverPendingError{Candidate: "trueopen1other", ActivationHeight: 1030}
	err = h.validate()
	wantConnectErr(t, err, connect.CodeFailedPrecondition, "NEXUS_INGRESS_TAKEOVER_PENDING")
	if d := openTaskDetail(t, err); d.GetBoundBuilder() != "trueopen1other" || d.GetTakeoverActivationHeight() != 1030 {
		t.Fatalf("detail = %v", d)
	}
	tk.admitErr = inflight.ErrSessionBalanceInsufficient
	wantConnectErr(t, h.validate(), connect.CodeFailedPrecondition, "NEXUS_INGRESS_SESSION_BALANCE_INSUFFICIENT")
	tk.admitErr = inflight.ErrUnavailable
	wantConnectErr(t, h.validate(), connect.CodeUnavailable, "NEXUS_SDKAUTH_CHAIN_UNAVAILABLE")
}

// openTakeoverTask sends the header and one chunk through OpenTask.
func openTakeoverTask(t *testing.T, h *registeredKeyHeader, handler *fakeHandler, api *fakeTaskDataAPI) (*nexusv1.OpenTaskResponse, error) {
	t.Helper()
	client := newTaskDataClientWithHandler(t, handler, api, h.svc.auth)
	stream := client.OpenTask(context.Background())
	if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: h.header}}); err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: make([]byte, 16)}})
	response, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

// An admitted takeover order is stored like any order, but goes to the takeovers, not to the
// coordinator: OpenTask answers TAKEOVER_PENDING naming this Builder.
func TestOpenTaskSubmitsATakeover(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	h.svc.auth.Precheck = boundElsewhere()
	h.svc.auth.BuilderAddress = testSelf
	tk := &fakeTakeovers{}
	h.svc.auth.Takeovers = tk
	api := &fakeTaskDataAPI{chunkSize: 4096}
	handler := &fakeHandler{}
	resp, err := openTakeoverTask(t, h, handler, api)
	if err != nil {
		t.Fatalf("OpenTask: %v", err)
	}
	if !resp.GetAccepted() || resp.GetStatus() != nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_TAKEOVER_PENDING ||
		resp.GetBoundBuilder() != testSelf || resp.TakeoverActivationHeight != nil {
		t.Fatalf("response = %v", resp)
	}
	if api.inputUpload == nil || api.inputRolledBack {
		t.Fatal("the takeover order's input was not stored")
	}
	if len(tk.submitted) != 1 || tk.submitted[0].OrderSequence != 7 || handler.lastOrder.TaskID != "" {
		t.Fatalf("submitted %v, coordinator got %q", tk.submitted, handler.lastOrder.TaskID)
	}
	if len(tk.released) != 0 {
		t.Fatalf("released %v", tk.released)
	}
}

// A takeover order that fails before or at Submit is released and its input dropped.
func TestOpenTaskReleasesAFailedTakeover(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeTakeovers, *fakeTaskDataAPI, *fakeHandler)
	}{
		{"no capacity", func(_ *fakeTakeovers, _ *fakeTaskDataAPI, h *fakeHandler) {
			h.checkOrder = func(context.Context, types.Order) error { return errors.New("NEXUS_INGRESS_NO_CAPACITY") }
		}},
		{"nonce replayed", func(_ *fakeTakeovers, api *fakeTaskDataAPI, _ *fakeHandler) { api.openTaskErr = errors.New("replayed") }},
		{"submit fails", func(tk *fakeTakeovers, _ *fakeTaskDataAPI, _ *fakeHandler) { tk.submitErr = errors.New("disk full") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisteredKeyHeader(t)
			h.signEnvelopeWithWallet(t)
			h.svc.auth.Precheck = boundElsewhere()
			tk := &fakeTakeovers{}
			h.svc.auth.Takeovers = tk
			api := &fakeTaskDataAPI{chunkSize: 4096}
			handler := &fakeHandler{}
			tc.setup(tk, api, handler)
			if _, err := openTakeoverTask(t, h, handler, api); err == nil {
				t.Fatal("OpenTask succeeded")
			}
			if len(tk.released) != 1 {
				t.Fatalf("released %v", tk.released)
			}
			if api.inputUpload != nil && !api.inputRolledBack && tc.name == "submit fails" {
				t.Fatal("the input of a failed takeover stayed")
			}
		})
	}
}

// A resend of an order this Builder holds for a takeover is answered with it before any
// precheck: nothing is stored again, the request nonce is still checked.
func TestOpenTaskAnswersAHeldTakeover(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	p := &fakePrechecker{}
	h.svc.auth.Precheck = p
	h.svc.auth.BuilderAddress = testSelf
	tk := &fakeTakeovers{held: &takeover.Admission{Existing: true, ActivationHeight: 1030}}
	h.svc.auth.Takeovers = tk
	api := &fakeTaskDataAPI{chunkSize: 4096}
	handler := &fakeHandler{}
	resp, err := openTakeoverTask(t, h, handler, api)
	if err != nil {
		t.Fatalf("OpenTask: %v", err)
	}
	if resp.GetStatus() != nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_TAKEOVER_PENDING || resp.GetTakeoverActivationHeight() != 1030 || resp.GetBoundBuilder() != testSelf {
		t.Fatalf("response = %v", resp)
	}
	if len(p.orders) != 0 || api.inputUpload != nil || len(tk.submitted) != 0 || api.openTaskNonce == nil {
		t.Fatalf("precheck %d, upload %v, submitted %d, nonce %x", len(p.orders), api.inputUpload, len(tk.submitted), api.openTaskNonce)
	}
}
