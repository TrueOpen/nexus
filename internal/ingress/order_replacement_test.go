package ingress

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/taskgroup"
	"github.com/TrueOpen/nexus/internal/types"
)

var orderVersionRefusals = []struct {
	name    string
	err     error
	message string
}{
	{
		name:    "replacement",
		err:     fmt.Errorf("%w: sequence 3 is being dispatched with task_hash aa", inflight.ErrOrderReplacementUnsupported),
		message: "NEXUS_INGRESS_ORDER_REPLACEMENT_UNSUPPORTED",
	},
	{
		name:    "no capacity",
		err:     fmt.Errorf("%w: no admitted handraise for the order's profile", dispatchdraw.ErrNoCapacity),
		message: "NEXUS_INGRESS_NO_CAPACITY",
	},
	{
		name:    "builder set stale",
		err:     fmt.Errorf("%w: order names BuilderSet \"term-1\", current is \"term-2\"", taskgroup.ErrBuilderSetStale),
		message: "NEXUS_INGRESS_BUILDER_SET_STALE",
	},
}

// An order the coordinator refuses is rejected before BeginInput, so nothing is stored and the
// stored version's input index is untouched. The client's remaining chunks are drained, so the
// SDK receives the code instead of blocking on Send.
func TestOpenTaskRefusesOrderVersionBeforeStoringInput(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	for index, tt := range orderVersionRefusals {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeTaskDataAPI{chunkSize: 4}
			handler := &fakeHandler{}
			handler.checkOrder = func(context.Context, types.Order) error { return tt.err }
			handler.onOrder = func(context.Context, types.Order) error {
				t.Fatal("OnOrder called after CheckOrder refused the order")
				return nil
			}
			client := newTaskDataClientWithHandler(t, handler, api, AuthParams{Chain: testUserChain,
				ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			input := []byte(strings.Repeat("abcd", 64))
			header := openTaskHeader(t, user, testSessionID(fmt.Sprintf("session-version-%d", index)), 4, input)
			stream := client.OpenTask(context.Background())
			if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}}); err != nil {
				t.Fatal(err)
			}
			for offset := 0; offset < len(input); offset += 4 {
				// The server may already have answered; a send error here is not the result.
				_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: input[offset : offset+4]}})
			}
			_, err := stream.CloseAndReceive()
			if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("OpenTask error=%v code=%v, want FailedPrecondition %s", err, connect.CodeOf(err), tt.message)
			}
			if api.inputUpload != nil || api.inputRolledBack {
				t.Fatalf("refused version touched storage: upload=%v rolled_back=%t", api.inputUpload != nil, api.inputRolledBack)
			}
		})
	}
}

// A refusal of OnOrder after the upload maps to the same code and rolls the prepared input back.
func TestOpenTaskMapsOrderVersionRefusalFromOnOrder(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	for index, tt := range orderVersionRefusals {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeTaskDataAPI{chunkSize: 64}
			client := newTaskDataClientWithHandler(t, &fakeHandler{orderErr: tt.err}, api, AuthParams{Chain: testUserChain,
				ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			header := openTaskHeader(t, user, testSessionID(fmt.Sprintf("session-version-race-%d", index)), 5, []byte("input"))
			stream := client.OpenTask(context.Background())
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: []byte("input")}})
			_, err := stream.CloseAndReceive()
			if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("OpenTask error=%v code=%v, want FailedPrecondition %s", err, connect.CodeOf(err), tt.message)
			}
			if !api.inputRolledBack {
				t.Fatal("prepared input was not rolled back")
			}
		})
	}
}

func TestMapOrderErrVersionRefusals(t *testing.T) {
	for _, tt := range orderVersionRefusals {
		err := mapOrderErr(tt.err)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.HasPrefix(connectMessage(err), tt.message+":") {
			t.Errorf("%s: mapOrderErr = %v (code %v)", tt.name, err, connect.CodeOf(err))
		}
	}
	for _, err := range []error{coordinator.ErrDispatchUnavailable, inflight.ErrUnavailable} {
		if got := mapOrderErr(err); connect.CodeOf(got) != connect.CodeUnavailable {
			t.Errorf("mapOrderErr(%v) = %v", err, got)
		}
	}
}

func connectMessage(err error) string {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr.Message()
	}
	return err.Error()
}

// An order whose epoch cannot dispatch yet is refused before its input is stored as the
// retryable NEXUS_INGRESS_DISPATCH_NOT_READY (Unavailable), its message ending with the height
// from which dispatch is possible.
func TestOpenTaskRefusesAnEpochNotReady(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 64}
	handler := &fakeHandler{}
	handler.checkOrder = func(context.Context, types.Order) error {
		return &dispatchdraw.NotReadyError{Epoch: 8, DispatchableHeight: 812, Reason: "snapshot not effective"}
	}
	client := newTaskDataClientWithHandler(t, handler, api, AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	header := openTaskHeader(t, user, testSessionID("session-not-ready"), 5, []byte("input"))
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: []byte("input")}})
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeUnavailable || !strings.HasPrefix(connectMessage(err), "NEXUS_INGRESS_DISPATCH_NOT_READY:") ||
		!strings.HasSuffix(connectMessage(err), "dispatchable_height=812") {
		t.Fatalf("OpenTask error=%v code=%v, want Unavailable DISPATCH_NOT_READY with the height", err, connect.CodeOf(err))
	}
	if api.inputUpload != nil {
		t.Fatal("an order not ready was stored")
	}
}
