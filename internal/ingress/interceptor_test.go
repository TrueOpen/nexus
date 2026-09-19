package ingress

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

func TestLoggingInterceptorIncludesRPCErrorCause(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	wantErr := connect.NewError(connect.CodeInternal, errors.New("publish open task: nats confirmation failed"))
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, wantErr
	}

	_, err := loggingInterceptor(log).WrapUnary(next)(
		context.Background(), connect.NewRequest(&nexusv1.SubmitOrderRequest{}),
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("interceptor error = %v, want original error", err)
	}
	got := logs.String()
	for _, want := range []string{
		`msg=rpc`,
		`code=internal`,
		`err="internal: publish open task: nats confirmation failed"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("logs missing %q:\n%s", want, got)
		}
	}
}

// Streaming handlers (UploadTaskResultObject etc.) must also leave an rpc log line when rejected,
// otherwise troubleshooting means digging through Cortex-side retry records.
func TestLoggingInterceptorCoversStreamingHandlers(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	wantErr := connect.NewError(connect.CodeDataLoss, errors.New("received bytes do not match declaration"))
	next := func(context.Context, connect.StreamingHandlerConn) error { return wantErr }
	conn := streamingConnStub{procedure: "/nexus.v1.IngressAPI/UploadTaskResultObject", peer: "127.0.0.1:1"}
	if err := loggingInterceptor(log).WrapStreamingHandler(next)(context.Background(), conn); !errors.Is(err, wantErr) {
		t.Fatalf("interceptor error = %v, want original error", err)
	}
	got := logs.String()
	for _, want := range []string{`msg=rpc`, `procedure=/nexus.v1.IngressAPI/UploadTaskResultObject`, `code=data_loss`, `received bytes do not match declaration`} {
		if !strings.Contains(got, want) {
			t.Fatalf("logs missing %q:\n%s", want, got)
		}
	}
}

type streamingConnStub struct {
	connect.StreamingHandlerConn
	procedure, peer string
}

func (s streamingConnStub) Spec() connect.Spec { return connect.Spec{Procedure: s.procedure} }
func (s streamingConnStub) Peer() connect.Peer { return connect.Peer{Addr: s.peer} }
