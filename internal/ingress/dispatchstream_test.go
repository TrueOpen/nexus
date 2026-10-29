package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
)

// fakeBidi is the Connect side of a DispatchStream call: requests in, responses out.
type fakeBidi struct {
	requests  []*nexusv1.DispatchStreamRequest
	responses []*nexusv1.DispatchStreamResponse
}

func (f *fakeBidi) Receive() (*nexusv1.DispatchStreamRequest, error) {
	if len(f.requests) == 0 {
		return nil, io.EOF
	}
	req := f.requests[0]
	f.requests = f.requests[1:]
	return req, nil
}

func (f *fakeBidi) Send(resp *nexusv1.DispatchStreamResponse) error {
	f.responses = append(f.responses, resp)
	return nil
}

// echoServer plays the hub: it echoes every frame back and ends with err.
type echoServer struct{ err error }

func (e echoServer) Serve(_ context.Context, stream dispatchstream.FrameStream) error {
	for {
		frame, err := stream.Receive()
		if err != nil {
			if e.err != nil {
				return e.err
			}
			return err
		}
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
}

// The handler only adapts Connect messages to frames and hub errors to Connect codes.
func TestDispatchStreamAdaptsFrames(t *testing.T) {
	frame := &nexusv1.DispatchStreamFrameV1{Cursor: 3}
	bidi := &fakeBidi{requests: []*nexusv1.DispatchStreamRequest{{Frame: frame}}}
	if err := serveDispatchStream(context.Background(), echoServer{}, bidi); err != nil {
		t.Fatalf("clean end = %v, want nil", err)
	}
	if len(bidi.responses) != 1 || bidi.responses[0].GetFrame().GetCursor() != 3 {
		t.Fatalf("responses = %v", bidi.responses)
	}
	empty := &fakeBidi{requests: []*nexusv1.DispatchStreamRequest{{}}}
	if err := serveDispatchStream(context.Background(), echoServer{}, empty); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("request without frame = %v, want InvalidArgument", err)
	}
}

func TestDispatchStreamErrorCodes(t *testing.T) {
	cases := []struct {
		err    error
		code   connect.Code
		prefix string
	}{
		{fmt.Errorf("%w: bad signature", dispatchstream.ErrBindingInvalid), connect.CodeUnauthenticated, "DISPATCH_STREAM_BINDING_INVALID"},
		{fmt.Errorf("%w: cursor", dispatchstream.ErrProtocol), connect.CodeInvalidArgument, ""},
		{fmt.Errorf("%w: node", dispatchstream.ErrTransient), connect.CodeUnavailable, ""},
		{dispatchstream.ErrReplaced, connect.CodeAborted, ""},
		{dispatchstream.ErrKeepaliveTimeout, connect.CodeUnavailable, ""},
		{dispatchstream.ErrStopped, connect.CodeUnavailable, ""},
		{context.Canceled, connect.CodeCanceled, ""},
		{errors.New("disk"), connect.CodeInternal, ""},
	}
	for _, tc := range cases {
		err := serveDispatchStream(context.Background(), echoServer{err: tc.err}, &fakeBidi{})
		if connect.CodeOf(err) != tc.code {
			t.Errorf("%v -> %v, want %v", tc.err, connect.CodeOf(err), tc.code)
		}
		var connectErr *connect.Error
		if tc.prefix != "" && (!errors.As(err, &connectErr) || !strings.HasPrefix(connectErr.Message(), tc.prefix)) {
			t.Errorf("%v message = %v, want prefix %s", tc.err, err, tc.prefix)
		}
	}
}

func TestDispatchStreamUnimplementedWithoutHub(t *testing.T) {
	s := newService(nil, AuthParams{})
	if err := s.DispatchStream(context.Background(), nil); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("DispatchStream without a hub = %v, want Unimplemented", err)
	}
}
