package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
)

// dispatchStreamServer runs one Cortex dispatch stream; *dispatchstream.Hub implements it.
type dispatchStreamServer interface {
	Serve(ctx context.Context, stream dispatchstream.FrameStream) error
}

// WithDispatchStream serves IngressAPI.DispatchStream from the hub.
func WithDispatchStream(server dispatchStreamServer) Option {
	return func(s *Server) { s.dispatchStream = server }
}

func withDispatchStreamServer(server dispatchStreamServer) serviceOption {
	return func(s *service) { s.dispatchStream = server }
}

// DispatchStream adapts the Connect bidirectional stream to the hub; all stream logic lives there.
func (s *service) DispatchStream(ctx context.Context, stream *connect.BidiStream[nexusv1.DispatchStreamRequest, nexusv1.DispatchStreamResponse]) error {
	if s.dispatchStream == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("dispatch stream is not served by this Builder"))
	}
	return serveDispatchStream(ctx, s.dispatchStream, stream)
}

// bidiStream is the part of connect.BidiStream the adapter uses.
type bidiStream interface {
	Receive() (*nexusv1.DispatchStreamRequest, error)
	Send(*nexusv1.DispatchStreamResponse) error
}

type frameStream struct{ bidi bidiStream }

func (f frameStream) Receive() (*nexusv1.DispatchStreamFrameV1, error) {
	req, err := f.bidi.Receive()
	if err != nil {
		return nil, err
	}
	if req.GetFrame() == nil {
		return nil, fmt.Errorf("%w: request carries no frame", dispatchstream.ErrProtocol)
	}
	return req.GetFrame(), nil
}

func (f frameStream) Send(frame *nexusv1.DispatchStreamFrameV1) error {
	return f.bidi.Send(&nexusv1.DispatchStreamResponse{Frame: frame})
}

func serveDispatchStream(ctx context.Context, server dispatchStreamServer, bidi bidiStream) error {
	return mapDispatchStreamErr(server.Serve(ctx, frameStream{bidi: bidi}))
}

// mapDispatchStreamErr turns the reason a stream ended into a Connect status. A Cortex that closed
// its side ends the call cleanly.
func mapDispatchStreamErr(err error) error {
	var connectErr *connect.Error
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return nil
	case errors.As(err, &connectErr):
		return err
	case errors.Is(err, dispatchstream.ErrBindingInvalid):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, dispatchstream.ErrProtocol):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, dispatchstream.ErrReplaced):
		return connect.NewError(connect.CodeAborted, err)
	case errors.Is(err, dispatchstream.ErrTransient), errors.Is(err, dispatchstream.ErrKeepaliveTimeout),
		errors.Is(err, dispatchstream.ErrStopped):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
