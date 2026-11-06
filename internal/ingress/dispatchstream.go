package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
)

// dispatchStreamWriteTimeout bounds the write of one frame to a Cortex, and of the end of the call
// after the hub returns. Nothing else does: an HTTP/2 write the peer's flow control holds back
// waits until the stream or the connection closes, and the request context does not end it. A
// Cortex that leaves a frame unread this long stopped reading; the deadline resets the stream, the
// write fails and the hub ends the stream.
const dispatchStreamWriteTimeout = 10 * time.Second

type responseControllerKey struct{}

// withResponseController gives the DispatchStream handler the controller of its HTTP response,
// which Connect does not expose, so that each frame write can carry a deadline.
func withResponseController(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), responseControllerKey{}, http.NewResponseController(w))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

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

type frameStream struct {
	bidi bidiStream
	// setWriteDeadline is the response's write deadline; nil when the response has none.
	setWriteDeadline func(time.Time) error
}

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
	if f.setWriteDeadline != nil {
		_ = f.setWriteDeadline(time.Now().Add(dispatchStreamWriteTimeout))
		defer func() { _ = f.setWriteDeadline(time.Time{}) }()
	}
	return f.bidi.Send(&nexusv1.DispatchStreamResponse{Frame: frame})
}

func serveDispatchStream(ctx context.Context, server dispatchStreamServer, bidi bidiStream) error {
	stream := frameStream{bidi: bidi}
	if rc, ok := ctx.Value(responseControllerKey{}).(*http.ResponseController); ok && rc.SetWriteDeadline(time.Time{}) == nil {
		stream.setWriteDeadline = rc.SetWriteDeadline
	}
	err := server.Serve(ctx, stream)
	if stream.setWriteDeadline != nil {
		// Connect writes the end of the call after the handler returns; it is bounded like a frame
		// and the deadline stays, as nothing is written after it.
		_ = stream.setWriteDeadline(time.Now().Add(dispatchStreamWriteTimeout))
	}
	return mapDispatchStreamErr(err)
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
