package ingress

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"connectrpc.com/connect"

	"github.com/TrueOpen/nexus/internal/middleware"
)

// loggingInterceptor records procedure, status code, source and latency for every RPC. Covers both unary and
// streaming handlers: when streaming methods such as UploadTaskResultObject / UploadTaskOutputStream /
// FetchTaskData are rejected, without this log line the only place to look for the cause is the Cortex side.
func loggingInterceptor(log *slog.Logger) connect.Interceptor {
	return rpcLogger{log: log}
}

type rpcLogger struct {
	log *slog.Logger
}

func (l rpcLogger) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		start := time.Now()
		resp, err := next(ctx, req)
		l.emit(req.Spec().Procedure, req.Peer().Addr, start, err)
		return resp, err
	}
}

func (l rpcLogger) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (l rpcLogger) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		start := time.Now()
		err := next(ctx, conn)
		l.emit(conn.Spec().Procedure, conn.Peer().Addr, start, err)
		return err
	}
}

func (l rpcLogger) emit(procedure, peer string, start time.Time, err error) {
	code := "ok"
	if err != nil {
		code = connect.CodeOf(err).String()
	}
	attrs := []any{
		"procedure", procedure,
		"peer", peer,
		"code", code,
		"dur_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	l.log.Info("rpc", attrs...)
}

// apiKeyInterceptor validates the api-key header. Empty keys = disabled.
func apiKeyInterceptor(keys map[string]struct{}) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if len(keys) == 0 {
				return next(ctx, req)
			}
			if !middleware.ValidKey(keys, req.Header().Get(middleware.HeaderAPIKey)) {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing or invalid api key"))
			}
			return next(ctx, req)
		}
	}
}

// ipWhitelistInterceptor only admits RPCs whose peer IP matches the allowlist. Empty allowed = disabled.
func ipWhitelistInterceptor(allowed []*net.IPNet) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if len(allowed) == 0 {
				return next(ctx, req)
			}
			host, _, err := net.SplitHostPort(req.Peer().Addr)
			if err != nil {
				host = req.Peer().Addr
			}
			if !middleware.IPAllowed(allowed, net.ParseIP(host)) {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("ip not allowed"))
			}
			return next(ctx, req)
		}
	}
}
