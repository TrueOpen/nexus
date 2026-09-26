// Package ingress is the single external entry point (implementation design §4.1).
// Connect: one net/http port (:8080) serving gRPC, gRPC-Web and HTTP/JSON at once.
// Cross-cutting concerns go through Connect unary interceptors (reusing middleware's pure functions);
// /healthz is a plain HTTP route on the same port, callable directly with curl.
package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/middleware"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

type Option func(*Server)

// WithTLS makes ingress terminate TLS itself: the same port switches to HTTP/2 over TLS (with HTTP/1.1 fallback)
// and no longer serves plaintext h2c. The caller registers the certificate public key hash on-chain with the descriptor, and clients verify identity against it.
func WithTLS(certificate tls.Certificate) Option {
	return func(s *Server) {
		s.tlsCertificate = &certificate
	}
}

func WithBuilderDescriptor(body []byte) Option {
	return func(s *Server) {
		s.builderDescriptor = append([]byte(nil), body...)
	}
}

func WithTaskDataService(service *taskdata.Service) Option {
	return func(s *Server) {
		if service != nil {
			s.taskData = taskDataRuntime{service: service}
		}
	}
}

const payloadMessageOverheadBytes = 64 << 10

// WithPayloadMaxBytes bounds both decoded Connect messages and raw HTTP bodies.
func WithPayloadMaxBytes(maxPayloadBytes int) Option {
	return func(s *Server) {
		if maxPayloadBytes <= 0 {
			return
		}
		maxInt := int(^uint(0) >> 1)
		if maxPayloadBytes > maxInt-payloadMessageOverheadBytes {
			s.readMaxBytes = maxInt
		} else {
			s.readMaxBytes = maxPayloadBytes + payloadMessageOverheadBytes
		}
		messageBytes := int64(s.readMaxBytes)
		maxInt64 := int64(^uint64(0) >> 1)
		if messageBytes > (maxInt64-payloadMessageOverheadBytes)/2 {
			s.httpMaxBytes = maxInt64
		} else {
			// Covers protobuf framing and HTTP/JSON base64 expansion.
			s.httpMaxBytes = messageBytes*2 + payloadMessageOverheadBytes
		}
	}
}

// WithReadMaxBytes sets the decoded per-message limit for task-data RPCs.
// Total streamed bytes remain bounded by taskdata.Store.
func WithReadMaxBytes(maxMessageBytes uint64) Option {
	return func(s *Server) {
		maxInt := uint64(^uint(0) >> 1)
		if maxMessageBytes == 0 {
			return
		}
		if maxMessageBytes > maxInt-payloadMessageOverheadBytes {
			s.taskDataReadMaxBytes = int(maxInt)
			return
		}
		s.taskDataReadMaxBytes = int(maxMessageBytes) + payloadMessageOverheadBytes
	}
}

type Server struct {
	log                  *slog.Logger
	cfg                  config.IngressConfig
	h                    Handler
	auth                 AuthParams
	apiKeys              map[string]struct{}
	whitelist            []*net.IPNet
	builderDescriptor    []byte
	natsSentinelFile     string
	natsAdvertiseServers []string
	natsAdvertiseCAFile  string
	natsSentinel         []byte
	readMaxBytes         int
	taskDataReadMaxBytes int
	httpMaxBytes         int64
	taskData             taskDataAPI
	outputStream         *outputStreamRuntime

	tlsCertificate *tls.Certificate

	srv    *http.Server
	listen func(network, address string) (net.Listener, error)
	mu     sync.Mutex
	ln     net.Listener
}

// Addr returns the actual listen address (how the port is obtained when ListenAddr is :0); empty string before start.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// New builds ingress; parses api-keys and the allowlist (an allowlist parse failure is an error).
// auth is the SDK envelope verification environment (chain_id / bech32 prefix / whether the envelope is enforced).
func New(log *slog.Logger, cfg config.IngressConfig, auth AuthParams, h Handler, opts ...Option) (*Server, error) {
	keys := make(map[string]struct{}, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		keys[k] = struct{}{}
	}
	nets, err := middleware.ParseCIDRs(cfg.IPWhitelist)
	if err != nil {
		return nil, fmt.Errorf("parse ip whitelist: %w", err)
	}
	s := &Server{log: log, cfg: cfg, h: h, auth: auth, apiKeys: keys, whitelist: nets, listen: net.Listen}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Server) Start(_ context.Context) error {
	if err := s.loadNATSSentinel(); err != nil {
		return err
	}
	handler := s.handler()

	s.log.Info("ingress middleware",
		"api_key_enabled", len(s.apiKeys) > 0,
		"ip_whitelist", len(s.whitelist),
		"sdk_envelope_required", s.auth.RequireEnvelope)

	ln, err := s.listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen ingress %q: %w", s.cfg.ListenAddr, err)
	}
	addr := ln.Addr().String()
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	if s.tlsCertificate != nil {
		// TLS: HTTP/2 is negotiated via ALPN; HTTP/1.1 clients (curl, browsers) can still fall back.
		s.srv = &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{*s.tlsCertificate},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2", "http/1.1"},
			},
		}
		go func() {
			s.log.Info("ingress listening with TLS (connect: grpc + grpc-web + http/json)", "addr", addr)
			if err := s.srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
				s.log.Error("ingress server error", "err", err)
			}
		}()
		return nil
	}

	// h2c: let plaintext HTTP/2 gRPC clients connect without TLS
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           h2c.NewHandler(handler, &http2.Server{}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		s.log.Info("ingress listening (connect: grpc + grpc-web + http/json)", "addr", addr)
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
			s.log.Error("ingress server error", "err", err)
		}
	}()
	return nil
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	baseHandlerOptions := []connect.HandlerOption{connect.WithInterceptors(
		loggingInterceptor(s.log), // outermost: logs every RPC (including rejected ones)
		ipWhitelistInterceptor(s.whitelist),
		apiKeyInterceptor(s.apiKeys),
	)}
	legacyHandlerOptions := append([]connect.HandlerOption(nil), baseHandlerOptions...)
	if s.readMaxBytes > 0 {
		legacyHandlerOptions = append(legacyHandlerOptions, connect.WithReadMaxBytes(s.readMaxBytes))
	}
	serviceOptions := make([]serviceOption, 0, 1)
	if s.taskData != nil {
		serviceOptions = append(serviceOptions, withTaskDataAPI(s.taskData))
	}
	if s.outputStream != nil {
		serviceOptions = append(serviceOptions, withOutputStream(s.outputStream))
	}
	service := newService(s.h, s.auth, serviceOptions...)
	path, legacyHandler := nexusv1connect.NewIngressAPIHandler(service, legacyHandlerOptions...)
	if s.httpMaxBytes > 0 {
		legacyHandler = http.MaxBytesHandler(legacyHandler, s.httpMaxBytes)
	}
	handler := legacyHandler
	if s.taskDataReadMaxBytes > 0 {
		taskDataHandlerOptions := append(append([]connect.HandlerOption(nil), baseHandlerOptions...), connect.WithReadMaxBytes(s.taskDataReadMaxBytes))
		_, taskDataHandler := nexusv1connect.NewIngressAPIHandler(service, taskDataHandlerOptions...)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isTaskDataProcedure(r.URL.Path) {
				taskDataHandler.ServeHTTP(w, r)
				return
			}
			legacyHandler.ServeHTTP(w, r)
		})
	}
	mux.Handle(path, handler)

	// gRPC reflection (grpcurl debugging)
	reflector := grpcreflect.NewStaticReflector(nexusv1connect.IngressAPIName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// health check: plain HTTP on the same port, callable directly with curl
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	// NATS sentinel: like /healthz, plain HTTP on the same port, bypassing the Connect interceptors (public, non-secret data)
	mux.Handle("GET "+NATSSentinelPath, s.natsSentinelHandler())
	if len(s.builderDescriptor) > 0 {
		mux.Handle(nodecontract.BuilderDescriptorPath, nodecontract.DescriptorHandler(s.builderDescriptor))
	}
	return mux
}

func isTaskDataProcedure(path string) bool {
	switch path {
	case nexusv1connect.IngressAPIOpenTaskProcedure,
		nexusv1connect.IngressAPIGetTaskDataMetadataProcedure,
		nexusv1connect.IngressAPIFetchTaskDataProcedure,
		nexusv1connect.IngressAPIUploadTaskResultObjectProcedure,
		nexusv1connect.IngressAPIUploadTaskOutputStreamProcedure:
		return true
	default:
		return false
	}
}

// BeginStop synchronously closes the listener without waiting for active RPCs.
// App then wakes output subscribers before Stop waits for HTTP drain completion.
func (s *Server) BeginStop(context.Context) error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if s.outputStream != nil {
		// Disconnect all streaming subscribers so pending SubscribeOutput calls return immediately and HTTP can drain.
		s.outputStream.dispatcher.Stop()
	}
	if ln == nil {
		return nil
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if err := s.BeginStop(ctx); err != nil {
		return err
	}
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}
