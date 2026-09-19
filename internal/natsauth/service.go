package natsauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
)

// AuthSubject is the fixed request subject of the NATS auth callout.
const AuthSubject = "$SYS.REQ.USER.AUTH"

// defaultHandleTimeout is the default total time limit for chain queries within one request.
const defaultHandleTimeout = 5 * time.Second

// defaultMaxInFlight is the default concurrency cap: each request queries the chain, and serial handling would let one slow query block the whole subscription.
const defaultMaxInFlight = 64

// ServiceConfig holds the callout service dependencies: verifier, issuer and one AUTH-account connection.
type ServiceConfig struct {
	Log      *slog.Logger
	Verifier *Verifier
	Issuer   *Issuer
	// Connect returns a NATS connection established as the AUTH account; injected by the subcommand (msgbus.ConnectOptions).
	Connect func(ctx context.Context) (*nats.Conn, error)
	// HandleTimeout bounds the total chain-query time within one request; default 5s.
	HandleTimeout time.Duration
	// MaxInFlight caps the number of requests handled concurrently; default 64. Once reached, the subscription
	// callback blocks waiting for a slot, and NATS's own slow-consumer mechanism is the backstop instead of unbounded goroutines.
	MaxInFlight int
}

// Service subscribes to AuthSubject and decodes, verifies, issues and replies per request.
// Each request is handled in its own goroutine (throttled by MaxInFlight), so a slow chain query does not block later requests.
type Service struct {
	cfg ServiceConfig
	// sem is the concurrency gate; its capacity is MaxInFlight.
	sem chan struct{}
	// wg counts in-flight handling; Stop relies on it to drain.
	wg sync.WaitGroup

	mu sync.Mutex
	// started is the start gate: true between one Start and the following Stop.
	started bool
	// stopping means Stop has begun shutting down: it shares mu with wg.Add so that the moment
	// "no more in-flight handling is added" is atomic -- otherwise wg.Add would race with wg.Wait (data race).
	stopping bool
	// cancel cancels the service lifetime context: derived in Start, cancelled in Stop,
	// so handlers still in chain queries stop immediately instead of each running out HandleTimeout.
	cancel context.CancelFunc
	nc     *nats.Conn
	sub    *nats.Subscription
}

// NewService validates required dependencies and constructs the service. Verifier and issuer are both
// mandatory and are rejected here rather than nil-dereferenced on the first request -- hence (*Service, error).
// Connect is only needed by Start, so it may be injected after construction.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Verifier == nil:
		return nil, errors.New("natsauth: verifier is required")
	case cfg.Issuer == nil:
		return nil, errors.New("natsauth: issuer is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.HandleTimeout <= 0 {
		cfg.HandleTimeout = defaultHandleTimeout
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = defaultMaxInFlight
	}
	return &Service{cfg: cfg, sem: make(chan struct{}, cfg.MaxInFlight)}, nil
}

// Handle processes one raw authorization request JWT and returns the response JWT to reply with.
// nil means no response can be signed for this request at all (undecodable, or missing user_nkey/server_id), so no reply:
// every failure that can be signed replies with an error code from the closed set.
func (s *Service) Handle(ctx context.Context, raw []byte) []byte {
	claims, err := jwt.DecodeAuthorizationRequestClaims(string(raw))
	if err != nil {
		s.cfg.Log.Warn("undecodable authorization request dropped", "err", err)
		return nil
	}
	req := Request{
		UserNkey:    claims.UserNkey,
		ServerID:    claims.Server.ID,
		ClientNonce: claims.ClientInformation.Nonce,
		ConnectNkey: claims.ConnectOptions.Nkey,
		ConnectSig:  claims.ConnectOptions.SignedNonce,
		AuthToken:   claims.ConnectOptions.Token,
		// sentinel JWT: already verified by the server; kept here only as a log/troubleshooting hint.
		ConnectJWT: claims.ConnectOptions.JWT,
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.HandleTimeout)
	defer cancel()

	decision, verr := s.cfg.Verifier.Verify(ctx, req)
	var userJWT string
	if verr == nil {
		userJWT, err = s.cfg.Issuer.UserJWT(req.UserNkey, decision)
		if err != nil {
			s.cfg.Log.Error("sign user jwt failed", "operator", decision.OperatorAddress, "err", err)
			// Failing to sign the user JWT is a defect of this service, but externally it must still be a closed-set error code.
			verr = Reject(CodeBindingMalformed, "issuer failure")
		}
	}
	resp, err := s.cfg.Issuer.Response(req.UserNkey, req.ServerID, userJWT, verr)
	if err != nil {
		s.cfg.Log.Error("sign authorization response failed", "err", err)
		return nil
	}
	if verr != nil {
		// sentinel=true with empty nkey is the normal shape in operator mode; sentinel=false with empty nkey is a client misconfiguration.
		attrs := []any{"host", claims.ClientInformation.Host, "nkey", req.ConnectNkey, "sentinel", req.ConnectJWT != "", "reason", verr.Error()}
		// Cause goes to logs only, and only when there is a real underlying cause: operators see the raw chain error,
		// the caller never sees it in the response.
		if cause := errors.Unwrap(verr); cause != nil {
			attrs = append(attrs, "cause", cause)
		}
		s.cfg.Log.Info("authorization request rejected", attrs...)
	} else {
		s.cfg.Log.Info("authorization request issued", "host", claims.ClientInformation.Host,
			"operator", decision.OperatorAddress, "nkey", decision.NATSUserPubkey)
	}
	return []byte(resp)
}

// handleMsg is the body of the subscription callback: it takes a concurrency slot, then handles and replies in its own goroutine.
// When no slot is free it blocks here (backpressure is left to NATS's slow-consumer mechanism); once the service is stopped it drops the request.
// reply == nil means the request has no reply subject; it is still handled, just not answered.
//
// The drop decision must be deterministic: check ctx on its own first, then re-check stopping/ctx under mu.
// A select alone is not enough -- when both cases are ready, select picks one at random, so backlog
// delivered during Drain would be let through randomly; and wg.Add must be mutually exclusive with Stop's wg.Wait.
func (s *Service) handleMsg(ctx context.Context, data []byte, reply func([]byte) error) {
	if ctx.Err() != nil {
		return
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	s.mu.Lock()
	if s.stopping || ctx.Err() != nil {
		s.mu.Unlock()
		<-s.sem
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer func() {
			<-s.sem
			s.wg.Done()
		}()
		resp := s.Handle(ctx, data)
		if resp == nil || reply == nil {
			return
		}
		if err := reply(resp); err != nil {
			s.cfg.Log.Warn("respond to authorization request failed", "err", err)
		}
	}()
}

// Start connects to NATS and subscribes to AuthSubject.
// ctx only governs the connection phase (dial timeout, startup cancellation): the service lifetime is derived
// from it via context.WithoutCancel, so it does not end with ctx and ends only on Stop.
// A Service holds at most one subscription at a time: a repeated Start while running is an error;
// Stop clears the fields, so Start is allowed again after Stop.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		return errors.New("natsauth: service already started")
	}
	if s.cfg.Connect == nil {
		return errors.New("natsauth: nats connector is required")
	}
	nc, err := s.cfg.Connect(ctx)
	if err != nil {
		return fmt.Errorf("natsauth: connect nats: %w", err)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	// stopping must be cleared before subscribing: as soon as Subscribe returns, server requests may arrive,
	// and clearing it after subscribing would drop requests in that window as "stopping" for nothing.
	// Leaving it false when Subscribe fails is harmless -- there is no subscription then, so nothing reaches handleMsg.
	s.mu.Lock()
	s.stopping = false
	s.mu.Unlock()
	sub, err := nc.Subscribe(AuthSubject, func(msg *nats.Msg) {
		var reply func([]byte) error
		if strings.TrimSpace(msg.Reply) != "" {
			reply = msg.Respond
		}
		s.handleMsg(runCtx, msg.Data, reply)
	})
	if err != nil {
		cancel()
		nc.Close()
		return fmt.Errorf("natsauth: subscribe %s: %w", AuthSubject, err)
	}
	// Set the gate only on successful start (stopping was already cleared before subscribing).
	s.mu.Lock()
	s.started = true
	s.cancel, s.nc, s.sub = cancel, nc, sub
	s.mu.Unlock()
	s.cfg.Log.Info("nats auth callout serving", "subject", AuthSubject, "server", nc.ConnectedServerName(), "tls", nc.TLSRequired())
	return nil
}

// Stop shuts down in a fixed order, and the order itself is part of the semantics:
//  1. cancel the service lifetime context -- in-flight chain queries stop immediately, requests still waiting for a slot are dropped;
//  2. drain the subscription -- the server delivers no new auth requests here;
//  3. wait for in-flight handling to finish (ctx as the deadline) -- accepted requests either get their reply or fail fast on cancellation;
//  4. close the connection -- strictly after the wait, otherwise replies would hit a closed connection.
//
// Without a prior Start it is a no-op; fields are cleared here, so repeated calls are safe and Start works again after Stop.
func (s *Service) Stop(ctx context.Context) error {
	// stopping must be set in the same critical section as the fields, and before waitInFlight:
	// no wg.Add happens after this point, so wg.Wait cannot race with wg.Add.
	s.mu.Lock()
	s.stopping, s.started = true, false
	cancel, sub, nc := s.cancel, s.sub, s.nc
	s.cancel, s.sub, s.nc = nil, nil, nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if sub != nil {
		_ = sub.Drain()
	}
	err := s.waitInFlight(ctx)
	if nc != nil {
		nc.Close()
	}
	return err
}

// waitInFlight waits for all in-flight handling to finish; when ctx expires it returns an error, but the caller still closes the connection.
// If the caller gives no deadline, a floor of HandleTimeout+1s applies: a single request runs at most that long,
// and a misbehaving ChainReader (e.g. one ignoring ctx) must not hang Stop forever.
func (s *Service) waitInFlight(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.HandleTimeout+time.Second)
		defer cancel()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("natsauth: waiting for in-flight authorization handlers: %w", ctx.Err())
	}
}
