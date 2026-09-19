package natsauth

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// encodeServerRequestAs simulates nats-server: it encodes AuthorizationRequestClaims into a JWT signed with a server nkey.
// subject is passed separately so a malformed request with an empty user_nkey can be built -- the jwt/v2 constructor does not accept an empty subject.
func encodeServerRequestAs(t *testing.T, subject string, req Request) []byte {
	t.Helper()
	server, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal(err)
	}
	serverPub := mustPublicKey(t, server)
	claims := jwt.NewAuthorizationRequestClaims(subject)
	if claims == nil {
		t.Fatalf("subject %q is not encodable", subject)
	}
	serverID := req.ServerID
	if serverID == "" {
		serverID = serverPub
	}
	claims.Server = jwt.ServerID{Name: "s1", ID: serverID}
	claims.UserNkey = req.UserNkey
	claims.ClientInformation = jwt.ClientInformation{Nonce: req.ClientNonce, Host: "127.0.0.1"}
	claims.ConnectOptions = jwt.ConnectOptions{Nkey: req.ConnectNkey, SignedNonce: req.ConnectSig, Token: req.AuthToken}
	token, err := claims.Encode(server)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(token)
}

func encodeServerRequest(t *testing.T, req Request) []byte {
	t.Helper()
	return encodeServerRequestAs(t, req.UserNkey, req)
}

func testService(t *testing.T, chain ChainQueries) *Service {
	t.Helper()
	iss, _, _ := testIssuer(t)
	svc, err := NewService(ServiceConfig{
		Log:      slog.Default(),
		Verifier: NewVerifier(VerifierConfig{ChainID: "c", Chain: NewCachedChain(chain, 0, time.Now), MaxClockSkew: time.Minute, Now: func() time.Time { return time.UnixMilli(1000) }}),
		Issuer:   iss,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestServiceHandleIssuesJWTOnValidRequest(t *testing.T) {
	req, chain, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	svc := testService(t, chain)
	resp := svc.Handle(context.Background(), encodeServerRequest(t, req))
	claims, err := jwt.DecodeAuthorizationResponseClaims(string(resp))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Error != "" || claims.Jwt == "" {
		t.Fatalf("expected jwt, got %+v", claims)
	}
	user, err := jwt.DecodeUserClaims(claims.Jwt)
	if err != nil {
		t.Fatal(err)
	}
	if user.Subject != req.UserNkey {
		t.Fatalf("user jwt sub = %s", user.Subject)
	}
}

// The response must be claimable by the server that asked: sub echoes the request's user_nkey, aud echoes its server_id.
func TestServiceHandleEchoesUserNkeyAndServerID(t *testing.T) {
	req, chain, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	serverKey, err := nkeys.CreateServer()
	if err != nil {
		t.Fatal(err)
	}
	req.ServerID = mustPublicKey(t, serverKey)
	resp := testService(t, chain).Handle(context.Background(), encodeServerRequest(t, req))
	claims, err := jwt.DecodeAuthorizationResponseClaims(string(resp))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != req.UserNkey || claims.Audience != req.ServerID {
		t.Fatalf("sub = %q (want %q), aud = %q (want %q)", claims.Subject, req.UserNkey, claims.Audience, req.ServerID)
	}
}

func TestServiceHandleReturnsCodedErrorOnRejection(t *testing.T) {
	req, chain, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	req.ClientNonce = "tampered"
	resp := testService(t, chain).Handle(context.Background(), encodeServerRequest(t, req))
	claims, err := jwt.DecodeAuthorizationResponseClaims(string(resp))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Jwt != "" || !strings.HasPrefix(claims.Error, string(CodeNonceSignatureInvalid)) {
		t.Fatalf("expected coded error, got %+v", claims)
	}
}

func TestServiceHandleIgnoresUndecodableRequest(t *testing.T) {
	_, chain, _ := goodRequest(t)
	if resp := testService(t, chain).Handle(context.Background(), []byte("not a jwt")); resp != nil {
		t.Fatalf("undecodable request must produce no response, got %q", resp)
	}
}

// A request with an empty user_nkey / server_id cannot be signed into a response (the jwt/v2 constructor returns nil),
// so it must silently produce no reply rather than panic.
func TestServiceHandleDropsRequestWithoutUserNkey(t *testing.T) {
	_, chain, _ := goodRequest(t)
	raw := encodeServerRequestAs(t, mustUserPub(t), Request{})
	if resp := testService(t, chain).Handle(context.Background(), raw); resp != nil {
		t.Fatalf("request without user_nkey must produce no response, got %q", resp)
	}
}

// ctxChain returns the ctx cancellation state as a chain error: it simulates the chain query observing the timeout/cancellation itself.
type ctxChain struct{}

func (ctxChain) QueryCurrentServiceKey(ctx context.Context, _, _ string) (chaincli.ServiceKeyState, error) {
	if err := ctx.Err(); err != nil {
		return chaincli.ServiceKeyState{}, err
	}
	return chaincli.ServiceKeyState{}, context.Canceled
}

func (ctxChain) QueryCortexNode(ctx context.Context, _ string) (chaincli.CortexNodeState, error) {
	if err := ctx.Err(); err != nil {
		return chaincli.CortexNodeState{}, err
	}
	return chaincli.CortexNodeState{}, context.Canceled
}

// When the upstream ctx is cancelled, the failed chain query maps to CHAIN_UNAVAILABLE: still a rejection from the closed set, not an empty reply.
func TestServiceHandleHonoursCancelledContext(t *testing.T) {
	req, _, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	svc := testService(t, ctxChain{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp := svc.Handle(ctx, encodeServerRequest(t, req))
	claims, err := jwt.DecodeAuthorizationResponseClaims(string(resp))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Jwt != "" || !strings.HasPrefix(claims.Error, string(CodeChainUnavailable)) {
		t.Fatalf("expected CHAIN_UNAVAILABLE, got %+v", claims)
	}
}

// Without a connector the service cannot start: Start must report a clear error rather than dereference nil.
func TestServiceStartRequiresConnector(t *testing.T) {
	_, chain, _ := goodRequest(t)
	err := testService(t, chain).Start(context.Background())
	if err == nil {
		t.Fatal("start without a connector must fail")
	}
	if !strings.Contains(err.Error(), "connector") {
		t.Fatalf("error should name the missing connector, got %v", err)
	}
}

// Verifier and issuer are required dependencies: they must be refused at construction, not fail with a nil pointer on the first request.
func TestNewServiceRequiresVerifierAndIssuer(t *testing.T) {
	iss, _, _ := testIssuer(t)
	cases := map[string]ServiceConfig{
		"missing verifier": {Issuer: iss},
		"missing issuer":   {Verifier: newVerifierWith(NewCachedChain(&fakeChain{}, 0, time.Now))},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewService(cfg); err == nil {
				t.Fatal("missing dependency must be refused at construction")
			}
		})
	}
}

func mustUserPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	return mustPublicKey(t, kp)
}

// Stop before Start is a no-op; repeated Stop must also be safe.
func TestServiceStopIsIdempotentAndSafeBeforeStart(t *testing.T) {
	_, chain, _ := goodRequest(t)
	svc := testService(t, chain)
	for i := 0; i < 3; i++ {
		if err := svc.Stop(context.Background()); err != nil {
			t.Fatalf("stop #%d: %v", i+1, err)
		}
	}
}

// A second Start while already running must fail outright; after Stop clears the fields, Start is allowed again
// (here the second Start reaching "missing connector" shows the start gate has reopened).
func TestServiceRefusesSecondStart(t *testing.T) {
	_, chain, _ := goodRequest(t)
	svc := testService(t, chain)
	svc.started = true // simulate "already running" without actually connecting to a server
	err := svc.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second start must be refused, got %v", err)
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "connector") {
		t.Fatalf("after stop the gate must reopen, got %v", err)
	}
}

// barrierChain makes the first n chain queries wait for each other: they can only all arrive together if handling is genuinely concurrent.
type barrierChain struct {
	inner *fakeChain
	n     int

	mu      sync.Mutex
	arrived int
	gate    chan struct{}
	timeout bool
}

func newBarrierChain(inner *fakeChain, n int) *barrierChain {
	return &barrierChain{inner: inner, n: n, gate: make(chan struct{})}
}

func (b *barrierChain) arrive() {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.n {
		close(b.gate)
	}
	b.mu.Unlock()
	select {
	case <-b.gate:
	case <-time.After(3 * time.Second):
		b.mu.Lock()
		b.timeout = true
		b.mu.Unlock()
	}
}

func (b *barrierChain) timedOut() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.timeout
}

func (b *barrierChain) QueryCurrentServiceKey(ctx context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	b.arrive()
	return b.inner.QueryCurrentServiceKey(ctx, participantType, operator)
}

func (b *barrierChain) QueryCortexNode(ctx context.Context, operator string) (chaincli.CortexNodeState, error) {
	return b.inner.QueryCortexNode(ctx, operator)
}

// One slow chain query must not block the requests behind it: 10 submitted at once must all arrive at the chain together.
func TestServiceHandlesRequestsConcurrently(t *testing.T) {
	const n = 10
	req, chain, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	barrier := newBarrierChain(chain, n)
	svc := testService(t, barrier)
	raw := encodeServerRequest(t, req)

	replies := make(chan []byte, n)
	for i := 0; i < n; i++ {
		svc.handleMsg(context.Background(), raw, func(resp []byte) error {
			replies <- resp
			return nil
		})
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if barrier.timedOut() {
		t.Fatal("requests were serialised: the chain never saw 10 concurrent queries")
	}
	if len(replies) != n {
		t.Fatalf("got %d replies, want %d", len(replies), n)
	}
	for i := 0; i < n; i++ {
		claims, err := jwt.DecodeAuthorizationResponseClaims(string(<-replies))
		if err != nil {
			t.Fatal(err)
		}
		if claims.Jwt == "" || claims.Error != "" {
			t.Fatalf("reply %d = %+v", i, claims)
		}
	}
}

// A request without a reply subject is still handled, just not answered; Stop must wait for it to finish.
func TestServiceHandleMsgWithoutReplyStillCompletes(t *testing.T) {
	req, chain, _ := goodRequest(t)
	req.UserNkey = mustUserPub(t)
	svc := testService(t, chain)
	svc.handleMsg(context.Background(), encodeServerRequest(t, req), nil)
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if keys, _ := chain.counts(); keys == 0 {
		t.Fatal("handler did not run to completion before stop returned")
	}
}

// Stop and handleMsg must be safe to happen at the same time: once Stop begins waiting, the wg counter must not bounce back up from 0,
// otherwise it is a WaitGroup "Add concurrent with Wait" (a data race, and it also lets Stop return before the handler registers).
// Each round uses a fresh service so Stop's Wait lands exactly on a handleMsg that has just taken off.
func TestServiceStopRacesHandleMsg(t *testing.T) {
	_, chain, _ := goodRequest(t)
	raw := []byte("not a jwt") // an undecodable request: the shortest single handling, so the counter most easily returns to zero
	for i := 0; i < 500; i++ {
		svc := testService(t, chain)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				svc.handleMsg(context.Background(), raw, nil)
			}()
		}
		if err := svc.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		// A request arriving after the stop must be deterministically dropped rather than starting another goroutine.
		svc.handleMsg(context.Background(), raw, nil)
		if err := svc.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// When the lifetime context is already cancelled, the request must be deterministically dropped: it takes no slot and does not enter the WaitGroup.
func TestServiceHandleMsgDropsWhenContextDone(t *testing.T) {
	_, chain, _ := goodRequest(t)
	svc := testService(t, chain)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.handleMsg(ctx, []byte("not a jwt"), func([]byte) error {
		t.Error("cancelled service must not reply")
		return nil
	})
	if len(svc.sem) != 0 {
		t.Fatalf("dropped request must not hold a slot, sem = %d", len(svc.sem))
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
