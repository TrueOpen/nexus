package ingress

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"connectrpc.com/connect"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	"github.com/TrueOpen/nexus/gen/buildersync/v1/buildersyncv1connect"
	"github.com/TrueOpen/nexus/internal/buildersync"
)

const (
	// builderSyncReadMaxBytes bounds one sync batch: a run of items and output frames.
	builderSyncReadMaxBytes = 8 << 20
	// defaultBuilderSyncPerSecond and defaultBuilderSyncBurst limit the sync requests of one source
	// address when ingress.builder_sync_requests_per_second / builder_sync_burst are unset. A
	// dispatching Builder sends one batch at a time to each member, on each of its orders.
	defaultBuilderSyncPerSecond = 1000
	defaultBuilderSyncBurst     = 2000
	// maxLimitedAddresses bounds the addresses the limiter remembers.
	maxLimitedAddresses = 4096
)

var errBuilderSyncRateLimited = connect.NewError(connect.CodeResourceExhausted, errors.New("NEXUS_BUILDER_SYNC_RATE_LIMITED: too many sync requests from this address"))

// BuilderSync applies the sync batches the dispatching Builders of this Builder's groups send
// (buildersync.Receiver).
type BuilderSync interface {
	Sync(ctx context.Context, req *buildersyncv1.SyncRequest) (*buildersyncv1.SyncResponse, error)
}

// WithBuilderSync serves BuilderSyncService on the ingress port. Its requests are authenticated
// by the sender's signature on each batch, so the SDK API key and IP allowlist do not apply; each
// source address may send perSecond requests a second with bursts of burst (0: 1000 and 2000).
func WithBuilderSync(sync BuilderSync, perSecond, burst uint32) Option {
	if perSecond == 0 {
		perSecond = defaultBuilderSyncPerSecond
	}
	if burst == 0 {
		burst = defaultBuilderSyncBurst
	}
	return func(s *Server) {
		s.builderSync = builderSyncService{sync: sync, limit: newAddressLimiter(float64(perSecond), float64(burst), time.Now)}
	}
}

// builderSyncService is the Connect handler of BuilderSyncService.
type builderSyncService struct {
	sync  BuilderSync
	limit *addressLimiter
}

var _ buildersyncv1connect.BuilderSyncServiceHandler = builderSyncService{}

// Sync applies one batch.
func (b builderSyncService) Sync(ctx context.Context, req *connect.Request[buildersyncv1.SyncRequest]) (*connect.Response[buildersyncv1.SyncResponse], error) {
	if b.limit != nil && !b.limit.allow(peerHost(req.Peer().Addr)) {
		return nil, errBuilderSyncRateLimited
	}
	resp, err := b.sync.Sync(ctx, req.Msg)
	if err != nil {
		return nil, mapBuilderSyncErr(err)
	}
	return connect.NewResponse(resp), nil
}

func mapBuilderSyncErr(err error) error {
	switch {
	case errors.Is(err, buildersync.ErrMalformed):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, buildersync.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, buildersync.ErrNotGroupMember):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, buildersync.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// peerHost is the host of a peer address, or the address as it is.
func peerHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// addressLimiter is a token bucket per source address.
type addressLimiter struct {
	perSecond, burst float64
	now              func() time.Time

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newAddressLimiter(perSecond, burst float64, now func() time.Time) *addressLimiter {
	return &addressLimiter{perSecond: perSecond, burst: burst, now: now, buckets: map[string]*tokenBucket{}}
}

// allow takes a token of addr's bucket.
func (l *addressLimiter) allow(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[addr]
	if b == nil {
		if len(l.buckets) >= maxLimitedAddresses {
			// Forgetting every bucket only lets each address start again from a full burst.
			clear(l.buckets)
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[addr] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
