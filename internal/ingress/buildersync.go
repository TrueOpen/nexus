package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/buildersync"
)

const (
	// builderSyncReadMaxBytes bounds one SyncRequest, as the contract does.
	builderSyncReadMaxBytes = buildersync.MaxRequestBytes
	// defaultBuilderSyncPerSecond and defaultBuilderSyncBurst limit the sync requests of one source
	// address when ingress.builder_sync_requests_per_second / builder_sync_burst are unset. A
	// dispatching Builder sends one batch at a time to each member, on each of its orders, and a
	// member's sender retries a rate-limited batch after a second. The limit applies to members as
	// well: membership is only known once a request (up to 1 MiB) was validated and decoded, the
	// work the limit bounds for a sender that is not one.
	defaultBuilderSyncPerSecond = 1000
	defaultBuilderSyncBurst     = 2000
	// maxLimitedAddresses bounds the addresses the limiter remembers.
	maxLimitedAddresses = 4096
)

var errBuilderSyncRateLimited = connect.NewError(connect.CodeResourceExhausted, errors.New("NEXUS_BUILDER_SYNC_RATE_LIMITED: too many sync requests from this address"))

// BuilderSync applies the sync batches the dispatching Builders of this Builder's groups send
// (buildersync.Receiver). It takes the request bytes as received: they are validated strictly before
// they are decoded, which a generated decoder would not do.
type BuilderSync interface {
	Sync(ctx context.Context, raw []byte) (*nexusv1.SyncResponse, error)
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

// rawSyncRequest is a SyncRequest as the bytes it arrived as.
type rawSyncRequest []byte

// handler is the Connect handler of BuilderSyncService.Sync, mounted at its path. It takes the
// binary protobuf encoding only, kept as received: a JSON request cannot be validated byte for byte.
func (b builderSyncService) handler(options ...connect.HandlerOption) (string, http.Handler) {
	options = append(options, connect.WithCodec(rawSyncCodec{}), connect.WithCodec(refusedSyncCodec{}))
	return nexusv1connect.BuilderSyncServiceSyncProcedure,
		connect.NewUnaryHandler(nexusv1connect.BuilderSyncServiceSyncProcedure, b.Sync, options...)
}

// Sync applies one batch.
func (b builderSyncService) Sync(ctx context.Context, req *connect.Request[rawSyncRequest]) (*connect.Response[nexusv1.SyncResponse], error) {
	if b.limit != nil && !b.limit.allow(peerHost(req.Peer().Addr)) {
		return nil, errBuilderSyncRateLimited
	}
	resp, err := b.sync.Sync(ctx, *req.Msg)
	if err != nil {
		return nil, mapBuilderSyncErr(err)
	}
	return connect.NewResponse(resp), nil
}

// rawSyncCodec is the binary protobuf codec of BuilderSyncService: requests are kept as their
// bytes, responses are marshaled as usual.
type rawSyncCodec struct{}

func (rawSyncCodec) Name() string { return "proto" }

func (rawSyncCodec) Marshal(msg any) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("%T is not a protobuf message", msg)
	}
	return proto.Marshal(m)
}

func (rawSyncCodec) Unmarshal(data []byte, msg any) error {
	raw, ok := msg.(*rawSyncRequest)
	if !ok {
		return fmt.Errorf("%T is not a sync request", msg)
	}
	*raw = append(rawSyncRequest(nil), data...)
	return nil
}

// errSyncEncoding refuses a sync request in any encoding but binary protobuf.
var errSyncEncoding = errors.New("NEXUS_BUILDER_SYNC_MALFORMED: unsupported encoding: BuilderSyncService takes binary protobuf only, validated byte for byte")

// refusedSyncCodec takes the place of the JSON codec on BuilderSyncService and refuses every
// request.
type refusedSyncCodec struct{}

func (refusedSyncCodec) Name() string                { return "json" }
func (refusedSyncCodec) Marshal(any) ([]byte, error) { return nil, errSyncEncoding }
func (refusedSyncCodec) Unmarshal([]byte, any) error { return errSyncEncoding }

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
