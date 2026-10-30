// Package dispatchstream serves the Cortex dispatch streams of one Builder.
//
// Every Cortex Node keeps one outbound duplex stream to each Builder it chose. The first frame binds
// the stream to the Cortex's current service key and a fresh 32-byte stream_nonce; every later
// business message carries its own service signature and is verified one by one before it reaches
// the rest of the Builder. Each direction numbers its business frames 1, 2, ... without gaps, scoped
// to the stream_nonce of the binding, and the peer acknowledges them cumulatively with StreamAckV1;
// binding, ack and keepalive frames carry cursor 0. Builder-signed downlink messages that are not
// acknowledged yet are kept in the stream_session namespace as the exact bytes first sent and are
// sent again when the Cortex reconnects: renumbered from 1 on the new stream, byte for byte
// unchanged.
//
// The transport is the FrameStream interface: the IngressAPI DispatchStream handler adapts a Connect
// bidirectional stream to it, and tests use an in-memory one.
package dispatchstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/lograte"
)

// FrameStream is one connected Cortex stream. Receive and Send may be called concurrently, each from
// one goroutine at a time.
type FrameStream interface {
	Receive() (*nexusv1.DispatchStreamFrameV1, error)
	Send(*nexusv1.DispatchStreamFrameV1) error
}

var (
	// ErrBindingInvalid refuses a stream whose first frame is not a valid binding: a missing or
	// malformed binding, another chain or Builder, a nonce or signature that does not match the
	// Cortex's current service key, or a binding that was already used once.
	ErrBindingInvalid = errors.New("DISPATCH_STREAM_BINDING_INVALID")
	// ErrProtocol ends a stream whose frames break the stream rules (wrong stream_nonce, a business
	// frame without a cursor, a message kind the Cortex may not send).
	ErrProtocol = errors.New("dispatch stream protocol violation")
	// ErrTransient ends a stream without acknowledging the frame in hand because it could not be
	// judged now (the chain could not be read, local state could not be written). The Cortex
	// reconnects and sends it again. Sinks wrap it to ask for the same treatment. A standing
	// handraise whose CORTEX key cannot be read is the exception: it is dropped and acknowledged.
	ErrTransient = errors.New("dispatch stream message cannot be processed now")
	// ErrReplaced ends a stream when the same Cortex opened a newer valid stream.
	ErrReplaced = errors.New("dispatch stream replaced by a newer stream of the same Cortex")
	// ErrKeepaliveTimeout ends a stream whose Cortex stopped answering keepalives.
	ErrKeepaliveTimeout = errors.New("dispatch stream keepalive timed out")
	// ErrStopped ends every stream when the hub stops, and refuses new ones.
	ErrStopped = errors.New("dispatch stream hub stopped")
	// ErrRebind ends every stream when this Builder's service key changed at a cutover: live
	// streams need the current key, so each Cortex binds again.
	ErrRebind = errors.New("dispatch stream ended: the Builder service key changed; bind again")
	// ErrNotConnected means a downlink message has no stream to go to.
	ErrNotConnected = errors.New("cortex dispatch stream not connected")
)

// Default stream timing and retention. They are deployment choices, not protocol parameters.
const (
	DefaultBindTimeout       = 10 * time.Second
	DefaultKeepaliveInterval = 5 * time.Second
	DefaultKeepaliveMisses   = 3
	DefaultMaxPending        = 1024
)

// Config is the identity and the timing of the streams one Builder serves.
type Config struct {
	// ChainID and BuilderOperator are what a binding must name.
	ChainID         string
	BuilderOperator string
	// BindTimeout bounds the wait for the binding frame.
	BindTimeout time.Duration
	// KeepaliveInterval is how often the Builder probes each stream, one probe at a time; a probe
	// left unanswered for KeepaliveMisses intervals ends the stream.
	KeepaliveInterval time.Duration
	KeepaliveMisses   int
	// MaxPending bounds the unacknowledged downlink messages kept per Cortex; the oldest are dropped
	// beyond it and the Cortex recovers those facts from chain queries.
	MaxPending int
}

func (c Config) withDefaults() Config {
	if c.BindTimeout <= 0 {
		c.BindTimeout = DefaultBindTimeout
	}
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if c.KeepaliveMisses <= 0 {
		c.KeepaliveMisses = DefaultKeepaliveMisses
	}
	if c.MaxPending <= 0 {
		c.MaxPending = DefaultMaxPending
	}
	return c
}

// Origin is where a verified uplink message came from.
type Origin struct {
	// Operator is the Cortex operator of the stream; the message names it as its signer.
	Operator string
	// Raw is the deterministic encoding of the message whose signature was verified, and Digest
	// its wire signing digest.
	Raw    []byte
	Digest [32]byte
}

// HandraiseSink takes verified standing handraises.
type HandraiseSink interface {
	HandleStandingHandraise(ctx context.Context, from Origin, m *taskv1.StandingHandraiseV1) error
}

// DispatchSink takes verified answers to dispatch tickets and input requests. Whether an input
// request may be served (only after a verified accept of that ticket, whose signing digest the
// request's dispatch_accept_digest must equal) is the sink's decision.
type DispatchSink interface {
	// OrderEarliestSubmitHeight is the earliest_submit_height of the signed order a ticket of this
	// Builder belongs to; false for a ticket it does not know. It decides whether an answer signed
	// with a Cortex's previous key can prove that order.
	OrderEarliestSubmitHeight(ticketHash []byte) (uint64, bool)
	HandleDispatchAccept(ctx context.Context, from Origin, m *taskv1.DispatchAcceptV1) error
	HandleDispatchReject(ctx context.Context, from Origin, m *taskv1.DispatchRejectV1) error
	HandleDispatchInputRequest(ctx context.Context, from Origin, m *nexusv1.DispatchInputRequestV1) error
}

// VerifierSink takes verified Verifier messages; the coordinator implements it.
type VerifierSink interface {
	HandleVerifierHandraise(ctx context.Context, cortexOperator string, m *taskv1.VerifierHandraiseV1) error
	HandleVerifyResultSubmitted(ctx context.Context, cortexOperator string, m *nexusv1.VerifyResultSubmittedNoticeV1) error
}

// Sinks routes verified uplink messages. A nil sink drops its messages after verification.
type Sinks struct {
	Handraise HandraiseSink
	Dispatch  DispatchSink
	Verifier  VerifierSink
}

// Option configures a Hub.
type Option func(*Hub)

// WithReplayFilter decides, when a Cortex reconnects, whether an unacknowledged downlink message is
// still worth sending; returning false drops it for good (for example a ticket past its accept
// deadline).
func WithReplayFilter(keep func(operator string, frame *nexusv1.DispatchStreamFrameV1) bool) Option {
	return func(h *Hub) { h.replayFilter = keep }
}

// WithResigner signs an unacknowledged downlink message again, in place, before a replay to a
// Cortex that bound again. Transport messages carry no key generation, so after a service key
// cutover only the current key vouches for them; the re-signer leaves messages bound to a
// generation (offers, verifier messages) alone. The message is kept as signed again.
func WithResigner(resign func(frame *nexusv1.DispatchStreamFrameV1) error) Option {
	return func(h *Hub) { h.resign = resign }
}

// WithConnectionObserver is told every time a Cortex becomes reachable (a valid stream bound) or
// unreachable (its stream ended without a replacement). It runs outside the hub's locks.
func WithConnectionObserver(observe func(operator string, connected bool)) Option {
	return func(h *Hub) { h.observe = observe }
}

// Hub owns every Cortex stream of this Builder: at most one per Cortex operator.
type Hub struct {
	cfg          Config
	log          *slog.Logger
	keys         CortexKeys
	store        kv.Store
	sinks        atomic.Pointer[Sinks]
	replayFilter func(string, *nexusv1.DispatchStreamFrameV1) bool
	resign       func(*nexusv1.DispatchStreamFrameV1) error
	observe      func(string, bool)
	// handraiseKeyWarn spaces the warnings about standing handraises dropped on key read failures.
	handraiseKeyWarn lograte.Limiter

	// now and keepaliveTicks are replaced in tests.
	now            func() time.Time
	keepaliveTicks func(time.Duration) (<-chan time.Time, func())

	mu       sync.Mutex
	stopped  bool
	sessions map[string]*session
	// pending holds, per Cortex operator, the unacknowledged downlink messages in send order; the
	// stream_session namespace holds the same entries durably.
	pending map[string][]*pendingMessage
	nextSeq map[string]uint64
	// retained holds the latest signed Verifier broadcast per (kind, task_id, verify_round) for
	// streams that connect later (see Broadcast).
	retained map[retainKey]*retainedMessage
}

// New builds a hub and loads the unacknowledged downlink messages left by the previous run.
func New(log *slog.Logger, cfg Config, keys CortexKeys, store kv.Store, opts ...Option) (*Hub, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if keys == nil || store == nil {
		return nil, fmt.Errorf("dispatch stream hub needs a Cortex key lookup and a store")
	}
	h := &Hub{
		cfg:              cfg.withDefaults(),
		log:              log,
		keys:             keys,
		store:            store,
		now:              time.Now,
		handraiseKeyWarn: lograte.Limiter{Every: handraiseKeyWarnInterval},
		sessions:         make(map[string]*session),
		pending:          make(map[string][]*pendingMessage),
		nextSeq:          make(map[string]uint64),
		retained:         make(map[retainKey]*retainedMessage),
		keepaliveTicks: func(d time.Duration) (<-chan time.Time, func()) {
			ticker := time.NewTicker(d)
			return ticker.C, ticker.Stop
		},
	}
	h.sinks.Store(&Sinks{})
	for _, opt := range opts {
		opt(h)
	}
	if err := h.loadPending(); err != nil {
		return nil, err
	}
	return h, nil
}

// SetSinks routes verified uplink messages. It is set once the receivers exist (the coordinator
// is built after the hub it sends through).
func (h *Hub) SetSinks(s Sinks) { h.sinks.Store(&s) }

// Start is a no-op: streams arrive through Serve. It lets the hub run as an app module.
func (h *Hub) Start(context.Context) error { return nil }

// Stop ends every stream and refuses new ones. Unacknowledged messages stay stored.
func (h *Hub) Stop(context.Context) error {
	h.mu.Lock()
	h.stopped = true
	sessions := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		s.end(ErrStopped)
	}
	return nil
}

// Rebind ends every stream with ErrRebind and keeps taking new ones; unacknowledged messages stay
// stored for the next binding.
func (h *Hub) Rebind() {
	h.mu.Lock()
	sessions := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		s.end(ErrRebind)
	}
}

// Connected reports whether operator has a bound stream, i.e. whether it can be dispatched to now.
func (h *Hub) Connected(operator string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.sessions[operator]
	return ok
}

// Operators lists the Cortex operators with a bound stream, sorted.
func (h *Hub) Operators() []string {
	h.mu.Lock()
	out := make([]string, 0, len(h.sessions))
	for operator := range h.sessions {
		out = append(out, operator)
	}
	h.mu.Unlock()
	sort.Strings(out)
	return out
}

// RTT is the smoothed keepalive round-trip time of operator's current stream; false when it is not
// connected or no keepalive came back yet.
func (h *Hub) RTT(operator string) (time.Duration, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[operator]
	if !ok || s.srtt == 0 {
		return 0, false
	}
	return s.srtt, true
}

// Backlog counts the bound streams and the Builder-signed downlink messages Cortex nodes have not
// acknowledged (sent again when their stream binds again, transport messages signed again).
type Backlog struct {
	Sessions   int `json:"sessions"`
	Unacked    int `json:"unacked"`
	Operators  int `json:"operators_with_unacked"`
	Broadcasts int `json:"retained_broadcasts"`
}

// Backlog counts the bound streams and the unacknowledged downlink messages.
func (h *Hub) Backlog() Backlog {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := Backlog{Sessions: len(h.sessions), Broadcasts: len(h.retained)}
	for _, pending := range h.pending {
		if len(pending) > 0 {
			b.Unacked += len(pending)
			b.Operators++
		}
	}
	return b
}

func (h *Hub) notify(operator string, connected bool) {
	if h.observe != nil {
		h.observe(operator, connected)
	}
}
