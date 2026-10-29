package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskgroup"
)

// rootStreams is the part of the stream hub the handraise root pushes use.
type rootStreams interface {
	Operators() []string
	Send(ctx context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error
}

// errNoHandraiseRoot means no handraise root was signed yet: rosters cannot be built.
var errNoHandraiseRoot = errors.New("no signed handraise root yet")

// directDispatch holds the direct dispatch building blocks of the app: the standing handraise
// registry and its root loop, the Cortex stream hub, the Builder VRF keys, the epoch and pool
// readers and the drawer, and the Task Builders group source. The dispatcher builds on them.
type directDispatch struct {
	log      *slog.Logger
	Registry *handraise.Registry
	Streams  *dispatchstream.Hub
	streams  rootStreams // Streams, as the root pushes use it
	VRF      *dispatchdraw.VRFKeys
	Epochs   *dispatchdraw.ChainEpochs
	Pools    *dispatchdraw.PoolCache
	Drawer   *dispatchdraw.Drawer
	Groups   taskgroup.Source
	Height   handraise.ChainHeight

	chainWarn warnLimiter

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Start runs the root loop: every new root goes to every connected stream with that Cortex's own
// inclusion proof.
func (d *directDispatch) Start(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		_ = d.Registry.Run(ctx, func(issued *handraise.IssuedRoot) { d.pushRoot(ctx, issued, d.streams.Operators()) })
	}()
	return nil
}

// Stop ends the root loop.
func (d *directDispatch) Stop(context.Context) error {
	if d.cancel != nil {
		d.cancel()
		d.wg.Wait()
	}
	return nil
}

// Ready reports whether new orders can be dispatched: a current BuilderSet snapshot is known, a
// handraise root is signed, and a local VRF key is the chain's registered key for the current
// epoch.
func (d *directDispatch) Ready(ctx context.Context) error {
	if err := taskgroup.Ready(d.Groups); err != nil {
		return err
	}
	if _, ok := d.Registry.LatestRoot(); !ok {
		return errNoHandraiseRoot
	}
	height, err := d.Height.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("read chain height: %w", err)
	}
	epoch, err := d.Epochs.CurrentEpoch(ctx, height)
	if err != nil {
		return err
	}
	return d.VRF.Ready(ctx, epoch)
}

// pushRoot sends issued to each operator that has a leaf in it.
func (d *directDispatch) pushRoot(ctx context.Context, issued *handraise.IssuedRoot, operators []string) {
	for _, operator := range operators {
		notice, ok := issued.Notice(operator)
		if !ok {
			continue
		}
		frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_HandraiseRoot{HandraiseRoot: notice}}
		if err := d.streams.Send(ctx, operator, frame); err != nil && !errors.Is(err, dispatchstream.ErrNotConnected) {
			d.log.Warn("handraise root not sent", "operator", operator, "err", err)
		}
	}
}

// onConnection gives a Cortex whose stream (re)bound the latest root and its proof at once.
func (d *directDispatch) onConnection(operator string, connected bool) {
	if !connected || d.Registry == nil || d.streams == nil {
		return
	}
	if latest, ok := d.Registry.LatestRoot(); ok {
		d.pushRoot(context.Background(), latest, []string{operator})
	}
}

// keepOnReplay drops stored handraise root notices when a Cortex reconnects: onConnection sends
// the latest root instead of the superseded ones.
func keepOnReplay(_ string, frame *nexusv1.DispatchStreamFrameV1) bool {
	_, root := frame.GetMessage().(*nexusv1.DispatchStreamFrameV1_HandraiseRoot)
	return !root
}

// HandleStandingHandraise implements dispatchstream.HandraiseSink. A refused handraise
// (HANDRAISE_INVALID, HANDRAISE_NOT_ELIGIBLE, HANDRAISE_AHEAD_OF_CHAIN) is dropped and the stream
// goes on. So is one whose chain reads failed: handraises are soft state the Cortex re-signs every
// heartbeat, and ending every stream on a chain hiccup would only start a reconnect storm. Only a
// failed store write ends the stream, leaving the frame unacknowledged so the Cortex resends it.
func (d *directDispatch) HandleStandingHandraise(ctx context.Context, from dispatchstream.Origin, m *taskv1.StandingHandraiseV1) error {
	err := d.Registry.Accept(ctx, from.Operator, m)
	switch {
	case errors.Is(err, handraise.ErrChainUnavailable):
		if suppressed, ok := d.chainWarn.allow(time.Now()); ok {
			d.log.Warn("handraise dropped: chain read failed", "operator", from.Operator, "suppressed", suppressed, "err", err)
		}
		return nil
	case errors.Is(err, handraise.ErrStorage):
		return fmt.Errorf("%w: %v", dispatchstream.ErrTransient, err)
	default:
		return err
	}
}

// handraiseChainWarnInterval spaces the warnings about handraises dropped on chain read failures:
// during an outage every Cortex heartbeat fails the same way.
const handraiseChainWarnInterval = time.Minute

// warnLimiter lets one warning through per handraiseChainWarnInterval and counts the rest.
type warnLimiter struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// allow reports whether a warning may be logged now and how many were suppressed since the last.
func (l *warnLimiter) allow(now time.Time) (suppressed int, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < handraiseChainWarnInterval {
		l.suppressed++
		return 0, false
	}
	suppressed, l.suppressed, l.last = l.suppressed, 0, now
	return suppressed, true
}

// directDispatchDeps are what newDirectDispatch wires together.
type directDispatchDeps struct {
	ChainID        string
	BuilderAddress string
	AddressPrefix  string
	Config         config.DispatchConfig
	VRFKeyFiles    []string
	VRFKeyPassword string
	Store          kv.Store
	// Chain answers the Hub reads: service keys come through Keys, the rest directly.
	Chain   chaincli.Client
	Keys    servicekey.Resolver
	Height  handraise.ChainHeight
	Signer  signer.Signer
	Streams *dispatchstream.Hub
	Groups  taskgroup.Source
}

// newDirectDispatch fills d (whose methods the stream hub already calls back): it loads the VRF
// keys and opens the handraise registry, which samples stream RTTs and signs roots with the
// service key.
func newDirectDispatch(d *directDispatch, deps directDispatchDeps) error {
	keys, err := dispatchdraw.LoadVRFKeys(deps.VRFKeyFiles, deps.VRFKeyPassword)
	if err != nil {
		return err
	}
	vrf, err := dispatchdraw.NewVRFKeys(keys, dispatchdraw.NewChainVRFKeys(deps.Chain, deps.Store, deps.ChainID, deps.BuilderAddress))
	if err != nil {
		return err
	}
	epochs := dispatchdraw.NewChainEpochs(deps.Chain)
	pools := dispatchdraw.NewPoolCache(deps.ChainID, dispatchdraw.ChainPools{Chain: deps.Chain})
	drawer, err := dispatchdraw.NewDrawer(deps.ChainID, epochs, vrf, pools)
	if err != nil {
		return err
	}
	registry, err := handraise.New(handraise.Options{
		ChainID:        deps.ChainID,
		BuilderAddress: deps.BuilderAddress,
		Config:         deps.Config,
		Store:          deps.Store,
		Keys: handraise.ChainServiceKeys{
			Resolver: deps.Keys, AddressPrefix: deps.AddressPrefix, BuilderAddress: deps.BuilderAddress, Signer: deps.Signer,
		},
		Pool:   handraise.NewChainPool(deps.Chain),
		Height: deps.Height,
		Signer: deps.Signer,
		RTT:    deps.Streams,
		Log:    d.log,
	})
	if err != nil {
		return fmt.Errorf("handraise registry: %w", err)
	}
	d.Registry, d.Streams, d.streams = registry, deps.Streams, deps.Streams
	d.VRF, d.Epochs, d.Pools, d.Drawer = vrf, epochs, pools, drawer
	d.Groups, d.Height = deps.Groups, deps.Height
	return nil
}

// heightCacheTTL bounds how stale the chain height of handraise checks may be; it keeps one chain
// read per interval instead of one per heartbeat.
const heightCacheTTL = 250 * time.Millisecond

// cachedHeight is a handraise.ChainHeight that reads the chain at most once per ttl.
type cachedHeight struct {
	read func(context.Context) (uint64, error)
	ttl  time.Duration
	now  func() time.Time

	mu     sync.Mutex
	height uint64
	at     time.Time
}

func newCachedHeight(read func(context.Context) (uint64, error)) *cachedHeight {
	return &cachedHeight{read: read, ttl: heightCacheTTL, now: time.Now}
}

func (h *cachedHeight) LatestHeight(ctx context.Context) (uint64, error) {
	h.mu.Lock()
	if h.height != 0 && h.now().Sub(h.at) < h.ttl {
		height := h.height
		h.mu.Unlock()
		return height, nil
	}
	h.mu.Unlock()
	height, err := h.read(ctx)
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if height > h.height || h.now().Sub(h.at) >= h.ttl {
		h.height, h.at = height, h.now()
	}
	return h.height, nil
}
