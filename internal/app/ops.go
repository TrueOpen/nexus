package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/ops"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// errDispatchNotConfigured fails readiness on a Builder without direct dispatch: it takes no order.
var errDispatchNotConfigured = errors.New("direct dispatch is not configured (needs the service key and identity.vrf_key_files)")

// opsDeps are what the operator monitor reads.
type opsDeps struct {
	DataDir        string
	BuilderAddress string
	AddressPrefix  string
	Dispatch       config.DispatchConfig
	Store          kv.Store
	Height         func(context.Context) (uint64, error)
	Keys           servicekey.Resolver
	Streams        *dispatchstream.Hub
	Metrics        *opsmetrics.Registry
	// Direct and Orders are nil without direct dispatch.
	Direct *directDispatch
	Orders *orderDispatch
	Log    *slog.Logger
}

// newOpsMonitor builds the operator monitor: readiness (the store takes writes, the chain answers,
// this Builder's key and compensation account allow orders, direct dispatch is ready, no drain),
// diagnostics, public statistics and the drain requests.
func newOpsMonitor(deps opsDeps) *ops.Monitor {
	checks := []ops.Check{
		{Name: "kv_writable", Run: func(context.Context) error {
			return deps.Store.Set(kv.NSOps, "probe", []byte(strconv.FormatInt(time.Now().UnixMilli(), 10)))
		}},
		{Name: "chain", Run: func(ctx context.Context) error {
			_, err := deps.Height(ctx)
			return err
		}},
	}
	cfg := ops.Config{DataDir: deps.DataDir, Metrics: deps.Metrics, Log: deps.Log}
	if deps.Orders == nil || deps.Direct == nil {
		checks = append(checks, ops.Check{Name: "direct_dispatch", Run: func(context.Context) error { return errDispatchNotConfigured }})
	} else {
		checks = append(checks,
			ops.Check{Name: "builder_key", Run: deps.Orders.Gate.CheckBuilderKey},
			ops.Check{Name: "direct_dispatch", Run: deps.Direct.Ready})
		cfg.Drain = deps.Orders.Drain
		cfg.Public = func(now time.Time) ops.PublicStats {
			return ops.BuildPublicStats(ops.PublicSources{
				Builder: deps.BuilderAddress, Dispatch: deps.Dispatch, Metrics: deps.Metrics, Handraises: deps.Direct.Registry,
				Height: deps.Orders.Sessions.Head,
			}, now)
		}
	}
	cfg.Checks = checks
	cfg.Diagnostics = func(ctx context.Context) any { return diagnostics(ctx, deps) }
	return ops.New(cfg)
}

// diagnostics gathers ops.Diagnostics; a part that cannot be read is named in Errors.
func diagnostics(ctx context.Context, deps opsDeps) ops.Diagnostics {
	d := ops.Diagnostics{BuilderAddress: deps.BuilderAddress}
	fail := func(part string, err error) {
		if d.Errors == nil {
			d.Errors = map[string]string{}
		}
		d.Errors[part] = err.Error()
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	height, err := deps.Height(readCtx)
	if err != nil {
		fail("chain_height", err)
	}
	d.ChainHeight = height
	if pub, state, err := servicekey.Current(readCtx, deps.Keys, deps.AddressPrefix, servicekey.ParticipantBuilder, deps.BuilderAddress); err != nil {
		fail("service_key", err)
	} else {
		d.ServiceAuthorizationNonce, d.ServicePubKey = state.AuthorizationNonce, hex.EncodeToString(pub)
	}
	b := deps.Streams.Backlog()
	d.Streams = ops.StreamDiagnostics{Sessions: b.Sessions, Unacked: b.Unacked, OperatorsWithBacklog: b.Operators, RetainedBroadcasts: b.Broadcasts}
	if deps.Direct == nil || deps.Orders == nil {
		return d
	}
	direct, od := deps.Direct, deps.Orders
	if snapshot, ok := direct.Groups.CurrentBuilderSet(); ok {
		d.BuilderSetID, d.BuilderSetMembers = snapshot.ID, len(snapshot.Members)
	}
	if height > 0 {
		if err := vrfDiagnostics(readCtx, direct, height, &d); err != nil {
			fail("vrf", err)
		}
	}
	d.StandingHandraises = direct.Registry.Standing()
	d.RejectRateSuspended = len(direct.Registry.Suspensions(od.Sessions.Head()))
	if root, ok := direct.Registry.LatestRoot(); ok {
		r := &ops.RootDiagnostics{RootHeight: root.Root.GetRootHeight(), RootVersion: root.Root.GetRootVersion(), Leaves: len(root.Leaves)}
		for _, leaf := range root.Leaves {
			if leaf.GetAdmitted() {
				r.Admitted++
			}
		}
		d.LatestRoot = r
	}
	d.BoundSessions = od.Sessions.BoundTo(deps.BuilderAddress)
	s := od.Ledger.Summary()
	d.InFlight = ops.InFlightDiagnostics{Sessions: s.Sessions, Orders: s.Pending, MaxFee: s.PendingMaxFee.String(), Recorded: s.Recorded, SuspendedSessions: s.Suspended}
	outbox := od.Recorder.Outbox()
	d.RecordOutbox = ops.RecordOutboxDiagnostics{Entries: outbox.Entries, Waiting: outbox.Waiting, Takeovers: outbox.Takeovers, Transactions: outbox.Transactions}
	d.Takeovers = od.Takeovers.Pending()
	counts := od.Sync.Counts()
	d.BuilderSync = ops.BuilderSyncDiagnostics{Batches: counts.Batches, Failures: counts.Failures, RateLimited: counts.RateLimited, Alarms: counts.Alarms, Outstanding: len(od.Sync.Outstanding())}
	r := od.Responder.Counts()
	d.Responses = ops.ResponseDiagnostics{
		ClaimsSeen: r.ClaimsSeen, ClaimsRebutted: r.ClaimsRebutted, ClaimsOwed: r.ClaimsOwed,
		ChallengesAnswered: r.ChallengesAnswered, UnanswerableChallenges: r.UnanswerableChallenges,
		AnswersHeldRevoked: r.AnswersHeldRevoked,
	}
	return d
}

// vrfDiagnostics fills the epoch at height and the local VRF key the chain registered for it.
func vrfDiagnostics(ctx context.Context, direct *directDispatch, height uint64, d *ops.Diagnostics) error {
	epoch, err := direct.Epochs.CurrentEpoch(ctx, height)
	if err != nil {
		return err
	}
	d.VRFEpoch = epoch
	pub, err := direct.VRF.PublicKeyFor(ctx, epoch)
	if err != nil {
		return fmt.Errorf("epoch %d: %w", epoch, err)
	}
	d.VRFPubKey = hex.EncodeToString(pub)
	return nil
}
