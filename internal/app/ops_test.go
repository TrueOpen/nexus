package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/drain"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/ops"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/types"
)

// newWiredOrderPath builds the order path over the wiring fixture.
func newWiredOrderPath(t *testing.T, f *wiringFixture, metrics *opsmetrics.Registry) *orderDispatch {
	t.Helper()
	chain := &orderChain{wiringChain: f.chain}
	log := slog.New(slog.DiscardHandler)
	attempts, err := attempt.New(f.store, f.builder, log)
	if err != nil {
		t.Fatal(err)
	}
	od, err := newOrderDispatch(context.Background(), orderDispatchDeps{
		ChainID: wiringChainID, BuilderAddress: f.builder.Address(), Config: config.Load().Dispatch, InputChunkBytes: 1024,
		Signer: f.builder, Store: f.store, TaskChain: chain, HubChain: chain, Direct: f.d,
		Records:  coordinator.NewRecordSubmitter(log, chain, f.builder, config.ChainConfig{ChainID: wiringChainID}, nil),
		Keys:     handraise.ChainServiceKeys{Resolver: chain, AddressPrefix: wiringPrefix, BuilderAddress: f.builder.Address(), Signer: f.builder},
		Observer: nopOrderObserver{}, Tasks: nopOrderObserver{}, Held: nopHeld{}, Attempts: attempts, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return od
}

// The operator's drain request, left in the data directory, reaches the order path through the
// monitor: the dispatcher refuses new orders, readiness turns false and the status file shows the
// drain with the current key binding; the public routes answer from the last tick.
func TestOperatorDrainReachesTheOrderPath(t *testing.T) {
	f := newWiringFixture(t)
	metrics := opsmetrics.New()
	od := newWiredOrderPath(t, f, metrics)
	dir := t.TempDir()
	monitor := newOpsMonitor(opsDeps{
		DataDir: dir, BuilderAddress: f.builder.Address(), AddressPrefix: wiringPrefix, Dispatch: config.Load().Dispatch,
		Store: f.store, Height: func(context.Context) (uint64, error) { return 150, nil }, Keys: f.chain,
		Streams: f.d.Streams, Metrics: metrics, Direct: f.d, Orders: od, Log: slog.New(slog.DiscardHandler),
	})
	if err := ops.WriteDrainRequest(dir, ops.DrainBegin); err != nil {
		t.Fatal(err)
	}
	status := monitor.Tick(context.Background())
	if !od.Drain.Draining() {
		t.Fatal("drain request did not reach the order path")
	}
	if err := od.Dispatcher.Probe(context.Background(), types.Order{}); !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.Is(err, dispatcher.ErrDraining) {
		t.Fatalf("Probe while draining = %v", err)
	}
	if status.Drain == nil || status.Drain.Phase != drain.PhaseDrained || status.Drain.Key == nil || status.Drain.Key.Nonce != 7 {
		t.Fatalf("drain status = %+v", status.Drain)
	}
	if status.Readiness.Ready || status.Readiness.Errors["drain"] == "" {
		t.Fatalf("readiness while draining = %+v", status.Readiness)
	}
	d, ok := status.Diagnostics.(ops.Diagnostics)
	if !ok || d.BuilderAddress != f.builder.Address() || d.ChainHeight != 150 || d.ServiceAuthorizationNonce != 7 || d.InFlight.MaxFee != "0" {
		t.Fatalf("diagnostics = %+v", status.Diagnostics)
	}

	rr := httptest.NewRecorder()
	monitor.ReadinessHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, ops.ReadinessPath, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz while draining = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	monitor.PublicStatsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, ops.PublicStatsPath, nil))
	var stats ops.PublicStats
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &stats) != nil || stats.Builder != f.builder.Address() ||
		stats.RTTAdmit.ThresholdMs != config.Load().Dispatch.BuilderRTTAdmitMs {
		t.Fatalf("public stats = %d %s", rr.Code, rr.Body.String())
	}

	if err := ops.WriteDrainRequest(dir, ops.DrainEnd); err != nil {
		t.Fatal(err)
	}
	monitor.Tick(context.Background())
	if od.Drain.Draining() {
		t.Fatal("drain end request did not reach the order path")
	}
}

// A Builder without direct dispatch is never ready and takes no drain.
func TestOpsMonitorWithoutDirectDispatch(t *testing.T) {
	f := newWiringFixture(t)
	dir := t.TempDir()
	monitor := newOpsMonitor(opsDeps{
		DataDir: dir, BuilderAddress: f.builder.Address(), AddressPrefix: wiringPrefix, Store: f.store,
		Height: func(context.Context) (uint64, error) { return 150, nil }, Keys: f.chain, Streams: f.d.Streams,
		Metrics: opsmetrics.New(),
	})
	status := monitor.Tick(context.Background())
	if status.Readiness.Ready || status.Readiness.Errors["direct_dispatch"] == "" || status.Drain != nil {
		t.Fatalf("status = %+v", status)
	}
}
