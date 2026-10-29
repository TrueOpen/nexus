package ops

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/drain"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

const localKey = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fixture struct {
	t       *testing.T
	dir     string
	store   kv.Store
	records int
	failing error
	drain   *drain.Controller
	m       *Monitor
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, dir: t.TempDir(), store: kv.NewMemStore()}
	f.open()
	return f
}

// open builds the drain and the monitor over the fixture's store and directory, as after a start.
func (f *fixture) open() {
	f.t.Helper()
	d, err := drain.New(drain.Config{
		Store: f.store, LocalPubKey: localKey,
		Key: func(context.Context) (chaincli.ServiceKeyState, error) {
			return chaincli.ServiceKeyState{ServicePubKey: localKey, AuthorizationNonce: 4}, nil
		},
		Sources: drain.Sources{
			InFlight:  func() (int, *big.Int) { return 0, new(big.Int) },
			Records:   func() int { return f.records },
			Takeovers: func() int { return 0 },
			Sync:      func() []drain.SyncPending { return nil },
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.drain = d
	f.m = New(Config{
		DataDir: f.dir, Drain: d, Metrics: opsmetrics.New(),
		Checks:      []Check{{Name: "chain", Run: func(context.Context) error { return f.failing }}},
		Diagnostics: func(context.Context) any { return Diagnostics{BuilderAddress: "trueopen1builder", ChainHeight: 7} },
	})
}

func (f *fixture) readyz() (int, map[string]any) {
	f.t.Helper()
	rr := httptest.NewRecorder()
	f.m.ReadinessHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, ReadinessPath, nil))
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		f.t.Fatalf("readyz body %q: %v", rr.Body.String(), err)
	}
	return rr.Code, body
}

func (f *fixture) status() Status {
	f.t.Helper()
	raw, err := ReadStatus(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// Before the first tick the Builder is not ready.
func TestNotReadyBeforeTheFirstTick(t *testing.T) {
	f := newFixture(t)
	if code, body := f.readyz(); code != http.StatusServiceUnavailable || !reflect.DeepEqual(body["failing"], []any{"not_checked"}) {
		t.Fatalf("readyz = %d %v", code, body)
	}
}

// Readiness follows the checks: a failing check makes /readyz 503 naming it, without its error;
// the status file says why.
func TestReadinessFlipsWithTheChecks(t *testing.T) {
	f := newFixture(t)
	f.m.Tick(context.Background())
	if code, body := f.readyz(); code != http.StatusOK || body["ready"] != true {
		t.Fatalf("readyz = %d %v", code, body)
	}
	f.failing = errors.New("node at http://10.0.0.1:26657 unreachable")
	f.m.Tick(context.Background())
	code, body := f.readyz()
	if code != http.StatusServiceUnavailable || body["ready"] != false || !reflect.DeepEqual(body["failing"], []any{"chain"}) {
		t.Fatalf("readyz = %d %v", code, body)
	}
	if _, leaked := body["errors"]; leaked {
		t.Fatalf("readyz shows the error: %v", body)
	}
	if s := f.status(); s.Readiness.Errors["chain"] == "" || s.Readiness.Ready {
		t.Fatalf("status readiness = %+v", s.Readiness)
	}
	f.failing = nil
	f.m.Tick(context.Background())
	if code, _ := f.readyz(); code != http.StatusOK {
		t.Fatalf("readyz after recovery = %d", code)
	}
}

// The operator's drain request is taken on the next tick: the Builder drains (not ready), the
// status file shows the drain and what remains, and an end request ends it. The drain survives a
// restart of the daemon.
func TestDrainRequestsThroughTheOperatorFiles(t *testing.T) {
	f := newFixture(t)
	f.records = 1
	if err := WriteDrainRequest(f.dir, DrainBegin); err != nil {
		t.Fatal(err)
	}
	f.m.Tick(context.Background())
	if _, err := os.Stat(DrainRequestPath(f.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drain request left in place: %v", err)
	}
	if !f.drain.Draining() {
		t.Fatal("drain request not applied")
	}
	s := f.status()
	if s.Drain == nil || s.Drain.Phase != drain.PhaseDraining || s.Drain.Remaining.RecordEntries != 1 || s.Readiness.Ready ||
		!reflect.DeepEqual(s.Readiness.Failing, []string{"drain"}) {
		t.Fatalf("status = %+v", s)
	}
	f.open()
	f.records = 0
	f.m.Tick(context.Background())
	if s := f.status(); s.Drain == nil || s.Drain.Phase != drain.PhaseDrained || !s.Drain.Complete {
		t.Fatalf("status after the restart = %+v", s.Drain)
	}
	if err := WriteDrainRequest(f.dir, DrainEnd); err != nil {
		t.Fatal(err)
	}
	f.m.Tick(context.Background())
	if f.drain.Draining() || !f.status().Readiness.Ready {
		t.Fatal("drain not ended by the end request")
	}
	if err := WriteDrainRequest(f.dir, "pause"); err == nil {
		t.Fatal("unknown drain request accepted")
	}
}

func TestStatusFileHoldsTheDiagnosticsAndMetrics(t *testing.T) {
	f := newFixture(t)
	f.m.cfg.Metrics.Inc(opsmetrics.CounterSkips, opsmetrics.SkipTimeout)
	f.m.Tick(context.Background())
	raw, err := ReadStatus(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"builder_address": "trueopen1builder"`) || !strings.Contains(string(raw), `"timeout": 1`) {
		t.Fatalf("status file = %s", raw)
	}
	info, err := os.Stat(StatusPath(f.dir))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status file mode = %v, %v", info.Mode(), err)
	}
	if time.Since(f.status().WrittenAt) > time.Minute {
		t.Fatal("written_at not set")
	}
}
