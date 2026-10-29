// Package ops is the operator surface of a Builder: the readiness verdict, the diagnostics, the
// order path metrics and the public dispatch statistics, and the service key rotation drain the
// operator asks for.
//
// A Monitor evaluates everything once per tick: it takes the drain request the operator left in
// <data_dir>/ops (see WriteDrainRequest), checks the drain, runs the readiness checks, gathers the
// diagnostics and writes them all to <data_dir>/ops/status.json for the operator (nexus status).
// The ingress serves the cached readiness verdict and public statistics as plain HTTP routes, so a
// public request never reads the chain or the store.
package ops

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TrueOpen/nexus/internal/drain"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// ReadinessPath is the readiness route on the ingress port.
const ReadinessPath = "/readyz"

const (
	defaultInterval = 2 * time.Second
	checkTimeout    = 5 * time.Second
	// StatusStaleAfter is how old a status file may be before readers warn that the daemon may not
	// be running: a few ticks of the default interval.
	StatusStaleAfter = 3 * defaultInterval
)

// Check is one readiness condition; Run fails while new orders must not be taken.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

// Readiness is the readiness verdict: Failing names the failed checks, Errors (in the status file
// only) says why.
type Readiness struct {
	Ready     bool              `json:"ready"`
	Failing   []string          `json:"failing,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
	CheckedAt time.Time         `json:"checked_at"`
}

// Status is the status file.
type Status struct {
	WrittenAt   time.Time           `json:"written_at"`
	Readiness   Readiness           `json:"readiness"`
	Drain       *drain.Status       `json:"drain,omitempty"`
	Diagnostics any                 `json:"diagnostics,omitempty"`
	Metrics     opsmetrics.Snapshot `json:"metrics"`
}

// Config wires a Monitor.
type Config struct {
	DataDir string
	// Drain is the rotation drain; nil when this Builder does not dispatch (drain requests are
	// then refused in the log).
	Drain  *drain.Controller
	Checks []Check
	// Diagnostics gathers the diagnostics; nil gathers none.
	Diagnostics func(ctx context.Context) any
	// Public builds the public statistics; nil serves none.
	Public  func(now time.Time) PublicStats
	Metrics *opsmetrics.Registry
	// Interval is the tick; 0 is two seconds.
	Interval time.Duration
	// CheckTimeout bounds each chain-reading step of a tick (a readiness check, the drain check,
	// a drain begin); 0 is five seconds.
	CheckTimeout time.Duration
	Now          func() time.Time
	Log          *slog.Logger
}

// Monitor runs the ticks and serves their results.
type Monitor struct {
	cfg Config
	log *slog.Logger

	readiness atomic.Pointer[Readiness]
	public    atomic.Pointer[[]byte]

	tickMu sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New builds a Monitor; nothing is checked before the first tick.
func New(cfg Config) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = checkTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Monitor{cfg: cfg, log: cfg.Log}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	return m
}

// Start takes a drain request left on disk before it returns (a restart drains before the order
// path resumes), then ticks in the background: at once, then once per interval until Stop.
func (m *Monitor) Start(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.tickMu.Lock()
	m.takeRequest(ctx)
	m.tickMu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.Tick(ctx)
		ticker := time.NewTicker(m.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Tick(ctx)
			}
		}
	}()
	return nil
}

// Stop ends the ticks.
func (m *Monitor) Stop(context.Context) error {
	if m.cancel != nil {
		m.cancel()
		m.wg.Wait()
	}
	return nil
}

// Tick applies a pending drain request, checks the drain and the readiness, gathers the
// diagnostics, refreshes the public statistics and writes the status file.
func (m *Monitor) Tick(ctx context.Context) Status {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()
	m.takeRequest(ctx)
	status := Status{Metrics: m.cfg.Metrics.Snapshot()}
	if m.cfg.Drain != nil {
		checkCtx, cancel := context.WithTimeout(ctx, m.cfg.CheckTimeout)
		d := m.cfg.Drain.Check(checkCtx)
		cancel()
		status.Drain = &d
	}
	status.Readiness = m.check(ctx)
	m.readiness.Store(&status.Readiness)
	if m.cfg.Diagnostics != nil {
		status.Diagnostics = m.cfg.Diagnostics(ctx)
	}
	if m.cfg.Public != nil {
		if raw, err := json.Marshal(m.cfg.Public(m.cfg.Now())); err == nil {
			m.public.Store(&raw)
		}
	}
	status.WrittenAt = m.cfg.Now()
	raw, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		err = writeFile(StatusPath(m.cfg.DataDir), append(raw, '\n'))
	}
	if err != nil {
		m.log.Warn("operator status file not written", "path", StatusPath(m.cfg.DataDir), "err", err)
	}
	return status
}

func (m *Monitor) takeRequest(ctx context.Context) {
	request, ok, err := takeDrainRequest(m.cfg.DataDir)
	switch {
	case err != nil:
		m.log.Warn("drain request not read", "path", DrainRequestPath(m.cfg.DataDir), "err", err)
		return
	case !ok:
		return
	case m.cfg.Drain == nil:
		m.log.Warn("drain request ignored: this Builder does not dispatch", "request", request)
		return
	case request == DrainBegin:
		beginCtx, cancel := context.WithTimeout(ctx, m.cfg.CheckTimeout)
		err = m.cfg.Drain.Begin(beginCtx)
		cancel()
	default:
		err = m.cfg.Drain.End()
	}
	if err != nil {
		m.log.Error("drain request not applied", "request", request, "err", err)
	}
}

func (m *Monitor) check(ctx context.Context) Readiness {
	r := Readiness{Ready: true, CheckedAt: m.cfg.Now()}
	checks := m.cfg.Checks
	if m.cfg.Drain != nil {
		checks = append(checks, Check{Name: "drain", Run: func(context.Context) error {
			if m.cfg.Drain.Draining() {
				return errors.New("draining before a service key rotation")
			}
			return nil
		}})
	}
	for _, c := range checks {
		checkCtx, cancel := context.WithTimeout(ctx, m.cfg.CheckTimeout)
		err := c.Run(checkCtx)
		cancel()
		if err == nil {
			continue
		}
		r.Ready = false
		r.Failing = append(r.Failing, c.Name)
		if r.Errors == nil {
			r.Errors = map[string]string{}
		}
		r.Errors[c.Name] = err.Error()
	}
	sort.Strings(r.Failing)
	return r
}

// Readiness returns the verdict of the last tick; before the first, not ready.
func (m *Monitor) Readiness() Readiness {
	if r := m.readiness.Load(); r != nil {
		return *r
	}
	return Readiness{Failing: []string{"not_checked"}}
}

// ReadinessHandler serves the last verdict: 200 when ready, 503 otherwise, naming the failed
// checks but not why.
func (m *Monitor) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r := m.Readiness()
		body, _ := json.Marshal(struct {
			Ready   bool     `json:"ready"`
			Failing []string `json:"failing,omitempty"`
		}{r.Ready, r.Failing})
		w.Header().Set("Content-Type", "application/json")
		if !r.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write(body)
	})
}

// PublicStatsHandler serves the public statistics of the last tick; 503 before the first.
func (m *Monitor) PublicStatsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		raw := m.public.Load()
		if raw == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"statistics not ready"}`))
			return
		}
		_, _ = w.Write(*raw)
	})
}
