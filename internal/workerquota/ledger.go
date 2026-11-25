// Package workerquota keeps this Builder's view of each Worker's order quota and pause state.
//
// The chain is the source of truth: Hub keeps, per Worker and settlement period, a quota derived
// from the Worker's bond and the value already reserved by recorded orders, and refuses to record a
// dispatch that does not fit. A Builder that offered such an order anyway would only learn at
// record time that it cannot be recorded, after the Worker accepted it. The ledger avoids that: it
// reads the chain's figure, subtracts the value of the orders this Builder has out for the Worker
// and not yet recorded, and tells the dispatcher whether one more order fits. It also carries the
// chain's pause flag (late submission pending, unbonding, jailed): a paused Worker is offered
// nothing.
//
// A reservation is held per order, not per ticket: an order has one ticket out at a time, so
// admitting the order's next candidate replaces the reservation of the previous one. Every
// reservation also ends by itself at its hold deadline, so a path that forgets to release cannot
// leak quota. After a restart the ledger starts without reservations; the chain still refuses a
// record that does not fit, so the worst case is one order per Worker that fails at record time.
//
// A chain without the quota query (an older node), or one that reports the quota as not enforced,
// gives every Worker an unlimited quota: the ledger then changes nothing.
package workerquota

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrUnsupported is the Source's answer on a chain that does not serve the Worker quota query.
var ErrUnsupported = errors.New("worker quota query is not supported by the chain")

// Pause reason bits of hub.v1.ServiceBondState.pause_reasons.
const (
	PauseLateSubmission uint32 = 1
	PauseUnbonding      uint32 = 2
	PauseJailed         uint32 = 4
)

// Facts is the chain's answer for one Worker (hub.v1.Query/WorkerQuota).
type Facts struct {
	Period        uint64
	Quota         uint64
	ReservedValue uint64
	SettledValue  uint64
	Remaining     uint64
	// Enforced is false while the network has not switched the quota on; Remaining then means nothing.
	Enforced     bool
	Paused       bool
	PauseReasons uint32
}

// Source reads a Worker's quota from the chain.
type Source interface {
	WorkerQuota(ctx context.Context, operator string) (Facts, error)
}

// Reasons a Worker is not offered an order.
const (
	ReasonNone   = ""
	ReasonPaused = "paused"
	ReasonQuota  = "quota"
)

// Decision is the answer to "may this order be offered to this Worker now".
type Decision struct {
	OK     bool
	Reason string
	// Known is false when the chain's figure could not be read and the order was let through.
	Known bool
	Facts Facts
	// Local is the value this Builder has out for the Worker, this order excluded.
	Local uint64
}

// Options tune the ledger.
type Options struct {
	// Refresh is how long a chain answer is used before it is read again.
	Refresh time.Duration
	// UnsupportedRetry is how long an ErrUnsupported answer is remembered.
	UnsupportedRetry time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

type reservation struct {
	operator string
	value    uint64
	until    time.Time
	// settledAt is set once the chain recorded the order: the reservation is then dropped by the
	// first chain answer read after that moment, which already counts the order.
	settledAt time.Time
}

type cached struct {
	facts Facts
	at    time.Time
	known bool
}

// Ledger is safe for concurrent use.
type Ledger struct {
	src  Source
	opts Options

	mu               sync.Mutex
	facts            map[string]cached
	res              map[string]*reservation // by order key
	unsupportedUntil time.Time
}

// New returns a ledger reading from src. A nil src yields a ledger that admits everything.
func New(src Source, opts Options) *Ledger {
	if opts.Refresh <= 0 {
		opts.Refresh = 2 * time.Second
	}
	if opts.UnsupportedRetry <= 0 {
		opts.UnsupportedRetry = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Ledger{src: src, opts: opts, facts: map[string]cached{}, res: map[string]*reservation{}}
}

// Admit decides whether the order orderKey of value may be offered to operator and, when it may,
// holds value for the Worker until hold from now (or until Release / Settle). A reservation the
// order held for another candidate is released first. An unreadable chain lets the order through
// (Known false): the chain refuses the record if it does not fit.
func (l *Ledger) Admit(ctx context.Context, operator, orderKey string, value uint64, hold time.Duration) Decision {
	if l == nil || l.src == nil {
		return Decision{OK: true}
	}
	now := l.opts.Now()
	facts, known := l.read(ctx, operator, now)

	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.res, orderKey)
	l.expireLocked(now)
	d := Decision{Known: known, Facts: facts, Local: l.localLocked(operator)}
	if !known {
		d.OK = true
		l.res[orderKey] = &reservation{operator: operator, value: value, until: now.Add(hold)}
		return d
	}
	if facts.Paused {
		d.Reason = ReasonPaused
		return d
	}
	if facts.Enforced {
		left := uint64(0)
		if facts.Remaining > d.Local {
			left = facts.Remaining - d.Local
		}
		if value > left {
			d.Reason = ReasonQuota
			return d
		}
	}
	d.OK = true
	l.res[orderKey] = &reservation{operator: operator, value: value, until: now.Add(hold)}
	return d
}

// Extend keeps the order's reservation until hold from now: the Worker accepted and the dispatch
// entry is on its way to the chain.
func (l *Ledger) Extend(orderKey string, hold time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.res[orderKey]; ok {
		r.until = l.opts.Now().Add(hold)
	}
}

// Release drops the order's reservation: its ticket was rejected, timed out or voided, or the
// order failed.
func (l *Ledger) Release(orderKey string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.res, orderKey)
}

// Settle marks the order as recorded on chain. Its value stays reserved here until the chain's
// figure is read again, which then includes it; counting it in both places at once is avoided,
// and so is a gap in which neither counts it.
func (l *Ledger) Settle(orderKey string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.res[orderKey]; ok && r.settledAt.IsZero() {
		r.settledAt = l.opts.Now()
	}
}

// View is one Worker's state for the public statistics.
type View struct {
	Operator      string `json:"operator"`
	Enforced      bool   `json:"enforced"`
	Period        uint64 `json:"period"`
	Quota         uint64 `json:"quota"`
	ChainReserved uint64 `json:"chain_reserved"`
	Remaining     uint64 `json:"remaining"`
	LocalReserved uint64 `json:"local_reserved"`
	Paused        bool   `json:"paused"`
	PauseReasons  uint32 `json:"pause_reasons"`
	AgeMs         int64  `json:"age_ms"`
}

// Snapshot lists the Workers whose chain figure is held, by operator address.
func (l *Ledger) Snapshot() []View {
	if l == nil {
		return nil
	}
	now := l.opts.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(now)
	out := make([]View, 0, len(l.facts))
	for op, c := range l.facts {
		if !c.known {
			continue
		}
		out = append(out, View{Operator: op, Enforced: c.facts.Enforced, Period: c.facts.Period, Quota: c.facts.Quota,
			ChainReserved: c.facts.ReservedValue, Remaining: c.facts.Remaining, LocalReserved: l.localLocked(op),
			Paused: c.facts.Paused, PauseReasons: c.facts.PauseReasons, AgeMs: now.Sub(c.at).Milliseconds()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operator < out[j].Operator })
	return out
}

// read returns the chain's figure for operator, from the cache while it is fresh.
func (l *Ledger) read(ctx context.Context, operator string, now time.Time) (Facts, bool) {
	l.mu.Lock()
	if now.Before(l.unsupportedUntil) {
		l.mu.Unlock()
		return Facts{}, true // not enforced: an older chain
	}
	if c, ok := l.facts[operator]; ok && now.Sub(c.at) < l.opts.Refresh {
		l.mu.Unlock()
		return c.facts, c.known
	}
	l.mu.Unlock()

	start := l.opts.Now()
	facts, err := l.src.WorkerQuota(ctx, operator)
	at := l.opts.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case errors.Is(err, ErrUnsupported):
		l.unsupportedUntil = at.Add(l.opts.UnsupportedRetry)
		l.facts[operator] = cached{at: at, known: true}
		return Facts{}, true
	case err != nil:
		// Keep an older answer rather than none: a paused Worker stays paused through a failed read.
		if c, ok := l.facts[operator]; ok && c.known {
			return c.facts, true
		}
		return Facts{}, false
	}
	l.facts[operator] = cached{facts: facts, at: at, known: true}
	// Orders the chain recorded before this read began are counted by its answer; one recorded
	// while the read was in flight may not be, and waits for the next read.
	for key, r := range l.res {
		if r.operator == operator && !r.settledAt.IsZero() && !r.settledAt.After(start) {
			delete(l.res, key)
		}
	}
	return facts, true
}

func (l *Ledger) expireLocked(now time.Time) {
	for key, r := range l.res {
		if !now.Before(r.until) {
			delete(l.res, key)
		}
	}
}

// localLocked is the value held here for operator and not yet counted by the chain's figure.
func (l *Ledger) localLocked(operator string) uint64 {
	var sum uint64
	for _, r := range l.res {
		if r.operator != operator {
			continue
		}
		if sum+r.value < sum {
			return ^uint64(0)
		}
		sum += r.value
	}
	return sum
}
