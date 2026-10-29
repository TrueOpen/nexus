// Package opsmetrics keeps the operational statistics of the direct dispatch order path in
// process: how long each stage of an order took, counters by label (skips by reason, tickets per
// order, record and takeover outcomes) and each Worker's ticket outcomes. They are read as a
// Snapshot for the diagnostics and the public statistics; nothing is persisted, so a restart starts
// them again (Snapshot.Since).
//
// Like a stagetiming.Recorder, every method is safe on a nil *Registry: code wired without one pays
// only the nil check.
package opsmetrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/TrueOpen/nexus/internal/stagetiming"
)

// Stages of the order path.
const (
	// StagePrecheck is the OpenTask precheck of a dispatching Builder.
	StagePrecheck = "precheck"
	// StageWaitESH is from the dispatcher taking an order until the head reached its
	// earliest_submit_height.
	StageWaitESH = "wait_for_esh"
	// StageDraw is the Builder VRF draw of an order's Worker order.
	StageDraw = "draw"
	// StageTicketToAccept is from issuing the winning ticket until its accept arrived.
	StageTicketToAccept = "ticket_to_accept"
	// StageAcceptToRecordSubmit is from an accept until its dispatch entry was broadcast.
	StageAcceptToRecordSubmit = "accept_to_record_submit"
	// StageRecordToAdmitted is from broadcasting a dispatch entry until the chain admitted it.
	StageRecordToAdmitted = "record_to_admitted"
	// StageAcceptToFirstOutput is from an accept until the Worker's first output frame was stored.
	StageAcceptToFirstOutput = "accept_to_first_output"
)

// Counters and their labels.
const (
	// CounterSkips counts skipped roster members by reason (the Skip* labels).
	CounterSkips = "skips"
	// CounterTicketsPerOrder counts the dispatch attempts that ended (accepted or failed) by the
	// tickets the order held then, label the count ("10+" above nine). A retry of a failed
	// sequence (an SDK resend) is a new attempt counted again, with the earlier tickets.
	CounterTicketsPerOrder = "tickets_per_order"
	// CounterOrders counts the dispatch attempts that ended: "accepted" or "failed"; a resend of a
	// failed sequence counts again.
	CounterOrders = "orders"
	// CounterRecordOutcomes counts resolved dispatch entries: "ADMITTED" or the reject code
	// without its DISPATCH_REJECT_CODE_V1_ prefix (RECORD_LATE for an entry past its deadline).
	CounterRecordOutcomes = "record_outcomes"
	// CounterTakeoverOutcomes counts ended takeovers by how they ended.
	CounterTakeoverOutcomes = "takeover_outcomes"
)

// Skip reasons.
const (
	SkipRejected        = "rejected"
	SkipTimeout         = "timeout"
	SkipUnreachable     = "unreachable"
	SkipRotationPending = "rotation_pending"
	// SkipNotInRoster counts drawn pool members passed over because the round's roster does not
	// hold them; they are not attempts.
	SkipNotInRoster = "not_in_roster"
)

// Outcome is how one ticket of a Worker ended.
type Outcome uint8

const (
	// OutcomeAccepted: the Worker accepted the ticket.
	OutcomeAccepted Outcome = iota + 1
	// OutcomeRejected: a signed reject while the Worker advertised a free slot; it counts in the
	// reject rate.
	OutcomeRejected
	// OutcomeRejectedWithoutFreeSlot: a signed reject at no free slot.
	OutcomeRejectedWithoutFreeSlot
	// OutcomeTimeout: the Worker received the ticket and did not answer before its deadline.
	OutcomeTimeout
	// OutcomeUnsent: the ticket never reached the Worker (no stream, a send failure or its key
	// rotation pending); it timed out unsent.
	OutcomeUnsent
)

// Bounds of the accept times kept for the first output frame.
const (
	maxAwaitingOutput    = 4096
	awaitingOutputMaxAge = 10 * time.Minute
)

// Timing sums one stage.
type Timing struct {
	Count   uint64  `json:"count"`
	TotalMs float64 `json:"total_ms"`
	MaxMs   float64 `json:"max_ms"`
	MeanMs  float64 `json:"mean_ms"`
}

// WorkerStats are the ticket outcomes of one Worker. Received, the tickets that reached it and fed
// its reject rate, is the denominator of both rates, as for the reject-rate suspension. A ticket
// accepted in time after its order could no longer be recorded (VOIDED) feeds neither and is not
// counted.
type WorkerStats struct {
	Received                uint64            `json:"received"`
	Accepted                uint64            `json:"accepted"`
	Rejected                uint64            `json:"rejected"`
	RejectedWithoutFreeSlot uint64            `json:"rejected_without_free_slot"`
	Timeouts                uint64            `json:"timeouts"`
	Unsent                  uint64            `json:"unsent"`
	ReceivedByTier          map[uint32]uint64 `json:"received_by_rtt_tier,omitempty"`
	TimeoutsByTier          map[uint32]uint64 `json:"timeouts_by_rtt_tier,omitempty"`
}

// RejectRate is Rejected over Received; 0 without tickets.
func (w WorkerStats) RejectRate() float64 { return ratio(w.Rejected, w.Received) }

// TimeoutRate is Timeouts over Received; 0 without tickets.
func (w WorkerStats) TimeoutRate() float64 { return ratio(w.Timeouts, w.Received) }

func ratio(n, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// Snapshot is a copy of the statistics.
type Snapshot struct {
	Since    time.Time                    `json:"since"`
	Stages   map[string]Timing            `json:"stages"`
	Counters map[string]map[string]uint64 `json:"counters"`
	Workers  map[string]WorkerStats       `json:"workers"`
}

// Registry holds the statistics.
type Registry struct {
	now   func() time.Time
	since time.Time

	mu       sync.Mutex
	stages   map[string]*Timing
	counters map[string]map[string]uint64
	workers  map[string]*WorkerStats

	// acceptedAt maps a task id to its accept time until its first output frame, awaiting counts
	// its entries. Every output frame looks it up, so it takes no lock shared with the rest.
	acceptedAt sync.Map
	awaiting   atomic.Int64
}

// New starts a Registry.
func New() *Registry {
	return &Registry{
		now: time.Now, since: time.Now(), stages: map[string]*Timing{}, counters: map[string]map[string]uint64{},
		workers: map[string]*WorkerStats{},
	}
}

// ObserveStage adds one run of stage that took d.
func (r *Registry) ObserveStage(stage string, d time.Duration) {
	if r == nil {
		return
	}
	ms := stagetiming.Millis(d)
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.stages[stage]
	if t == nil {
		t = &Timing{}
		r.stages[stage] = t
	}
	t.Count++
	t.TotalMs += ms
	t.MaxMs = max(t.MaxMs, ms)
}

// Inc adds one to counter under label.
func (r *Registry) Inc(counter, label string) { r.Add(counter, label, 1) }

// Add adds n to counter under label; 0 changes nothing.
func (r *Registry) Add(counter, label string, n uint64) {
	if r == nil || n == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.counters[counter]
	if c == nil {
		c = map[string]uint64{}
		r.counters[counter] = c
	}
	c[label] += n
}

// WorkerOutcome records how a ticket offered to operator under accept timeout tier ended.
func (r *Registry) WorkerOutcome(operator string, tier uint32, o Outcome) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.workers[operator]
	if w == nil {
		w = &WorkerStats{ReceivedByTier: map[uint32]uint64{}, TimeoutsByTier: map[uint32]uint64{}}
		r.workers[operator] = w
	}
	if o == OutcomeUnsent {
		w.Unsent++
		return
	}
	w.Received++
	w.ReceivedByTier[tier]++
	switch o {
	case OutcomeAccepted:
		w.Accepted++
	case OutcomeRejected:
		w.Rejected++
	case OutcomeRejectedWithoutFreeSlot:
		w.RejectedWithoutFreeSlot++
	case OutcomeTimeout:
		w.Timeouts++
		w.TimeoutsByTier[tier]++
	}
}

// Accepted notes when the winner of taskID accepted, for StageAcceptToFirstOutput. At most
// maxAwaitingOutput tasks wait for their first frame; older than awaitingOutputMaxAge are dropped.
func (r *Registry) Accepted(taskID string) {
	if r == nil {
		return
	}
	now := r.now()
	if r.awaiting.Load() >= maxAwaitingOutput {
		r.acceptedAt.Range(func(id, at any) bool {
			if now.Sub(at.(time.Time)) > awaitingOutputMaxAge {
				if _, ok := r.acceptedAt.LoadAndDelete(id); ok {
					r.awaiting.Add(-1)
				}
			}
			return true
		})
		if r.awaiting.Load() >= maxAwaitingOutput {
			return
		}
	}
	if _, loaded := r.acceptedAt.Swap(taskID, now); !loaded {
		r.awaiting.Add(1)
	}
}

// OutputFrame notes an output frame of taskID; the first after its accept is timed.
func (r *Registry) OutputFrame(taskID string) {
	if r == nil {
		return
	}
	if r.awaiting.Load() == 0 {
		return
	}
	at, ok := r.acceptedAt.LoadAndDelete(taskID)
	if !ok {
		return
	}
	r.awaiting.Add(-1)
	r.ObserveStage(StageAcceptToFirstOutput, r.now().Sub(at.(time.Time)))
}

// Snapshot copies the statistics.
func (r *Registry) Snapshot() Snapshot {
	s := Snapshot{Stages: map[string]Timing{}, Counters: map[string]map[string]uint64{}, Workers: map[string]WorkerStats{}}
	if r == nil {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s.Since = r.since
	for name, t := range r.stages {
		c := *t
		if c.Count > 0 {
			c.MeanMs = c.TotalMs / float64(c.Count)
		}
		s.Stages[name] = c
	}
	for name, labels := range r.counters {
		s.Counters[name] = copyMap(labels)
	}
	for operator, w := range r.workers {
		c := *w
		c.ReceivedByTier, c.TimeoutsByTier = copyMap(w.ReceivedByTier), copyMap(w.TimeoutsByTier)
		s.Workers[operator] = c
	}
	return s
}

func copyMap[K comparable](m map[K]uint64) map[K]uint64 {
	out := make(map[K]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
