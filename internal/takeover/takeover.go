// Package takeover is the candidate side of a session takeover: a Builder that receives an order
// for a session bound to another Builder registers a takeover with that order, and dispatches the
// order itself once the chain moved the binding here.
//
// The order is checked against the chain first. If the bound Builder already recorded its
// sequence, the SDK is sent there (SessionBoundElsewhereError); if a takeover of the session is
// registered, the SDK waits for it (TakeoverPendingError). Otherwise, with the sequence the
// chain's next one and the session's funds covering the order, the order and its input are kept
// and the takeover entry goes out with the next record transaction. No freshness check applies:
// the takeover waits on the registration height, not on the order.
//
// The chain only registers the takeover; it takes effect record_deadline_blocks later unless the
// bound Builder records the sequence first, the sequence is cancelled or the session closes (the
// registration is voided: the order and its input are dropped). Once the binding moved here,
// confirmed with the session query, the order is prechecked again without freshness and
// dispatched from scratch with this Builder's own VRF and handraise roots; its record deadline
// runs from the activation height. An order that can no longer be recorded before it expires
// ends as ORDER_EXPIRED; the SDK sends the sequence again re-signed, to this Builder.
//
// One takeover per session at a time. Takeovers persist in kv.NSTakeover and a restart resumes
// them.
package takeover

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/recorder"
	"github.com/TrueOpen/nexus/internal/types"
)

// Chain is what the takeover reads from the task chain.
type Chain interface {
	QuerySession(ctx context.Context, sessionID string) (chaincli.SessionState, error)
	QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error)
}

// Recorder records takeover entries (recorder.Recorder).
type Recorder interface {
	RecordTakeover(ctx context.Context, b *recorder.TakeoverBundle) error
	WithdrawTakeover(ctx context.Context, sessionID string, sequence uint64)
}

// Keys gates new takeovers on this Builder's own key and compensation account (recorder.Gate).
type Keys interface {
	// CheckBuilderKey fails with handraise.ErrBuilderRotationPending while this Builder's own
	// replacement key is pending, with dispatcher.ErrCompensationBelowMin while its compensation
	// account is below the minimum, and otherwise when its key cannot be confirmed.
	CheckBuilderKey(ctx context.Context) error
}

// Prechecker runs the dispatching Builder's precheck once the takeover took effect
// (inflight.Prechecker).
type Prechecker interface {
	Reserve(ctx context.Context, o inflight.Order) (inflight.Result, error)
	Release(r *inflight.Reservation) error
}

// Tasks keeps the task and journal of a held order and dispatches it (the coordinator).
type Tasks interface {
	OnTakeover(ctx context.Context, o types.Order) error
	TakeoverRegistered(sessionID, taskID string, activation uint64)
	TakeoverActivated(sessionID, taskID string, height uint64)
	TakeoverEnded(sessionID, taskID, code string, height uint64, dropInput bool, where *types.SessionElsewhere)
	OnOrder(ctx context.Context, o types.Order) error
}

// Config wires a Manager.
type Config struct {
	// Builder is this Builder's operator address, the takeover candidate.
	Builder  string
	Store    kv.Store
	Chain    Chain
	Recorder Recorder
	Precheck Prechecker
	Tasks    Tasks
	Keys     Keys
	// Track, when set, follows a session's events; a restart asks it for every held session.
	Track func(sessionID string) error
	// Background runs chain reads and dispatch off the caller's goroutine; nil runs them on a new
	// goroutine.
	Background func(func())
	Log        *slog.Logger
}

// Admission is an admitted takeover order.
type Admission struct {
	// Existing is set when this Builder already holds the same order for a takeover: nothing new
	// is stored, the SDK follows the task.
	Existing bool
	// ActivationHeight is the height the registered takeover takes effect at; 0 until the chain
	// registered it.
	ActivationHeight uint64
}

type phase uint8

const (
	// phaseReserved: admitted, its input still uploading; kept in memory only.
	phaseReserved phase = iota + 1
	// phaseSubmitted: the takeover entry is with the recorder.
	phaseSubmitted
	// phaseRegistered: the chain registered the takeover.
	phaseRegistered
)

// record is the takeover of one session.
type record struct {
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id"`
	TaskHash  string `json:"task_hash"`
	Phase     phase  `json:"phase"`
	// BoundChangeHeight is the session's bound_change_height the takeover is registered under.
	BoundChangeHeight uint64 `json:"bound_change_height"`
	ActivationHeight  uint64 `json:"activation_height,omitempty"`
	// Order is the order as the coordinator takes it; Precheck as the precheck judges it.
	Order    types.Order    `json:"order"`
	Precheck inflight.Order `json:"precheck"`

	checking bool  // Admit's chain checks are under way
	jobs     []job // what is to be handled, in order; one at a time
	running  bool  // a job is being handled
	// retry is the job to run again at the next block, after a chain read gave no verdict.
	retry *job
	// misses counts session reads showing a registered takeover neither pending nor taken effect:
	// the node read may trail the registration, so it is voided only on the second.
	misses int
}

// Manager runs the takeovers this Builder registers as candidate.
type Manager struct {
	cfg  Config
	log  *slog.Logger
	head atomic.Uint64

	mu      sync.Mutex
	records map[string]*record // session id -> takeover
	// broken are stored takeovers that could not be resumed; Start ends their tasks.
	broken []*record
}

// New builds a Manager over its stored takeovers; Start resumes them.
func New(cfg Config) (*Manager, error) {
	if cfg.Builder == "" || cfg.Store == nil || cfg.Chain == nil || cfg.Recorder == nil || cfg.Precheck == nil || cfg.Tasks == nil || cfg.Keys == nil {
		return nil, fmt.Errorf("takeover needs the Builder address, store, chain, recorder, precheck, tasks and keys")
	}
	m := &Manager{cfg: cfg, log: cfg.Log, records: map[string]*record{}}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

// Start follows the held sessions again and resolves every stored takeover with the chain: a
// submitted entry is judged again by Admit's rules and handed to the recorder again, under the
// session's current bound_change_height (the same entry is the same entry; one already resolved
// is answered as a replay); a registered takeover is checked. A stored takeover that cannot be
// read ends as TASK_FAILED; nothing here stops the start.
func (m *Manager) Start(context.Context) error {
	m.mu.Lock()
	records := make([]*record, 0, len(m.records))
	for _, r := range m.records {
		records = append(records, r)
	}
	broken := m.broken
	m.broken = nil
	m.mu.Unlock()
	for _, r := range broken {
		m.cfg.Tasks.TakeoverEnded(r.SessionID, r.TaskID, codeTaskFailed, m.head.Load(), false, nil)
	}
	for _, r := range records {
		if m.cfg.Track != nil {
			if err := m.cfg.Track(r.SessionID); err != nil {
				m.log.Warn("held session not followed", "session_id", r.SessionID, "err", err)
			}
		}
		why := causeCheck
		if r.Phase == phaseSubmitted {
			why = causeSettle
		}
		m.schedule(r.SessionID, r.Sequence, job{why: why})
	}
	return nil
}

// Held reports whether this Builder holds the order (session, sequence, task_hash) for a
// takeover past its upload: an exact resend is answered with it, before any precheck.
func (m *Manager) Held(sessionID string, sequence uint64, taskHash string) (Admission, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[sessionID]
	if r == nil || r.Phase == phaseReserved || r.Sequence != sequence || r.TaskHash != taskHash {
		return Admission{}, false
	}
	return Admission{Existing: true, ActivationHeight: r.ActivationHeight}, true
}

// Admit decides an order the precheck found bound to another Builder (pre is the order as the
// precheck judged it) and, when it may register a takeover, reserves the session's takeover for
// it until Submit or Release. In this order:
//
//   - a takeover this Builder holds for the session: the same order is Admission.Existing (or
//     inflight.ErrOrderUploading while its input uploads), another one a TakeoverPendingError
//     naming this Builder: one takeover per session;
//   - this Builder's own key and compensation account: a pending key rotation or an account below
//     its minimum is dispatchdraw.ErrNoCapacity (no new takeover), an unconfirmed key
//     inflight.ErrUnavailable;
//   - the dispatch record of the sequence: recorded, a SessionBoundElsewhereError naming the
//     recording Builder and task;
//   - the session state read from the chain: a registered takeover is a TakeoverPendingError
//     naming its candidate; a sequence other than the chain's next is ErrOrderSequenceConflict;
//     funds are inflight.CheckTakeoverFunds.
//
// A chain that cannot be read is inflight.ErrUnavailable, never a verdict.
func (m *Manager) Admit(ctx context.Context, o types.Order, pre inflight.Order) (Admission, error) {
	m.mu.Lock()
	if r := m.records[o.SessionID]; r != nil {
		defer m.mu.Unlock()
		switch {
		case r.TaskHash != o.TaskHash || r.Sequence != o.OrderSequence:
			return Admission{}, &inflight.TakeoverPendingError{Candidate: m.cfg.Builder, ActivationHeight: r.ActivationHeight}
		case r.Phase == phaseReserved:
			return Admission{}, fmt.Errorf("%w: the takeover order of session %s is still uploading; retry", inflight.ErrOrderUploading, o.SessionID)
		}
		return Admission{Existing: true, ActivationHeight: r.ActivationHeight}, nil
	}
	reserved := &record{
		SessionID: o.SessionID, Sequence: o.OrderSequence, TaskID: o.TaskID, TaskHash: o.TaskHash,
		Phase: phaseReserved, Order: o, Precheck: pre, checking: true,
	}
	reserved.Order.Payload = nil
	m.records[o.SessionID] = reserved
	m.mu.Unlock()

	bound, err := m.checkKey(ctx)
	if err == nil {
		bound, err = m.check(ctx, o.SessionID, o.OrderSequence, pre.MaxFee)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if m.records[o.SessionID] == reserved {
			delete(m.records, o.SessionID)
		}
		return Admission{}, err
	}
	reserved.BoundChangeHeight, reserved.checking = bound, false
	return Admission{}, nil
}

// checkKey is Admit's check of this Builder's own key and compensation account.
func (m *Manager) checkKey(ctx context.Context) (uint64, error) {
	err := m.cfg.Keys.CheckBuilderKey(ctx)
	switch {
	case err == nil:
		return 0, nil
	case errors.Is(err, handraise.ErrBuilderRotationPending), errors.Is(err, dispatcher.ErrCompensationBelowMin):
		return 0, fmt.Errorf("%w: no takeover: %v", dispatchdraw.ErrNoCapacity, err)
	default:
		return 0, fmt.Errorf("%w: %v", inflight.ErrUnavailable, err)
	}
}

// check runs Admit's chain checks and returns the session's bound_change_height.
func (m *Manager) check(ctx context.Context, sessionID string, seq, maxFee uint64) (uint64, error) {
	rec, err := m.cfg.Chain.QueryDispatchRecordByOrder(ctx, sessionID, seq)
	switch {
	case err == nil:
		return 0, &inflight.SessionBoundElsewhereError{Builder: rec.GetBuilderAddress(), TaskID: hex.EncodeToString(rec.GetTaskId())}
	case !errors.Is(err, chaincli.ErrNotFound):
		return 0, fmt.Errorf("%w: dispatch record of sequence %d: %v", inflight.ErrUnavailable, seq, err)
	}
	state, err := m.cfg.Chain.QuerySession(ctx, sessionID)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return 0, fmt.Errorf("%w: session %s is closed", inflight.ErrSessionClosing, sessionID)
	case err != nil:
		return 0, fmt.Errorf("%w: session state: %v", inflight.ErrUnavailable, err)
	}
	if t := state.PendingTakeover; t != nil {
		return 0, &inflight.TakeoverPendingError{Candidate: t.CandidateBuilder, ActivationHeight: t.ActivationHeight}
	}
	if state.BoundBuilder == m.cfg.Builder {
		return 0, fmt.Errorf("%w: session %s is bound to this Builder now; send the order again", inflight.ErrUnavailable, sessionID)
	}
	if seq != state.NextExpectedSequence {
		return 0, fmt.Errorf("%w: sequence %d is not the chain's next sequence %d", inflight.ErrOrderSequenceConflict, seq, state.NextExpectedSequence)
	}
	if err := inflight.CheckTakeoverFunds(inflight.Session{SessionState: state, Found: true}, maxFee); err != nil {
		return 0, err
	}
	return state.BoundChangeHeight, nil
}

// Submit takes the admitted order once its input is stored: the takeover is stored, the order's
// task started and the takeover entry handed to the recorder. On an error nothing stays held and
// the caller drops the input.
func (m *Manager) Submit(ctx context.Context, o types.Order) error {
	m.mu.Lock()
	r := m.records[o.SessionID]
	if r == nil || r.Phase != phaseReserved || r.TaskHash != o.TaskHash || r.checking {
		m.mu.Unlock()
		return fmt.Errorf("no takeover of session %s is reserved for task_hash %s", o.SessionID, o.TaskHash)
	}
	r.Phase = phaseSubmitted
	if err := m.saveLocked(r); err != nil {
		delete(m.records, o.SessionID)
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	if err := m.cfg.Tasks.OnTakeover(ctx, o); err != nil {
		m.forget(r)
		return err
	}
	if err := m.submitEntry(ctx, r); err != nil {
		m.end(ctx, r, codeTaskFailed, false, nil)
		return err
	}
	m.log.Info("takeover entry submitted", "session_id", r.SessionID, "order_sequence", r.Sequence, "bound_change_height", r.BoundChangeHeight)
	return nil
}

// Release drops an admitted order that did not reach Submit.
func (m *Manager) Release(sessionID, taskHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[sessionID]; r != nil && r.Phase == phaseReserved && r.TaskHash == taskHash {
		delete(m.records, sessionID)
	}
}

// submitEntry hands the takeover entry of r to the recorder; it can be recorded until the block
// before the order expires.
func (m *Manager) submitEntry(ctx context.Context, r *record) error {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(r.Order.SignedOrder, &signed); err != nil || signed.GetOrder() == nil {
		return fmt.Errorf("takeover order of session %s does not decode", r.SessionID)
	}
	deadline := signed.GetOrder().GetOrderExpireHeight()
	if deadline > 0 {
		deadline--
	}
	return m.cfg.Recorder.RecordTakeover(ctx, &recorder.TakeoverBundle{
		SessionID: r.SessionID, Sequence: r.Sequence, TaskID: r.TaskID, BoundChangeHeight: r.BoundChangeHeight,
		Deadline: deadline, Entry: &taskv1.TakeoverEntryV1{SignedOrder: &signed},
	})
}

// backgroundTimeout bounds one background job: its chain reads and the hand-over of the order.
const backgroundTimeout = 30 * time.Second

// later runs f in the background.
func (m *Manager) later(f func(context.Context)) {
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), backgroundTimeout)
		defer cancel()
		f(ctx)
	}
	if m.cfg.Background != nil {
		m.cfg.Background(run)
		return
	}
	go run()
}
