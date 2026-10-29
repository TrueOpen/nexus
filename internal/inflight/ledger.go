// Package inflight is the OpenTask precheck of a dispatching Builder and the ledger it relies on.
//
// The chain admits an order only when this Builder records its dispatch entry, a block or more
// after the order was dispatched, and several orders of one session may be dispatched before the
// first is recorded. The Ledger keeps, per session, the orders this Builder dispatched whose
// dispatch entry the chain has not admitted yet, with their max_fee, so the precheck can count them
// against the session's sequence, balance and session key spend cap. Only the Builder bound to a
// session dispatches and records for it, so this Builder's in-flight orders are all of them.
//
// The ledger is not a chain fact: it serves only the precheck and the suspension of a session
// after a failed record.
package inflight

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/TrueOpen/nexus/internal/kv"
)

// State is the local state of one in-flight order.
type State uint8

const (
	// StateDispatching: the precheck admitted the order and dispatch tickets are being offered.
	StateDispatching State = iota + 1
	// StateAccepted: a Worker accepted a ticket; the dispatch entry is not admitted yet.
	StateAccepted
	// StateRecorded: the chain admitted the dispatch entry. The order still counts while the
	// cached session state has not caught up with the record.
	StateRecorded
	// StateFailed: the attempt ended without a record (no capacity, record rejected, revoked or
	// cancelled). It no longer counts; a new order for its sequence is a retry.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateDispatching:
		return "DISPATCHING"
	case StateAccepted:
		return "ACCEPTED"
	case StateRecorded:
		return "RECORDED"
	case StateFailed:
		return "FAILED"
	}
	return "UNKNOWN(" + strconv.Itoa(int(s)) + ")"
}

// live reports whether an order in this state counts as in flight.
func (s State) live() bool { return s == StateDispatching || s == StateAccepted || s == StateRecorded }

// Entry is one order in the ledger.
type Entry struct {
	Sequence uint64 `json:"sequence"`
	TaskID   string `json:"task_id"`
	TaskHash string `json:"task_hash"`
	// MaxFee is the order's max_fee in atomic units: what the chain freezes when it admits it.
	MaxFee uint64 `json:"max_fee"`
	// SessionKey is true when the session's registered key signed the order, so admitting it adds
	// MaxFee to the key's spent amount.
	SessionKey bool `json:"session_key"`
	// Deadline is the last height the dispatch entry can be recorded at:
	// max(earliest_submit_height, bound_change_height) + record_deadline_blocks.
	Deadline uint64 `json:"deadline"`
	State    State  `json:"state"`
	// Committed is set once the order reached the dispatcher (Ledger.Commit, or any state change
	// the dispatcher makes). Until then the entry is a reservation whose input is still being
	// uploaded: an exact resend is told to retry, not that the order is accepted, and a restart
	// releases it.
	Committed bool `json:"committed,omitempty"`
}

// ErrUnknownOrder is a ledger update for an order the ledger does not hold.
var ErrUnknownOrder = errors.New("inflight: order is not in the ledger")

// sessionMeta is the persisted per-session state besides the orders.
type sessionMeta struct {
	// SuspendedFrom is set after the record of this sequence failed: until the order of that
	// sequence is dispatched again, no other order of the session is.
	SuspendedFrom *uint64 `json:"suspended_from,omitempty"`
	// CancelRequested maps a sequence with a registered cancellation to its effective height.
	CancelRequested map[uint64]uint64 `json:"cancel_requested,omitempty"`
}

func (m sessionMeta) empty() bool { return m.SuspendedFrom == nil && len(m.CancelRequested) == 0 }

type sessionLedger struct {
	orders map[uint64]*Entry
	meta   sessionMeta
}

// inFlightSum is what the precheck counts for one session.
type inFlightSum struct {
	count            uint64
	maxFee           *big.Int // all in-flight orders
	sessionKeyMaxFee *big.Int // in-flight orders the registered key signed
}

// inFlight sums the live orders at or above next, the chain's next expected sequence as the
// caller's session state has it: orders below it are already in that state's frozen amounts.
func (s *sessionLedger) inFlight(next uint64) inFlightSum {
	sum := inFlightSum{maxFee: new(big.Int), sessionKeyMaxFee: new(big.Int)}
	var fee big.Int
	for seq, e := range s.orders {
		if seq < next || !e.State.live() {
			continue
		}
		sum.count++
		fee.SetUint64(e.MaxFee)
		sum.maxFee.Add(sum.maxFee, &fee)
		if e.SessionKey {
			sum.sessionKeyMaxFee.Add(sum.sessionKeyMaxFee, &fee)
		}
	}
	return sum
}

// Ledger is the in-flight order ledger, persisted in kv.NSInflight and recovered on restart.
type Ledger struct {
	store kv.Store

	mu       sync.Mutex
	sessions map[string]*sessionLedger
}

// Keys of kv.NSInflight: "order/<session>/<zero-padded sequence>" and "session/<session>".
const (
	orderPrefix   = "order/"
	sessionPrefix = "session/"
)

func orderKey(sessionID string, seq uint64) string {
	return fmt.Sprintf("%s%s/%020d", orderPrefix, sessionID, seq)
}

func sessionKey(sessionID string) string { return sessionPrefix + sessionID }

// NewLedger loads the ledger from store. A record that does not parse fails the load: counting
// without it could admit orders the chain will refuse.
func NewLedger(store kv.Store) (*Ledger, error) {
	l := &Ledger{store: store, sessions: make(map[string]*sessionLedger)}
	var loadErr error
	err := store.Scan(kv.NSInflight, func(key string, val []byte) bool {
		loadErr = l.load(key, val)
		return loadErr == nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan in-flight ledger: %w", err)
	}
	if loadErr != nil {
		return nil, loadErr
	}
	if err := l.releaseUncommitted(); err != nil {
		return nil, err
	}
	return l, nil
}

// releaseUncommitted drops the reservations a previous run left uncommitted: their orders never
// reached the dispatcher. A dropped order with live orders after it is a hole the next order for
// its sequence fills; the failed attempt or suspension such a reservation replaced is not
// restored, and the sequence rule refuses orders past the hole all the same.
func (l *Ledger) releaseUncommitted() error {
	var ops []kv.WriteOp
	type key struct {
		session string
		seq     uint64
	}
	var dropped []key
	for id, s := range l.sessions {
		for seq, e := range s.orders {
			if e.State == StateDispatching && !e.Committed {
				ops = append(ops, kv.WriteOp{NS: kv.NSInflight, Key: orderKey(id, seq), Delete: true})
				dropped = append(dropped, key{id, seq})
			}
		}
	}
	if len(ops) == 0 {
		return nil
	}
	if err := l.store.WriteBatch(ops...); err != nil {
		return fmt.Errorf("release uncommitted in-flight orders: %w", err)
	}
	for _, k := range dropped {
		delete(l.sessions[k.session].orders, k.seq)
		l.dropIfEmptyLocked(k.session)
	}
	return nil
}

func (l *Ledger) load(key string, val []byte) error {
	switch {
	case strings.HasPrefix(key, orderPrefix):
		sessionID, seqText, ok := strings.Cut(strings.TrimPrefix(key, orderPrefix), "/")
		seq, err := strconv.ParseUint(seqText, 10, 64)
		var e Entry
		if !ok || err != nil || json.Unmarshal(val, &e) != nil || e.Sequence != seq || !validState(e.State) {
			return fmt.Errorf("malformed in-flight ledger record %q", key)
		}
		l.sessionLocked(sessionID).orders[seq] = &e
	case strings.HasPrefix(key, sessionPrefix):
		var meta sessionMeta
		if err := json.Unmarshal(val, &meta); err != nil {
			return fmt.Errorf("malformed in-flight ledger record %q", key)
		}
		l.sessionLocked(strings.TrimPrefix(key, sessionPrefix)).meta = meta
	default:
		return fmt.Errorf("unknown in-flight ledger record %q", key)
	}
	return nil
}

func validState(s State) bool { return s >= StateDispatching && s <= StateFailed }

func (l *Ledger) sessionLocked(sessionID string) *sessionLedger {
	s := l.sessions[sessionID]
	if s == nil {
		s = &sessionLedger{orders: make(map[uint64]*Entry)}
		l.sessions[sessionID] = s
	}
	return s
}

// putOp is the write of e; the caller applies it before changing memory.
func putOp(sessionID string, e Entry) (kv.WriteOp, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return kv.WriteOp{}, err
	}
	return kv.WriteOp{NS: kv.NSInflight, Key: orderKey(sessionID, e.Sequence), Val: raw}, nil
}

func metaOp(sessionID string, meta sessionMeta) (kv.WriteOp, error) {
	if meta.empty() {
		return kv.WriteOp{NS: kv.NSInflight, Key: sessionKey(sessionID), Delete: true}, nil
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return kv.WriteOp{}, err
	}
	return kv.WriteOp{NS: kv.NSInflight, Key: sessionKey(sessionID), Val: raw}, nil
}

// put writes e as a new or replaced order of the session.
func (l *Ledger) put(sessionID string, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.putLocked(sessionID, e)
}

func (l *Ledger) putLocked(sessionID string, e Entry) error {
	op, err := putOp(sessionID, e)
	if err != nil {
		return err
	}
	if err := l.store.WriteBatch(op); err != nil {
		return fmt.Errorf("write in-flight order: %w", err)
	}
	l.sessionLocked(sessionID).orders[e.Sequence] = &e
	return nil
}

func (l *Ledger) setState(sessionID string, seq uint64, state State) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.setStateLocked(sessionID, seq, state)
}

func (l *Ledger) setStateLocked(sessionID string, seq uint64, state State) error {
	s := l.sessions[sessionID]
	if s == nil || s.orders[seq] == nil {
		return fmt.Errorf("%w: session %s sequence %d", ErrUnknownOrder, sessionID, seq)
	}
	if s.orders[seq].State == state && s.orders[seq].Committed {
		return nil
	}
	e := *s.orders[seq]
	e.State, e.Committed = state, true
	return l.putLocked(sessionID, e)
}

// MarkAccepted records that a Worker accepted a ticket of the order.
func (l *Ledger) MarkAccepted(sessionID string, seq uint64) error {
	return l.setState(sessionID, seq, StateAccepted)
}

// MarkRecorded records that the chain admitted the order's dispatch entry. The order keeps
// counting until the session state the precheck reads includes the record.
func (l *Ledger) MarkRecorded(sessionID string, seq uint64) error {
	return l.setState(sessionID, seq, StateRecorded)
}

// MarkFailed records that the attempt ended without a record. The order stops counting; a new
// order for the sequence is a retry, not a replacement.
func (l *Ledger) MarkFailed(sessionID string, seq uint64) error {
	return l.setState(sessionID, seq, StateFailed)
}

// Reservation is an order Prechecker.Reserve entered in the ledger as DISPATCHING. Release undoes
// it when the order never reaches dispatch.
type Reservation struct {
	SessionID string
	Sequence  uint64
	TaskHash  string
	// replaced is the failed attempt the reservation replaced; resumed the suspension it ended.
	replaced *Entry
	resumed  *uint64
}

// Commit marks the reservation's order as handed to the dispatcher: from now on an exact resend
// is the existing order, Release leaves it alone and a restart keeps it.
func (l *Ledger) Commit(r *Reservation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[r.SessionID]
	if s == nil || s.orders[r.Sequence] == nil || s.orders[r.Sequence].TaskHash != r.TaskHash {
		return fmt.Errorf("%w: session %s sequence %d task_hash %s", ErrUnknownOrder, r.SessionID, r.Sequence, r.TaskHash)
	}
	if s.orders[r.Sequence].Committed {
		return nil
	}
	e := *s.orders[r.Sequence]
	e.Committed = true
	return l.putLocked(r.SessionID, e)
}

// Release undoes a reservation whose order never started dispatching (the request nonce was
// replayed, the input could not be stored, the dispatcher refused it): a new order is dropped, a
// retry puts the failed attempt back and a suspension the retry ended is restored. A reservation
// that was committed, or that the order moved past (no longer DISPATCHING with its task_hash), is
// left alone. A dropped order
// with live orders after it is a hole that a new order for its sequence fills.
func (l *Ledger) Release(r *Reservation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[r.SessionID]
	if s == nil {
		return nil
	}
	e := s.orders[r.Sequence]
	if e == nil || e.State != StateDispatching || e.Committed || e.TaskHash != r.TaskHash {
		return nil
	}
	var ops []kv.WriteOp
	if r.replaced != nil {
		op, err := putOp(r.SessionID, *r.replaced)
		if err != nil {
			return err
		}
		ops = append(ops, op)
	} else {
		ops = append(ops, kv.WriteOp{NS: kv.NSInflight, Key: orderKey(r.SessionID, r.Sequence), Delete: true})
	}
	meta := s.meta
	if r.resumed != nil && meta.SuspendedFrom == nil {
		from := *r.resumed
		meta.SuspendedFrom = &from
		op, err := metaOp(r.SessionID, meta)
		if err != nil {
			return err
		}
		ops = append(ops, op)
	}
	if err := l.store.WriteBatch(ops...); err != nil {
		return fmt.Errorf("release in-flight order: %w", err)
	}
	if r.replaced != nil {
		replaced := *r.replaced
		s.orders[r.Sequence] = &replaced
	} else {
		delete(s.orders, r.Sequence)
	}
	s.meta = meta
	l.dropIfEmptyLocked(r.SessionID)
	return nil
}

// Suspend stops dispatch for the session from sequence from, after the record of that sequence
// failed: every later order fails with it, since the chain cannot admit them before it. Until the
// order of from is dispatched again, the precheck admits no other order of the session.
func (l *Ledger) Suspend(sessionID string, from uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessionLocked(sessionID)
	meta := s.meta
	meta.SuspendedFrom = &from
	var ops []kv.WriteOp
	var failed []Entry
	for seq, e := range s.orders {
		if seq < from || e.State == StateRecorded || e.State == StateFailed {
			continue
		}
		updated := *e
		updated.State, updated.Committed = StateFailed, true
		op, err := putOp(sessionID, updated)
		if err != nil {
			return err
		}
		ops = append(ops, op)
		failed = append(failed, updated)
	}
	op, err := metaOp(sessionID, meta)
	if err != nil {
		return err
	}
	if err := l.store.WriteBatch(append(ops, op)...); err != nil {
		return fmt.Errorf("write session suspension: %w", err)
	}
	for _, e := range failed {
		e := e
		s.orders[e.Sequence] = &e
	}
	s.meta = meta
	return nil
}

// SuspendedFrom reports the session's suspension mark.
func (l *Ledger) SuspendedFrom(sessionID string) (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil || s.meta.SuspendedFrom == nil {
		return 0, false
	}
	return *s.meta.SuspendedFrom, true
}

// cancelRequested records a registered cancellation of seq, effective at height.
func (l *Ledger) cancelRequested(sessionID string, seq, effective uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessionLocked(sessionID)
	if got, ok := s.meta.CancelRequested[seq]; ok && got == effective {
		return nil
	}
	meta := s.meta
	meta.CancelRequested = cloneCancels(s.meta.CancelRequested)
	meta.CancelRequested[seq] = effective
	return l.writeMetaLocked(sessionID, meta)
}

// cancelled applies an effective cancellation of seq: the sequence is consumed, so the order of it
// (if any) fails, its cancellation mark and a suspension at or below it end.
func (l *Ledger) cancelled(sessionID string, seq uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil {
		return nil
	}
	if e := s.orders[seq]; e != nil && e.State != StateRecorded && e.State != StateFailed {
		if err := l.setStateLocked(sessionID, seq, StateFailed); err != nil {
			return err
		}
	}
	return l.consumedLocked(sessionID, seq+1)
}

// consumedLocked drops the marks below next, the chain's next expected sequence.
func (l *Ledger) consumedLocked(sessionID string, next uint64) error {
	s := l.sessions[sessionID]
	if s == nil {
		return nil
	}
	meta := s.meta
	changed := false
	if meta.SuspendedFrom != nil && *meta.SuspendedFrom < next {
		meta.SuspendedFrom = nil
		changed = true
	}
	var cancels map[uint64]uint64
	for seq := range s.meta.CancelRequested {
		if seq < next {
			if cancels == nil {
				cancels = cloneCancels(s.meta.CancelRequested)
			}
			delete(cancels, seq)
		}
	}
	if cancels != nil {
		meta.CancelRequested = cancels
		changed = true
	}
	if !changed {
		return nil
	}
	if err := l.writeMetaLocked(sessionID, meta); err != nil {
		return err
	}
	l.dropIfEmptyLocked(sessionID)
	return nil
}

func cloneCancels(in map[uint64]uint64) map[uint64]uint64 {
	out := make(map[uint64]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (l *Ledger) writeMetaLocked(sessionID string, meta sessionMeta) error {
	op, err := metaOp(sessionID, meta)
	if err != nil {
		return err
	}
	if err := l.store.WriteBatch(op); err != nil {
		return fmt.Errorf("write in-flight session state: %w", err)
	}
	l.sessionLocked(sessionID).meta = meta
	return nil
}

// CancelRequested reports whether a cancellation of seq is registered: no new dispatch round may
// start for it.
func (l *Ledger) CancelRequested(sessionID string, seq uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil {
		return false
	}
	_, ok := s.meta.CancelRequested[seq]
	return ok
}

// Prune drops recorded and failed orders below next (the chain's next expected sequence) whose
// record deadline is before head, and the marks below next. Orders still dispatching or accepted
// stay for their owner to finish.
func (l *Ledger) Prune(sessionID string, next, head uint64) error {
	return l.pruneIf(sessionID, next, head, func() bool { return true })
}

// pruneIf is Prune when ok, asked under the ledger lock, holds.
func (l *Ledger) pruneIf(sessionID string, next, head uint64, ok func() bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !ok() {
		return nil
	}
	return l.pruneLocked(sessionID, next, head)
}

func (l *Ledger) pruneLocked(sessionID string, next, head uint64) error {
	s := l.sessions[sessionID]
	if s == nil {
		return nil
	}
	var ops []kv.WriteOp
	var dropped []uint64
	for seq, e := range s.orders {
		if seq < next && (e.State == StateRecorded || e.State == StateFailed) && e.Deadline < head {
			ops = append(ops, kv.WriteOp{NS: kv.NSInflight, Key: orderKey(sessionID, seq), Delete: true})
			dropped = append(dropped, seq)
		}
	}
	if len(ops) > 0 {
		if err := l.store.WriteBatch(ops...); err != nil {
			return fmt.Errorf("prune in-flight orders: %w", err)
		}
		for _, seq := range dropped {
			delete(s.orders, seq)
		}
	}
	if err := l.consumedLocked(sessionID, next); err != nil {
		return err
	}
	l.dropIfEmptyLocked(sessionID)
	return nil
}

func (l *Ledger) dropIfEmptyLocked(sessionID string) {
	if s := l.sessions[sessionID]; s != nil && len(s.orders) == 0 && s.meta.empty() {
		delete(l.sessions, sessionID)
	}
}

// Get returns one order of the session.
func (l *Ledger) Get(sessionID string, seq uint64) (Entry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil || s.orders[seq] == nil {
		return Entry{}, false
	}
	return *s.orders[seq], true
}

// Entries returns the session's orders in sequence order.
func (l *Ledger) Entries(sessionID string) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil {
		return nil
	}
	out := make([]Entry, 0, len(s.orders))
	for _, e := range s.orders {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

// SessionEntry is an order of the ledger with its session.
type SessionEntry struct {
	SessionID string
	Entry
}

// Unfinished lists the committed orders still DISPATCHING or ACCEPTED, by session and sequence:
// orders the dispatcher took. After a restart nothing else remembers them: each must be
// dispatched again, recorded or marked failed (MarkFailed, or Suspend when a record failed) by
// the dispatcher, or its sequence stays taken. Uncommitted reservations are not listed; a restart
// releases them (they never reached the dispatcher).
func (l *Ledger) Unfinished() []SessionEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []SessionEntry
	for id, s := range l.sessions {
		for _, e := range s.orders {
			if e.Committed && (e.State == StateDispatching || e.State == StateAccepted) {
				out = append(out, SessionEntry{SessionID: id, Entry: *e})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID != out[j].SessionID {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].Sequence < out[j].Sequence
	})
	return out
}

// Sessions lists the sessions the ledger holds state for, sorted; after a restart these are the
// sessions whose events must be followed again.
func (l *Ledger) Sessions() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.sessions))
	for id := range l.sessions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
