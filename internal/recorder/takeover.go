package recorder

import (
	"context"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// TakeoverBundle is a takeover entry: the signed order this Builder registers a takeover of a
// session bound to another Builder with.
type TakeoverBundle struct {
	SessionID string
	Sequence  uint64
	TaskID    string
	// BoundChangeHeight is the session's bound_change_height the registration is made under: it
	// keys the entry, so the same order under a new binding generation is a new entry.
	BoundChangeHeight uint64
	// Deadline is the last height the entry can be recorded at: the order is valid until then.
	Deadline uint64
	Entry    *taskv1.TakeoverEntryV1
}

// Takeovers is told the outcome of each takeover entry; the takeover manager implements it.
type Takeovers interface {
	// TakeoverRegistered: the chain registered the takeover, or answered the entry as the exact
	// replay of its registration, in the transaction of height.
	TakeoverRegistered(sessionID string, sequence, height uint64)
	// TakeoverRefused: the chain refused the entry with code.
	TakeoverRefused(sessionID string, sequence uint64, code taskv1.DispatchRejectCodeV1)
	// TakeoverLapsed: the entry got no result by its deadline; the session state tells what
	// happened.
	TakeoverLapsed(sessionID string, sequence uint64)
	// TakeoverUnsettled: the entry's result could not be attributed to it (its key did not match,
	// as when the session's binding generation moved since it was sent); the entry is dropped and
	// the chain settles the takeover.
	TakeoverUnsettled(sessionID string, sequence uint64)
}

// SetTakeovers wires the takeover manager, which is built after the Recorder.
func (r *Recorder) SetTakeovers(t Takeovers) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.takeovers = t
}

// RecordTakeover stores a takeover entry; it goes out at the next block with the dispatch
// entries. The same takeover again is the same entry. Its result goes to the Takeovers, never to
// the ledger, the dispatcher or the tasks: a takeover consumes no sequence.
func (r *Recorder) RecordTakeover(_ context.Context, b *TakeoverBundle) error {
	id, err := chaincli.TakeoverEntryObjectID(r.cfg.ChainID, r.cfg.Builder, b.Entry, b.BoundChangeHeight)
	if err != nil {
		return fmt.Errorf("takeover entry key: %w", err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&taskv1.DispatchRecordEntryV1{
		Entry: &taskv1.DispatchRecordEntryV1_Takeover{Takeover: b.Entry},
	})
	if err != nil {
		return fmt.Errorf("encode takeover entry: %w", err)
	}
	e := &entry{
		ObjectID: hex.EncodeToString(id[:]), SessionID: b.SessionID, Sequence: b.Sequence, TaskID: b.TaskID,
		Deadline: b.Deadline, BoundChange: b.BoundChangeHeight, Entry: raw, Takeover: true,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[e.ObjectID]; ok {
		return nil
	}
	op, err := putOp(entryKey(e.ObjectID), e)
	if err == nil {
		err = r.cfg.Store.WriteBatch(op)
	}
	if err != nil {
		return fmt.Errorf("store takeover entry: %w", err)
	}
	r.entries[e.ObjectID] = e
	return nil
}

// WithdrawTakeover drops the session's takeover entry of sequence: an entry not sent yet is
// removed; a sent one, or one a transaction being signed carries, is marked so that its result is
// dropped without a report.
func (r *Recorder) WithdrawTakeover(_ context.Context, sessionID string, sequence uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ops []kv.WriteOp
	for _, e := range r.entries {
		if !e.Takeover || e.SessionID != sessionID || e.Sequence != sequence {
			continue
		}
		if e.Tx == "" && !e.packing {
			r.removeLocked(e, &ops)
		} else {
			e.Withdrawn = true
			ops = append(ops, r.entryOp(e))
		}
	}
	r.writeLocked(ops)
}

// WithdrawUnsentTakeover removes the session's takeover entry of sequence only while no
// transaction carries it or is being signed with it, and reports whether it did: such an entry
// cannot be on chain. An entry that went out or is going out (its result may still come) is left
// alone.
func (r *Recorder) WithdrawUnsentTakeover(sessionID string, sequence uint64) bool {
	withdrawn, _ := r.withdrawUnsent(sessionID, sequence)
	return withdrawn
}

// WithdrawTakeoverUnlessSent reports whether no transaction carries the takeover entry of
// (session, sequence), withdrawing it when it is held unsent: true also when no such entry is held
// (never recorded, or already resolved, as one the chain refused), false only while a
// transaction carries it, or one is being signed with it.
func (r *Recorder) WithdrawTakeoverUnlessSent(sessionID string, sequence uint64) bool {
	_, sent := r.withdrawUnsent(sessionID, sequence)
	return !sent
}

// withdrawUnsent removes the takeover entry of (session, sequence) when it is held and no
// transaction carries it or is being signed with it, and reports whether it did and whether one
// does.
func (r *Recorder) withdrawUnsent(sessionID string, sequence uint64) (withdrawn, sent bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if !e.Takeover || e.SessionID != sessionID || e.Sequence != sequence || e.Withdrawn {
			continue
		}
		if e.Tx != "" || e.packing {
			return false, true
		}
		var ops []kv.WriteOp
		r.removeLocked(e, &ops)
		r.writeLocked(ops)
		return true, false
	}
	return false, false
}

// takeoverLocked resolves the takeover entry e and tells the Takeovers with report. Caller holds
// r.mu.
func (r *Recorder) takeoverLocked(e *entry, ops *[]kv.WriteOp, fx *effects, what string, report func(Takeovers)) {
	r.removeLocked(e, ops)
	if e.Withdrawn {
		return
	}
	r.log.Info("takeover entry "+what, "session_id", e.SessionID, "order_sequence", e.Sequence)
	t := r.takeovers
	if t == nil {
		r.log.Error("takeover entry resolved with no takeover manager to tell", "session_id", e.SessionID, "order_sequence", e.Sequence)
		return
	}
	fx.add(func(context.Context) { report(t) })
}

func (r *Recorder) takeoverRegisteredLocked(e *entry, height uint64, ops *[]kv.WriteOp, fx *effects) {
	r.takeoverLocked(e, ops, fx, "registered", func(t Takeovers) { t.TakeoverRegistered(e.SessionID, e.Sequence, height) })
}

func (r *Recorder) takeoverRefusedLocked(e *entry, code taskv1.DispatchRejectCodeV1, ops *[]kv.WriteOp, fx *effects) {
	r.takeoverLocked(e, ops, fx, "refused "+code.String(), func(t Takeovers) { t.TakeoverRefused(e.SessionID, e.Sequence, code) })
}

func (r *Recorder) takeoverLapsedLocked(e *entry, ops *[]kv.WriteOp, fx *effects) {
	r.takeoverLocked(e, ops, fx, "lapsed", func(t Takeovers) { t.TakeoverLapsed(e.SessionID, e.Sequence) })
}

func (r *Recorder) takeoverUnsettledLocked(e *entry, ops *[]kv.WriteOp, fx *effects) {
	r.takeoverLocked(e, ops, fx, "result not attributed", func(t Takeovers) { t.TakeoverUnsettled(e.SessionID, e.Sequence) })
}
