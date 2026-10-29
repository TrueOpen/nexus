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

// takeoverLocked resolves the takeover entry e and tells the Takeovers with report. Caller holds
// r.mu.
func (r *Recorder) takeoverLocked(e *entry, ops *[]kv.WriteOp, fx *effects, what string, report func(Takeovers)) {
	r.removeLocked(e, ops)
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
