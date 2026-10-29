package recorder

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	// rebroadcastAfterBlocks is how many blocks a transaction the chain does not show waits before
	// it is broadcast again.
	rebroadcastAfterBlocks = 2
	// codeTxInMempoolCache is cosmos-sdk's refusal of a transaction already in the mempool.
	codeTxInMempoolCache = 19

	statusRecorded = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED
	statusRejected = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED
	// codeLaterSequence is what the chain answers an order past a sequence it did not consume, the
	// code of every later entry a refusal fails.
	codeLaterSequence = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_CONSUMED
	codeRecordLate    = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
)

// pendingTxs lists the transactions still carrying an unresolved entry and drops the others.
func (r *Recorder) pendingTxs() []txRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	carried := map[string]bool{}
	for _, e := range r.entries {
		carried[e.Tx] = true
	}
	var out []txRecord
	var ops []kv.WriteOp
	for hash, tx := range r.txs {
		if !carried[hash] {
			delete(r.txs, hash)
			ops = append(ops, deleteOp(txKey(hash)))
			continue
		}
		out = append(out, *tx)
	}
	r.writeLocked(ops)
	sort.Slice(out, func(i, j int) bool { return out[i].SentHeight < out[j].SentHeight })
	return out
}

// checkTxs reads the block result of every transaction out.
func (r *Recorder) checkTxs(ctx context.Context, height uint64) {
	for _, tx := range r.pendingTxs() {
		hash, _ := hex.DecodeString(tx.Hash)
		res, err := r.cfg.Chain.QueryTx(ctx, hash)
		switch {
		case isNotFound(err):
			r.notFound(ctx, tx, height)
		case err != nil:
			r.log.Warn("record transaction result not read", "tx_hash", tx.Hash, "err", err)
		case res.Code != 0:
			// Refused as a whole (the compensation account below its minimum, out of gas...): no
			// entry has a result, so all of them go out again.
			r.log.Warn("record transaction refused by the chain; its entries go out again", "tx_hash", tx.Hash,
				"code", res.Code, "codespace", res.Codespace, "raw_log", res.RawLog)
			r.cfg.Gate.markStale()
			r.requeue(tx.Hash)
		default:
			r.applyResult(ctx, tx, res)
		}
	}
}

// notFound broadcasts a transaction the chain does not show again, as stored, once it waited
// rebroadcastAfterBlocks (at once after a restart) and while an entry of it can still be
// recorded. A transaction the chain refuses now can no longer land: its entries go out again.
func (r *Recorder) notFound(ctx context.Context, tx txRecord, height uint64) {
	if !tx.replay && height < tx.SentHeight+rebroadcastAfterBlocks || !r.recordable(tx.Hash, height) {
		return
	}
	res, err := r.cfg.Tx.BroadcastTx(ctx, tx.Raw)
	switch {
	case err != nil:
		r.log.Warn("record transaction not broadcast again", "tx_hash", tx.Hash, "err", err)
	case res.Code == 0 || res.Code == codeTxInMempoolCache && res.Codespace == "sdk":
		r.mu.Lock()
		if stored := r.txs[tx.Hash]; stored != nil {
			stored.SentHeight, stored.replay = height, false
			op, err := putOp(txKey(tx.Hash), stored)
			if err == nil {
				r.writeLocked([]kv.WriteOp{op})
			}
		}
		r.mu.Unlock()
		r.log.Info("record transaction broadcast again", "tx_hash", tx.Hash)
	default:
		r.log.Info("record transaction can no longer land; its entries go out again", "tx_hash", tx.Hash,
			"code", res.Code, "codespace", res.Codespace, "raw_log", res.RawLog)
		r.requeue(tx.Hash)
	}
}

// recordable reports whether an entry the transaction carries can still be recorded after height.
func (r *Recorder) recordable(hash string, height uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.Tx == hash && e.Deadline > height {
			return true
		}
	}
	return false
}

// requeue drops a transaction that will not land: its unresolved entries wait for the next block.
func (r *Recorder) requeue(hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ops := []kv.WriteOp{deleteOp(txKey(hash))}
	delete(r.txs, hash)
	for _, e := range r.entries {
		if e.Tx == hash {
			e.Tx = ""
			ops = append(ops, r.entryOp(e))
		}
	}
	r.writeLocked(ops)
}

// applyResult takes the per-entry results of an executed transaction. Results that do not check
// out (object_id or batch_digest) are not attributed to any entry: each entry is checked with the
// dispatch record query instead.
func (r *Recorder) applyResult(ctx context.Context, tx txRecord, res chaincli.TxResult) {
	ids := make([][32]byte, len(tx.Objects))
	for i, id := range tx.Objects {
		raw, _ := hex.DecodeString(id)
		ids[i] = [32]byte(raw)
	}
	resp, err := chaincli.DecodeRecordDispatchResponse(res, 0, r.cfg.ChainID, ids)
	if err != nil {
		r.log.Error("record results do not match the entries sent; checking each entry on chain", "tx_hash", tx.Hash, "err", err)
		r.verifyByQuery(ctx, tx)
		return
	}
	var fx effects
	r.mu.Lock()
	var ops []kv.WriteOp
	for i, item := range resp.GetResults() {
		e := r.entries[tx.Objects[i]]
		if e == nil {
			continue
		}
		if item.GetStatus() == sharedv1.MutationStatusV1_MUTATION_STATUS_V1_REJECTED {
			r.rejectLocked(e, item.GetRejectCode(), false, &ops, &fx)
		} else {
			r.recordLocked(e, uint64(res.Height), &ops, &fx)
		}
	}
	r.dropTxLocked(tx.Hash, &ops)
	r.writeLocked(ops)
	r.mu.Unlock()
	fx.run(ctx)
}

// verifyByQuery resolves the entries of a transaction whose results could not be attributed: an
// entry the chain recorded with its winner ticket is recorded; any other goes out again.
func (r *Recorder) verifyByQuery(ctx context.Context, tx txRecord) {
	for _, id := range tx.Objects {
		r.mu.Lock()
		e := r.entries[id]
		var session string
		var seq uint64
		if e != nil {
			session, seq = e.SessionID, e.Sequence
		}
		r.mu.Unlock()
		if e == nil {
			continue
		}
		rec, err := r.cfg.Chain.QueryDispatchRecordByOrder(ctx, session, seq)
		var fx effects
		r.mu.Lock()
		var ops []kv.WriteOp
		if e = r.entries[id]; e != nil {
			if err == nil && bytes.Equal(rec.GetDispatchTicketHash(), e.TicketHash) {
				r.recordLocked(e, rec.GetRecordedHeight(), &ops, &fx)
			} else if e.Tx == tx.Hash {
				e.Tx = ""
				ops = append(ops, r.entryOp(e))
			}
		}
		r.writeLocked(ops)
		r.mu.Unlock()
		fx.run(ctx)
	}
	r.mu.Lock()
	var ops []kv.WriteOp
	r.dropTxLocked(tx.Hash, &ops)
	r.writeLocked(ops)
	r.mu.Unlock()
}

func (r *Recorder) dropTxLocked(hash string, ops *[]kv.WriteOp) {
	delete(r.txs, hash)
	*ops = append(*ops, deleteOp(txKey(hash)))
	for _, e := range r.entries {
		if e.Tx == hash {
			e.Tx = ""
			*ops = append(*ops, r.entryOp(e))
		}
	}
}

// expire resolves the entries past their record deadline with the dispatch record query: recorded
// with their winner ticket, they are recorded; otherwise the chain can no longer admit them and
// they are RECORD_LATE. An unreadable chain decides nothing.
func (r *Recorder) expire(ctx context.Context, height uint64) {
	r.mu.Lock()
	var due []*entry
	for _, e := range r.entries {
		if height > e.Deadline {
			due = append(due, e)
		}
	}
	r.mu.Unlock()
	sortEntries(due)
	for _, d := range due {
		rec, err := r.cfg.Chain.QueryDispatchRecordByOrder(ctx, d.SessionID, d.Sequence)
		if err != nil && !isNotFound(err) {
			r.log.Warn("dispatch record of an entry past its deadline not read", "session_id", d.SessionID, "order_sequence", d.Sequence, "err", err)
			continue
		}
		var fx effects
		r.mu.Lock()
		var ops []kv.WriteOp
		if e := r.entries[d.ObjectID]; e != nil {
			switch {
			case err == nil && bytes.Equal(rec.GetDispatchTicketHash(), e.TicketHash):
				r.recordLocked(e, rec.GetRecordedHeight(), &ops, &fx)
			case err == nil:
				// Another record holds the sequence.
				r.rejectLocked(e, codeLaterSequence, true, &ops, &fx)
			default:
				r.rejectLocked(e, codeRecordLate, true, &ops, &fx)
			}
		}
		r.writeLocked(ops)
		r.mu.Unlock()
		fx.run(ctx)
	}
}

// recordLocked resolves e as admitted at height: the order leaves the ledger and the dispatcher,
// its task is reconciled and the winner notified. Caller holds r.mu.
func (r *Recorder) recordLocked(e *entry, height uint64, ops *[]kv.WriteOp, fx *effects) {
	r.removeLocked(e, ops)
	if e.Withdrawn {
		r.log.Warn("withdrawn dispatch entry recorded", "session_id", e.SessionID, "order_sequence", e.Sequence)
	}
	r.log.Info("dispatch recorded", "session_id", e.SessionID, "order_sequence", e.Sequence, "task_id", e.TaskID, "height", height)
	fx.add(func(ctx context.Context) {
		if err := r.cfg.Ledger.MarkRecorded(e.SessionID, e.Sequence); err != nil && !isUnknownOrder(err) {
			r.log.Error("record not written to the ledger", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		if err := r.orders.Recorded(e.SessionID, e.Sequence); err != nil {
			r.log.Error("record not given to the dispatcher", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		r.cfg.Attempts.Recorded(e.TaskID, [32]byte(e.TicketHash))
		r.cfg.Tasks.DispatchRecorded(e.SessionID, e.TaskID, height)
		r.notify(ctx, e, statusRecorded, 0, height)
	})
}

// rejectLocked resolves e as refused with code. A withdrawn entry is only dropped. Unless final,
// SEQUENCE_CONSUMED behind an unresolved earlier entry of the session holds e for a later
// attempt. Otherwise e and every later entry of its session fail (RECORD_REJECTED, REJECTED
// notices), the session is suspended from e's sequence and the dispatcher fails its later orders.
// Caller holds r.mu.
func (r *Recorder) rejectLocked(e *entry, code taskv1.DispatchRejectCodeV1, final bool, ops *[]kv.WriteOp, fx *effects) {
	if e.Withdrawn {
		r.removeLocked(e, ops)
		r.log.Info("withdrawn dispatch entry refused", "session_id", e.SessionID, "order_sequence", e.Sequence, "reject_code", code)
		return
	}
	if !final && code == codeLaterSequence && r.earlierUnresolvedLocked(e) {
		e.Held, e.Tx = true, ""
		*ops = append(*ops, r.entryOp(e))
		r.log.Info("dispatch entry held behind an unresolved earlier entry", "session_id", e.SessionID, "order_sequence", e.Sequence)
		return
	}
	var failed []*entry
	for _, x := range r.entries {
		if x.SessionID == e.SessionID && x.Sequence >= e.Sequence && !x.Withdrawn {
			failed = append(failed, x)
		}
	}
	sortEntries(failed)
	for _, x := range failed {
		r.removeLocked(x, ops)
	}
	r.log.Warn("dispatch record rejected; session suspended", "session_id", e.SessionID, "order_sequence", e.Sequence,
		"task_id", e.TaskID, "reject_code", code, "later_entries", len(failed)-1)
	reason := fmt.Errorf("%w: sequence %d: %s", dispatcher.ErrRecordRejected, e.Sequence, code)
	fx.add(func(ctx context.Context) {
		for _, x := range failed {
			c := codeLaterSequence
			if x == e {
				c = code
			}
			r.cfg.Attempts.Rejected(x.TaskID, [32]byte(x.TicketHash))
			r.cfg.Tasks.RecordRejected(x.SessionID, x.TaskID, c)
			r.notify(ctx, x, statusRejected, c, 0)
		}
		if err := r.cfg.Ledger.Suspend(e.SessionID, e.Sequence); err != nil {
			r.log.Error("session suspension not written to the ledger", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		r.orders.Suspend(ctx, e.SessionID, e.Sequence, reason)
	})
}

// earlierUnresolvedLocked reports whether an earlier entry of e's session is unresolved.
func (r *Recorder) earlierUnresolvedLocked(e *entry) bool {
	for _, x := range r.entries {
		if x.SessionID == e.SessionID && x.Sequence < e.Sequence && !x.Withdrawn {
			return true
		}
	}
	return false
}

func sortEntries(es []*entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].SessionID != es[j].SessionID {
			return es[i].SessionID < es[j].SessionID
		}
		return es[i].Sequence < es[j].Sequence
	})
}

func isUnknownOrder(err error) bool { return errors.Is(err, inflight.ErrUnknownOrder) }
