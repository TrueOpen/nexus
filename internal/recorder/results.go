package recorder

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

const (
	// rebroadcastAfterBlocks is how many blocks a transaction the chain does not show waits before
	// it is broadcast again.
	rebroadcastAfterBlocks = 2
	// codeTxInMempoolCache is cosmos-sdk's refusal of a transaction already in the mempool.
	codeTxInMempoolCache = 19

	statusRecorded = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED
	statusRejected = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED
	// codeSequenceConsumed retires a sequence: it is behind the session's next expected sequence,
	// or another record holds it. codeSequenceNotNext is an entry ahead of the next expected
	// sequence: not consumed, it goes again at the same sequence once the earlier ones are
	// recorded.
	codeSequenceConsumed = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_CONSUMED
	codeSequenceNotNext  = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_NOT_NEXT
	codeRecordLate       = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
	codeConflict         = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_CONFLICT
	// codeCascaded is the rejection category a later entry of a refused one is reported with, to its
	// task and its Worker: its sequence was not consumed, and the client resends the same sequence.
	codeCascaded = codeConflict
	// outcomeCascaded is the record outcome metric label of such a later entry, apart from the
	// chain's own rejection codes.
	outcomeCascaded = "CASCADED"
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
			// Refused as a whole: no entry has a result, so all of them go out again, sized or
			// held back by what the refusal says.
			r.log.Warn("record transaction refused by the chain", "tx_hash", tx.Hash,
				"code", res.Code, "codespace", res.Codespace, "raw_log", res.RawLog)
			r.cfg.Gate.markStale()
			r.refused(res, len(tx.Objects), height)
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
		if e.Tx == hash && r.deadlineLocked(e) > height {
			return true
		}
	}
	return false
}

// requeue drops a transaction that will not land: its unresolved entries wait for the next block;
// a withdrawn takeover entry of it is dropped.
func (r *Recorder) requeue(hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ops := []kv.WriteOp{deleteOp(txKey(hash))}
	delete(r.txs, hash)
	for _, e := range r.entries {
		switch {
		case e.Tx != hash:
		case e.Takeover && e.Withdrawn:
			r.removeLocked(e, &ops)
		default:
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
	resp, mismatched, err := chaincli.DecodeRecordDispatchResults(res, 0, r.cfg.ChainID, ids)
	// Only a takeover entry's key may legitimately differ (it commits to the binding generation
	// when it was sent); any other mismatch leaves no result attributable.
	unattributed := map[int]bool{}
	r.mu.Lock()
	for _, i := range mismatched {
		if e := r.entries[tx.Objects[i]]; e != nil && !e.Takeover {
			err = fmt.Errorf("result %d object_id is not the key of its dispatch entry", i)
		}
		unattributed[i] = true
	}
	r.mu.Unlock()
	if err != nil {
		r.log.Error("record results do not match the entries sent; checking each entry on chain", "tx_hash", tx.Hash, "err", err)
		if r.verifyByQuery(ctx, tx) {
			// Every entry is recorded with its own ticket: the chain executed the batch and only
			// the result encoding failed, which no smaller batch or pause would change.
			r.succeeded()
		} else {
			r.unattributable(len(tx.Objects), uint64(res.Height), err.Error())
		}
		return
	}
	r.succeeded()
	var fx effects
	var replays, conflicts []string
	r.mu.Lock()
	var ops []kv.WriteOp
	for i, item := range resp.GetResults() {
		e := r.entries[tx.Objects[i]]
		if e == nil {
			continue
		}
		switch rejected := item.GetStatus() == sharedv1.MutationStatusV1_MUTATION_STATUS_V1_REJECTED; {
		case unattributed[i]:
			r.takeoverUnsettledLocked(e, &ops, &fx)
		case e.Takeover && rejected:
			r.takeoverRefusedLocked(e, item.GetRejectCode(), &ops, &fx)
		case e.Takeover:
			// Applied, or the exact replay of the registration: either way it is registered.
			r.takeoverRegisteredLocked(e, uint64(res.Height), &ops, &fx)
		case item.GetStatus() == sharedv1.MutationStatusV1_MUTATION_STATUS_V1_NOOP:
			replays = append(replays, e.ObjectID)
		case item.GetRejectCode() == codeConflict:
			conflicts = append(conflicts, e.ObjectID)
		case rejected:
			r.rejectLocked(e, item.GetRejectCode(), false, &ops, &fx)
		default:
			r.recordLocked(e, uint64(res.Height), &ops, &fx)
		}
	}
	r.dropTxLocked(tx.Hash, &ops)
	r.writeLocked(ops)
	r.mu.Unlock()
	fx.run(ctx)
	for _, id := range replays {
		r.resolveReplay(ctx, id, uint64(res.Height))
	}
	for _, id := range conflicts {
		r.resolveConflict(ctx, id)
	}
}

// resolveReplay records an entry the chain answered as an exact replay of its first admission, at
// the height of that admission when the record query has it, else at the replay's.
func (r *Recorder) resolveReplay(ctx context.Context, id string, replayHeight uint64) {
	e := r.lookup(id)
	if e == nil {
		return
	}
	height := replayHeight
	if rec, err := r.cfg.Chain.QueryDispatchRecordByOrder(ctx, e.SessionID, e.Sequence); err == nil && bytes.Equal(rec.GetDispatchTicketHash(), e.TicketHash) {
		height = rec.GetRecordedHeight()
	}
	var fx effects
	r.mu.Lock()
	var ops []kv.WriteOp
	if e = r.entries[id]; e != nil {
		r.recordLocked(e, height, &ops, &fx)
	}
	r.writeLocked(ops)
	r.mu.Unlock()
	fx.run(ctx)
}

// resolveConflict takes a CONFLICT refusal: the order is recorded with another entry. A record of
// this Builder means the order is recorded: with e's own ticket e is recorded; with another of
// this Builder's tickets for it the order is, and e's Worker is told its ticket lost. A record of
// another Builder, or none readable, fails e as refused. An unreadable chain keeps e for the next
// attempt.
func (r *Recorder) resolveConflict(ctx context.Context, id string) {
	e := r.lookup(id)
	if e == nil {
		return
	}
	rec, err := r.cfg.Chain.QueryDispatchRecordByOrder(ctx, e.SessionID, e.Sequence)
	if err != nil && !isNotFound(err) {
		r.log.Warn("dispatch record of a conflicting entry not read; it goes out again", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		return
	}
	var fx effects
	r.mu.Lock()
	var ops []kv.WriteOp
	if e = r.entries[id]; e != nil {
		switch {
		case err == nil && bytes.Equal(rec.GetDispatchTicketHash(), e.TicketHash):
			r.recordLocked(e, rec.GetRecordedHeight(), &ops, &fx)
		case err == nil && rec.GetBuilderAddress() == r.cfg.Builder:
			r.recordedByAnotherTicketLocked(e, rec, &ops, &fx)
		default:
			r.rejectLocked(e, codeConflict, true, &ops, &fx)
		}
	}
	r.writeLocked(ops)
	r.mu.Unlock()
	fx.run(ctx)
}

// recordedByAnotherTicketLocked resolves e whose order the chain recorded with another ticket of
// this Builder: the order leaves the ledger and the dispatcher and its task is reconciled; e's
// Worker hears its ticket was not recorded. Caller holds r.mu.
func (r *Recorder) recordedByAnotherTicketLocked(e *entry, rec *taskv1.DispatchRecordState, ops *[]kv.WriteOp, fx *effects) {
	r.removeLocked(e, ops)
	height := rec.GetRecordedHeight()
	r.log.Warn("order recorded with another ticket of this Builder", "session_id", e.SessionID, "order_sequence", e.Sequence,
		"recorded_ticket", hex.EncodeToString(rec.GetDispatchTicketHash()))
	fx.add(func(ctx context.Context) {
		if err := r.cfg.Ledger.MarkRecorded(e.SessionID, e.Sequence); err != nil && !isUnknownOrder(err) {
			r.log.Error("record not written to the ledger", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		if err := r.orders.Recorded(e.SessionID, e.Sequence, height); err != nil {
			r.log.Error("record not given to the dispatcher", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		// The attempt book takes the recorded ticket (one a binding change voided comes back) and
		// then e's ticket is rejected: a no-op once the recorded ticket replaced it, and otherwise
		// it does not stay PENDING with subscribers waiting on it.
		var recorded [32]byte
		copy(recorded[:], rec.GetDispatchTicketHash())
		r.cfg.Attempts.Recorded(e.TaskID, recorded)
		r.cfg.Attempts.Rejected(e.TaskID, [32]byte(e.TicketHash))
		r.cfg.Tasks.DispatchRecorded(e.SessionID, e.TaskID, height)
		r.notify(ctx, e, statusRejected, codeConflict, 0)
	})
}

func (r *Recorder) lookup(id string) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[id]
}

// verifyByQuery resolves the entries of a transaction whose results could not be attributed: an
// entry the chain recorded with its winner ticket is recorded; one whose order the chain recorded
// with another ticket of this Builder is resolved as with a CONFLICT; any other goes out again. A
// takeover entry is dropped and the takeovers settle it with the chain. It reports whether every
// entry still held was recorded with its own ticket.
func (r *Recorder) verifyByQuery(ctx context.Context, tx txRecord) bool {
	allRecorded, checked := true, 0
	for _, id := range tx.Objects {
		r.mu.Lock()
		e := r.entries[id]
		var session string
		var seq uint64
		if e != nil && e.Takeover {
			allRecorded = false
			var fx effects
			var ops []kv.WriteOp
			r.takeoverUnsettledLocked(e, &ops, &fx)
			r.writeLocked(ops)
			r.mu.Unlock()
			fx.run(ctx)
			continue
		}
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
			checked++
			own := err == nil && bytes.Equal(rec.GetDispatchTicketHash(), e.TicketHash)
			allRecorded = allRecorded && own
			if own {
				r.recordLocked(e, rec.GetRecordedHeight(), &ops, &fx)
			} else if err == nil && rec.GetBuilderAddress() == r.cfg.Builder {
				r.recordedByAnotherTicketLocked(e, rec, &ops, &fx)
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
	return allRecorded && checked > 0
}

func (r *Recorder) dropTxLocked(hash string, ops *[]kv.WriteOp) {
	delete(r.txs, hash)
	*ops = append(*ops, deleteOp(txKey(hash)))
	for _, e := range r.entries {
		switch {
		case e.Tx != hash:
		case e.Takeover && e.Withdrawn:
			r.removeLocked(e, ops)
		default:
			e.Tx = ""
			*ops = append(*ops, r.entryOp(e))
		}
	}
}

// expire resolves the entries past their record deadline with the dispatch record query: recorded
// with their winner ticket, they are recorded; otherwise the chain can no longer admit them and
// they are RECORD_LATE. An unreadable chain decides nothing. A takeover entry past its deadline
// lapses: the Takeovers read the session.
func (r *Recorder) expire(ctx context.Context, height uint64) {
	r.mu.Lock()
	var due []*entry
	var lapsed effects
	var lapsedOps []kv.WriteOp
	for _, e := range r.entries {
		switch {
		case height <= r.deadlineLocked(e):
		case e.Takeover:
			r.takeoverLapsedLocked(e, &lapsedOps, &lapsed)
		default:
			due = append(due, e)
		}
	}
	r.writeLocked(lapsedOps)
	r.mu.Unlock()
	lapsed.run(ctx)
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
				r.rejectLocked(e, codeSequenceConsumed, true, &ops, &fx)
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
// its task is reconciled and the winner notified. A withdrawn entry the chain admitted anyway is
// resolved the same way: it is the order's record, so the dispatcher ends the new round it opened
// and the attempt book takes the voided ticket back as the task's recorded attempt (never the new
// round's ticket). Caller holds r.mu.
func (r *Recorder) recordLocked(e *entry, height uint64, ops *[]kv.WriteOp, fx *effects) {
	if at, ok := r.sentAt[e.ObjectID]; ok {
		r.cfg.Metrics.ObserveStage(opsmetrics.StageRecordToAdmitted, time.Since(at))
	}
	r.cfg.Metrics.Inc(opsmetrics.CounterRecordOutcomes, "ADMITTED")
	r.removeLocked(e, ops)
	if e.Withdrawn {
		r.log.Warn("withdrawn dispatch entry recorded: it is the order's record", "session_id", e.SessionID, "order_sequence", e.Sequence, "height", height)
	} else {
		r.log.Info("dispatch recorded", "session_id", e.SessionID, "order_sequence", e.Sequence, "task_id", e.TaskID, "height", height)
	}
	fx.add(func(ctx context.Context) {
		if err := r.cfg.Ledger.MarkRecorded(e.SessionID, e.Sequence); err != nil && !isUnknownOrder(err) {
			r.log.Error("record not written to the ledger", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		if err := r.orders.Recorded(e.SessionID, e.Sequence, height); err != nil {
			r.log.Error("record not given to the dispatcher", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		if e.Withdrawn && r.cfg.Evidence != nil {
			// The dispatcher already let the order go: its evidence is marked here.
			if err := r.cfg.Evidence.MarkRecorded(e.TicketHash, height); err != nil {
				r.log.Error("evidence of a recorded entry not marked recorded", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
			}
		}
		r.cfg.Attempts.Recorded(e.TaskID, [32]byte(e.TicketHash))
		r.cfg.Tasks.DispatchRecorded(e.SessionID, e.TaskID, height)
		r.notify(ctx, e, statusRecorded, 0, height)
	})
}

// rejectLocked resolves e as refused with code. A withdrawn entry is only dropped. Unless final,
// SEQUENCE_NOT_NEXT behind an unresolved earlier entry of the session holds e for a later attempt
// at the same sequence. Otherwise e and every later entry of its session fail (RECORD_REJECTED,
// REJECTED notices), the session is suspended from e's sequence and the dispatcher fails its later
// orders. SEQUENCE_CONSUMED is always final: the sequence is retired.
// Caller holds r.mu.
func (r *Recorder) rejectLocked(e *entry, code taskv1.DispatchRejectCodeV1, final bool, ops *[]kv.WriteOp, fx *effects) {
	if e.Withdrawn {
		r.removeLocked(e, ops)
		r.log.Info("withdrawn dispatch entry refused", "session_id", e.SessionID, "order_sequence", e.Sequence, "reject_code", code)
		return
	}
	if !final && code == codeSequenceNotNext && r.earlierUnresolvedLocked(e) {
		e.Held, e.Tx = true, ""
		*ops = append(*ops, r.entryOp(e))
		r.log.Info("dispatch entry held behind an unresolved earlier entry", "session_id", e.SessionID, "order_sequence", e.Sequence)
		return
	}
	if code == codeSequenceConsumed && r.earlierUnresolvedLocked(e) {
		// The sequence is retired although an earlier one of the session is not recorded: the
		// chain says the next expected sequence is past it.
		r.log.Warn("dispatch entry refused SEQUENCE_CONSUMED while an earlier entry of its session is unresolved",
			"session_id", e.SessionID, "order_sequence", e.Sequence)
	}
	var failed []*entry
	for _, x := range r.entries {
		if x.SessionID == e.SessionID && x.Sequence >= e.Sequence && !x.Withdrawn && !x.Takeover {
			failed = append(failed, x)
		}
	}
	sortEntries(failed)
	for _, x := range failed {
		r.removeLocked(x, ops)
		outcome := outcomeCascaded
		if x == e {
			outcome = strings.TrimPrefix(code.String(), "DISPATCH_REJECT_CODE_V1_")
		}
		r.cfg.Metrics.Inc(opsmetrics.CounterRecordOutcomes, outcome)
	}
	r.log.Warn("dispatch record rejected; session suspended", "session_id", e.SessionID, "order_sequence", e.Sequence,
		"task_id", e.TaskID, "reject_code", code, "later_entries", len(failed)-1)
	reason := fmt.Errorf("%w: sequence %d: %s", dispatcher.ErrRecordRejected, e.Sequence, code)
	fx.add(func(ctx context.Context) {
		// Suspended first: a resend the task's RECORD_REJECTED prompts must find the suspension
		// it lifts.
		if err := r.cfg.Ledger.Suspend(e.SessionID, e.Sequence); err != nil {
			r.log.Error("session suspension not written to the ledger", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		}
		r.orders.Suspend(ctx, e.SessionID, e.Sequence, reason)
		for _, x := range failed {
			c := codeCascaded
			if x == e {
				c = code
			}
			r.cfg.Attempts.Rejected(x.TaskID, [32]byte(x.TicketHash))
			r.cfg.Tasks.RecordRejected(x.SessionID, x.TaskID, [32]byte(x.TicketHash), c)
			r.notify(ctx, x, statusRejected, c, 0)
		}
	})
}

// earlierUnresolvedLocked reports whether an earlier entry of e's session is unresolved.
func (r *Recorder) earlierUnresolvedLocked(e *entry) bool {
	for _, x := range r.entries {
		if x.SessionID == e.SessionID && x.Sequence < e.Sequence && !x.Withdrawn && !x.Takeover {
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
