package recorder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// split cuts entries, in record order, into transactions of at most maxEntries entries and
// maxBytes encoded message bytes. base is the encoded size of a message without entries and
// sizes[i] what entry i adds to it. An entry that does not fit in a message alone is left out and
// listed in tooLarge.
func split(base int, sizes []int, maxEntries uint32, maxBytes uint64) (batches [][]int, tooLarge []int) {
	var current []int
	size := base
	for i, s := range sizes {
		if uint64(base+s) > maxBytes {
			tooLarge = append(tooLarge, i)
			continue
		}
		if len(current) > 0 && (uint32(len(current)) >= maxEntries || uint64(size+s) > maxBytes) {
			batches = append(batches, current)
			current, size = nil, base
		}
		current = append(current, i)
		size += s
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches, tooLarge
}

// pack sends the entries waiting for a block: not sent yet, not held until their sequence is the
// session's next (release) and still recordable in the next block, sorted by (session_id,
// order_sequence) and split by the params. Nothing goes out while the compensation account is
// known to be below its minimum: the chain would refuse the whole transaction.
func (r *Recorder) pack(ctx context.Context, height uint64) {
	params := r.params.Load()
	if until, why := r.stopped(height); until != 0 {
		r.log.Warn("dispatch records stopped after a refusal sending again cannot fix", "until_height", until, "reason", why)
		return
	}
	maxEntries, gasFactor := r.limits(params.MaxEntries)
	r.mu.Lock()
	var waiting []*entry
	for _, e := range r.entries {
		if e.Tx == "" && !e.Withdrawn && r.deadlineLocked(e) > height && !e.Held {
			e.packing = true
			waiting = append(waiting, e)
		}
	}
	r.mu.Unlock()
	// Whatever the sends did, the chosen entries are carried by a transaction (Tx) or waiting
	// again; one withdrawn meanwhile that no transaction carried is dropped now.
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		var ops []kv.WriteOp
		for _, e := range waiting {
			e.packing = false
			if e.Withdrawn && e.Tx == "" && r.entries[e.ObjectID] == e {
				r.removeLocked(e, &ops)
			}
		}
		r.writeLocked(ops)
	}()
	if len(waiting) == 0 {
		return
	}
	if r.cfg.Gate.belowMin() {
		r.log.Warn("dispatch entries not recorded: the compensation account is below its minimum", "entries", len(waiting))
		return
	}
	sortEntries(waiting)
	msgs := make([]*taskv1.DispatchRecordEntryV1, 0, len(waiting))
	sizes := make([]int, 0, len(waiting))
	var kept []*entry
	for _, e := range waiting {
		var m taskv1.DispatchRecordEntryV1
		if err := proto.Unmarshal(e.Entry, &m); err != nil {
			r.log.Error("stored dispatch entry does not decode", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
			continue
		}
		kept = append(kept, e)
		msgs = append(msgs, &m)
		sizes = append(sizes, proto.Size(&taskv1.MsgRecordDispatch{Entries: []*taskv1.DispatchRecordEntryV1{&m}}))
	}
	base := proto.Size(&taskv1.MsgRecordDispatch{SubmitterAddress: r.cfg.Signer.Address()})
	batches, tooLarge := split(base, sizes, maxEntries, params.MaxBytes)
	for _, i := range tooLarge {
		if e := kept[i]; !r.tooLarge[e.ObjectID] {
			r.tooLarge[e.ObjectID] = true
			r.log.Error("dispatch entry larger than max_dispatch_record_bytes; it cannot be recorded", "session_id", e.SessionID,
				"order_sequence", e.Sequence, "bytes", base+sizes[i], "max_dispatch_record_bytes", params.MaxBytes)
		}
	}
	for _, batch := range batches {
		entries := make([]*entry, len(batch))
		msg := &taskv1.MsgRecordDispatch{SubmitterAddress: r.cfg.Signer.Address()}
		for j, i := range batch {
			entries[j] = kept[i]
			msg.Entries = append(msg.Entries, msgs[i])
		}
		gas := gasFactor * (r.cfg.GasBase + r.cfg.GasPerEntry*uint64(len(entries)))
		r.submit(ctx, height, msg, entries, gas)
	}
}

// submit signs and broadcasts one record transaction. Each signed transaction is stored, and its
// entries point at it, before it is broadcast. A transaction refused before it reached the
// mempool is dropped and its entries wait for the next block; one whose broadcast outcome is
// unknown is followed on chain.
func (r *Recorder) submit(ctx context.Context, height uint64, msg *taskv1.MsgRecordDispatch, entries []*entry, gasLimit uint64) {
	objects := make([]string, len(entries))
	for i, e := range entries {
		objects[i] = e.ObjectID
	}
	var current string
	persist := func(raw []byte) error {
		sum := sha256.Sum256(raw)
		tx := &txRecord{Hash: hex.EncodeToString(sum[:]), Raw: append([]byte(nil), raw...), Objects: objects, SentHeight: height}
		r.mu.Lock()
		defer r.mu.Unlock()
		op, err := putOp(txKey(tx.Hash), tx)
		if err != nil {
			return err
		}
		ops := []kv.WriteOp{op}
		if current != "" {
			ops = append(ops, deleteOp(txKey(current)))
		}
		var carried []*entry
		for _, id := range objects {
			if e := r.entries[id]; e != nil && (e.Tx == "" || e.Tx == current) {
				updated := *e
				updated.Tx, updated.Held = tx.Hash, false
				op, err := putOp(entryKey(e.ObjectID), &updated)
				if err != nil {
					return err
				}
				ops = append(ops, op)
				carried = append(carried, e)
			}
		}
		if err := r.cfg.Store.WriteBatch(ops...); err != nil {
			return fmt.Errorf("store record transaction: %w", err)
		}
		delete(r.txs, current)
		r.txs[tx.Hash] = tx
		for _, e := range carried {
			e.Tx, e.Held = tx.Hash, false
		}
		current = tx.Hash
		return nil
	}
	_, err := r.cfg.Tx.SubmitRecordDispatch(ctx, msg, gasLimit, persist)
	if err == nil {
		r.broadcast(objects)
		r.log.Info("record transaction broadcast", "tx_hash", current, "entries", len(entries), "height", height)
		return
	}
	var se *coordinator.SubmissionError
	if errors.As(err, &se) && se.Phase == coordinator.SubmissionBroadcast && !se.Definitive && current != "" {
		r.broadcast(objects)
		r.log.Warn("record transaction broadcast outcome unknown; following it on chain", "tx_hash", current, "err", err)
		return
	}
	r.log.Warn("record transaction not sent; its entries go out at the next block", "entries", len(entries), "err", err)
	if errors.As(err, &se) && se.Definitive && se.Result.Code != 0 {
		r.refused(se.Result, len(entries), height)
	}
	if current != "" {
		r.requeue(current)
	}
}

// broadcast times the first broadcast of each entry of this run since it was handed over.
func (r *Recorder) broadcast(objects []string) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range objects {
		if _, live := r.entries[id]; !live {
			continue
		}
		if _, sent := r.sentAt[id]; sent {
			continue
		}
		r.sentAt[id] = now
		if at, ok := r.queuedAt[id]; ok {
			r.cfg.Metrics.ObserveStage(opsmetrics.StageAcceptToRecordSubmit, now.Sub(at))
		}
	}
}
