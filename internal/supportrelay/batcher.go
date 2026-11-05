package supportrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// hubCodespace is the codespace of the Hub module's errors: a batch the Hub handler refused
// failed on one of its confirmations (or on the epoch it names), not on the transaction.
const hubCodespace = "hub"

// maxGasFactor bounds how far a single confirmation's gas limit is doubled after running out.
const maxGasFactor = 4

// slot is a held confirmation under its store key.
type slot struct {
	key string
	e   *entry
}

// Start begins the batching loop: every FlushInterval, or as soon as FlushItems confirmations are
// held, the held confirmations are rechecked and the valid ones sent.
func (r *Relay) Start(context.Context) error {
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-r.stop
		cancel()
	}()
	go r.run(ctx)
	return nil
}

// Stop ends the batching loop. Held confirmations stay in the store for the next run.
func (r *Relay) Stop(context.Context) error {
	if r.stop == nil {
		return nil
	}
	close(r.stop)
	<-r.done
	r.stop = nil
	return nil
}

func (r *Relay) run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.kick:
		}
		r.flush(ctx)
	}
}

// flush settles what the chain decided, retires what can no longer be included, and sends the
// rest of the current epoch in batches within the Hub limits.
func (r *Relay) flush(ctx context.Context) {
	held := r.snapshot()
	if len(held) == 0 {
		return
	}
	v, err := r.readView(ctx)
	if err != nil {
		r.log.Warn("support relay: chain state unavailable, batches wait", "err", err)
		return
	}
	var ready []slot
	for _, s := range held {
		r.resolveTxs(ctx, s.key)
		e, ok := r.get(s.key)
		if !ok {
			continue
		}
		if r.settle(ctx, v, slot{key: s.key, e: e}) {
			ready = append(ready, slot{key: s.key, e: e})
		}
	}
	for _, batch := range r.pack(v, ready) {
		r.send(ctx, v, batch, 1)
	}
}

// settle decides a held confirmation against v and reports whether it should be sent now. One the
// chain holds is done. One that is no longer valid is retired once a DailySupport read made after
// the check found no row, and only when no transaction already sent can still get it accepted:
// none is in flight, or the chain refuses it from now on (its epoch ended, its expiry passed, its
// key or nonce changed).
func (r *Relay) settle(ctx context.Context, v view, s slot) bool {
	var invalid error
	switch {
	case s.e.Epoch > v.epoch:
		return false // the chain read lags the one that accepted it
	case s.e.Epoch < v.epoch:
		invalid = fmt.Errorf("%w: epoch %d ended: %w", ErrStale, s.e.Epoch, errChainRefuses)
	default:
		_, invalid = r.check(ctx, v, s.e.Epoch, s.e.c)
	}
	if errors.Is(invalid, ErrUnavailable) {
		r.log.Warn("support relay: cannot recheck a confirmation now", "operator", s.e.c.Operator, "epoch", s.e.Epoch, "err", invalid)
		return false
	}
	row, err := r.chain.QueryDailySupport(ctx, s.e.c.Operator, s.e.Epoch)
	switch {
	case err == nil:
		if sameMaterial(row, s.e.c) {
			r.drop(s.key, "accepted on chain")
		} else {
			r.drop(s.key, "the chain accepted other material for its operator and epoch")
		}
		return false
	case !errors.Is(err, chaincli.ErrNotFound):
		r.log.Warn("support relay: cannot read daily support", "operator", s.e.c.Operator, "epoch", s.e.Epoch, "err", err)
		return false
	}
	if invalid == nil && !s.e.Rejected {
		return true
	}
	if s.e.inFlight() && !errors.Is(invalid, errChainRefuses) {
		return false
	}
	reason := "the chain refused it"
	if invalid != nil {
		reason = invalid.Error()
	}
	r.drop(s.key, reason)
	return false
}

// pack orders confirmations by operator address bytes and cuts them into batches within the Hub's
// confirmation, model item and byte limits. Every confirmation passed the limits on its own.
func (r *Relay) pack(v view, ready []slot) [][]slot {
	sort.Slice(ready, func(i, j int) bool { return bytes.Compare(ready[i].e.c.OperatorRaw, ready[j].e.c.OperatorRaw) < 0 })
	var batches [][]slot
	var current []slot
	models := 0
	for _, s := range ready {
		n := len(s.e.c.Models)
		if len(current) > 0 {
			next := append(slices.Clone(current), s)
			if len(next) > int(v.params.MaxConfirmationsPerBatch) || uint64(models+n) > uint64(v.params.MaxItemsPerBatch) ||
				uint64(r.batchBytes(v.epoch, confirmations(next))) > v.params.MaxBatchBytes {
				batches = append(batches, current)
				current, models = nil, 0
			}
		}
		current = append(current, s)
		models += n
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

func confirmations(batch []slot) []Confirmation {
	out := make([]Confirmation, len(batch))
	for i, s := range batch {
		out[i] = s.e.c
	}
	return out
}

// send signs and broadcasts one batch and waits for its block result. A confirmation is settled
// only by its DailySupport row, never by the broadcast; a refused batch has its failing
// confirmations isolated.
func (r *Relay) send(ctx context.Context, v view, batch []slot, gasFactor uint64) {
	models := 0
	for _, s := range batch {
		models += len(s.e.c.Models)
	}
	gas := (r.cfg.GasBase + r.cfg.GasPerConfirmation*uint64(len(batch)) + r.cfg.GasPerModel*uint64(models)) * gasFactor
	res, err := r.submit.SubmitBatchConfirmModelSupport(ctx, r.batchMsg(v.epoch, confirmations(batch)), gas)
	if err != nil && res.Code == 0 {
		// No verdict: the transaction may still have reached the mempool.
		r.markSent(batch, res.TxHash)
		r.log.Warn("support relay: batch broadcast failed, kept for the next round", "confirmations", len(batch), "err", err)
		return
	}
	if err != nil {
		r.refused(ctx, batch, res, gasFactor)
		return
	}
	r.markSent(batch, res.TxHash)
	r.log.Info("support relay: batch broadcast", "epoch", v.epoch, "confirmations", len(batch), "models", models,
		"tx_hash", hex.EncodeToString(res.TxHash))
	result, err := chaincli.WaitTx(ctx, r.log, r.chain, res.TxHash, r.cfg.TxWait)
	if err != nil {
		r.log.Warn("support relay: batch result unknown, rechecked next round", "tx_hash", hex.EncodeToString(res.TxHash), "err", err)
		return
	}
	r.resolved(batch, res.TxHash)
	if result.Code != 0 {
		r.refused(ctx, batch, result, gasFactor)
		return
	}
	for _, s := range batch {
		row, err := r.chain.QueryDailySupport(ctx, s.e.c.Operator, v.epoch)
		if err == nil && sameMaterial(row, s.e.c) {
			r.drop(s.key, "accepted on chain")
		}
	}
}

// refused handles a batch the chain did not execute. A Hub refusal of a single confirmation marks
// it rejected; of several, or running out of gas, splits the batch and sends each half again
// after rechecking it. Any other refusal concerns the transaction, not the confirmations, which
// wait for the next round.
func (r *Relay) refused(ctx context.Context, batch []slot, res chaincli.TxResult, gasFactor uint64) {
	switch {
	case len(batch) > 1 && (res.Codespace == hubCodespace || chaincli.IsOutOfGas(res)):
		half := len(batch) / 2
		r.resend(ctx, batch[:half])
		r.resend(ctx, batch[half:])
	case chaincli.IsOutOfGas(res) && gasFactor < maxGasFactor:
		v, err := r.readView(ctx)
		if err != nil {
			return
		}
		if r.settle(ctx, v, batch[0]) {
			r.send(ctx, v, batch, gasFactor*2)
		}
	case res.Codespace == hubCodespace:
		s := batch[0]
		r.log.Warn("support relay: the chain refused a confirmation", "operator", s.e.c.Operator, "epoch", s.e.Epoch,
			"code", res.Code, "raw_log", chaincli.TruncateRawLog(res.RawLog))
		r.update(s.key, func(e *entry) { e.Rejected = true })
		if e, ok := r.get(s.key); ok {
			if v, err := r.readView(ctx); err == nil {
				r.settle(ctx, v, slot{key: s.key, e: e})
			}
		}
	default:
		r.log.Warn("support relay: batch refused, kept for the next round", "confirmations", len(batch),
			"code", res.Code, "codespace", res.Codespace, "raw_log", chaincli.TruncateRawLog(res.RawLog))
	}
}

// resend rechecks part of a refused batch against fresh chain state and sends what is still valid.
func (r *Relay) resend(ctx context.Context, part []slot) {
	v, err := r.readView(ctx)
	if err != nil {
		return
	}
	var ready []slot
	for _, s := range part {
		e, ok := r.get(s.key)
		if !ok {
			continue
		}
		if r.settle(ctx, v, slot{key: s.key, e: e}) {
			ready = append(ready, slot{key: s.key, e: e})
		}
	}
	for _, batch := range r.pack(v, ready) {
		r.send(ctx, v, batch, 1)
	}
}

// resolveTxs forgets the sent batches of a held confirmation whose block result is now known.
func (r *Relay) resolveTxs(ctx context.Context, key string) {
	e, ok := r.get(key)
	if !ok || len(e.TxHashes) == 0 {
		return
	}
	var known [][]byte
	for _, hash := range e.TxHashes {
		if _, err := r.chain.QueryTx(ctx, hash); err == nil {
			known = append(known, hash)
		}
	}
	if len(known) > 0 {
		r.update(key, func(e *entry) {
			e.TxHashes = slices.DeleteFunc(e.TxHashes, func(h []byte) bool {
				return slices.ContainsFunc(known, func(k []byte) bool { return bytes.Equal(h, k) })
			})
		})
	}
}

// markSent records a batch that may be in flight; without a hash it cannot be looked up.
func (r *Relay) markSent(batch []slot, txHash []byte) {
	for _, s := range batch {
		r.update(s.key, func(e *entry) {
			if len(txHash) == 0 {
				e.Blind = true
				return
			}
			e.TxHashes = append(e.TxHashes, append([]byte(nil), txHash...))
		})
	}
}

func (r *Relay) resolved(batch []slot, txHash []byte) {
	for _, s := range batch {
		r.update(s.key, func(e *entry) {
			e.TxHashes = slices.DeleteFunc(e.TxHashes, func(h []byte) bool { return bytes.Equal(h, txHash) })
		})
	}
}

// snapshot copies the held confirmations in key order.
func (r *Relay) snapshot() []slot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]slot, 0, len(r.entries))
	for key, e := range r.entries {
		out = append(out, slot{key: key, e: e.clone()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func (r *Relay) get(key string) (*entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return nil, false
	}
	return e.clone(), true
}

// update changes a held confirmation and stores it; a failed write keeps the old state.
func (r *Relay) update(key string, change func(*entry)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return
	}
	next := e.clone()
	change(next)
	if err := r.save(key, next); err != nil {
		r.log.Error("support relay: cannot store a confirmation", "key", key, "err", err)
		return
	}
	r.entries[key] = next
}

// drop retires a held confirmation.
func (r *Relay) drop(key, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return
	}
	if err := r.store.Delete(kv.NSSupportRelay, key); err != nil {
		r.log.Error("support relay: cannot remove a confirmation", "key", key, "err", err)
		return
	}
	delete(r.entries, key)
	r.log.Info("support relay: confirmation settled", "operator", e.c.Operator, "epoch", e.Epoch, "reason", reason)
}

// Held reports how many confirmations are held.
func (r *Relay) Held() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
