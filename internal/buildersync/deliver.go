package buildersync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// retry is the backoff of one member on one order. limitedSince is when the member began
// rate-limiting the order without a batch going through or failing since; limitWarned is set once
// that was warned about.
type retry struct {
	next         time.Time
	delay        time.Duration
	failingSince time.Time
	alarmed      bool
	limitedSince time.Time
	limitWarned  bool
}

// ensureWorkerLocked starts the delivery worker of a member once. Caller holds s.mu.
func (s *Sender) ensureWorkerLocked(peer string) {
	if s.ctx == nil || s.workers[peer] != nil {
		return
	}
	wake := make(chan struct{}, 1)
	s.workers[peer] = wake
	ctx := s.ctx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.cfg.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-ticker.C:
			}
			s.deliverPeer(ctx, peer)
		}
	}()
}

// wakeWorkerLocked has a member's worker look at its orders now. Caller holds s.mu.
func (s *Sender) wakeWorkerLocked(peer string) {
	if wake := s.workers[peer]; wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// deliverPeer sends a member what it is due on each of its orders.
func (s *Sender) deliverPeer(ctx context.Context, peer string) {
	s.mu.Lock()
	var keys []string
	for key, st := range s.streams {
		for _, p := range st.Peers {
			if p == peer {
				keys = append(keys, key)
			}
		}
	}
	s.mu.Unlock()
	for _, key := range keys {
		for range maxBatchesPerPass {
			if ctx.Err() != nil {
				return
			}
			if sent, ok := s.deliverOne(ctx, key, peer); !sent || !ok {
				break
			}
		}
	}
}

// plan is what one batch to one member starts from, taken under s.mu.
type plan struct {
	stream   outStream
	from, to uint64
	output   outputAck
}

// deliverOne sends a member the next batch of an order when it is due. sent reports whether a
// batch went out, ok whether the member took it.
func (s *Sender) deliverOne(ctx context.Context, key, peer string) (sent, ok bool) {
	now := s.cfg.Clock()
	s.mu.Lock()
	st := s.streams[key]
	if st == nil {
		s.mu.Unlock()
		return false, true
	}
	from, probe := st.Acked[peer]+1, st.Lost[peer]
	switch {
	case probe:
		// A member marked lost is only sent the items still held now and then: once it holds what
		// was deleted again (its store restored) it takes them and the mark is cleared.
		if now.Before(s.probes[key+"|"+peer]) || st.Pruned >= st.Last {
			s.mu.Unlock()
			return false, true
		}
		s.probes[key+"|"+peer] = now.Add(lostProbeEvery)
		from = st.Pruned + 1
	case s.retries[key+"|"+peer] != nil && now.Before(s.retries[key+"|"+peer].next):
		s.mu.Unlock()
		return false, true
	case st.Acked[peer] < st.Pruned:
		s.markLostLocked(st, peer)
		s.mu.Unlock()
		return false, false
	}
	p := plan{stream: *st.clone(), from: from, to: st.Last, output: st.Output[peer]}
	s.mu.Unlock()

	batch, err := s.batch(ctx, p, peer)
	if err != nil {
		s.failed(key, peer, err)
		return false, false
	}
	if batch == nil {
		return false, true
	}
	// Every send signs again with the current service key: a retransmission after a rotation
	// carries the new key's signature. So does each RECORDED result header in it: it carries no
	// key generation, and members check it against this Builder's current key.
	// Both are signed from one key snapshot, so a cutover in between cannot split them.
	current := s.cfg.Signer.Key()
	err = resignHeaders(current, batch)
	var req *nexusv1.SyncRequest
	if err == nil {
		req, err = SignRequest(current.Signer, batch)
	}
	if err == nil {
		callCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		var resp *nexusv1.SyncResponse
		resp, err = s.cfg.Peers.Sync(callCtx, peer, req)
		cancel()
		if err == nil {
			s.acked(key, peer, resp)
			if resp.GetRefused() != "" {
				err = fmt.Errorf("member refused: %s", resp.GetRefused())
			}
		}
	}
	if err != nil {
		if connect.CodeOf(err) == connect.CodeResourceExhausted {
			s.limited(key, peer, err)
			return true, false
		}
		if probe {
			s.failures.Add(1)
			s.log.Info("group member marked lost on an order still lacks its deleted sync items", "order", key, "member", peer, "err", err)
			return true, false
		}
		s.failed(key, peer, err)
		return true, false
	}
	s.succeeded(key, peer)
	return true, true
}

// batch builds the next batch of p for peer: the items it has not applied, then, once it gets the
// order item, the recorded winner's frames it does not hold. The signed request stays within
// MaxBatchBytes and dispatch.MaxBuilderSyncEntries items and chunks; an item or frame that cannot
// fit even alone is errOversized and nothing is sent. nil when nothing is due.
func (s *Sender) batch(ctx context.Context, p plan, peer string) (*nexusv1.BuilderSyncBatchV1, error) {
	st := &p.stream
	batch := &nexusv1.BuilderSyncBatchV1{
		SchemaVersion: schemaVersion, ChainId: s.cfg.ChainID, SenderOperatorAddress: s.cfg.Builder, ReceiverOperatorAddress: peer,
		SessionId: mustHex(st.SessionID), OrderSequence: st.Sequence, BuilderSetId: st.BuilderSetID, BuilderSetHash: st.BuilderSetHash,
	}
	size := proto.Size(batch)
	for n := p.from; n <= p.to && len(batch.Items) < dispatch.MaxBuilderSyncEntries; n++ {
		raw, found, err := s.cfg.Store.GetWithError(kv.NSBuilderSyncOutbox, outItemKey(st.key(), n))
		if err != nil {
			return nil, fmt.Errorf("read sync item %d: %w", n, err)
		}
		if !found {
			return nil, fmt.Errorf("sync item %d is no longer held; the member is behind what every member acknowledged", n)
		}
		if requestSize(size+fieldSize(len(raw))) > s.cfg.MaxBatchBytes {
			if len(batch.Items) == 0 {
				return nil, fmt.Errorf("%w: sync item %d of %d bytes", errOversized, n, len(raw))
			}
			break
		}
		var item nexusv1.BuilderSyncItemV1
		if err := proto.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("stored sync item %d: %w", n, err)
		}
		batch.Items = append(batch.Items, &item)
		size += fieldSize(len(raw))
	}
	allItems := p.from+uint64(len(batch.Items)) > p.to
	if st.Winner != nil && allItems && !p.output.Sealed && !p.output.NotHeld {
		output, err := s.output(ctx, st, p.output, size, len(batch.Items) == 0)
		if err != nil {
			return nil, err
		}
		batch.Output = output
	}
	if len(batch.Items) == 0 && batch.Output == nil {
		return nil, nil
	}
	return batch, nil
}

// fieldSize is the size of a length-delimited field of n bytes with a one-byte tag.
func fieldSize(n int) int { return 1 + protowire.SizeBytes(n) }

// requestSize is the size of a signed SyncRequest whose batch is batchSize bytes.
func requestSize(batchSize int) int { return fieldSize(batchSize) + fieldSize(dispatch.SignatureSize) }

// output is the run of the winner's frames after what the member holds that fits a batch of
// batchSize bytes. alone is set for a batch without items: a first frame that does not fit it
// cannot be sent at all (errOversized).
func (s *Sender) output(ctx context.Context, st *outStream, held outputAck, batchSize int, alone bool) (*nexusv1.BuilderSyncOutputV1, error) {
	key := taskdata.ObjectKey{SessionID: st.SessionID, TaskID: st.TaskID, Kind: taskdata.ObjectKindOutput}
	progress, found, err := s.cfg.Outputs.OutputStreamProgressOf(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("output progress: %w", err)
	}
	if !found || !progress.Received || held.Received && progress.LastSeq <= held.LastSeq && !progress.Sealed {
		return nil, nil
	}
	var after *uint64
	if held.Received {
		after = &held.LastSeq
	}
	out := &nexusv1.BuilderSyncOutputV1{
		DispatchTicketHash: st.Winner.TicketHash, WinnerTicket: &taskv1.DispatchTicketV1{}, DispatchAcceptDigest: st.Winner.AcceptDigest,
	}
	if err := proto.Unmarshal(st.Winner.Ticket, out.WinnerTicket); err != nil {
		return nil, fmt.Errorf("winner ticket: %w", err)
	}
	// outSize grows with each frame; a frame that does not fit ends the run, and the Fin only
	// follows a complete run of chunks. Only as much chunk text as the request has room for is read.
	outSize := proto.Size(out)
	room := s.cfg.MaxBatchBytes - requestSize(batchSize+fieldSize(outSize))
	frames, err := s.cfg.Outputs.OutputFramesUpTo(ctx, key, after, max(room, 1))
	if err != nil {
		return nil, fmt.Errorf("output frames: %w", err)
	}
	fits := func(frame int) bool {
		return requestSize(batchSize+fieldSize(outSize+fieldSize(frame))) <= s.cfg.MaxBatchBytes
	}
	for _, frame := range frames {
		if frame.Chunk != nil {
			if !bytes.Equal(frame.Chunk.DispatchTicketHash, st.Winner.TicketHash) {
				return nil, nil // the stored stream is not the winner's
			}
			chunk := chunkToPB(frame.Chunk)
			n := proto.Size(chunk)
			if !fits(n) && alone && len(out.Chunks) == 0 {
				return nil, fmt.Errorf("%w: output frame %d of %d bytes", errOversized, chunk.GetSeq(), n)
			}
			if len(out.Chunks) == dispatch.MaxBuilderSyncEntries || !fits(n) {
				break
			}
			out.Chunks = append(out.Chunks, chunk)
			outSize += fieldSize(n)
			continue
		}
		if frame.Fin != nil && bytes.Equal(frame.Fin.DispatchTicketHash, st.Winner.TicketHash) {
			fin := finToPB(frame.Fin)
			switch {
			case fits(proto.Size(fin)):
				out.Fin = fin
			case alone && len(out.Chunks) == 0:
				return nil, fmt.Errorf("%w: output Fin", errOversized)
			}
		}
	}
	if len(out.Chunks) == 0 && out.Fin == nil {
		return nil, nil
	}
	return out, nil
}

func chunkToPB(c *taskdata.OutputChunk) *nexusv1.OutputChunkV1 {
	return &nexusv1.OutputChunkV1{
		Seq: c.Seq, Text: c.Text, MmrRoot: c.MMRRoot, WorkerSignature: c.WorkerSignature,
		DispatchTicketHash: c.DispatchTicketHash, CumulativeGeneratedTokens: c.CumulativeGeneratedTokens,
	}
}

func finToPB(f *taskdata.OutputFin) *nexusv1.OutputFinV1 {
	return &nexusv1.OutputFinV1{
		FinalSeq: f.FinalSeq, OutputMmrRoot: f.OutputMMRRoot, FinishReason: taskv1.FinishReasonV1(f.FinishReason),
		WorkerSignature: f.WorkerSignature, DispatchTicketHash: f.DispatchTicketHash,
	}
}

// acked takes a member's answer: how far it applied the order's items and holds its output. Items
// every member applied are deleted.
func (s *Sender) acked(key, peer string, resp *nexusv1.SyncResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[key]
	if st == nil {
		return
	}
	next := st.clone()
	if resp.GetAppliedThrough() < next.Acked[peer] {
		s.log.Warn("group member holds fewer sync items than it acknowledged before", "order", key, "member", peer,
			"acknowledged", next.Acked[peer], "holds", resp.GetAppliedThrough())
	}
	next.Acked[peer] = min(resp.GetAppliedThrough(), next.Last)
	next.Output[peer] = outputAck{Received: resp.GetOutputReceived(), LastSeq: resp.GetOutputLastSeq(), Sealed: resp.GetOutputSealed(),
		NotHeld: resp.GetOutputNotHeld()}
	acked := next.Last
	for _, p := range next.Peers {
		acked = min(acked, next.Acked[p])
	}
	var ops []kv.WriteOp
	for n := next.Pruned + 1; n <= acked; n++ {
		ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncOutbox, Key: outItemKey(key, n), Delete: true})
	}
	next.Pruned = max(next.Pruned, acked)
	lost := next.Acked[peer] < next.Pruned && !next.Lost[peer]
	if lost {
		next.Lost[peer] = true
	}
	restored := next.Lost[peer] && next.Acked[peer] >= next.Pruned
	if restored {
		delete(next.Lost, peer)
	}
	op, err := streamOp(next)
	if err == nil {
		err = s.cfg.Store.WriteBatch(append(ops, op)...)
	}
	if err != nil {
		s.log.Warn("sync progress not stored; the member is sent the same items again", "order", key, "member", peer, "err", err)
		return
	}
	s.streams[key] = next
	if lost {
		s.probes[key+"|"+peer] = s.cfg.Clock().Add(lostProbeEvery)
		s.alarmLost(next, peer)
	}
	if restored {
		delete(s.probes, key+"|"+peer)
		s.log.Info("group member marked lost on an order holds its sync items again; the mark is cleared", "order", key, "member", peer)
	}
}

// markLostLocked marks a member that holds fewer items than were deleted: it lost its store and
// needs a manual resync of the order. Caller holds s.mu.
func (s *Sender) markLostLocked(st *outStream, peer string) {
	next := st.clone()
	next.Lost[peer] = true
	if op, err := streamOp(next); err == nil {
		if err := s.cfg.Store.WriteBatch(op); err != nil {
			s.log.Warn("lost member not stored", "order", st.key(), "member", peer, "err", err)
		}
	}
	s.streams[st.key()] = next
	s.probes[st.key()+"|"+peer] = s.cfg.Clock().Add(lostProbeEvery)
	s.alarmLost(next, peer)
}

// alarmLost reports a member marked lost on an order, once.
func (s *Sender) alarmLost(st *outStream, peer string) {
	s.alarms.Add(1)
	s.log.Error("group member holds fewer of an order's sync items than every member acknowledged (it lost its store): "+
		"it cannot stand in for this Builder on the order. Restore the member's data directory from a backup taken after "+
		"it held the deleted items; it is probed every 10 minutes and the mark clears once it holds them. Otherwise the "+
		"mark is dropped with the order's sync stream at the end of its retention", "order", st.key(), "member", peer,
		"holds", st.Acked[peer], "deleted_through", st.Pruned)
}

// failed counts a failed batch and backs the member off on the order; a member failing for
// longer than AlarmAfter is logged as an error once.
func (s *Sender) failed(key, peer string, err error) {
	s.failures.Add(1)
	now := s.cfg.Clock()
	s.mu.Lock()
	r := s.retries[key+"|"+peer]
	if r == nil {
		r = &retry{}
		s.retries[key+"|"+peer] = r
	}
	if r.failingSince.IsZero() { // new, or only rate-limited so far
		r.failingSince = now
	}
	r.limitedSince, r.limitWarned = time.Time{}, false
	r.delay = min(max(2*r.delay, s.cfg.RetryMin), s.cfg.RetryMax)
	r.next = now.Add(r.delay)
	alarm := !r.alarmed && now.Sub(r.failingSince) >= s.cfg.AlarmAfter
	if alarm {
		r.alarmed = true
	}
	since, delay := r.failingSince, r.delay
	s.mu.Unlock()
	s.log.Warn("sync to a group member failed; retried", "order", key, "member", peer, "retry_in", delay, "err", err)
	if alarm {
		s.alarms.Add(1)
		s.log.Error("group member has not taken an order's sync for too long: it cannot stand in for this Builder on the order",
			"order", key, "member", peer, "failing_since", since, "err", err)
	}
}

// limited leaves a member that rate-limited a batch alone on the order for RetryMin: it is busy,
// not failing, so neither the backoff of a failing member grows nor its alarm runs, and the
// member's client is kept. The batch is counted apart from failures, and a member rate-limiting
// the order for longer than AlarmAfter is warned about once.
func (s *Sender) limited(key, peer string, err error) {
	s.rateLimited.Add(1)
	s.cfg.Metrics.Inc(opsmetrics.CounterSyncRateLimited, peer)
	now := s.cfg.Clock()
	s.mu.Lock()
	r := s.retries[key+"|"+peer]
	if r == nil {
		r = &retry{}
		s.retries[key+"|"+peer] = r
	}
	if r.limitedSince.IsZero() {
		r.limitedSince = now
	}
	r.next = now.Add(s.cfg.RetryMin)
	warn := !r.limitWarned && now.Sub(r.limitedSince) >= s.cfg.AlarmAfter
	if warn {
		r.limitWarned = true
	}
	since := r.limitedSince
	s.mu.Unlock()
	if warn {
		s.log.Warn("group member has rate-limited an order's sync for longer than the alarm delay; raise its ingress.builder_sync_requests_per_second",
			"order", key, "member", peer, "limited_since", since, "err", err)
		return
	}
	s.log.Debug("group member rate-limited the sync; tried again shortly", "order", key, "member", peer, "retry_in", s.cfg.RetryMin, "err", err)
}

// succeeded clears a member's backoff on the order.
func (s *Sender) succeeded(key, peer string) {
	s.batches.Add(1)
	s.mu.Lock()
	r := s.retries[key+"|"+peer]
	delete(s.retries, key+"|"+peer)
	s.mu.Unlock()
	if r != nil && r.alarmed {
		s.log.Info("group member caught up with an order's sync", "order", key, "member", peer)
	}
}

// errOversized is an item or output frame that does not fit a sync request on its own; the member
// is backed off and warned about until the configuration changes (task_data.chunk_size_bytes is
// bounded so that a frame fits).
var errOversized = errors.New("larger than the builder sync request cap")

// errNoPeer is returned by Peers that cannot reach a member.
var errNoPeer = errors.New("group member endpoint unavailable")

// resignHeaders signs the result header of every order item of batch with the current service
// key; with an unchanged key the deterministic signature gives the same bytes.
func resignHeaders(key servicekey.Key, batch *nexusv1.BuilderSyncBatchV1) error {
	for _, item := range batch.GetItems() {
		if h := item.GetOrder().GetResultHeader(); h != nil {
			if _, err := attempt.SignResultHeader(key, h); err != nil {
				return fmt.Errorf("result header: %w", err)
			}
		}
	}
	return nil
}
