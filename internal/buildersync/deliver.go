package buildersync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// retry is the backoff of one member on one order.
type retry struct {
	next         time.Time
	delay        time.Duration
	failingSince time.Time
	alarmed      bool
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
	if r := s.retries[key+"|"+peer]; r != nil && now.Before(r.next) || st.Lost[peer] {
		s.mu.Unlock()
		return false, true
	}
	if st.Acked[peer] < st.Pruned {
		s.markLostLocked(st, peer)
		s.mu.Unlock()
		return false, false
	}
	p := plan{stream: *st.clone(), from: st.Acked[peer] + 1, to: st.Last, output: st.Output[peer]}
	s.mu.Unlock()

	batch, err := s.batch(ctx, p, peer)
	if err != nil {
		s.failed(key, peer, err)
		return false, false
	}
	if batch == nil {
		return false, true
	}
	raw, err := marshal(batch)
	if err == nil {
		var sig []byte
		if sig, err = SignBatch(s.cfg.Signer, s.cfg.ChainID, s.cfg.Builder, raw); err == nil {
			callCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
			var resp *buildersyncv1.SyncResponse
			resp, err = s.cfg.Peers.Sync(callCtx, peer, &buildersyncv1.SyncRequest{Batch: raw, SenderSignature: sig})
			cancel()
			if err == nil {
				s.acked(key, peer, resp)
				if resp.GetRefused() != "" {
					err = fmt.Errorf("member refused: %s", resp.GetRefused())
				}
			}
		}
	}
	if err != nil {
		s.failed(key, peer, err)
		return true, false
	}
	s.succeeded(key, peer)
	return true, true
}

// batch builds the next batch of p for peer: the items it has not applied, then, once it gets the
// order item, the recorded winner's frames it does not hold. nil when nothing is due.
func (s *Sender) batch(ctx context.Context, p plan, peer string) (*buildersyncv1.BuilderSyncBatchV1, error) {
	st := &p.stream
	batch := &buildersyncv1.BuilderSyncBatchV1{
		SchemaVersion: schemaVersion, ChainId: s.cfg.ChainID, SenderOperatorAddress: s.cfg.Builder, ReceiverOperatorAddress: peer,
		SessionId: mustHex(st.SessionID), OrderSequence: st.Sequence, BuilderSetId: st.BuilderSetID, BuilderSetHash: st.BuilderSetHash,
	}
	size := 0
	for n := p.from; n <= p.to; n++ {
		raw, found, err := s.cfg.Store.GetWithError(kv.NSBuilderSyncOutbox, outItemKey(st.key(), n))
		if err != nil {
			return nil, fmt.Errorf("read sync item %d: %w", n, err)
		}
		if !found {
			return nil, fmt.Errorf("sync item %d is no longer held; the member is behind what every member acknowledged", n)
		}
		if len(batch.Items) > 0 && size+len(raw) > s.cfg.MaxBatchBytes {
			break
		}
		var item buildersyncv1.BuilderSyncItemV1
		if err := proto.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("stored sync item %d: %w", n, err)
		}
		batch.Items = append(batch.Items, &item)
		size += len(raw)
	}
	allItems := p.from+uint64(len(batch.Items)) > p.to
	if st.Winner != nil && allItems && !p.output.Sealed && !p.output.NotHeld {
		output, err := s.output(ctx, st, p.output, size)
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

// output is the run of the winner's frames after what the member holds, within the batch size.
func (s *Sender) output(ctx context.Context, st *outStream, held outputAck, size int) (*buildersyncv1.BuilderSyncOutputV1, error) {
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
	frames, err := s.cfg.Outputs.OutputFramesUpTo(ctx, key, after, max(s.cfg.MaxBatchBytes-size, 1))
	if err != nil {
		return nil, fmt.Errorf("output frames: %w", err)
	}
	out := &buildersyncv1.BuilderSyncOutputV1{
		DispatchTicketHash: st.Winner.TicketHash, WinnerTicket: st.Winner.Ticket, DispatchAcceptDigest: st.Winner.AcceptDigest,
	}
	for _, frame := range frames {
		if frame.Chunk != nil {
			if !bytes.Equal(frame.Chunk.DispatchTicketHash, st.Winner.TicketHash) {
				return nil, nil // the stored stream is not the winner's
			}
			if size > 0 && size+len(frame.Chunk.Text) > s.cfg.MaxBatchBytes {
				break
			}
			size += len(frame.Chunk.Text)
			out.Chunks = append(out.Chunks, chunkToPB(frame.Chunk))
			continue
		}
		if frame.Fin != nil && bytes.Equal(frame.Fin.DispatchTicketHash, st.Winner.TicketHash) {
			out.Fin = finToPB(frame.Fin)
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
func (s *Sender) acked(key, peer string, resp *buildersyncv1.SyncResponse) {
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
		s.alarmLost(next, peer)
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
	s.alarmLost(next, peer)
}

// alarmLost reports a member marked lost on an order, once.
func (s *Sender) alarmLost(st *outStream, peer string) {
	s.alarms.Add(1)
	s.log.Error("group member holds fewer of an order's sync items than every member acknowledged (it lost its store); "+
		"the outbox cannot catch it up and it needs a manual resync of the order", "order", st.key(), "member", peer,
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
		r = &retry{failingSince: now}
		s.retries[key+"|"+peer] = r
	}
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

// errNoPeer is returned by Peers that cannot reach a member.
var errNoPeer = errors.New("group member endpoint unavailable")
