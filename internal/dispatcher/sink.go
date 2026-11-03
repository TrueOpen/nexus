package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// The dispatcher is the stream hub's DispatchSink: the hub verified each answer's signature under
// the key its nonce selects for the answered ticket's order before it arrives here.
var _ dispatchstream.DispatchSink = (*Dispatcher)(nil)

// TicketProofContext implements dispatchstream.DispatchSink: the earliest_submit_height of the
// signed order a ticket of this Builder was issued for, and the bound_change_height the ticket
// commits.
func (d *Dispatcher) TicketProofContext(ticketHash []byte) (earliestSubmitHeight, boundChangeHeight uint64, ok bool) {
	d.mu.Lock()
	o := d.tickets[string(ticketHash)]
	d.mu.Unlock()
	if o == nil {
		return 0, 0, false
	}
	o.mu.Lock()
	var raw []byte
	if a := o.st.attemptByHash(ticketHash); a != nil {
		raw = a.Ticket
	}
	o.mu.Unlock()
	var ticket taskv1.DispatchTicketV1
	if raw == nil || proto.Unmarshal(raw, &ticket) != nil {
		return 0, 0, false
	}
	return o.signed.GetOrder().GetEarliestSubmitHeight(), ticket.GetBoundChangeHeight(), true
}

// answered finds the ticket an accept or reject answers and checks the answer names that ticket's
// task, order version and target. Caller holds nothing; on success the order is locked and the
// attempt and decoded ticket returned.
func (d *Dispatcher) answered(from dispatchstream.Origin, hash []byte, chainID string, taskID, taskHash []byte, member *taskv1.CandidateMemberRefV1, schema uint32) (*order, *attemptState, *taskv1.DispatchTicketV1, error) {
	d.mu.Lock()
	o := d.tickets[string(hash)]
	d.mu.Unlock()
	if o == nil {
		return nil, nil, nil, fmt.Errorf("%w %x", ErrUnknownTicket, hash)
	}
	o.mu.Lock()
	a := o.st.attemptByHash(hash)
	var ticket taskv1.DispatchTicketV1
	if a == nil || proto.Unmarshal(a.Ticket, &ticket) != nil {
		o.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("%w %x", ErrUnknownTicket, hash)
	}
	if schema != schemaVersion || chainID != ticket.GetChainId() || !bytes.Equal(taskID, ticket.GetTaskId()) || !bytes.Equal(taskHash, ticket.GetTaskHash()) ||
		!proto.Equal(member, ticket.GetTarget()) || from.Operator != a.Operator {
		o.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("%w: ticket %x", ErrAnswerInvalid, hash)
	}
	return o, a, &ticket, nil
}

// HandleDispatchAccept takes a Worker's accept. Only the ticket out, answered before its accept
// deadline on the Builder's clock while the order can still be recorded in time, can win; any
// other accept is DISPATCH_TICKET_CLOSED. The winner ends the walk: the order is ACCEPTED in the
// ledger, the Worker's local free slots drop by one, the record is signed and the dispatch entry
// goes to the Recorder. A state that cannot be stored leaves the accept unacknowledged
// (ErrTransient) so the Cortex sends it again.
func (d *Dispatcher) HandleDispatchAccept(ctx context.Context, from dispatchstream.Origin, m *taskv1.DispatchAcceptV1) error {
	o, a, ticket, err := d.answered(from, m.GetDispatchTicketHash(), m.GetChainId(), m.GetTaskId(), m.GetTaskHash(), m.GetMember(), m.GetSchemaVersion())
	if err != nil {
		return err
	}
	st := o.st
	if st.Phase != phaseDispatching || st.pending() != a {
		o.mu.Unlock()
		return fmt.Errorf("%w: ticket %x is not out", ErrTicketClosed, a.Hash)
	}
	if now := uint64(d.clock.Now().UnixMilli()); now > a.DeadlineMs {
		d.timeoutLocked(o, a, true)
		out := d.step(ctx, o)
		o.mu.Unlock()
		d.finish(ctx, out)
		return fmt.Errorf("%w: accept of ticket %x after its deadline", ErrTicketClosed, a.Hash)
	}
	if deadline, ok := d.liveRecordDeadline(ctx, o); ok && TooLateToRecord(d.cfg.Sessions.Head(), deadline) {
		// The entry can no longer be recorded in time, and a late record is charged to this
		// Builder. The Worker answered in time, so the attempt is not its timeout: it is VOIDED
		// with the accept kept as received, the reject rate is not fed, and the order fails on its
		// record deadline.
		a.Outcome, a.LateAccept, a.LateAcceptDigest = outcomeVoided, from.Raw, append([]byte(nil), from.Digest[:]...)
		out := d.fail(o, fmt.Errorf("%w: deadline %d", ErrRecordDeadline, deadline))
		o.mu.Unlock()
		d.finish(ctx, out)
		return fmt.Errorf("%w: accept of ticket %x after the record deadline %d", ErrTicketClosed, a.Hash, deadline)
	}
	key := d.cfg.Signer.Key()
	if key.Revoked {
		// This Builder's current service key was revoked after it signed the ticket: it signs no
		// record, and the chain would admit none. The attempt is VOIDED with the accept kept as
		// received, as above, and the order fails as no capacity.
		a.Outcome, a.LateAccept, a.LateAcceptDigest = outcomeVoided, from.Raw, append([]byte(nil), from.Digest[:]...)
		out := d.fail(o, fmt.Errorf("%w: %w", dispatchdraw.ErrNoCapacity, servicekey.ErrRevoked))
		o.mu.Unlock()
		d.finish(ctx, out)
		return fmt.Errorf("%w: accept of ticket %x while this Builder's service key is revoked", ErrTicketClosed, a.Hash)
	}
	prev := cloneState(st)
	a.Outcome = outcomeAccepted
	st.Phase, st.Accept, st.AcceptDigest = phaseAccepted, from.Raw, append([]byte(nil), from.Digest[:]...)
	record, err := buildRecord(d.cfg.ChainID, d.cfg.Builder, st, ticket, a.Hash)
	if err == nil {
		st.Record, _, err = signRecord(key, record)
	}
	if err == nil {
		err = d.saveWithEvidence(st)
	}
	if err != nil {
		o.st = prev
		o.mu.Unlock()
		return fmt.Errorf("%w: store accept: %v", dispatchstream.ErrTransient, err)
	}
	if o.timer != nil {
		o.timer.Stop()
	}
	if err := d.cfg.Ledger.MarkAccepted(st.SessionID, st.Sequence); err != nil {
		d.log.Error("accept not written to the ledger", "session_id", st.SessionID, "order_sequence", st.Sequence, "err", err)
	}
	if current, ok := d.cfg.Handraises.Current(a.Operator); ok {
		d.slots.accepted(a.Operator, current)
	}
	d.recordOutcome(a, opsmetrics.OutcomeAccepted)
	if !o.ticketAt.IsZero() {
		d.cfg.Metrics.ObserveStage(opsmetrics.StageTicketToAccept, d.clock.Now().Sub(o.ticketAt))
	}
	d.cfg.Metrics.Accepted(st.TaskID)
	d.orderLeft(st, "accepted")
	out := done{session: st.SessionID, sequence: st.Sequence, taskID: st.TaskID, worker: a.Operator, ticket: [32]byte(a.Hash)}
	if entry, ok := d.cfg.Ledger.Get(st.SessionID, st.Sequence); ok {
		out.accepted, err = d.bundle(st, d.recordDeadline(o, entry.Deadline))
	} else {
		err = errors.New("ledger entry missing")
	}
	o.mu.Unlock()
	if err != nil {
		d.log.Error("accepted order has no dispatch entry", "session_id", out.session, "order_sequence", out.sequence, "err", err)
		out.accepted = nil
		d.cfg.Observer.DispatchAccepted(out.session, out.taskID, out.ticket, out.worker)
		return nil
	}
	d.log.Info("dispatch accepted", "session_id", out.session, "order_sequence", out.sequence, "worker", out.worker, "rank", a.Rank)
	d.finish(ctx, out)
	return nil
}

// HandleDispatchReject takes a Worker's reject of the ticket out: the attempt is REJECTED with
// the reject's digest (its bytes are kept for a skip challenge), it counts as a skip and in the
// Worker's reject rate when it advertised a free slot, and the walk goes on. A reject of a ticket
// no longer out changes nothing.
func (d *Dispatcher) HandleDispatchReject(ctx context.Context, from dispatchstream.Origin, m *taskv1.DispatchRejectV1) error {
	o, a, _, err := d.answered(from, m.GetDispatchTicketHash(), m.GetChainId(), m.GetTaskId(), m.GetTaskHash(), m.GetMember(), m.GetSchemaVersion())
	if err != nil {
		return err
	}
	st := o.st
	if st.Phase != phaseDispatching || st.pending() != a {
		o.mu.Unlock()
		return fmt.Errorf("%w: ticket %x is not out", ErrTicketClosed, a.Hash)
	}
	prev := cloneState(st)
	a.Outcome, a.Reject, a.RejectDigest = outcomeRejected, from.Raw, append([]byte(nil), from.Digest[:]...)
	st.Skips++
	if err := d.save(st); err != nil {
		o.st = prev
		o.mu.Unlock()
		return fmt.Errorf("%w: store reject: %v", dispatchstream.ErrTransient, err)
	}
	if o.timer != nil {
		o.timer.Stop()
	}
	current, _ := d.cfg.Handraises.Current(a.Operator)
	outcome := opsmetrics.OutcomeRejectedWithoutFreeSlot
	if d.slots.free(a.Operator, current) > 0 {
		outcome = opsmetrics.OutcomeRejected
	}
	d.cfg.Metrics.Inc(opsmetrics.CounterSkips, opsmetrics.SkipRejected)
	d.recordOutcome(a, outcome)
	out := d.step(ctx, o)
	o.mu.Unlock()
	d.finish(ctx, out)
	return nil
}

// HandleDispatchInputRequest serves the order's input to the Worker that won it: the request must
// name the winner ticket of an ACCEPTED order, come from its target and carry the
// dispatch_accept_digest of the accept this Builder holds. The input goes back as signed
// DispatchInputResponseV1 chunks of at most InputChunkBytes.
func (d *Dispatcher) HandleDispatchInputRequest(ctx context.Context, from dispatchstream.Origin, m *nexusv1.DispatchInputRequestV1) error {
	d.mu.Lock()
	o := d.tickets[string(m.GetDispatchTicketHash())]
	d.mu.Unlock()
	if o == nil {
		return fmt.Errorf("%w: unknown ticket %x", ErrInputRefused, m.GetDispatchTicketHash())
	}
	o.mu.Lock()
	st := o.st
	w := st.winner()
	var ticket taskv1.DispatchTicketV1
	ok := st.Phase == phaseAccepted && w != nil && bytes.Equal(w.Hash, m.GetDispatchTicketHash()) && w.Operator == from.Operator &&
		proto.Unmarshal(w.Ticket, &ticket) == nil && proto.Equal(m.GetMember(), ticket.GetTarget()) &&
		bytes.Equal(m.GetTaskId(), ticket.GetTaskId()) && bytes.Equal(m.GetDispatchAcceptDigest(), st.AcceptDigest)
	sessionID, taskID, taskHash := st.SessionID, st.TaskID, st.TaskHash
	inputHash := o.signed.GetOrder().GetInputHash()
	o.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: ticket %x is not an accepted winner with that accept", ErrInputRefused, m.GetDispatchTicketHash())
	}
	return d.sendInput(ctx, from.Operator, sessionID, taskID, taskHash, ticket.GetTaskId(), m.GetDispatchTicketHash(), inputHash,
		ticket.GetServiceAuthorizationNonce())
}

// sendInput sends the input as signed chunks answering the ticket of ticketHash, whose nonce is
// ticketNonce. Each chunk is signed with the current service key.
func (d *Dispatcher) sendInput(ctx context.Context, operator, sessionID, taskID, taskHash string, rawTaskID, ticketHash, inputHash []byte, ticketNonce uint64) error {
	input, size, err := d.cfg.Inputs.OpenInput(ctx, sessionID, taskID, taskHash)
	if err != nil {
		return fmt.Errorf("%w: open input: %v", dispatchstream.ErrTransient, err)
	}
	defer input.Close()
	chunk := d.cfg.InputChunkBytes
	count := (size + chunk - 1) / chunk
	if size == 0 || count > uint64(^uint32(0)) {
		return fmt.Errorf("%w: input of %d bytes cannot be served", ErrInputRefused, size)
	}
	buf := make([]byte, chunk)
	for index := uint64(0); index < count; index++ {
		n := min(chunk, size-index*chunk)
		if _, err := io.ReadFull(input, buf[:n]); err != nil {
			return fmt.Errorf("%w: read input: %v", dispatchstream.ErrTransient, err)
		}
		resp := &nexusv1.DispatchInputResponseV1{
			TaskId:             append([]byte(nil), rawTaskID...),
			DispatchTicketHash: append([]byte(nil), ticketHash...),
			InputHash:          append([]byte(nil), inputHash...),
			InputSizeBytes:     size,
			Input:              append([]byte(nil), buf[:n]...),
			ChunkIndex:         uint32(index),
			ChunkCount:         uint32(count),
		}
		if _, _, err := signInputResponse(d.cfg.Signer.Key(), ticketNonce, resp); err != nil {
			return fmt.Errorf("%w: %v", dispatchstream.ErrTransient, err)
		}
		frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_InputResponse{InputResponse: resp}}
		if err := d.cfg.Streams.Send(ctx, operator, frame); err != nil {
			return fmt.Errorf("%w: send input: %v", dispatchstream.ErrTransient, err)
		}
	}
	return nil
}
