package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// AttemptBook is the book of winning dispatch attempts (attempt.Book).
type AttemptBook interface {
	Current(taskID string) (attempt.Attempt, bool)
	Watch(taskID string) (<-chan struct{}, func())
	MaxPrerecordTokens() uint64
}

var (
	errAttemptStale = connect.NewError(connect.CodeFailedPrecondition,
		errors.New("NEXUS_INGRESS_ATTEMPT_STALE: dispatch_ticket_hash is not the task's current attempt; subscribe again for the new header"))
	errRecordRejected = connect.NewError(connect.CodeFailedPrecondition,
		errors.New("RECORD_REJECTED: the chain did not record this attempt; its frames are void"))
)

// ResumeOutput resumes an output subscription: SubscribeOutput's replay and live delivery for the
// order user, under its own request body domain.
func (s *service) ResumeOutput(
	ctx context.Context,
	req *connect.Request[nexusv1.ResumeOutputRequest],
	stream *connect.ServerStream[nexusv1.ResumeOutputResponse],
) error {
	if s.outputStream == nil {
		return errOutputStreamDisabled
	}
	m := req.Msg
	if m.GetSessionId() == "" || m.GetTaskId() == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_INGRESS_MALFORMED: session_id and task_id are required"))
	}
	if m.GetRequestEnvelope() == nil {
		return errEnvelopeRequired
	}
	body, err := sdkauth.ResumeOutputBody(m.GetSessionId(), m.GetTaskId(), m.ResumeAfterSeq, m.GetDispatchTicketHash())
	if err != nil {
		return bodyErr(err)
	}
	requester, err := s.checkTaskEnvelope(ctx, m.GetRequestEnvelope(), m.GetSessionId(), m.GetTaskId(), envelopeCheck{
		method: "ResumeOutput", body: body, sessionAllowed: true, replay: s.replay,
	})
	if err != nil {
		return err
	}
	return s.serveOutput(ctx, m.GetSessionId(), m.GetTaskId(), requester, m.ResumeAfterSeq, m.GetDispatchTicketHash(),
		func(r *nexusv1.SubscribeOutputResponse) error {
			return stream.Send(&nexusv1.ResumeOutputResponse{Frame: r})
		})
}

// serveOutput delivers a task's output to its order user through send.
//
// The first message is the Builder-signed DispatchResultHeaderV1 of the task's current attempt
// (sent once a Worker accepted; until then the call waits). It is sent again when the chain admits
// the attempt's record (RECORDED) and when it refuses it (REJECTED, which ends the call with
// RECORD_REJECTED). A ticket the request names that is not the current attempt, or an attempt
// voided while the call runs, ends it with NEXUS_INGRESS_ATTEMPT_STALE.
//
// Stored frames of the attempt after resumeAfter are replayed, then live frames follow, all as the
// Worker signed them. While the record is pending only chunks whose cumulative_generated_tokens is
// within max_prerecord_output_tokens are sent; the first chunk past it and everything after are
// held (they are stored) and released once the record is admitted. The call ends after the Fin
// once the record is admitted.
func (s *service) serveOutput(ctx context.Context, wireSession, wireTask, requester string, resumeAfter *uint64, ticket []byte,
	send func(*nexusv1.SubscribeOutputResponse) error) error {
	ids, err := parseTaskIDs(wireSession, wireTask)
	if err != nil {
		return err
	}
	if err := s.requireTaskOwner(ctx, ids.session, ids.task, requester); err != nil {
		return err
	}
	rt := s.outputStream
	if rt.attempts == nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_OUTPUT_STREAM_STOPPED: no dispatch attempts are held"))
	}
	changed, stopWatch := rt.attempts.Watch(ids.task)
	defer stopWatch()
	current, err := s.awaitAttempt(ctx, ids.session, ids.task, ticket, changed)
	if err != nil || current == nil {
		return err
	}
	key := taskdata.ObjectKey{SessionID: ids.session, TaskID: ids.task, Kind: taskdata.ObjectKindOutput}
	sub := rt.dispatcher.Subscribe(key)
	defer sub.Close()

	d := &outputDelivery{service: s, key: key, attempt: *current, lastSent: resumeAfter, send: send}
	if err := d.sendHeader(); err != nil {
		return err
	}
	if d.attempt.Status == attempt.Rejected {
		return errRecordRejected
	}
	if err := d.pump(ctx); err != nil {
		return err
	}
	for {
		if d.finSent && d.attempt.Status == attempt.Recorded {
			return nil
		}
		select {
		case frame, ok := <-sub.Frames:
			if !ok {
				if sub.Overflowed() {
					return connect.NewError(connect.CodeResourceExhausted,
						errors.New("NEXUS_OUTPUT_SUBSCRIBER_OVERFLOW: subscriber buffer full, re-subscribe with resume_after_seq"))
				}
				return connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_OUTPUT_STREAM_STOPPED: builder is shutting down"))
			}
			if d.inOrder(frame) {
				err = d.offer(frame)
			} else {
				err = d.pump(ctx)
			}
			if err != nil {
				return err
			}
		case <-changed:
			next, ok := rt.attempts.Current(ids.task)
			if !ok || next.TicketHash != d.attempt.TicketHash {
				return errAttemptStale
			}
			if next.Status == d.attempt.Status {
				continue
			}
			d.attempt = next
			if err := d.sendHeader(); err != nil {
				return err
			}
			if next.Status == attempt.Rejected {
				return errRecordRejected
			}
			if next.Status == attempt.Recorded {
				d.held = false
				if err := d.pump(ctx); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// awaitAttempt waits until the task has an attempt of its session and checks the ticket the
// request names against it. A nil attempt with a nil error means the caller went away.
func (s *service) awaitAttempt(ctx context.Context, sessionID, taskID string, ticket []byte, changed <-chan struct{}) (*attempt.Attempt, error) {
	for {
		a, ok := s.outputStream.attempts.Current(taskID)
		if ok && a.SessionID == sessionID {
			if ticket != nil && !bytes.Equal(ticket, a.TicketHash[:]) {
				return nil, errAttemptStale
			}
			return &a, nil
		}
		if ticket != nil {
			return nil, errAttemptStale
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, nil
		}
	}
}

// outputDelivery is one subscriber's position in an attempt's output.
type outputDelivery struct {
	service  *service
	key      taskdata.ObjectKey
	attempt  attempt.Attempt
	lastSent *uint64
	// held is set once a chunk past the pre-record cap was withheld: nothing more is sent until
	// the record is admitted.
	held    bool
	finSent bool
	send    func(*nexusv1.SubscribeOutputResponse) error
}

func (d *outputDelivery) sendHeader() error {
	header, err := d.attempt.ResultHeader()
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("dispatch result header: %v", err))
	}
	return d.send(&nexusv1.SubscribeOutputResponse{DispatchResult: header})
}

// pump sends the stored frames after the last one sent, as far as the cap allows.
func (d *outputDelivery) pump(ctx context.Context) error {
	frames, err := d.service.outputStream.service.OutputFrames(ctx, d.key, d.lastSent)
	if err != nil {
		return mapTaskDataError(err)
	}
	for _, frame := range frames {
		if d.held || d.finSent {
			return nil
		}
		if err := d.offer(frame); err != nil {
			return err
		}
	}
	return nil
}

// inOrder reports whether a live frame can be offered as it is: a chunk not past the next sequence,
// or a Fin right after the last chunk sent. Anything else is read from the store instead.
func (d *outputDelivery) inOrder(frame taskdata.OutputFrame) bool {
	next := uint64(0)
	if d.lastSent != nil {
		next = *d.lastSent + 1
	}
	if frame.Chunk != nil {
		return frame.Chunk.Seq <= next
	}
	return d.lastSent != nil && *d.lastSent == frame.Fin.FinalSeq
}

// offer sends frame if it belongs to the attempt, is the next one and the cap allows it.
func (d *outputDelivery) offer(frame taskdata.OutputFrame) error {
	if d.finSent {
		return nil
	}
	switch {
	case frame.Chunk != nil:
		if !bytes.Equal(frame.Chunk.DispatchTicketHash, d.attempt.TicketHash[:]) ||
			d.lastSent != nil && frame.Chunk.Seq <= *d.lastSent {
			return nil
		}
		if d.held || d.attempt.Status == attempt.Pending && frame.Chunk.CumulativeGeneratedTokens > d.service.outputStream.attempts.MaxPrerecordTokens() {
			d.held = true
			return nil
		}
		if err := d.send(outputFrameToPB(frame)); err != nil {
			return err
		}
		seq := frame.Chunk.Seq
		d.lastSent = &seq
	case frame.Fin != nil:
		if !bytes.Equal(frame.Fin.DispatchTicketHash, d.attempt.TicketHash[:]) || d.held ||
			d.lastSent == nil || *d.lastSent != frame.Fin.FinalSeq {
			return nil
		}
		if err := d.send(outputFrameToPB(frame)); err != nil {
			return err
		}
		d.finSent = true
	}
	return nil
}
