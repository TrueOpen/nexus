package dispatchstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// session is one bound stream. queue, wake, nextCursor and srtt are guarded by Hub.mu; lastUplink
// and probes belong to the Serve goroutine.
type session struct {
	operator    string
	streamNonce []byte
	stream      FrameStream

	done    chan struct{}
	endOnce sync.Once
	endErr  error

	// guarded by Hub.mu
	queue      []*nexusv1.DispatchStreamFrameV1
	wake       chan struct{}
	nextCursor uint64 // cursor of the next business frame sent; cursors start at 1
	srtt       time.Duration

	// owned by the Serve goroutine
	lastUplink uint64 // cursor of the last business frame received; the next must be lastUplink+1
	probes     map[uint64]time.Time
}

func newSession(operator string, streamNonce []byte, stream FrameStream) *session {
	return &session{
		operator: operator, streamNonce: append([]byte(nil), streamNonce...), stream: stream,
		done: make(chan struct{}), wake: make(chan struct{}, 1), nextCursor: 1,
		probes: make(map[uint64]time.Time),
	}
}

// end stops the session with err; the first reason wins.
func (s *session) end(err error) {
	s.endOnce.Do(func() {
		s.endErr = err
		close(s.done)
	})
}

// queueLocked numbers m on this stream and queues the frame that carries it. Caller holds Hub.mu.
func (s *session) queueLocked(m *pendingMessage) error {
	frame := &nexusv1.DispatchStreamFrameV1{}
	if err := proto.Unmarshal(m.raw, frame); err != nil {
		return fmt.Errorf("decode stored dispatch stream message: %w", err)
	}
	m.cursor = s.nextCursor
	s.nextCursor++
	frame.StreamNonce, frame.Cursor = s.streamNonce, m.cursor
	s.pushLocked(frame)
	return nil
}

// pushLocked queues a frame for the sender. Caller holds Hub.mu.
func (s *session) pushLocked(frame *nexusv1.DispatchStreamFrameV1) {
	s.queue = append(s.queue, frame)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// transport queues an unnumbered transport frame (ack or keepalive).
func (h *Hub) transport(s *session, frame *nexusv1.DispatchStreamFrameV1) {
	frame.StreamNonce = s.streamNonce
	h.mu.Lock()
	s.pushLocked(frame)
	h.mu.Unlock()
}

// Serve runs one Cortex stream until it ends: the binding, the replay of unacknowledged messages,
// then uplink frames and keepalives. It returns ErrBindingInvalid for a refused binding, io.EOF
// style errors from the transport, or the reason the hub ended the stream.
func (h *Hub) Serve(ctx context.Context, stream FrameStream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	frames := make(chan *nexusv1.DispatchStreamFrameV1)
	recvErr := make(chan error, 1)
	go func() {
		for {
			frame, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()

	var first *nexusv1.DispatchStreamFrameV1
	bindTimer := time.NewTimer(h.cfg.BindTimeout)
	select {
	case first = <-frames:
		bindTimer.Stop()
	case err := <-recvErr:
		bindTimer.Stop()
		return err
	case <-bindTimer.C:
		return fmt.Errorf("%w: no binding within %s", ErrBindingInvalid, h.cfg.BindTimeout)
	case <-ctx.Done():
		bindTimer.Stop()
		return ctx.Err()
	}
	binding, err := h.verifyBinding(ctx, first)
	if err != nil {
		return err
	}
	s, err := h.bind(binding, stream)
	if err != nil {
		return err
	}
	defer h.unbind(s)

	sendErr := make(chan error, 1)
	go func() { sendErr <- h.sendLoop(s) }()
	ticks, stopTicks := h.keepaliveTicks(h.cfg.KeepaliveInterval)
	defer stopTicks()
	for {
		select {
		case frame := <-frames:
			if err := h.handleFrame(ctx, s, frame); err != nil {
				s.end(err)
				return err
			}
		case err := <-recvErr:
			s.end(err)
			return err
		case err := <-sendErr:
			if err == nil {
				err = s.endErr
			}
			s.end(err)
			return err
		case <-ticks:
			if err := h.keepalive(s); err != nil {
				s.end(err)
				return err
			}
		case <-s.done:
			return s.endErr
		case <-ctx.Done():
			s.end(ctx.Err())
			return ctx.Err()
		}
	}
}

// bind claims the binding, makes s the operator's stream (ending an older one) and queues the
// replay.
func (h *Hub) bind(binding *nexusv1.DispatchStreamBindingV1, stream FrameStream) (*session, error) {
	operator := binding.GetCortexOperator()
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return nil, ErrStopped
	}
	if err := h.claimBindingLocked(binding); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	s := newSession(operator, binding.GetStreamNonce(), stream)
	old := h.sessions[operator]
	h.sessions[operator] = s
	err := h.replayLocked(s)
	if err != nil {
		delete(h.sessions, operator)
	}
	h.mu.Unlock()
	if old != nil {
		old.end(ErrReplaced)
	}
	if err != nil {
		if old != nil {
			h.notify(operator, false)
		}
		return nil, err
	}
	h.log.Info("cortex dispatch stream bound", "operator", operator, "replaced", old != nil)
	h.notify(operator, true)
	return s, nil
}

// unbind forgets s unless a newer stream already replaced it.
func (h *Hub) unbind(s *session) {
	h.mu.Lock()
	current := h.sessions[s.operator] == s
	if current {
		delete(h.sessions, s.operator)
	}
	h.mu.Unlock()
	if current {
		h.log.Info("cortex dispatch stream ended", "operator", s.operator, "reason", s.endErr)
		h.notify(s.operator, false)
	}
}

// sendLoop writes queued frames in order until the session ends or a write fails.
func (h *Hub) sendLoop(s *session) error {
	for {
		h.mu.Lock()
		batch := s.queue
		s.queue = nil
		h.mu.Unlock()
		for _, frame := range batch {
			select {
			case <-s.done:
				return nil
			default:
			}
			if err := s.stream.Send(frame); err != nil {
				return err
			}
		}
		select {
		case <-s.wake:
		case <-s.done:
			return nil
		}
	}
}

// handleFrame applies one frame received after the binding. Acks and keepalives carry cursor 0;
// business frames carry the cursors 1, 2, ... of this stream without a gap or a repeat (a resent
// message comes on a new stream, under its new binding). An ack may not exceed the last cursor
// this side numbered; zero acknowledges nothing.
func (h *Hub) handleFrame(ctx context.Context, s *session, frame *nexusv1.DispatchStreamFrameV1) error {
	if !bytes.Equal(frame.GetStreamNonce(), s.streamNonce) {
		return fmt.Errorf("%w: frame stream_nonce is not the bound one", ErrProtocol)
	}
	cursor := frame.GetCursor()
	switch m := frame.GetMessage().(type) {
	case *nexusv1.DispatchStreamFrameV1_Ack:
		if cursor != 0 {
			return fmt.Errorf("%w: ack with cursor %d", ErrProtocol, cursor)
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.sessions[s.operator] != s {
			return nil
		}
		if acked := m.Ack.GetAckedCursor(); acked >= s.nextCursor {
			return fmt.Errorf("%w: ack of cursor %d, last sent %d", ErrProtocol, acked, s.nextCursor-1)
		}
		return h.ackLocked(s, m.Ack.GetAckedCursor())
	case *nexusv1.DispatchStreamFrameV1_Keepalive:
		if cursor != 0 {
			return fmt.Errorf("%w: keepalive with cursor %d", ErrProtocol, cursor)
		}
		h.keepaliveReceived(s, m.Keepalive.GetSentAtMs())
		return nil
	case nil:
		return fmt.Errorf("%w: frame carries no message", ErrProtocol)
	}
	if cursor != s.lastUplink+1 {
		return fmt.Errorf("%w: business frame cursor %d, want %d", ErrProtocol, cursor, s.lastUplink+1)
	}
	if err := h.handleUplink(ctx, s.operator, frame); err != nil {
		if errors.Is(err, ErrTransient) || errors.Is(err, ErrProtocol) {
			return err
		}
		h.log.Warn("cortex dispatch stream message refused", "operator", s.operator, "cursor", cursor, "err", err)
	}
	s.lastUplink = cursor
	h.transport(s, &nexusv1.DispatchStreamFrameV1{
		Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{AckedCursor: cursor}},
	})
	return nil
}

// keepalive sends one probe, or ends the stream after too many unanswered ones.
func (h *Hub) keepalive(s *session) error {
	if len(s.probes) >= h.cfg.KeepaliveMisses {
		return fmt.Errorf("%w: %d probes unanswered", ErrKeepaliveTimeout, len(s.probes))
	}
	now := h.now()
	sentAt := uint64(now.UnixMilli())
	s.probes[sentAt] = now
	h.transport(s, &nexusv1.DispatchStreamFrameV1{
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: sentAt}},
	})
	return nil
}

// keepaliveReceived handles a peer keepalive. One that echoes an outstanding probe of ours measures
// the round trip and clears it and every older probe; any other is the peer's own probe, echoed
// back unchanged.
func (h *Hub) keepaliveReceived(s *session, sentAt uint64) {
	sent, ours := s.probes[sentAt]
	if !ours {
		h.transport(s, &nexusv1.DispatchStreamFrameV1{
			Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: sentAt}},
		})
		return
	}
	for probe := range s.probes {
		if probe <= sentAt {
			delete(s.probes, probe)
		}
	}
	sample := max(h.now().Sub(sent), time.Millisecond)
	h.mu.Lock()
	if s.srtt == 0 {
		s.srtt = sample
	} else {
		// Smoothed like TCP's SRTT: one eighth of each new sample.
		s.srtt += (sample - s.srtt) / 8
	}
	h.mu.Unlock()
}
