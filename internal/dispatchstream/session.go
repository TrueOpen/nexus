package dispatchstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// receiveQueue bounds the frames received and not yet handled on one stream. Keepalives skip the
// queue, so it only absorbs the business frames and acks a Cortex sends while one uplink message is
// being handled: a few at a time in practice. Beyond it the receive goroutine waits, which holds
// the Cortex back through transport flow control, and memory stays bounded by this many frames of
// the read limit per stream.
const receiveQueue = 32

// session is one bound stream. queue, wake, nextCursor and srtt are guarded by Hub.mu; lastUplink
// belongs to the Serve goroutine. The keepalive state is guarded by keepaliveMu, taken before
// Hub.mu: the Serve goroutine probes and the receive goroutine takes the answers.
type session struct {
	operator    string
	streamNonce []byte
	// bindingNonce is the authorization nonce of the CORTEX key that authenticated the binding.
	bindingNonce uint64
	stream       FrameStream

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

	keepaliveMu sync.Mutex
	// probe is the value of the outstanding local keepalive (0 when none), sent at probeSentAt and
	// unanswered for probeTicks keepalive ticks; lastProbe is the latest value sent, lastPeerProbe
	// the latest peer probe echoed. probeFrame is the probe's frame until the sender writes it:
	// probeSentAt is when it was queued until then.
	probe, lastProbe, lastPeerProbe uint64
	probeSentAt                     time.Time
	probeTicks                      int
	probeFrame                      *nexusv1.DispatchStreamFrameV1
}

func newSession(operator string, streamNonce []byte, bindingNonce uint64, stream FrameStream) *session {
	return &session{
		operator: operator, streamNonce: append([]byte(nil), streamNonce...), bindingNonce: bindingNonce, stream: stream,
		done: make(chan struct{}), wake: make(chan struct{}, 1), nextCursor: 1,
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
// then uplink frames and keepalives; each keepalive tick also checks that the binding's key is
// still the Cortex's current one. It returns ErrBindingInvalid for a refused binding, io.EOF
// style errors from the transport, or the reason the hub ended the stream.
//
// Once bound, Serve returns only after its sender stopped writing to stream: an HTTP/2 handler's
// stream may not be written after the handler returned. A write in progress is waited for, so the
// transport must bound each write. The receive goroutine may still be inside stream.Receive when
// Serve returns; it only reads, and the end of the call unblocks it.
func (h *Hub) Serve(ctx context.Context, stream FrameStream) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The receive goroutine answers keepalives itself, so a round trip is timed when the frame
	// arrives, however long the loop below spends on an uplink message (a standing handraise reads
	// the chain). Other frames queue in order for the loop; a full queue stops receiving.
	frames := make(chan *nexusv1.DispatchStreamFrameV1, receiveQueue)
	recvErr := make(chan error, 1)
	var bound atomic.Pointer[session]
	go func() {
		for {
			frame, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			if s := bound.Load(); s != nil && h.receiveKeepalive(s, frame) {
				continue
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
	bound.Store(s)
	sendErr := make(chan error, 1)
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		sendErr <- h.sendLoop(s)
	}()
	defer func() {
		s.end(err)
		h.unbind(s)
		<-sendDone
	}()
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
			err := h.keepalive(s)
			if err == nil {
				err = h.checkBindingKey(ctx, s)
			}
			if err != nil {
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
	s := newSession(operator, binding.GetStreamNonce(), binding.GetServiceAuthorizationNonce(), stream)
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
			if frame.GetKeepalive() != nil {
				h.probeWriting(s, frame)
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

// keepalive runs on each keepalive tick. At most one probe is outstanding: while it is, the tick
// only counts against it, and KeepaliveMisses such ticks end the stream. Otherwise a new probe goes
// out; its value is the clock in milliseconds made odd, raised above the previous probe when needed
// so the values sent always increase. A Builder probes with odd values and a Cortex with even ones,
// so a Cortex probe from the same millisecond is never taken for our probe's echo.
func (h *Hub) keepalive(s *session) error {
	s.keepaliveMu.Lock()
	defer s.keepaliveMu.Unlock()
	if s.probe != 0 {
		s.probeTicks++
		if s.probeTicks >= h.cfg.KeepaliveMisses {
			return fmt.Errorf("%w: probe unanswered for %d intervals", ErrKeepaliveTimeout, s.probeTicks)
		}
		return nil
	}
	now := h.now()
	s.probe = uint64(now.UnixMilli()) | 1
	if s.probe <= s.lastProbe {
		s.probe = s.lastProbe + 2 // lastProbe is odd
	}
	s.probeFrame = &nexusv1.DispatchStreamFrameV1{
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: s.probe}},
	}
	s.lastProbe, s.probeSentAt, s.probeTicks = s.probe, now, 0
	h.transport(s, s.probeFrame)
	return nil
}

// probeWriting runs on the sender just before it writes a keepalive frame: when the frame is the
// outstanding probe, its round trip starts now, not when it was queued behind earlier frames.
func (h *Hub) probeWriting(s *session, frame *nexusv1.DispatchStreamFrameV1) {
	s.keepaliveMu.Lock()
	if frame == s.probeFrame {
		s.probeSentAt, s.probeFrame = h.now(), nil
	}
	s.keepaliveMu.Unlock()
}

// receiveKeepalive answers frame on the receive goroutine when it is a well-formed keepalive of s
// and reports whether it did. Anything else, a malformed keepalive included, is left to
// handleFrame.
func (h *Hub) receiveKeepalive(s *session, frame *nexusv1.DispatchStreamFrameV1) bool {
	m, ok := frame.GetMessage().(*nexusv1.DispatchStreamFrameV1_Keepalive)
	if !ok || frame.GetCursor() != 0 || !bytes.Equal(frame.GetStreamNonce(), s.streamNonce) {
		return false
	}
	h.keepaliveReceived(s, m.Keepalive.GetSentAtMs())
	return true
}

// keepaliveReceived handles a peer keepalive. The value of the outstanding probe is its echo: it
// measures the round trip, clears the probe and is not answered. Any other value is a peer probe,
// echoed back unchanged once; a value not above the latest peer probe echoed is a repeat and is
// dropped. Both sides probing at once therefore never bounce keepalives back and forth.
func (h *Hub) keepaliveReceived(s *session, value uint64) {
	s.keepaliveMu.Lock()
	defer s.keepaliveMu.Unlock()
	if s.probe != 0 && value == s.probe {
		s.probe, s.probeFrame = 0, nil
		sample := max(h.now().Sub(s.probeSentAt), time.Millisecond)
		h.mu.Lock()
		if s.srtt == 0 {
			s.srtt = sample
		} else {
			// Smoothed like TCP's SRTT: one eighth of each new sample.
			s.srtt += (sample - s.srtt) / 8
		}
		h.mu.Unlock()
		return
	}
	if value <= s.lastPeerProbe {
		return
	}
	s.lastPeerProbe = value
	h.transport(s, &nexusv1.DispatchStreamFrameV1{
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: value}},
	})
}
