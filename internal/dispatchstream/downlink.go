package dispatchstream

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

const outKeyPrefix = "out|"

// pendingMessage is one Builder-signed downlink message the Cortex has not acknowledged. raw is the
// marshalled frame with only the message set, produced once when the message was first sent;
// cursor is its number on the operator's current stream (0 before it is assigned one); retained is
// the Verifier broadcast it carries, if any, which counts as given to the Cortex once acknowledged.
type pendingMessage struct {
	seq      uint64
	raw      []byte
	cursor   uint64
	retained *retainedMessage
}

func outKey(operator string, seq uint64) string {
	return fmt.Sprintf("%s%s|%020d", outKeyPrefix, operator, seq)
}

// loadPending reads the unacknowledged downlink messages of the previous run.
func (h *Hub) loadPending() error {
	var bad []string
	err := h.store.Scan(kv.NSStreamSession, func(key string, val []byte) bool {
		rest, ok := strings.CutPrefix(key, outKeyPrefix)
		if !ok {
			return true
		}
		operator, seqText, ok := strings.Cut(rest, "|")
		seq, err := strconv.ParseUint(seqText, 10, 64)
		if !ok || err != nil || operator == "" {
			bad = append(bad, key)
			return true
		}
		h.pending[operator] = append(h.pending[operator], &pendingMessage{seq: seq, raw: append([]byte(nil), val...)})
		if seq >= h.nextSeq[operator] {
			h.nextSeq[operator] = seq + 1
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("load dispatch stream state: %w", err)
	}
	for _, key := range bad {
		h.log.Warn("dropping malformed dispatch stream entry", "key", key)
		if err := h.store.Delete(kv.NSStreamSession, key); err != nil {
			return fmt.Errorf("drop malformed dispatch stream entry: %w", err)
		}
	}
	return nil
}

// downlinkKind names a message the Builder may send, or "" for any other frame content.
func downlinkKind(frame *nexusv1.DispatchStreamFrameV1) string {
	switch frame.GetMessage().(type) {
	case *nexusv1.DispatchStreamFrameV1_HandraiseRoot:
		return "handraise_root"
	case *nexusv1.DispatchStreamFrameV1_Offer:
		return "offer"
	case *nexusv1.DispatchStreamFrameV1_InputResponse:
		return "input_response"
	case *nexusv1.DispatchStreamFrameV1_Revoke:
		return "revoke"
	case *nexusv1.DispatchStreamFrameV1_RecordResult:
		return "record_result"
	case *nexusv1.DispatchStreamFrameV1_OpenVerify:
		return "open_verify"
	case *nexusv1.DispatchStreamFrameV1_VerifierAssignment:
		return "verifier_assignment"
	default:
		return ""
	}
}

// encodeDownlink marshals the business message of frame once; these bytes are what every later
// send and resend carries. The stream layer owns stream_nonce and cursor.
func encodeDownlink(frame *nexusv1.DispatchStreamFrameV1) ([]byte, error) {
	if downlinkKind(frame) == "" {
		return nil, fmt.Errorf("frame does not carry a Builder downlink message")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(
		&nexusv1.DispatchStreamFrameV1{Message: frame.GetMessage()})
	if err != nil {
		return nil, fmt.Errorf("encode downlink message: %w", err)
	}
	return raw, nil
}

// Send queues one Builder-signed message to operator's stream. It returns once the message is
// stored and queued, not when it is delivered; ErrNotConnected when operator has no stream.
func (h *Hub) Send(ctx context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error {
	return h.SendBatch(ctx, operator, []*nexusv1.DispatchStreamFrameV1{frame})
}

// SendBatch queues Builder-signed messages to operator's stream, in order. They are stored in one
// synced write before any is queued, so none can leave the process before all are durable. It
// returns once they are stored and queued; ErrNotConnected when operator has no stream.
//
// The store runs without the hub's lock, which every stream's sender, every ack and every other
// Cortex's messages need: only the operator's own batches wait for each other. A stream that
// binds or ends meanwhile is handled as for a message stored just before: the messages are queued
// to the operator's stream bound once they are stored, or kept for its next one.
func (h *Hub) SendBatch(_ context.Context, operator string, frames []*nexusv1.DispatchStreamFrameV1) error {
	if len(frames) == 0 {
		return nil
	}
	raws := make([][]byte, len(frames))
	for i, frame := range frames {
		raw, err := encodeDownlink(frame)
		if err != nil {
			return err
		}
		raws[i] = raw
	}
	h.mu.Lock()
	if _, ok := h.sessions[operator]; !ok {
		h.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotConnected, operator)
	}
	lock := h.sendMu[operator]
	if lock == nil {
		lock = &sync.Mutex{}
		h.sendMu[operator] = lock
	}
	h.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()

	h.mu.Lock()
	first := h.nextSeq[operator]
	h.nextSeq[operator] = first + uint64(len(raws))
	ops := make([]kv.WriteOp, 0, len(raws))
	messages := make([]*pendingMessage, len(raws))
	for i, raw := range raws {
		messages[i] = &pendingMessage{seq: first + uint64(i), raw: raw}
		ops = append(ops, kv.WriteOp{NS: kv.NSStreamSession, Key: outKey(operator, messages[i].seq), Val: raw})
	}
	// The oldest messages beyond the retention are dropped in the same write.
	dropped := map[uint64]bool{}
	pending := h.pending[operator]
	for i := 0; len(pending)-i+len(raws) > h.cfg.MaxPending && i < len(pending); i++ {
		dropped[pending[i].seq] = true
		ops = append(ops, kv.WriteOp{NS: kv.NSStreamSession, Key: outKey(operator, pending[i].seq), Delete: true})
	}
	h.mu.Unlock()

	if err := h.store.WriteBatch(ops...); err != nil {
		return fmt.Errorf("store dispatch stream message: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(dropped) > 0 {
		h.log.Warn("dispatch stream retention full; dropping the oldest unacknowledged messages",
			"operator", operator, "dropped", len(dropped))
		kept := h.pending[operator][:0:0]
		for _, m := range h.pending[operator] {
			if !dropped[m.seq] {
				kept = append(kept, m)
			}
		}
		h.pending[operator] = kept
	}
	h.pending[operator] = insertBySeq(h.pending[operator], messages)
	s, ok := h.sessions[operator]
	if !ok {
		return nil
	}
	for _, m := range messages {
		if err := s.queueLocked(m); err != nil {
			return err
		}
	}
	return nil
}

// insertBySeq adds messages, in seq order, to pending, kept in seq order: a message stored under
// the hub's lock (a broadcast) may have taken a later seq and joined pending meanwhile.
func insertBySeq(pending, messages []*pendingMessage) []*pendingMessage {
	at := len(pending)
	for at > 0 && pending[at-1].seq > messages[0].seq {
		at--
	}
	out := make([]*pendingMessage, 0, len(pending)+len(messages))
	out = append(out, pending[:at]...)
	out = append(out, messages...)
	return append(out, pending[at:]...)
}

// SendAll queues one Builder-signed message to every connected stream and returns how many it
// reached; ErrNotConnected when there is none.
func (h *Hub) SendAll(_ context.Context, frame *nexusv1.DispatchStreamFrameV1) (int, error) {
	raw, err := encodeDownlink(frame)
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) == 0 {
		return 0, ErrNotConnected
	}
	sent := 0
	for _, s := range h.sessions {
		if err := h.enqueueLocked(s, raw); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// enqueueLocked stores raw as the next unacknowledged message of the session's Cortex, numbers it
// on the current stream and wakes the sender. Caller holds h.mu.
func (h *Hub) enqueueLocked(s *session, raw []byte) error {
	_, err := h.enqueueMessageLocked(s, raw)
	return err
}

// enqueueMessageLocked is enqueueLocked returning the queued message. Caller holds h.mu.
func (h *Hub) enqueueMessageLocked(s *session, raw []byte) (*pendingMessage, error) {
	operator := s.operator
	seq := h.nextSeq[operator]
	ops := []kv.WriteOp{{NS: kv.NSStreamSession, Key: outKey(operator, seq), Val: raw}}
	pending := h.pending[operator]
	dropped := 0
	for len(pending)-dropped >= h.cfg.MaxPending {
		ops = append(ops, kv.WriteOp{NS: kv.NSStreamSession, Key: outKey(operator, pending[dropped].seq), Delete: true})
		dropped++
	}
	if err := h.store.WriteBatch(ops...); err != nil {
		return nil, fmt.Errorf("store dispatch stream message: %w", err)
	}
	if dropped > 0 {
		h.log.Warn("dispatch stream retention full; dropping the oldest unacknowledged messages",
			"operator", operator, "dropped", dropped)
		pending = pending[dropped:]
	}
	h.nextSeq[operator] = seq + 1
	m := &pendingMessage{seq: seq, raw: raw}
	h.pending[operator] = append(pending, m)
	return m, s.queueLocked(m)
}

// replayLocked renumbers every unacknowledged message of the session's Cortex on the new stream,
// dropping those the replay filter no longer wants, then queues the retained Verifier broadcasts
// this Cortex has not been given. Caller holds h.mu.
func (h *Hub) replayLocked(s *session) error {
	operator := s.operator
	var keep []*pendingMessage
	var drop []kv.WriteOp
	for _, m := range h.pending[operator] {
		if h.replayFilter != nil {
			frame := &nexusv1.DispatchStreamFrameV1{}
			if err := proto.Unmarshal(m.raw, frame); err != nil || !h.replayFilter(operator, frame) {
				drop = append(drop, kv.WriteOp{NS: kv.NSStreamSession, Key: outKey(operator, m.seq), Delete: true})
				continue
			}
		}
		keep = append(keep, m)
	}
	if len(drop) > 0 {
		if err := h.store.WriteBatch(drop...); err != nil {
			return fmt.Errorf("%w: drop expired dispatch stream messages: %v", ErrTransient, err)
		}
	}
	h.pending[operator] = keep
	for _, m := range keep {
		if err := s.queueLocked(m); err != nil {
			return err
		}
	}
	for _, r := range h.retained {
		if err := h.giveRetainedLocked(s, r); err != nil {
			return fmt.Errorf("%w: %v", ErrTransient, err)
		}
	}
	return nil
}

// giveRetainedLocked queues the retained broadcast r to the session's Cortex unless the Cortex
// acknowledged it already or it is still waiting in the retention. Caller holds h.mu.
func (h *Hub) giveRetainedLocked(s *session, r *retainedMessage) error {
	if r.delivered[s.operator] {
		return nil
	}
	for _, m := range h.pending[s.operator] {
		if m.retained == r {
			return nil
		}
	}
	m, err := h.enqueueMessageLocked(s, r.raw)
	if m != nil {
		m.retained = r
	}
	return err
}

// ackLocked releases every message the Cortex acknowledged on stream s. Caller holds h.mu.
//
// The release does not wait for the disk (kv.WriteDeferred). A crash that loses it sends those
// messages again, byte for byte, on the Cortex's next stream, which a Cortex already gets for an
// ack in flight at a crash; nothing else reads them.
func (h *Hub) ackLocked(s *session, acked uint64) error {
	operator := s.operator
	var keep []*pendingMessage
	var release []kv.WriteOp
	for _, m := range h.pending[operator] {
		if m.cursor != 0 && m.cursor <= acked {
			release = append(release, kv.WriteOp{NS: kv.NSStreamSession, Key: outKey(operator, m.seq), Delete: true})
			continue
		}
		keep = append(keep, m)
	}
	if len(release) == 0 {
		return nil
	}
	if err := kv.WriteDeferred(h.store, release...); err != nil {
		return fmt.Errorf("%w: release acknowledged dispatch stream messages: %v", ErrTransient, err)
	}
	for _, m := range h.pending[operator] {
		if m.retained != nil && m.cursor != 0 && m.cursor <= acked {
			m.retained.delivered[operator] = true
		}
	}
	h.pending[operator] = keep
	return nil
}

// retainKey identifies one Verifier broadcast: its kind, task and verify round.
type retainKey struct {
	kind        string
	taskID      string
	verifyRound uint32
}

// retainedMessage is one retained Verifier broadcast; delivered holds the Cortex operators that
// acknowledged it.
type retainedMessage struct {
	raw       []byte
	delivered map[string]bool
}

// Broadcast implements the coordinator's CortexLink for OpenVerifyV1 and VerifierAssignmentNotifyV1:
// the message goes to every connected stream and is kept, as the bytes signed once, for every
// stream that connects later until Retire. With no stream connected it is only kept. A
// VerifierAssignmentNotifyV1 retires the OpenVerifyV1 of the same task and round, whose handraise
// window it closes.
//
// Keeping the latest signed bytes is preferred over failing sends with no stream: a Cortex that
// connects after the single send would miss the message either way, and the task FSM has no timer
// to retry a failed send.
func (h *Hub) Broadcast(_ context.Context, frame *nexusv1.DispatchStreamFrameV1) error {
	var key retainKey
	switch m := frame.GetMessage().(type) {
	case *nexusv1.DispatchStreamFrameV1_OpenVerify:
		key = retainKey{"open_verify", string(m.OpenVerify.GetTaskId()), m.OpenVerify.GetVerifyRound()}
	case *nexusv1.DispatchStreamFrameV1_VerifierAssignment:
		key = retainKey{"verifier_assignment", string(m.VerifierAssignment.GetTaskId()), m.VerifierAssignment.GetVerifyRound()}
	default:
		return fmt.Errorf("broadcast carries only OpenVerifyV1 or VerifierAssignmentNotifyV1")
	}
	raw, err := encodeDownlink(frame)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if key.kind == "verifier_assignment" {
		delete(h.retained, retainKey{"open_verify", key.taskID, key.verifyRound})
	}
	r, ok := h.retained[key]
	if !ok || !bytes.Equal(r.raw, raw) {
		r = &retainedMessage{raw: raw, delivered: make(map[string]bool)}
		h.retained[key] = r
	}
	for _, s := range h.sessions {
		if err := h.giveRetainedLocked(s, r); err != nil {
			return err
		}
	}
	return nil
}

// Retire stops giving the Verifier broadcasts of (task_id, verify_round) to streams that connect
// later; the task has left that round.
func (h *Hub) Retire(taskID []byte, verifyRound uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.retained, retainKey{"open_verify", string(taskID), verifyRound})
	delete(h.retained, retainKey{"verifier_assignment", string(taskID), verifyRound})
}
