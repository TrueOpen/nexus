package taskdata

import "sync"

// OutputDispatcher fans out streamed OUTPUT (Streaming Output Delivery Design §5.6): per
// Task it pushes validated frames to subscribers unchanged, without re-signing, without
// waiting for Fin or the receipt. Each subscriber has a bounded buffer and publishing never
// blocks the write path: a full buffer disconnects that subscriber, and the SDK resubscribes
// with last_seq. Replaces the whole-object plaintext delivery of internal/outputdelivery.
type OutputDispatcher struct {
	mu      sync.Mutex
	buffer  int
	next    uint64
	subs    map[string]map[uint64]*OutputSubscription
	stopped bool
}

// OutputSubscription is one subscriber. Frames is closed on disconnect (buffer overflow, Stop, Close).
type OutputSubscription struct {
	Frames <-chan OutputFrame
	ch     chan OutputFrame
	key    string
	id     uint64
	d      *OutputDispatcher
	closed bool
	over   bool
}

// NewOutputDispatcher creates a dispatcher; bufferFrames is the per-subscriber buffer size in frames (design §6 subscriber_buffer_frames).
func NewOutputDispatcher(bufferFrames int) *OutputDispatcher {
	if bufferFrames <= 0 {
		bufferFrames = 1
	}
	return &OutputDispatcher{buffer: bufferFrames, subs: make(map[string]map[uint64]*OutputSubscription)}
}

// Subscribe registers a subscriber for key: live frames arriving afterwards go into its buffer.
func (d *OutputDispatcher) Subscribe(key ObjectKey) *OutputSubscription {
	d.mu.Lock()
	defer d.mu.Unlock()
	encoded := streamKeyString(key)
	ch := make(chan OutputFrame, d.buffer)
	d.next++
	sub := &OutputSubscription{Frames: ch, ch: ch, key: encoded, id: d.next, d: d}
	if d.stopped {
		sub.closed = true
		close(ch)
		return sub
	}
	if d.subs[encoded] == nil {
		d.subs[encoded] = make(map[uint64]*OutputSubscription)
	}
	d.subs[encoded][sub.id] = sub
	return sub
}

// Publish pushes one frame to all subscribers of key. Subscribers with a full buffer are disconnected (Overflowed is true).
func (d *OutputDispatcher) Publish(key ObjectKey, frame OutputFrame) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, sub := range d.subs[streamKeyString(key)] {
		select {
		case sub.ch <- frame:
		default:
			sub.over = true
			d.removeLocked(sub)
		}
	}
}

// Stop disconnects all subscribers; later Subscribe calls return an already-closed subscription.
func (d *OutputDispatcher) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopped = true
	for _, subs := range d.subs {
		for _, sub := range subs {
			d.removeLocked(sub)
		}
	}
}

// Close unsubscribes.
func (s *OutputSubscription) Close() {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	s.d.removeLocked(s)
}

// Overflowed reports whether the dispatcher disconnected this subscriber due to a full buffer.
func (s *OutputSubscription) Overflowed() bool {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	return s.over
}

func (d *OutputDispatcher) removeLocked(sub *OutputSubscription) {
	if sub.closed {
		return
	}
	sub.closed = true
	if subs := d.subs[sub.key]; subs != nil {
		delete(subs, sub.id)
		if len(subs) == 0 {
			delete(d.subs, sub.key)
		}
	}
	close(sub.ch)
}
