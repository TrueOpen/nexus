package chaincli

import (
	"context"
	"time"
)

const (
	eventLoopMinBackoff = 1 * time.Second
	eventLoopMaxBackoff = 30 * time.Second
)

// WithEventObserver has observe see every event just before it is queued on Events(), on the
// goroutine of the stream that produced it. It must return quickly; caches use it to drop entries
// an event made stale (a rotated service key) without consuming Events().
func WithEventObserver(observe func(ChainEvent)) Option {
	return func(c *client) {
		if observe != nil {
			c.observers = append(c.observers, observe)
		}
	}
}

func (c *client) sendEvent(ctx context.Context, event ChainEvent) error {
	for _, observe := range c.observers {
		observe(event)
	}
	select {
	case c.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return context.Canceled
	}
}
