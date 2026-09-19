package chaincli

import (
	"context"
	"time"
)

const (
	eventLoopMinBackoff = 1 * time.Second
	eventLoopMaxBackoff = 30 * time.Second
)

func (c *client) sendEvent(ctx context.Context, event ChainEvent) error {
	select {
	case c.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return context.Canceled
	}
}
