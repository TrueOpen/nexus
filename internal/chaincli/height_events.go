package chaincli

import (
	"context"
	"math"
	"time"
)

type Option func(*client)

func WithHeightEvents(interval time.Duration) Option {
	return func(c *client) {
		c.heightEventsInterval = interval
	}
}

func (c *client) startHeightEventsLocked() {
	if c.heightEventsInterval <= 0 || c.heightCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.heightCancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.heightEventLoop(ctx, c.heightEventsInterval, c.LatestHeight)
	}()
}

func (c *client) heightEventLoop(
	ctx context.Context,
	interval time.Duration,
	latestHeight func(context.Context) (uint64, error),
) {
	if interval <= 0 || latestHeight == nil {
		return
	}
	var lastHeight uint64
	poll := func() bool {
		height, err := latestHeight(ctx)
		if err != nil {
			if ctx.Err() == nil {
				c.log.Warn("chaincli: latest height poll failed", "err", redactSensitiveText(err.Error()))
			}
			return ctx.Err() == nil
		}
		if height == 0 || height <= lastHeight {
			return true
		}
		if height > math.MaxInt64 {
			c.log.Warn("chaincli: latest height exceeds supported range", "height", height)
			return true
		}
		if err := c.sendEvent(ctx, ChainEvent{Type: EventNewBlock, Height: int64(height)}); err != nil {
			return false
		}
		lastHeight = height
		return true
	}

	if !poll() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}
