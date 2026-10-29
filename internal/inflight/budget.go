package inflight

import "time"

// readBudget is a token bucket of chain reads refilled at a rate per second, with a burst of
// readBurstSeconds' worth. The caller serialises access.
type readBudget struct {
	rate   int64
	tokens int64
	refill time.Time
}

const readBurstSeconds int64 = 2

func newReadBudget(perSecond uint32, now time.Time) readBudget {
	rate := int64(perSecond)
	return readBudget{rate: rate, tokens: rate * readBurstSeconds, refill: now}
}

// take spends one read, reporting false when none is left.
func (b *readBudget) take(now time.Time) bool {
	if elapsed := now.Sub(b.refill); elapsed > 0 {
		add := elapsed.Nanoseconds() * b.rate / int64(time.Second)
		if add > 0 {
			b.tokens += add
			b.refill = b.refill.Add(time.Duration(add * int64(time.Second) / b.rate))
		}
	}
	if burst := b.rate * readBurstSeconds; b.tokens >= burst {
		b.tokens = burst
		b.refill = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}
