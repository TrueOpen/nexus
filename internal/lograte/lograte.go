// Package lograte spaces out repeated log lines.
package lograte

import (
	"sync"
	"time"
)

// Limiter lets one log line through per Every and counts the ones it holds back. The zero value
// with Every set is ready to use.
type Limiter struct {
	Every time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// Allow reports whether a line may be logged at now and how many were held back since the last
// one let through.
func (l *Limiter) Allow(now time.Time) (suppressed int, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < l.Every {
		l.suppressed++
		return 0, false
	}
	suppressed, l.suppressed, l.last = l.suppressed, 0, now
	return suppressed, true
}
