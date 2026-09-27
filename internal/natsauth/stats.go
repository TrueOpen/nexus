package natsauth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LookupStat describes one chain lookup made while handling a request, for the request's log line.
type LookupStat struct {
	Name     string
	Duration time.Duration
	// CacheHit: answered from the cache. Joined: waited on a query another request had started.
	CacheHit bool
	Joined   bool
	// NewConn: this request's own query had to open a new connection to the chain node.
	NewConn bool
}

func (s LookupStat) String() string {
	how := "chain"
	switch {
	case s.CacheHit:
		how = "cache"
	case s.Joined:
		how = "shared"
	case s.NewConn:
		how = "chain,new_conn"
	}
	return fmt.Sprintf("%s=%dms(%s)", s.Name, s.Duration.Milliseconds(), how)
}

// requestStats collects the lookups of one request; lookups may run in parallel.
type requestStats struct {
	mu      sync.Mutex
	lookups []LookupStat
}

func (r *requestStats) add(s LookupStat) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.lookups = append(r.lookups, s)
	r.mu.Unlock()
}

func (r *requestStats) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	parts := make([]string, len(r.lookups))
	for i, s := range r.lookups {
		parts[i] = s.String()
	}
	return strings.Join(parts, " ")
}

type statsKey struct{}

func withStats(ctx context.Context) (context.Context, *requestStats) {
	stats := &requestStats{}
	return context.WithValue(ctx, statsKey{}, stats), stats
}

func statsFrom(ctx context.Context) *requestStats {
	stats, _ := ctx.Value(statsKey{}).(*requestStats)
	return stats
}

type arrivalKey struct{}

// withArrival records when the request reached the service, before it waited for a free handling slot.
func withArrival(ctx context.Context, at time.Time) context.Context {
	return context.WithValue(ctx, arrivalKey{}, at)
}

func arrivalFrom(ctx context.Context) (time.Time, bool) {
	at, ok := ctx.Value(arrivalKey{}).(time.Time)
	return at, ok
}
