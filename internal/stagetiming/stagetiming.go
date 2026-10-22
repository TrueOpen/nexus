// Package stagetiming collects the duration of the stages of one request, for a single log line.
//
// A Recorder rides the request context, so a layer several calls down (a chain read, a broadcast)
// can add its own stage without a signature change. Every method is safe on a nil Recorder and on
// a context without one: code that is not handling a timed request pays only a context lookup.
package stagetiming

import (
	"context"
	"math"
	"sync"
	"time"
)

// Recorder sums durations per stage name. Stages may be added concurrently.
type Recorder struct {
	mu     sync.Mutex
	start  time.Time
	order  []string
	totals map[string]time.Duration
}

type recorderKey struct{}

// New starts a Recorder whose total runs from now.
func New() *Recorder {
	return &Recorder{start: time.Now(), totals: map[string]time.Duration{}}
}

// With returns ctx carrying a new Recorder, and the Recorder.
func With(ctx context.Context) (context.Context, *Recorder) {
	r := New()
	return context.WithValue(ctx, recorderKey{}, r), r
}

// From returns the Recorder ctx carries, or nil.
func From(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(recorderKey{}).(*Recorder)
	return r
}

// Add adds d to stage name; a stage added more than once reports the sum.
func (r *Recorder) Add(name string, d time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.totals[name]; !ok {
		r.order = append(r.order, name)
	}
	r.totals[name] += d
}

// Since adds the time elapsed since start to stage name.
func (r *Recorder) Since(name string, start time.Time) {
	if r == nil {
		return
	}
	r.Add(name, time.Since(start))
}

// Attrs returns slog key/value pairs: each stage as "<name>_ms" in insertion order, then
// "total_ms", the time since the Recorder started.
func (r *Recorder) Attrs() []any {
	if r == nil {
		return nil
	}
	total := time.Since(r.start)
	r.mu.Lock()
	defer r.mu.Unlock()
	attrs := make([]any, 0, 2*(len(r.order)+1))
	for _, name := range r.order {
		attrs = append(attrs, name+"_ms", Millis(r.totals[name]))
	}
	return append(attrs, "total_ms", Millis(total))
}

// Millis renders d in milliseconds with two decimals, so sub-millisecond stages stay visible.
func Millis(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/10) / 100
}
