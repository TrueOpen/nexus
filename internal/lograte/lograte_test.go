package lograte

import (
	"testing"
	"time"
)

func TestLimiterLetsOneLinePerInterval(t *testing.T) {
	l := Limiter{Every: time.Minute}
	start := time.Unix(1_800_000_000, 0)
	if n, ok := l.Allow(start); !ok || n != 0 {
		t.Fatalf("first line = %d, %v", n, ok)
	}
	for _, d := range []time.Duration{time.Second, 59 * time.Second} {
		if _, ok := l.Allow(start.Add(d)); ok {
			t.Fatalf("line after %v let through", d)
		}
	}
	if n, ok := l.Allow(start.Add(time.Minute)); !ok || n != 2 {
		t.Fatalf("line after a minute = %d, %v; want 2 held back", n, ok)
	}
}
