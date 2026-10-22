package stagetiming

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRecorderSumsStagesInOrder(t *testing.T) {
	ctx, rec := With(context.Background())
	if From(ctx) != rec {
		t.Fatal("From did not return the context's Recorder")
	}
	rec.Add("b", 2*time.Millisecond)
	rec.Add("a", 1500*time.Microsecond)
	rec.Add("b", 3*time.Millisecond)
	attrs := rec.Attrs()
	if len(attrs) != 6 {
		t.Fatalf("attrs = %v", attrs)
	}
	if attrs[0] != "b_ms" || attrs[1] != 5.0 || attrs[2] != "a_ms" || attrs[3] != 1.5 || attrs[4] != "total_ms" {
		t.Fatalf("attrs = %v", attrs)
	}
}

func TestRecorderAcceptsConcurrentStages(t *testing.T) {
	rec := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.Add("read", time.Millisecond)
		}()
	}
	wg.Wait()
	if attrs := rec.Attrs(); attrs[0] != "read_ms" || attrs[1] != 8.0 {
		t.Fatalf("attrs = %v", attrs)
	}
}

func TestNilRecorderIsANoOp(t *testing.T) {
	var rec *Recorder
	rec.Add("a", time.Second)
	rec.Since("a", time.Now())
	if rec.Attrs() != nil {
		t.Fatal("nil Recorder produced output")
	}
	if From(context.Background()) != nil {
		t.Fatal("From found a Recorder in a plain context")
	}
}

func TestMillisKeepsTwoDecimals(t *testing.T) {
	if got := Millis(1234567 * time.Nanosecond); got != 1.23 {
		t.Fatalf("Millis = %v, want 1.23", got)
	}
}
