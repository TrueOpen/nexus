package msgbus

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type recordAcker struct {
	acks, naks int
	delays     []time.Duration
}

func (a *recordAcker) Ack(...nats.AckOpt) error { a.acks++; return nil }
func (a *recordAcker) Nak(...nats.AckOpt) error { a.naks++; return nil }
func (a *recordAcker) NakWithDelay(delay time.Duration, _ ...nats.AckOpt) error {
	a.delays = append(a.delays, delay)
	return nil
}

// A handler error wrapped with RetryAfter is redelivered only after its delay; a plain error
// still Naks at once, and success acks.
func TestSettleJSHonoursRequestedRedeliveryDelay(t *testing.T) {
	b := &natsBus{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	delayed := &recordAcker{}
	b.settleJS(delayed, "subject", "durable", RetryAfter(errors.New("mempool full"), 10*time.Second))
	if delayed.naks != 0 || delayed.acks != 0 || len(delayed.delays) != 1 || delayed.delays[0] != 10*time.Second {
		t.Fatalf("delayed retry: %+v", delayed)
	}

	plain := &recordAcker{}
	b.settleJS(plain, "subject", "durable", errors.New("stopping"))
	if plain.naks != 1 || len(plain.delays) != 0 {
		t.Fatalf("plain error: %+v", plain)
	}

	ok := &recordAcker{}
	b.settleJS(ok, "subject", "durable", nil)
	if ok.acks != 1 || ok.naks != 0 || len(ok.delays) != 0 {
		t.Fatalf("success: %+v", ok)
	}

	wrapped := RetryAfter(errors.New("x"), time.Second)
	if delay, ok := RetryDelay(errors.Join(errors.New("outer"), wrapped)); !ok || delay != time.Second {
		t.Fatalf("RetryDelay through a wrapper = %v, %v", delay, ok)
	}
	if _, ok := RetryDelay(errors.New("plain")); ok || RetryAfter(nil, time.Second) != nil {
		t.Fatal("a plain or nil error must not ask for a delay")
	}
}
