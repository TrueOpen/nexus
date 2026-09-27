// Package msgbus is the off-chain message bus client (Implementation Design §4.3).
// The chosen bus is NATS (core + JetStream). In the skeleton stage it is a stub: it never actually
// connects to NATS and only logs, so the process runs offline; it is replaced by the nats.go implementation later.
package msgbus

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// MsgHandler is the subscription callback. Returning an error means local handling failed; core NATS only
// logs it, while a JetStream consumer Naks on it so nothing is acked before it was reliably handled.
// Wrapping the error with RetryAfter asks for the redelivery to wait.
type MsgHandler func(subject string, data []byte) error

// retryAfterError is a handler error that asks for a delayed redelivery.
type retryAfterError struct {
	err   error
	delay time.Duration
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// RetryAfter wraps a JetStream handler error so the message is redelivered only after delay. A
// plain error is redelivered at once, which for a failure that needs time to clear (a chain
// query, a full mempool) only repeats the same work in a tight loop.
func RetryAfter(err error, delay time.Duration) error {
	if err == nil {
		return nil
	}
	return &retryAfterError{err: err, delay: delay}
}

// RetryDelay reports the redelivery delay a handler error asks for.
func RetryDelay(err error) (time.Duration, bool) {
	var retry *retryAfterError
	if errors.As(err, &retry) && retry.delay > 0 {
		return retry.delay, true
	}
	return 0, false
}

// Unsubscribe cancels a subscription.
type Unsubscribe func()

// Bus is the bus abstraction (the core and JetStream tiers).
type Bus interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	// core NATS: best effort, lowest latency (orders / hand-raise / prepare)
	Publish(subject string, data []byte) error
	Subscribe(subject string, h MsgHandler) (Unsubscribe, error)
	// QueueSubscribe is a queue subscription (§6.1): delivery is load-balanced within one queue (for
	// example a single operator's pool of workers jointly consuming trueopen.orders.*).
	QueueSubscribe(subject, queue string, h MsgHandler) (Unsubscribe, error)

	// JetStream: at-least-once + dedup + durable (output availability / VerifyResult).
	// Contract §5.12: msgID must be BusEnvelopeV1.message_id (Nats-Msg-Id), no longer the dedup_id inside the payload.
	JSPublish(subject string, data []byte, msgID string) error
	JSSubscribe(subject, durable string, h MsgHandler) (Unsubscribe, error)
}

// stubBus is the skeleton implementation: it logs publishes and subscribes and never touches the network.
type stubBus struct {
	log     *slog.Logger
	servers []string

	mu   sync.Mutex
	subs map[string][]MsgHandler
}

// NewStub returns the stub bus. servers is only used for log output.
func NewStub(log *slog.Logger, servers []string) Bus {
	return &stubBus{log: log, servers: servers, subs: make(map[string][]MsgHandler)}
}

func (b *stubBus) Start(_ context.Context) error {
	if len(b.servers) == 0 {
		b.log.Warn("msgbus running in STUB mode (no NATS servers configured)")
	} else {
		b.log.Warn("msgbus STUB mode: NATS client not implemented yet", "servers", b.servers)
	}
	return nil
}

func (b *stubBus) Stop(_ context.Context) error { return nil }

func (b *stubBus) Publish(subject string, data []byte) error {
	b.log.Debug("bus publish (stub)", "subject", subject, "bytes", len(data))
	b.deliver(subject, data)
	return nil
}

func (b *stubBus) Subscribe(subject string, h MsgHandler) (Unsubscribe, error) {
	b.mu.Lock()
	b.subs[subject] = append(b.subs[subject], h)
	b.mu.Unlock()
	b.log.Debug("bus subscribe (stub)", "subject", subject)
	return func() {}, nil
}

func (b *stubBus) QueueSubscribe(subject, queue string, h MsgHandler) (Unsubscribe, error) {
	// The stub has no load-balancing semantics: it degrades to a plain subscription (enough for local loopback self-tests).
	b.mu.Lock()
	b.subs[subject] = append(b.subs[subject], h)
	b.mu.Unlock()
	b.log.Debug("bus queue subscribe (stub)", "subject", subject, "queue", queue)
	return func() {}, nil
}

func (b *stubBus) JSPublish(subject string, data []byte, msgID string) error {
	b.log.Debug("bus JS publish (stub)", "subject", subject, "msg_id", msgID, "bytes", len(data))
	b.deliver(subject, data)
	return nil
}

func (b *stubBus) JSSubscribe(subject, durable string, h MsgHandler) (Unsubscribe, error) {
	b.mu.Lock()
	b.subs[subject] = append(b.subs[subject], h)
	b.mu.Unlock()
	b.log.Debug("bus JS subscribe (stub)", "subject", subject, "durable", durable)
	return func() {}, nil
}

// deliver performs local loopback delivery (stub only, for self-tests).
func (b *stubBus) deliver(subject string, data []byte) {
	b.mu.Lock()
	hs := append([]MsgHandler(nil), b.subs[subject]...)
	b.mu.Unlock()
	for _, h := range hs {
		if err := h(subject, data); err != nil {
			b.log.Warn("bus handler failed (stub)", "subject", subject, "err", err)
		}
	}
}
