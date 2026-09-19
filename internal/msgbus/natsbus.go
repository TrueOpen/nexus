// natsBus is the real NATS implementation of Bus (core + JetStream), replacing the stub.
// core: best effort, lowest latency (orders / hand-raise / prepare).
// JetStream: at-least-once + dedup (dedup_id = MsgId) + durable (output-avail / verify-select / assign / verify-result).
// Reconnects indefinitely after a disconnect (matching Nexus Detailed Design §6.1 "NATS reconnect backoff").
package msgbus

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TrueOpen/nexus/internal/config"
)

// jsStreamName is the single stream covering every task-level JS subject (contract §5.12).
const jsStreamName = JetStreamName

// jsDuplicatesWindow is the JetStream dedup window (should be >= the stage timeout; parameterization is TBD, Nexus Detailed Design §8).
// Contract §5.12: broker dedup is only an optimization and cannot replace the application-level replay store.
const jsDuplicatesWindow = 2 * time.Minute

// Core NATS has no per-message ack; the PONG from Flush is the boundary confirming the server processed the preceding publishes.
const corePublishConfirmTimeout = 5 * time.Second

type natsBus struct {
	log *slog.Logger
	cfg config.NATSConfig

	nc *nats.Conn
	js nats.JetStreamContext
}

// NewNATS constructs the real NATS bus (connecting is deferred to Start).
func NewNATS(log *slog.Logger, cfg config.NATSConfig) Bus {
	return &natsBus{log: log, cfg: cfg}
}

func (b *natsBus) Start(_ context.Context) error {
	opts := []nats.Option{
		nats.Name("nexus"),
		nats.Timeout(10 * time.Second),
		nats.MaxReconnects(-1), // reconnect indefinitely
		nats.ReconnectWait(250 * time.Millisecond),
		nats.ReconnectJitter(100*time.Millisecond, time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			b.log.Warn("nats disconnected", "err", err)
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			b.log.Info("nats reconnected", "server", c.ConnectedUrlRedacted())
		}),
		nats.ErrorHandler(func(c *nats.Conn, sub *nats.Subscription, err error) {
			subject := ""
			if sub != nil {
				subject = sub.Subject
			}
			b.log.Error("nats asynchronous error",
				"server", c.ConnectedUrlRedacted(), "subject", subject, "err", err)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			if err := c.LastError(); err != nil {
				b.log.Warn("nats connection closed",
					"server", c.ConnectedUrlRedacted(), "err", err)
				return
			}
			b.log.Info("nats connection closed", "server", c.ConnectedUrlRedacted())
		}),
	}
	authOpts, err := natsConnectOptions(b.cfg)
	if err != nil {
		return err
	}
	opts = append(opts, authOpts...)

	nc, err := nats.Connect(strings.Join(b.cfg.Servers, ","), opts...)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	b.nc = nc
	b.log.Info("nats connected",
		"server", nc.ConnectedServerName(),
		"version", nc.ConnectedServerVersion(),
		"max_payload", nc.MaxPayload(),
		"tls", nc.TLSRequired(),
	)

	js, err := nc.JetStream(nats.MaxWait(10 * time.Second))
	if err != nil {
		// core is still usable; JS subjects error out when used. Do not fail Start (run degraded).
		b.log.Warn("jetstream context unavailable; JS subjects will fail, core still works", "err", err)
		return nil
	}
	b.js = js
	b.ensureStreams()
	return nil
}

// ensureStreams idempotently creates or updates the stream covering the JS subjects. Without permission to
// create streams it only warns and runs degraded.
//
// The JS subject list is the v1 list of contract §5.1. An existing stream can only
// have its subjects changed through UpdateStream: AddStream has no effect on a stream that already exists,
// which is the easiest thing to miss here.
// **This function never deletes an existing stream**: deleting one also drops in-flight messages and every
// durable consumer position. That is an operations action left to the operator.
func (b *natsBus) ensureStreams() {
	subjects := JetStreamSubjectWildcardsV1()
	cfg := &nats.StreamConfig{
		Name:       jsStreamName,
		Subjects:   subjects,
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		Duplicates: jsDuplicatesWindow,
		MaxAge:     24 * time.Hour,
	}
	if _, err := b.js.AddStream(cfg); err != nil {
		if _, uerr := b.js.UpdateStream(cfg); uerr != nil {
			b.log.Warn("ensure jetstream stream failed (the server must pre-create the stream or the account must be authorized)",
				"stream", jsStreamName, "add_err", err, "update_err", uerr)
			return
		}
		b.log.Warn("jetstream stream subjects updated in place; in-flight messages on the old subjects are no longer delivered, "+
			"and existing durable consumers must be handled per the migration document",
			"stream", jsStreamName, "subjects", subjects)
	}
	b.log.Info("jetstream stream ready", "stream", jsStreamName, "subjects", subjects, "dedup_window", jsDuplicatesWindow)
}

func (b *natsBus) Stop(_ context.Context) error {
	if b.nc != nil {
		return b.nc.Drain() // graceful unsubscribe + flush
	}
	return nil
}

func (b *natsBus) Publish(subject string, data []byte) error {
	if b.nc == nil {
		return fmt.Errorf("nats core publish: connection is not started")
	}
	if err := b.nc.Publish(subject, data); err != nil {
		return fmt.Errorf("nats core publish %s: %w", subject, err)
	}
	if err := b.nc.FlushTimeout(corePublishConfirmTimeout); err != nil {
		return fmt.Errorf("nats core publish %s confirmation: %w", subject, err)
	}
	return nil
}

func (b *natsBus) Subscribe(subject string, h MsgHandler) (Unsubscribe, error) {
	sub, err := b.nc.Subscribe(subject, func(m *nats.Msg) {
		if err := h(m.Subject, m.Data); err != nil {
			b.log.Warn("nats core handler failed", "subject", m.Subject, "err", err)
		}
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

func (b *natsBus) QueueSubscribe(subject, queue string, h MsgHandler) (Unsubscribe, error) {
	sub, err := b.nc.QueueSubscribe(subject, queue, func(m *nats.Msg) {
		if err := h(m.Subject, m.Data); err != nil {
			b.log.Warn("nats queue handler failed", "subject", m.Subject, "queue", queue, "err", err)
		}
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

func (b *natsBus) JSPublish(subject string, data []byte, msgID string) error {
	if b.js == nil {
		return fmt.Errorf("jetstream not available")
	}
	// Contract §5.12: Nats-Msg-Id = BusEnvelopeV1.message_id.
	_, err := b.js.Publish(subject, data, nats.MsgId(msgID))
	return err
}

func (b *natsBus) JSSubscribe(subject, durable string, h MsgHandler) (Unsubscribe, error) {
	if b.js == nil {
		return nil, fmt.Errorf("jetstream not available")
	}
	sub, err := b.js.Subscribe(subject, func(m *nats.Msg) {
		if err := h(m.Subject, m.Data); err != nil {
			b.log.Warn("jetstream handler failed; message will be redelivered", "subject", m.Subject, "durable", durable, "err", err)
			_ = m.Nak()
			return
		}
		_ = m.Ack() // at-least-once: ack only after reliable handling
	}, nats.Durable(durable), nats.ManualAck(), nats.DeliverAll())
	if err != nil {
		return nil, err
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

// natsConnectOptions assembles the authentication and transport options (ADR-0016 transition state):
//   - creds_file: NATS creds (user JWT + nkey seed) replacing username and password;
//   - ca_file: the server certificate / CA PEM the server is verified against;
//   - any server on tls://: TLS is required (without ca_file the system root certificates are used);
//   - user/password: dev compatibility only, already rejected by config validation in production mode.
func natsConnectOptions(cfg config.NATSConfig) ([]nats.Option, error) {
	var opts []nats.Option
	if creds := strings.TrimSpace(cfg.CredsFile); creds != "" {
		if _, err := os.Stat(creds); err != nil {
			return nil, fmt.Errorf("nats creds_file: %w", err)
		}
		opts = append(opts, nats.UserCredentials(creds))
	} else if cfg.User != "" {
		opts = append(opts, nats.UserInfo(cfg.User, cfg.Password))
	}
	if ca := strings.TrimSpace(cfg.CAFile); ca != "" {
		if _, err := os.Stat(ca); err != nil {
			return nil, fmt.Errorf("nats ca_file: %w", err)
		}
		opts = append(opts, nats.RootCAs(ca))
	}
	if cfg.TLS() {
		opts = append(opts, nats.Secure())
	}
	return opts, nil
}

// ConnectOptions turns a NATSConfig into nats.go connection options (creds, CA, tls://).
// Reused by the natsauth subcommand when it connects to the same NATS with the AUTH account, so there is no second implementation.
func ConnectOptions(cfg config.NATSConfig) ([]nats.Option, error) {
	return natsConnectOptions(cfg)
}
