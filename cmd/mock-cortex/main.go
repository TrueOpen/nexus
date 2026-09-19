package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

type options struct {
	NATSServers   []string
	NATSUser      string
	NATSPassword  string
	WorkerCount   int
	ResponseDelay time.Duration
	Once          bool
}

func main() {
	options, err := parseOptions(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mock-cortex: %v\n", err)
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, options, log); err != nil {
		log.Error("mock-cortex stopped", "err", err)
		os.Exit(1)
	}
}

func parseOptions(args []string, getenv func(string) string, output io.Writer) (options, error) {
	serversDefault := firstNonEmpty(getenv("MOCK_CORTEX_NATS_SERVERS"), getenv("NEXUS_NATS_SERVERS"), nats.DefaultURL)
	userDefault := firstNonEmpty(getenv("MOCK_CORTEX_NATS_USER"), getenv("NEXUS_NATS_USER"))
	passwordDefault := firstNonEmpty(getenv("MOCK_CORTEX_NATS_PASSWORD"), getenv("NEXUS_NATS_PASSWORD"))

	flags := flag.NewFlagSet("mock-cortex", flag.ContinueOnError)
	flags.SetOutput(output)
	servers := flags.String("nats-servers", serversDefault, "comma-separated NATS server URLs")
	user := flags.String("nats-user", userDefault, "NATS username")
	password := flags.String("nats-password", passwordDefault, "NATS password")
	workers := flags.Int("workers", 3, "number of mock worker handraises")
	delay := flags.Duration("response-delay", 500*time.Millisecond, "delay before publishing handraises")
	once := flags.Bool("once", false, "exit after responding to the first order")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	parsed := options{
		NATSServers:   splitNonEmpty(*servers),
		NATSUser:      strings.TrimSpace(*user),
		NATSPassword:  *password,
		WorkerCount:   *workers,
		ResponseDelay: *delay,
		Once:          *once,
	}
	if err := parsed.validate(); err != nil {
		return options{}, err
	}
	return parsed, nil
}

func (o options) validate() error {
	switch {
	case len(o.NATSServers) == 0:
		return fmt.Errorf("at least one NATS server is required")
	case o.WorkerCount < 3:
		return fmt.Errorf("workers must be at least 3")
	case o.ResponseDelay < 0:
		return fmt.Errorf("response-delay must not be negative")
	case o.NATSPassword != "" && o.NATSUser == "":
		return fmt.Errorf("nats-user is required when nats-password is set")
	default:
		return nil
	}
}

func run(ctx context.Context, options options, log *slog.Logger) error {
	if err := options.validate(); err != nil {
		return err
	}
	connectOptions := []nats.Option{
		nats.Name("mock-cortex"),
		nats.Timeout(10 * time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(250 * time.Millisecond),
		nats.ReconnectJitter(100*time.Millisecond, time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("NATS disconnected", "err", err)
		}),
		nats.ReconnectHandler(func(connection *nats.Conn) {
			log.Info("NATS reconnected", "server", connection.ConnectedUrlRedacted())
		}),
	}
	if options.NATSUser != "" {
		connectOptions = append(connectOptions, nats.UserInfo(options.NATSUser, options.NATSPassword))
	}
	connection, err := nats.Connect(strings.Join(options.NATSServers, ","), connectOptions...)
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}

	done := make(chan struct{})
	var doneOnce sync.Once
	responder := newOrderResponder(responderConfig{
		WorkerCount:   options.WorkerCount,
		ResponseDelay: options.ResponseDelay,
	}, connection.Publish)
	subscription, err := connection.Subscribe(ordersWildcard, func(message *nats.Msg) {
		if err := responder.Handle(ctx, message.Subject, message.Data); err != nil {
			log.Warn("order ignored", "subject", message.Subject, "err", err)
			return
		}
		if err := connection.FlushTimeout(5 * time.Second); err != nil {
			log.Warn("flush worker handraises failed", "subject", message.Subject, "err", err)
			return
		}
		log.Info("worker handraises published", "order_subject", message.Subject, "workers", options.WorkerCount)
		if options.Once {
			doneOnce.Do(func() { close(done) })
		}
	})
	if err != nil {
		connection.Close()
		return fmt.Errorf("subscribe %s: %w", ordersWildcard, err)
	}
	if err := connection.FlushTimeout(5 * time.Second); err != nil {
		connection.Close()
		return fmt.Errorf("activate subscription: %w", err)
	}
	log.Info("mock-cortex listening", "servers", options.NATSServers, "subject", ordersWildcard, "workers", options.WorkerCount)

	select {
	case <-ctx.Done():
	case <-done:
	}
	if err := subscription.Unsubscribe(); err != nil {
		connection.Close()
		return fmt.Errorf("unsubscribe %s: %w", ordersWildcard, err)
	}
	if err := connection.Drain(); err != nil {
		connection.Close()
		return fmt.Errorf("drain NATS: %w", err)
	}
	return nil
}

func splitNonEmpty(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
