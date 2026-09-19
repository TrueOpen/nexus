package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TrueOpen/nexus/internal/msgbus"
)

func TestRunRespondsOverRealNATS(t *testing.T) {
	url := os.Getenv("MOCK_CORTEX_NATS_TEST_URL")
	if url == "" {
		t.Skip("set MOCK_CORTEX_NATS_TEST_URL to run the real-NATS integration test")
	}

	observer, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect observer: %v", err)
	}
	defer observer.Close()

	// A unique order_sequence isolates each run (task_id is derived from (session, seq)).
	signedOrder := testSignedOrder()
	signedOrder.Order.OrderSequence = uint64(time.Now().UnixNano())
	subject := msgbus.SubjectTaskOpen(signedOrder.GetOrder().GetModelId())
	data := testOrderBroadcastFrame(t, signedOrder, subject)
	taskIDHex, _, err := orderIdentity(signedOrder.GetOrder())
	if err != nil {
		t.Fatal(err)
	}

	received := make(chan struct{}, 3)
	subscription, err := observer.Subscribe(msgbus.SubjectWorkerHandraiseV1(taskIDHex), func(*nats.Msg) {
		received <- struct{}{}
	})
	if err != nil {
		t.Fatalf("subscribe observer: %v", err)
	}
	defer subscription.Unsubscribe()
	if err := observer.Flush(); err != nil {
		t.Fatalf("flush observer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, options{
			NATSServers:   []string{url},
			WorkerCount:   3,
			ResponseDelay: 0,
			Once:          true,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	count := 0
	for count < 3 {
		select {
		case <-ticker.C:
			if err := observer.Publish(subject, data); err != nil {
				t.Fatalf("publish order: %v", err)
			}
		case <-received:
			count++
		case <-ctx.Done():
			t.Fatalf("waiting for handraises: %v", ctx.Err())
		}
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("waiting for mock-cortex exit: %v", ctx.Err())
	}
}
