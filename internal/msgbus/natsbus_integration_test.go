package msgbus

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/config"
)

// TestNATSIntegration connects to a real NATS to check the core and JetStream round-trips plus dedup.
// It only runs when NEXUS_NATS_TEST_URL is set, and skips otherwise (so it does not slow down regular CI).
//
// How to run:
//
//	NEXUS_NATS_TEST_URL=<host>:4222 \
//	NEXUS_NATS_TEST_USER=<user> NEXUS_NATS_TEST_PASS=<password> \
//	go test ./internal/msgbus -run TestNATSIntegration -v
func TestNATSIntegration(t *testing.T) {
	url := os.Getenv("NEXUS_NATS_TEST_URL")
	if url == "" {
		t.Skip("set NEXUS_NATS_TEST_URL to run the real-NATS integration test")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := NewNATS(log, config.NATSConfig{
		Servers:  []string{url},
		User:     os.Getenv("NEXUS_NATS_TEST_USER"),
		Password: os.Getenv("NEXUS_NATS_TEST_PASS"),
	})
	if err := bus.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer bus.Stop(context.Background())

	// Use a unique task-id per run: JetStream FileStorage is durable for 24h, so a fixed id would replay the
	// previous run's messages to a freshly created durable consumer (DeliverAll) and cause cross-run interference.
	taskID := fmt.Sprintf("task-it-%d", time.Now().UnixNano())

	// ---- core round-trip ----
	got := make(chan []byte, 1)
	unsub, err := bus.Subscribe(SubjectWorkerHandraiseV1(taskID), func(_ string, d []byte) error {
		got <- d
		return nil
	})
	if err != nil {
		t.Fatalf("core subscribe: %v", err)
	}
	defer unsub()
	time.Sleep(200 * time.Millisecond) // let the subscription take effect

	if err := bus.Publish(SubjectWorkerHandraiseV1(taskID), []byte("hello")); err != nil {
		t.Fatalf("core publish: %v", err)
	}
	select {
	case d := <-got:
		if string(d) != "hello" {
			t.Fatalf("core payload = %q, want hello", d)
		}
		t.Log("✅ core round-trip ok")
	case <-time.After(5 * time.Second):
		t.Fatal("core round-trip timeout")
	}

	// ---- JetStream round-trip + dedup ----
	jsGot := make(chan []byte, 8)
	jsUnsub, err := bus.JSSubscribe(SubjectWorkerAssignment(taskID), DurableConsumer("it", "assign-"+taskID),
		func(_ string, d []byte) error {
			jsGot <- d
			return nil
		})
	if err != nil {
		t.Skipf("JetStream unavailable (core already passed): %v", err)
	}
	defer jsUnsub()
	time.Sleep(200 * time.Millisecond)

	// Contract §5.12: Nats-Msg-Id = envelope message_id, and a retry reuses the same id.
	// Generating message_id moved into busadapter with the envelope change; this test only exercises broker
	// dedup, so a UUID text of fixed shape is enough.
	messageID := "01890000-0000-7000-8000-00000000abcd"
	if err := bus.JSPublish(SubjectWorkerAssignment(taskID), []byte("assign1"), messageID); err != nil {
		t.Fatalf("js publish #1: %v", err)
	}
	if err := bus.JSPublish(SubjectWorkerAssignment(taskID), []byte("assign1"), messageID); err != nil {
		t.Fatalf("js publish #2 (same message_id): %v", err)
	}

	// Publishing the same message_id twice must deliver only one message.
	n := 0
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-jsGot:
			n++
		case <-deadline:
			if n != 1 {
				t.Fatalf("JS dedup: received %d messages, want 1 (dedup in effect)", n)
			}
			t.Log("✅ JetStream round-trip + dedup ok")
			return
		}
	}
}
