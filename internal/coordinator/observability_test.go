package coordinator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
)

type corePublishErrorBus struct {
	msgbus.Bus
	err error
}

func (b *corePublishErrorBus) Publish(string, []byte) error { return b.err }

func TestOnOrderPropagatesCoreNATSPublishFailure(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	bus := &corePublishErrorBus{
		Bus: msgbus.NewStub(log, nil),
		err: errors.New("nats server confirmation failed"),
	}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log),
		kv.NewMemStore(), testBuilderSelf, testChainID)
	enableTestBusEnvelopes(c)

	session := "session-publish-failure"
	task := testTaskID("publish-failure")
	err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress))
	if err == nil || !strings.Contains(err.Error(), "publish order broadcast") ||
		!strings.Contains(err.Error(), "nats server confirmation failed") {
		t.Fatalf("OnOrder error = %v, want confirmed NATS publish failure", err)
	}
	if _, ok := c.getFSM(session, task); ok {
		t.Fatal("failed OPEN_TASK publish left an active FSM")
	}
	gotLogs := logs.String()
	for _, want := range []string{
		`msg="bus publish failed"`,
		`phase=publish_order_broadcast`,
		`kind=BUS_MESSAGE_KIND_ORDER_BROADCAST`,
		`session_id=session-publish-failure`,
		`task_id=` + task,
	} {
		if !strings.Contains(gotLogs, want) {
			t.Fatalf("logs missing %q:\n%s", want, gotLogs)
		}
	}
}

func TestOnOrderLogsConfirmedCoreNATSPublish(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	bus := msgbus.NewStub(log, nil)
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log),
		kv.NewMemStore(), testBuilderSelf, testChainID)
	enableTestBusEnvelopes(c)

	session := "session-publish-success"
	task := testTaskID("publish-success")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	gotLogs := logs.String()
	for _, want := range []string{
		`msg="bus publish confirmed"`,
		`tier=core`,
		`confirmed=true`,
		`kind=BUS_MESSAGE_KIND_ORDER_BROADCAST`,
		`message_id=`,
		`session_id=session-publish-success`,
		`task_id=` + task,
	} {
		if !strings.Contains(gotLogs, want) {
			t.Fatalf("logs missing %q:\n%s", want, gotLogs)
		}
	}
}
