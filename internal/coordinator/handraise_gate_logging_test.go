package coordinator

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	wirebus "github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// TestHandraiseGatesAreVisibleAtInfo pins that each of the three submit gates leaves a trace.
//
// Before this fix, `len(workerHR) < min || assignSubmitted || !inProposalGroup` was folded into
// one condition with a silent return: when a task stalled at "collecting hand-raises", the three
// causes looked identical in the logs -- nothing was logged. Integration debugging was guesswork.
func TestHandraiseGatesAreVisibleAtInfo(t *testing.T) {
	session := "sess-gate"
	task := testTaskID("task-gate")

	newCoordinator := func(t *testing.T, buf *bytes.Buffer, self string) *Coordinator {
		t.Helper()
		log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		return New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}),
			relay.NewMem(log), kv.NewMemStore(), self, testChainID)
	}

	t.Run("accepted handraise is visible", func(t *testing.T) {
		var buf bytes.Buffer
		c := newCoordinator(t, &buf, testBuilderSelf)
		keys := enableTestBusEnvelopes(c)
		if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
			t.Fatalf("OnOrder: %v", err)
		}
		publishEnvelope(t, c.bus, keys, testOperator("worker-1"), msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, testOperator("worker-1")))

		if !strings.Contains(buf.String(), "worker handraise accepted") {
			t.Fatalf("accepted hand-raise not visible at Info level:\n%s", buf.String())
		}
		// The §5.5 threshold is 1, so the first one is enough to propose; no "N more needed" should appear.
		if strings.Contains(buf.String(), "waiting for more worker handraises") {
			t.Fatalf("with proposalHandraiseMin=1 it must not wait for more hand-raises:\n%s", buf.String())
		}
	})

	t.Run("not in proposal group is visible", func(t *testing.T) {
		var buf bytes.Buffer
		// self is not in the order's builder_set -- the proposal is submitted by a group member, so this
		// node keeps collecting hand-raises but never submits. That is by design, but it must be visible.
		c := newCoordinator(t, &buf, testOperator("builder-outsider"))
		keys := enableTestBusEnvelopes(c)
		c.active.Update(1, []types.BuilderRef{
			{Address: "builder-a"}, {Address: "builder-b"}, {Address: "builder-c"},
		}, testBuilderSetRef)
		if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
			t.Fatalf("OnOrder: %v", err)
		}
		publishEnvelope(t, c.bus, keys, testOperator("worker-1"), msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, testOperator("worker-1")))

		if !strings.Contains(buf.String(), "not in the task's proposal group") {
			t.Fatalf("not being in the proposal group is not visible at Info level:\n%s", buf.String())
		}
	})
}

// TestSingleHandraiseIsEnoughToPropose pins the §5.5 threshold itself.
//
// This used to be hard-coded to 3, which moved the on-chain "sufficiency" decision to a local one
// with narrower input: when three Task Builders each receive 1 distinct hand-raise, the union of 3
// is plenty, but under the local threshold nobody submits and the task can only time out. The spec
// leaves sufficiency to the Keeper, evaluated on the accumulated union bitmap when the window closes.
func TestSingleHandraiseIsEnoughToPropose(t *testing.T) {
	if proposalHandraiseMin != 1 {
		t.Fatalf("Interface & Topic Catalogue §5.5 requires a single proposal to need only 1 hand-raise, current threshold = %d", proposalHandraiseMin)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	sub := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub

	session := "sess-single"
	task := testTaskID("task-single")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	publishEnvelope(t, bus, keys, testOperator("worker-1"), msgbus.SubjectWorkerHandraiseV1(task),
		wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, testOperator("worker-1")))

	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.assign) != 1 {
		t.Fatalf("one valid hand-raise should trigger a proposal, got %d submissions", len(sub.assign))
	}
	if len(sub.assign[0].WorkerHandraises) != 1 {
		t.Fatalf("proposal carries %d hand-raises, want 1", len(sub.assign[0].WorkerHandraises))
	}
}
