package coordinator

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	wirebus "github.com/TrueOpen/wire/bus"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// TestRealNATSHappyPath runs the full order orchestration happy path against a REAL NATS server:
// nexus sends OrderBroadcast / AssignNotify / VerifySelectNotify over the real bus, the test plays
// cortex and replies with hand-raises / V_i over the real bus, with network round trips throughout.
// It runs only when NEXUS_NATS_TEST_URL is set.
//
// How to run:
//
//	NEXUS_NATS_TEST_URL=127.0.0.1:4222 \
//	NEXUS_NATS_TEST_USER=<user> NEXUS_NATS_TEST_PASS=<password> \
//	go test ./internal/coordinator -run TestRealNATSHappyPath -v -count=1
func TestRealNATSHappyPath(t *testing.T) {
	url := os.Getenv("NEXUS_NATS_TEST_URL")
	if url == "" {
		t.Skip("set NEXUS_NATS_TEST_URL to run the real-NATS e2e test")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewNATS(log, config.NATSConfig{
		Servers:  []string{url},
		User:     os.Getenv("NEXUS_NATS_TEST_USER"),
		Password: os.Getenv("NEXUS_NATS_TEST_PASS"),
	})
	if err := bus.Start(context.Background()); err != nil {
		t.Fatalf("bus start: %v", err)
	}
	defer bus.Stop(context.Background())

	// A unique ID isolates each run (JetStream messages persist for 24h).
	run := time.Now().UnixNano()
	session := fmt.Sprintf("sess-e2e-%d", run)
	// task_id must be a real-shaped Hash32: the frozen contract's WorkerHandraiseV1.task_id is 32
	// bytes, and a fake ID cannot form a proposal.
	task := testTaskID(fmt.Sprintf("task-e2e-%d", run))
	model := "model-1"
	winner := testOperator("worker-1")

	rl := relay.NewMem(log)
	sub := &fakeSubmitter{}
	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), rl, kv.NewMemStore(), testOperator("builder-e2e"), testChainID)
	keys := enableTestBusEnvelopes(c)
	c.submit = sub

	// Observe the four contract subjects nexus publishes on (a JS publish is equally visible to core
	// subscribers).
	orders, assign, verifySelect, openVerify := &captured{}, &captured{}, &captured{}, &captured{}
	mustSub(t, bus, msgbus.SubjectTaskOpen(model), orders)
	mustSub(t, bus, msgbus.SubjectWorkerAssignment(task), assign)
	mustSub(t, bus, msgbus.SubjectVerifierAssignment(task), verifySelect)
	mustSub(t, bus, msgbus.SubjectVerifyOpen(task), openVerify)
	time.Sleep(300 * time.Millisecond) // let the subscriptions take effect on the server

	ctx := context.Background()

	// 1) Place the order -> nexus broadcasts OrderBroadcast over real NATS
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	waitFor(t, "OrderBroadcast arrives over real NATS", func() bool { return orders.count() >= 1 })
	ob := decodeTestPayload[busv1.OrderBroadcastV1](t, orders.last())
	if ob.GetSignedOrder().GetOrder() == nil {
		t.Fatalf("OrderBroadcast mismatch: %+v", ob)
	}
	t.Logf("✅ OrderBroadcast real round trip ok (subject=%s)", msgbus.SubjectTaskOpen(model))
	time.Sleep(300 * time.Millisecond) // wait for nexus's hand-raise subscription to take effect

	// 2) Simulate 3 Workers raising hands over real NATS -> triggers AssignTx
	for _, cand := range []string{testOperator("worker-1"), testOperator("worker-2"), testOperator("worker-3")} {
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, cand))
	}
	waitFor(t, "hand-raises collected and AssignTx submitted", func() bool { sub.mu.Lock(); defer sub.mu.Unlock(); return len(sub.assign) == 1 })
	t.Log("✅ 3×WorkerHandraise real round trip -> AssignTx submitted")

	// 3) Chain events (two phases): AssignAccepted only enters randomness pending (no start notice);
	// only after AssignmentFinalized does nexus send AssignNotify over JetStream.
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 100})
	time.Sleep(500 * time.Millisecond)
	if assign.count() != 0 {
		t.Fatalf("AssignNotify must not be sent before finalize, got %d", assign.count())
	}
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: winner, Height: 101})
	waitFor(t, "AssignNotify arrives over JetStream", func() bool { return assign.count() >= 1 })
	an := decodeTestPayload[busv1.WorkerAssignmentNotifyV1](t, assign.last())
	if an.GetWinnerOperatorAddress() != winner || an.GetFinalizedHeight() != 101 {
		t.Fatalf("AssignNotify mismatch: %+v", an)
	}
	t.Logf("✅ two-phase assignment ok: no start notice before finalize; AssignNotify(JS) real round trip (winner=%s)", an.GetWinnerOperatorAddress())
	time.Sleep(300 * time.Millisecond) // wait for the verifier hand-raise + verify-result(durable) subscriptions to take effect

	// 4) The Worker returns the result reference
	outputHash := []byte("output-root-e2e")
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, winner, outputHash)); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}

	// 5) Simulate 3 Verifiers raising hands over real NATS -> triggers OpenVerifyTx
	for _, cand := range []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")} {
		publishEnvelope(t, bus, keys, cand, msgbus.SubjectVerifierHandraiseV1(task),
			wirebus.KindVerifierHandraise,
			testVerifierHandraise(session, task, cand, outputHash, []byte("infer-receipt")))
	}
	waitFor(t, "Verifier hand-raises collected and OpenVerifyTx submitted", func() bool { sub.mu.Lock(); defer sub.mu.Unlock(); return len(sub.openVerify) == 1 })
	t.Log("✅ 3×VerifierHandraise real round trip -> OpenVerifyTx submitted")

	// 6) Chain event: open-verify is included in a block -> nexus sends VERIFIER_ASSIGNMENT_NOTIFY
	// over JetStream.
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task,
		Verifiers: []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")},
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: rankRevealDeadline, Verify: rankVerifyDeadline},
		Height:    200,
	})
	waitFor(t, "VerifySelectNotify arrives over JetStream", func() bool { return verifySelect.count() >= 1 })
	t.Log("✅ VerifySelectNotify(JS, no seed) real round trip ok")

	// The on-chain SampleReady only records the seed: contract §5.1 has no trueopen.sample-ready.*.
	c.OnSampleReady(chaincli.SampleReady{SessionID: session, TaskID: task, SampleSeed: []byte("seed-e2e"), ReadyHeight: 210, Height: 211})
	time.Sleep(300 * time.Millisecond)
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("fsm missing before settle selection")
	}
	fsm.mu.Lock()
	fsm.settleSelection = settleSelection(session, task, testBuilderSelf)
	fsm.settleGraceBlocks = rankGraceBlocks
	fsm.mu.Unlock()

	// 7) Simulate 2 Verifiers returning matching V_i over JetStream (the coordinator receives them
	// with a durable consumer)
	vi := [][]byte{[]byte("v0"), []byte("v1")}
	for _, v := range []string{testOperator("verifier-1"), testOperator("verifier-2")} {
		subject := msgbus.SubjectVerifyResultV1(task)
		wire := signTestEnvelope(t, keys, wirebus.ParticipantCortex, v, subject,
			wirebus.KindVerifyResult, testVerifyResult(task, v, vi), nil)
		// Contract §5.12: Nats-Msg-Id = the envelope message_id.
		if err := bus.JSPublish(subject, wire, decodeTestEnvelope(t, wire).GetMessageId()); err != nil {
			t.Fatalf("JS publish verify-result: %v", err)
		}
	}
	// 8) Once the coordinator has 2 matching V_i it submits SettleTx; normal verification has no
	// Worker reveal step. Settlement timing follows the chain height (§10.10a): feed one new block
	// per round until the V_i are complete and the height enters this node's slot.
	settleHeight := int64(rankRevealDeadline)
	waitFor(t, "SettleTx submitted (2 matching V_i)", func() bool {
		settleHeight++
		c.onNewBlock(settleHeight)
		sub.mu.Lock()
		defer sub.mu.Unlock()
		return len(sub.settle) >= 1
	})
	sub.mu.Lock()
	settleTx := sub.settle[0]
	sub.mu.Unlock()
	if settleTx.TaskID != task {
		t.Fatalf("SettleTx task binding mismatch: %+v", settleTx)
	}
	t.Log("✅ 2×VerifyResult(JS durable) real round trip -> SettleTx submitted")

	// 9) The settlement is included in a block -> Settled
	c.OnSettleAccepted(chaincli.SettleAccepted{SessionID: session, TaskID: task, TaskVerdict: types.VerdictPass,
		Settlement: chaincli.TaskSettlementState{
			SettlementStatus: "SETTLED_PASS", SettlementHeight: 400, TaskFinalityHeight: 600,
		}, Height: 400})
	assertState(t, c, session, task, types.Settled)
	t.Log("✅ full-path (real NATS) happy path complete: PENDING->ASSIGNED->VERIFYING->SETTLED")
}

// waitFor polls until the condition holds or it times out (real network, asynchronous delivery).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", what)
}
