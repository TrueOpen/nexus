package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	wirebus "github.com/TrueOpen/wire/bus"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// TestWorkerHandraiseBridgeFromNATSToBroadcastTx is the end-to-end case for gh #23 acceptance 4:
// from a WorkerHandraise envelope on NATS all the way to the MsgSubmitWorkerHandraises that is
// actually broadcast, with no stubbing and no layer bypassed.
//
// The path: the SDK places an order (carrying a frozen SignedOrderV2) -> a real BusEnvelope is
// delivered over the bus -> taskFSM decodes/validates/deduplicates -> workerHandraiseScope +
// workerHandraisesV1 -> the real NewSignedSubmitter assembles and signs the Tx -> the broadcast
// bytes are intercepted by captureChain -> they are decoded back into MsgSubmitWorkerHandraises and
// asserted field by field.
//
// "Included in a block" can only go as far as CheckTx code=0 in this repository: a real DeliverTx
// needs a running Task Chain, which the repository does not have. So what is asserted here is that
// "the Tx assembled on the nexus side matches the frozen contract exactly and is accepted by the
// node interface"; on-chain inclusion has to be verified in the four-component integration
// environment.
func TestWorkerHandraiseBridgeFromNATSToBroadcastTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := msgbus.NewStub(log, nil)
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	c := New(log, bus, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log),
		kv.NewMemStore(), sg.Address(), testChainID)
	keys := enableTestBusEnvelopes(c)
	// The real submitter: full §4.2.1 validation + Cosmos signing + broadcast.
	c.submit = NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
		ChainID: testChainID, GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})

	session := "sess-bridge"
	task := testTaskID("task-bridge")
	order := testCurrentOrder(session, task, testUserAddress)
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}

	candidates := []string{testOperator("bridge-a"), testOperator("bridge-b"), testOperator("bridge-c")}
	for _, candidate := range candidates {
		publishEnvelope(t, bus, keys, candidate, msgbus.SubjectWorkerHandraiseV1(task),
			wirebus.KindWorkerHandraise, testWorkerHandraise(session, task, candidate))
	}

	if len(chain.broadcast) != 1 {
		t.Fatalf("broadcast count = %d, want 1 (the submission bridge is not wired up)", len(chain.broadcast))
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if len(body.Messages) != 1 || body.Messages[0].TypeUrl != chaincli.TypeURLMsgSubmitWorkerHandraises {
		t.Fatalf("messages: %+v", body.Messages)
	}

	// 1) Field numbers: scan the wire directly to confirm scope=1 / handraises=2 /
	// submitter_address=3. This is the core of #23 -- under the same type URL, misplaced field
	// numbers are rejected by the chain no matter how complete the content is.
	assertTopLevelFieldNumbers(t, body.Messages[0].Value, map[protowire.Number]protowire.Type{
		1: protowire.BytesType, // scope
		2: protowire.BytesType, // handraises (repeated message)
		3: protowire.BytesType, // submitter_address
	})

	var msg taskv1.MsgSubmitWorkerHandraises
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal msg: %v", err)
	}

	// 2) scope: the first proposal must take the signed_order branch, and it must be exactly what the
	// SDK sent.
	signedOrder := msg.GetScope().GetSignedOrder()
	if signedOrder == nil || msg.GetScope().GetExistingTask() != nil {
		t.Fatalf("first proposal scope = %+v, want signed_order", msg.GetScope())
	}
	relayed, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(signedOrder)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if !bytesEqual(relayed, order.SignedOrder) {
		t.Fatal("signed_order is not the one the SDK forwarded verbatim: the user signature covers the frozen TaskOrderV2, nexus must not rebuild it")
	}

	// 3) handraises: §5.5 states that a single proposal only needs 1 valid hand-raise, so the first
	// one to arrive triggers the proposal and the two that follow produce no new broadcast
	// (chain.broadcast stays 1). Sufficiency is decided by the keeper over the union of all Builder
	// proposals when the window closes; it is not padded here.
	if len(msg.GetHandraises()) != proposalHandraiseMin {
		t.Fatalf("handraises = %d, want %d", len(msg.GetHandraises()), proposalHandraiseMin)
	}
	wantTaskID, decodeErr := hex.DecodeString(task)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	// The task_hash that goes on chain must be the one derived from the user-signed order, never
	// swapped along the way (gh #42 acceptance 4: ORDER_BROADCAST -> WorkerHandraise -> Msg all carry
	// the same value).
	wantTaskHash, decodeErr := hex.DecodeString(order.TaskHash)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	previousSlot := -1
	seen := map[string]bool{}
	for i, hr := range msg.GetHandraises() {
		if slot := int(hr.GetMember().GetSlot()); slot <= previousSlot {
			t.Fatalf("handraise %d slot %d does not ascend past %d", i, slot, previousSlot)
		} else {
			previousSlot = slot
		}
		if hr.GetSchemaVersion() != 1 || hr.GetChainId() != testChainID ||
			hr.GetDuty() != sharedv1.Duty_DUTY_WORKER || hr.GetServiceAuthorizationNonce() != 7 ||
			hr.GetExpiryHeight() != 1000 {
			t.Fatalf("handraise %d frozen scalars: %+v", i, hr)
		}
		if !bytesEqual(hr.GetTaskId(), wantTaskID) || !bytesEqual(hr.GetTaskHash(), wantTaskHash) {
			t.Fatalf("handraise %d task binding: task_id=%x task_hash=%x", i, hr.GetTaskId(), hr.GetTaskHash())
		}
		if hr.GetModelId() != order.ModelID || hr.GetProfileVersion() != order.ProfileVersion {
			t.Fatalf("handraise %d model binding: %s/%d", i, hr.GetModelId(), hr.GetProfileVersion())
		}
		if len(hr.GetServiceSignature()) != 64 || len(hr.GetMember().GetCandidatePoolSnapshotId()) != 32 ||
			hr.GetMember().GetSlotVersion() == 0 {
			t.Fatalf("handraise %d member/signature shape: %+v", i, hr)
		}
		seen[hr.GetMember().GetOperatorAddress()] = true
	}
	// What reaches the chain must be the one that arrived first, and it must really come from this
	// NATS hand-raise set.
	if !seen[candidates[0]] {
		t.Fatalf("first handraise %q did not reach the chain message, seen=%v", candidates[0], seen)
	}

	if msg.GetSubmitterAddress() != sg.Address() {
		t.Fatalf("submitter_address = %q, want the Cosmos signer %q", msg.GetSubmitterAddress(), sg.Address())
	}
}

// TestWorkerHandraiseBridgeAcceptsFrozenOnlyOrder covers the kind of order the new ingress path
// actually produces: order_envelope holds a proto-encoded SignedOrderV2 and none of the old JSON
// envelope fields such as max_fee / infer_timeout_blocks. Those facts are already derived by the
// keeper from the signed order, so the old envelope cross-check must no longer block it.
func TestWorkerHandraiseBridgeAcceptsFrozenOnlyOrder(t *testing.T) {
	sub := &fakeSubmitter{}
	c, _ := newTestCoordinator(t)
	c.submit = sub

	session := "sess-frozen"
	task := testTaskID("task-frozen")
	signedOrder := testSignedOrderBytes(testUserAddress)
	// Keep only the fields ingress can fill from SignedOrderV2; leave the rest empty.
	order := types.Order{
		SessionID: session, TaskID: task, OrderSequence: 1,
		ModelID: "model-1", ProfileVersion: 2, TaskType: "text_generation",
		PayloadCID: "cid-in", User: testUserAddress,
		OrderEnvelope:   hex.EncodeToString(signedOrder),
		TaskHash:        testCanonicalTaskHash(testUserAddress),
		SignatureScheme: "eip712", UserSignature: hex.EncodeToString(append(bytes.Repeat([]byte{0x55}, 64), 27)),
		DeadlineHeight: 1000, ValidAfterHeight: 100,
		SignedOrder: signedOrder,
	}
	if err := c.OnOrder(context.Background(), order); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}
	for _, candidate := range []string{testOperator("frozen-a"), testOperator("frozen-b"), testOperator("frozen-c")} {
		fsm.onWorkerHandraise(testWorkerHandraise(session, task, candidate))
	}

	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.assign) != 1 {
		t.Fatalf("assign submissions = %d, want 1 (the frozen order was blocked by the old envelope validation)", len(sub.assign))
	}
	// §5.5: a single proposal needs at least 1 entry, so the first hand-raise triggers the proposal
	// and the two that follow open no new submission.
	if sub.assign[0].SignedOrder == nil || len(sub.assign[0].WorkerHandraises) != proposalHandraiseMin {
		t.Fatalf("assign tx = %+v", sub.assign[0])
	}
}

// TestWorkerHandraiseBridgeUsesExistingTaskAfterAcceptance covers the other half of §4.2.1: once
// the chain has accepted the task, later proposals must carry existing_task instead of another
// signed_order (filling both is rejected). The only criterion is the authoritative on-chain
// task_hash.
func TestWorkerHandraiseBridgeUsesExistingTaskAfterAcceptance(t *testing.T) {
	sub := &fakeSubmitter{}
	c, _ := newTestCoordinator(t)
	c.submit = sub

	session := "sess-existing"
	task := testTaskID("task-existing")
	if err := c.OnOrder(context.Background(), testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	fsm, ok := c.getFSM(session, task)
	if !ok {
		t.Fatal("task FSM was not created")
	}

	acceptedTaskHash := testHash32("accepted-task-hash", task)
	c.applyAuthoritativeTask(fsm, chaincli.OnChainTask{
		SessionID: session, TaskID: task, State: types.Pending,
		Assignment: chaincli.TaskAssignmentState{AcceptedTaskHash: acceptedTaskHash},
	}, 500)

	for _, candidate := range []string{testOperator("existing-a"), testOperator("existing-b"), testOperator("existing-c")} {
		fsm.onWorkerHandraise(testWorkerHandraise(session, task, candidate))
	}

	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.assign) != 1 {
		t.Fatalf("assign submissions = %d, want 1", len(sub.assign))
	}
	tx := sub.assign[0]
	if tx.SignedOrder != nil {
		t.Fatal("follow-up proposal must not repeat signed_order")
	}
	if tx.ExistingTask == nil || hex.EncodeToString(tx.ExistingTask.GetTaskHash()) != acceptedTaskHash ||
		hex.EncodeToString(tx.ExistingTask.GetTaskId()) != task {
		t.Fatalf("existing_task = %+v", tx.ExistingTask)
	}
}

// TestWorkerHandraiseBridgeRefusesFirstProposalWithoutSignedOrder pins the boundary: while the SDK
// is still sending the old JSON envelope, nexus would rather submit nothing than make up an order
// of its own.
func TestWorkerHandraiseBridgeRefusesFirstProposalWithoutSignedOrder(t *testing.T) {
	sub := &fakeSubmitter{}
	c, _ := newTestCoordinator(t)
	c.submit = sub

	session := "sess-legacy"
	task := testTaskID("task-legacy")
	order := testCurrentOrder(session, task, testUserAddress)
	order.SignedOrder = nil // the old JSON envelope path
	// After the bus format migration the fail-closed point moved earlier: without a frozen
	// SignedOrderV2 not even ORDER_BROADCAST can be assembled (the payload is the signed_order
	// itself), so OnOrder rejects outright and no task is created.
	if err := c.OnOrder(context.Background(), order); err == nil {
		t.Fatal("legacy order without SignedOrderV2 must fail closed at OnOrder")
	}
	if _, ok := c.getFSM(session, task); ok {
		t.Fatal("legacy order must not leave an active FSM")
	}
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.assign) != 0 {
		t.Fatalf("assign submissions = %d, want 0 (signed_order must not be forged)", len(sub.assign))
	}
}

// assertTopLevelFieldNumbers scans the proto wire and asserts that the top-level field numbers and
// wire types match the frozen contract exactly. Decoding into Go structs cannot reveal misplaced
// field numbers -- both sides use the same mirror.
func assertTopLevelFieldNumbers(t *testing.T, raw []byte, want map[protowire.Number]protowire.Type) {
	t.Helper()
	got := map[protowire.Number]protowire.Type{}
	for len(raw) > 0 {
		number, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatalf("consume tag: %v", protowire.ParseError(n))
		}
		raw = raw[n:]
		got[number] = typ
		size := protowire.ConsumeFieldValue(number, typ, raw)
		if size < 0 {
			t.Fatalf("consume field %d: %v", number, protowire.ParseError(size))
		}
		raw = raw[size:]
	}
	if len(got) != len(want) {
		t.Fatalf("top level fields = %v, want %v", got, want)
	}
	for number, typ := range want {
		if got[number] != typ {
			t.Fatalf("field %d wire type = %v, want %v (field number differs from the frozen contract)", number, got[number], typ)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
