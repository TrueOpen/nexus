package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/types"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// wireDispatchVector is one signed message of wire testdata/v1/task/dispatch_v1.json.
type wireDispatchVector struct {
	Name         string `json:"name"`
	MessageName  string `json:"message_name"`
	ProtobufHex  string `json:"protobuf_hex"`
	DigestHex    string `json:"digest_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
}

func loadWireDispatchVector(t *testing.T, name string) wireDispatchVector {
	t.Helper()
	var file struct {
		Vectors []wireDispatchVector `json:"vectors"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/dispatch_v1.json"), &file); err != nil {
		t.Fatalf("decode dispatch vectors: %v", err)
	}
	for _, vector := range file.Vectors {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("dispatch vector %q not found", name)
	return wireDispatchVector{}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return raw
}

// The Builder messages to Cortex are signed over the wire signing digest: the nexus mirror decodes
// the wire vector's encoding, re-encodes it byte for byte, and builderMessageDigest reproduces the
// vector's digest, under which the vector's signature verifies.
func TestBuilderMessageDigestMatchesWireVectors(t *testing.T) {
	cases := []struct {
		vector string
		msg    proto.Message
	}{
		{"nexus_v1_openverifyv1", &nexusv1.OpenVerifyV1{}},
		{"open_verify_conflicting_output", &nexusv1.OpenVerifyV1{}},
		{"nexus_v1_verifierassignmentnotifyv1", &nexusv1.VerifierAssignmentNotifyV1{}},
	}
	for _, tc := range cases {
		t.Run(tc.vector, func(t *testing.T) {
			vector := loadWireDispatchVector(t, tc.vector)
			raw := mustDecodeHex(t, vector.ProtobufHex)
			if err := proto.Unmarshal(raw, tc.msg); err != nil {
				t.Fatalf("decode %s: %v", vector.MessageName, err)
			}
			if name := string(tc.msg.ProtoReflect().Descriptor().FullName()); name != vector.MessageName {
				t.Fatalf("message = %s, vector names %s", name, vector.MessageName)
			}
			again, err := proto.MarshalOptions{Deterministic: true}.Marshal(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(again) != vector.ProtobufHex {
				t.Fatalf("re-encoding differs from the wire vector:\n got %x\nwant %s", again, vector.ProtobufHex)
			}
			digest, err := builderMessageDigest(vector.MessageName, tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest[:]) != vector.DigestHex {
				t.Fatalf("digest = %x, want %s", digest, vector.DigestHex)
			}
			if err := dispatch.VerifyDigestSignature(mustDecodeHex(t, vector.PublicKeyHex), digest[:],
				mustDecodeHex(t, vector.SignatureHex)); err != nil {
				t.Fatalf("vector signature does not verify under the reproduced digest: %v", err)
			}
		})
	}
}

// Without a service key, or without a CortexLink, a Builder message is neither signed nor sent:
// there is no unsigned fallback.
func TestBuilderMessagesRefuseToSendUnsigned(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	link := &fakeCortexLink{}
	c.cortex = link
	messages := builderMessages{coord: c}
	if err := messages.signOpenVerify(context.Background(), &nexusv1.OpenVerifyV1{}, 1); !errors.Is(err, errBuilderMessageUnsigned) {
		t.Fatalf("signOpenVerify without a service key = %v, want errBuilderMessageUnsigned", err)
	}
	if err := (builderMessages{}).signVerifierAssignment(context.Background(), &nexusv1.VerifierAssignmentNotifyV1{}, 1); !errors.Is(err, errBuilderMessageUnsigned) {
		t.Fatalf("signVerifierAssignment without a coordinator = %v, want errBuilderMessageUnsigned", err)
	}

	keys, _ := enableTestBuilderMessages(c)
	c.cortex = nil
	if err := messages.broadcast(context.Background(), &nexusv1.DispatchStreamFrameV1{}); err == nil {
		t.Fatal("broadcast without a CortexLink must fail")
	}
	// A revoked on-chain binding cannot sign either.
	keys.revoke(servicekey.ParticipantBuilder, c.active.self)
	if err := messages.signOpenVerify(context.Background(), &nexusv1.OpenVerifyV1{}, 1); !errors.Is(err, errBuilderMessageUnsigned) {
		t.Fatalf("signOpenVerify with a revoked binding = %v, want errBuilderMessageUnsigned", err)
	}
	if len(link.frames) != 0 {
		t.Fatalf("frames sent = %d, want 0", len(link.frames))
	}
}

// While this Builder's key replacement is pending, Verifier messages of a Task recorded at or after
// the block before its registration are not signed (the other group members send them); an older
// Task's are signed with the current nonce.
func TestBuilderMessagesDuringOwnKeyRotation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(), testBuilderSelf, testChainID)
	keys, _ := enableTestBuilderMessages(c)
	keys.setPending(servicekey.ParticipantBuilder, c.active.self, &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: testAuthorizationNo + 1, RegisteredHeight: 100})
	messages := builderMessages{coord: c}
	ctx := context.Background()

	raw32 := make([]byte, 32)
	old := &nexusv1.OpenVerifyV1{
		TaskId: raw32, TaskHash: raw32, ModelId: raw32, ProfileVersion: 1, InferReceiptHash: raw32, OutputHash: raw32,
		WorkerOperatorAddress: testBuilderSelf, VerifyRound: 1,
	}
	if err := messages.signOpenVerify(ctx, old, 98); err != nil {
		t.Fatalf("task recorded before the rotation: %v", err)
	}
	signature := old.GetBuilderServiceSignature()
	old.BuilderServiceSignature = nil
	assertBuilderSigned(t, c, "nexus.v1.OpenVerifyV1", old, old.GetBinding(), signature)
	for _, height := range []uint64{99, 100, 150, 0} {
		if err := messages.signOpenVerify(ctx, &nexusv1.OpenVerifyV1{}, height); !errors.Is(err, errRotationPendingTask) {
			t.Fatalf("OpenVerify of a task recorded at %d = %v, want errRotationPendingTask", height, err)
		}
		if err := messages.signVerifierAssignment(ctx, &nexusv1.VerifierAssignmentNotifyV1{}, height); !errors.Is(err, errRotationPendingTask) {
			t.Fatalf("VerifierAssignmentNotify of a task recorded at %d = %v, want errRotationPendingTask", height, err)
		}
	}
	keys.setPending(servicekey.ParticipantBuilder, c.active.self, nil)
	old.Binding, old.BuilderServiceSignature = nil, nil
	if err := messages.signOpenVerify(ctx, old, 150); err != nil {
		t.Fatalf("after the rotation cleared: %v", err)
	}
}

// HandleVerifierHandraise takes a handraise only from the Cortex that raised it, for a live task.
func TestHandleVerifierHandraiseChecksTheStreamOperator(t *testing.T) {
	fx := newVerifierProposalFixture(t, "cortex-handraise")
	ctx := context.Background()
	verifier := testOperator("verifier-1")
	hr := testVerifierHandraise(fx.session, fx.task, verifier, fx.output, fx.receipt)

	if err := fx.c.HandleVerifierHandraise(ctx, testOperator("someone-else"), hr); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("handraise from another Cortex = %v, want ErrUnauthorized", err)
	}
	if err := fx.c.HandleVerifierHandraise(ctx, verifier, nil); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("nil handraise = %v, want ErrInvalidArgument", err)
	}
	unknown := testVerifierHandraise("sess-unknown", testTaskID("unknown"), verifier, fx.output, fx.receipt)
	if err := fx.c.HandleVerifierHandraise(ctx, verifier, unknown); err == nil {
		t.Fatal("handraise for an unknown task must be refused")
	}
	short := testVerifierHandraise(fx.session, fx.task, verifier, fx.output, fx.receipt)
	short.TaskId = short.TaskId[:31]
	if err := fx.c.HandleVerifierHandraise(ctx, verifier, short); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("short task_id = %v, want ErrInvalidArgument", err)
	}
	fx.fsm.mu.Lock()
	collected := len(fx.fsm.verifierHR)
	fx.fsm.mu.Unlock()
	if collected != 0 {
		t.Fatalf("refused handraises were collected: %d", collected)
	}

	if err := fx.c.HandleVerifierHandraise(ctx, verifier, hr); err != nil {
		t.Fatalf("handraise from its own Cortex: %v", err)
	}
	fx.fsm.mu.Lock()
	_, ok := fx.fsm.verifierHR[verifier]
	fx.fsm.mu.Unlock()
	if !ok {
		t.Fatal("the handraise was not collected")
	}
}

// A selected Verifier's VerifyResultSubmitted notice only wakes this Builder up: it asks for a
// reconcile of the task and records nothing. A notice from anyone else is refused.
func TestHandleVerifyResultSubmittedOnlyRequestsReconcile(t *testing.T) {
	c, _ := newTestCoordinator(t)
	const session = "sess-verify-notice"
	task := testTaskID("verify-notice")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2")}
	verifyingTask(t, c, session, task, verifiers)
	fsm, _ := c.getFSM(session, task)
	ctx := context.Background()
	notice := func(operator string) *nexusv1.VerifyResultSubmittedNoticeV1 {
		return &nexusv1.VerifyResultSubmittedNoticeV1{
			TaskId: mustHex32(task), TaskHash: fsm.taskHashBytes(),
			VerifyRound: uint32(nodecontract.SupportedVerifyRoundV1), OperatorAddress: operator,
		}
	}

	if err := c.HandleVerifyResultSubmitted(ctx, verifiers[1], notice(verifiers[0])); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("notice relayed by another Cortex = %v, want ErrUnauthorized", err)
	}
	stranger := testOperator("stranger")
	if err := c.HandleVerifyResultSubmitted(ctx, stranger, notice(stranger)); !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("notice from a non-selected verifier = %v, want ErrUnauthorized", err)
	}
	wrongHash := notice(verifiers[0])
	wrongHash.TaskHash = make([]byte, 32)
	if err := c.HandleVerifyResultSubmitted(ctx, verifiers[0], wrongHash); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("notice for another task_hash = %v, want ErrInvalidArgument", err)
	}
	wrongRound := notice(verifiers[0])
	wrongRound.VerifyRound = 2
	if err := c.HandleVerifyResultSubmitted(ctx, verifiers[0], wrongRound); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("notice for an unsupported round = %v, want ErrInvalidArgument", err)
	}

	if err := c.HandleVerifyResultSubmitted(ctx, verifiers[0], notice(verifiers[0])); err != nil {
		t.Fatalf("notice from a selected verifier: %v", err)
	}
	fsm.mu.Lock()
	recorded := len(fsm.verifyResults)
	fsm.mu.Unlock()
	if recorded != 0 {
		t.Fatalf("a notice recorded %d verify results; it must only trigger a chain read", recorded)
	}
	c.reconcilePendingMu.Lock()
	_, queued := c.reconcilePending[reconcileRequestKey(reconcileRequest{sessionID: session, taskID: task})]
	c.reconcilePendingMu.Unlock()
	if !queued {
		t.Fatal("the notice did not request a reconcile of the task")
	}
}

// Before this Builder has seen the assignment the task is still Assigned and the selected set is
// unknown here: a notice is then taken as the wake-up it is, from any Cortex, and asks for a
// reconcile. A task that has no winner yet takes no notice.
func TestHandleVerifyResultSubmittedInAssignedRequestsReconcile(t *testing.T) {
	c, _ := newTestCoordinator(t)
	const session = "sess-verify-notice-assigned"
	task := testTaskID("verify-notice-assigned")
	if err := trackTestOrder(c, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatal(err)
	}
	fsm, _ := c.getFSM(session, task)
	verifier := testOperator("verifier-1")
	notice := &nexusv1.VerifyResultSubmittedNoticeV1{
		TaskId: mustHex32(task), TaskHash: fsm.taskHashBytes(),
		VerifyRound: uint32(nodecontract.SupportedVerifyRoundV1), OperatorAddress: verifier,
	}
	ctx := context.Background()
	if err := c.HandleVerifyResultSubmitted(ctx, verifier, notice); !errors.Is(err, types.ErrFailedPrecondition) {
		t.Fatalf("notice for a Pending task = %v, want ErrFailedPrecondition", err)
	}
	recordTestWinner(c, session, task, testOperator("worker-1"), 101)
	if err := c.HandleVerifyResultSubmitted(ctx, verifier, notice); err != nil {
		t.Fatalf("notice for an Assigned task: %v", err)
	}
	c.reconcilePendingMu.Lock()
	_, queued := c.reconcilePending[reconcileRequestKey(reconcileRequest{sessionID: session, taskID: task})]
	c.reconcilePendingMu.Unlock()
	if !queued {
		t.Fatal("the notice did not request a reconcile of the Assigned task")
	}
}

// A closed task leaves its verification round: its Verifier broadcasts are retired, so streams
// that connect later are not given them.
func TestClosedTaskRetiresItsVerifierBroadcasts(t *testing.T) {
	c, _ := newTestCoordinator(t)
	link := c.cortex.(*fakeCortexLink)
	const session = "sess-retire"
	task := testTaskID("retire")
	verifyingTask(t, c, session, task, []string{testOperator("verifier-1")})
	fsm, _ := c.getFSM(session, task)
	if len(link.retiredRounds()) != 0 {
		t.Fatalf("retired before close: %v", link.retiredRounds())
	}
	if !fsm.closeGone(300) {
		t.Fatal("task did not close")
	}
	want := hex.EncodeToString(mustHex32(task)) + "/1"
	if got := link.retiredRounds(); len(got) != 1 || got[0] != want {
		t.Fatalf("retired %v, want [%s]", got, want)
	}
}
