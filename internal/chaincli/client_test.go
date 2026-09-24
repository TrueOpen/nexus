package chaincli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	tmtypes "cosmossdk.io/api/tendermint/types"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/types"
)

func TestProfileVersionWireTypesMatchNode(t *testing.T) {
	tests := []struct {
		name  string
		field protoreflect.FieldDescriptor
	}{
		{"hub profile", (&hubv1.ProfileState{}).ProtoReflect().Descriptor().Fields().ByName("profile_version")},
		{"hub previous profile", (&hubv1.ProfileState{}).ProtoReflect().Descriptor().Fields().ByName("previous_profile_version")},
		{"hub profile request", (&hubv1.QueryProfileRequest{}).ProtoReflect().Descriptor().Fields().ByName("profile_version")},
		{"task core", (&taskv1.TaskCoreState{}).ProtoReflect().Descriptor().Fields().ByName("profile_version")},
		{"task assignment view", (&taskv1.WorkerHandraiseV1{}).ProtoReflect().Descriptor().Fields().ByName("profile_version")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.field == nil {
				t.Fatal("profile_version field is missing")
			}
			if test.field.Kind() != protoreflect.Uint32Kind {
				t.Fatalf("profile_version kind = %v, want uint32", test.field.Kind())
			}
		})
	}
}

func TestCurrentNodeQueryWireFields(t *testing.T) {
	profile := (&hubv1.ProfileState{}).ProtoReflect().Descriptor()
	assertNodeField(t, profile, 3, "manifest_hash", protoreflect.BytesKind, false, "")
	assertNodeField(t, profile, 9, "resource_tier", protoreflect.Uint32Kind, false, "")
	assertNodeField(t, profile, 18, "status", protoreflect.EnumKind, false, "hub.v1.ModelProfileStatus")
	assertNodeField(t, profile, 28, "updated_height", protoreflect.Uint64Kind, false, "")

	// Frozen contract QueryTask projection: TaskAssignmentViewV1 replaced the old monolithic TaskAssignment.
	assignment := (&taskv1.TaskAssignmentViewV1{}).ProtoReflect().Descriptor()
	assertNodeField(t, assignment, 12, "profile_execution_snapshot_hash", protoreflect.BytesKind, false, "")
	assertNodeField(t, assignment, 16, "generation_params_digest", protoreflect.BytesKind, false, "")
	assertNodeField(t, assignment, 18, "assignment_status", protoreflect.EnumKind, false, "task.v1.AssignmentStatus")

	// The event model is unified on shared.v1.ProtocolEventCodeV1 (since wire v0.4.1
	// the event code registry lives in shared) + typed payload oneof.
	envelope := (&taskv1.TaskEvent{}).ProtoReflect().Descriptor()
	assertNodeField(t, envelope, 8, "session_id", protoreflect.BytesKind, false, "")
	assertNodeField(t, envelope, 15, "code", protoreflect.EnumKind, false, "shared.v1.ProtocolEventCodeV1")
	assertNodeField(t, envelope, 17, "payload", protoreflect.MessageKind, false, "task.v1.TaskProtocolEventPayloadV1")

	// current service key query: participant_type is an enum (varint), not a string
	// (length-delimited). These two guard against "no falling back to the string domain":
	// a fallback would make the request unsendable.
	keyRequest := (&hubv1.QueryCurrentServiceKeyRequest{}).ProtoReflect().Descriptor()
	assertNodeField(t, keyRequest, 1, "participant_type", protoreflect.EnumKind, false, "shared.v1.ParticipantType")
	keyResponse := (&hubv1.QueryCurrentServiceKeyResponse{}).ProtoReflect().Descriptor()
	assertNodeField(t, keyResponse, 1, "binding", protoreflect.MessageKind, false, "hub.v1.CurrentServiceKeyViewV1")
	view := (&hubv1.CurrentServiceKeyViewV1{}).ProtoReflect().Descriptor()
	assertNodeField(t, view, 4, "service_pubkey", protoreflect.BytesKind, false, "")
	assertNodeField(t, view, 5, "service_authorization_nonce", protoreflect.Uint64Kind, false, "")
	assertNodeField(t, view, 6, "cortex_service_key_status", protoreflect.EnumKind, false, "hub.v1.ServiceKeyStatus")
	assertNodeField(t, view, 7, "builder_service_key_status", protoreflect.EnumKind, false, "hub.v1.ServiceKeyStatus")
}

func assertNodeField(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	number protoreflect.FieldNumber,
	name protoreflect.Name,
	kind protoreflect.Kind,
	repeated bool,
	typeName protoreflect.FullName,
) {
	t.Helper()
	field := message.Fields().ByNumber(number)
	if field == nil {
		t.Fatalf("%s field %d is missing", message.FullName(), number)
	}
	if field.Name() != name || field.Kind() != kind || field.Cardinality() == protoreflect.Repeated != repeated {
		t.Fatalf("%s field %d = %s/%s/%s, want %s/%s/repeated=%t",
			message.FullName(), number, field.Name(), field.Kind(), field.Cardinality(), name, kind, repeated)
	}
	if typeName == "" {
		return
	}
	var got protoreflect.FullName
	switch field.Kind() {
	case protoreflect.MessageKind:
		got = field.Message().FullName()
	case protoreflect.EnumKind:
		got = field.Enum().FullName()
	default:
		t.Fatalf("%s field %d has scalar kind %s with expected type name %s", message.FullName(), number, field.Kind(), typeName)
	}
	if got != typeName {
		t.Fatalf("%s field %d type = %s, want %s", message.FullName(), number, got, typeName)
	}
}

func TestRemoteAddressNormalization(t *testing.T) {
	const host = "node.example.invalid"

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "plain grpc address becomes h2c base url",
			got:  grpcBaseURL(host + ":12345"),
			want: "http://" + host + ":12345",
		},
		{
			name: "tcp grpc address becomes h2c base url",
			got:  grpcBaseURL("tcp://" + host + ":12345"),
			want: "http://" + host + ":12345",
		},
		// Deployment Security Baseline: once the node port has TLS enabled, grpc_addr is
		// written as https:// or grpcs://, verified against system CA roots, and no longer rewritten to http.
		{
			name: "https grpc address stays https",
			got:  grpcBaseURL("https://" + host + ":12345"),
			want: "https://" + host + ":12345",
		},
		{
			name: "grpcs grpc address becomes https base url",
			got:  grpcBaseURL("grpcs://" + host + ":12345"),
			want: "https://" + host + ":12345",
		},
		{
			name: "explicit http grpc address stays http",
			got:  grpcBaseURL("http://" + host + ":12345"),
			want: "http://" + host + ":12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("url=%q want %q", tt.got, tt.want)
			}
		})
	}
}

func TestStartLogsDoNotExposeConnectionDetails(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	c := &client{
		log:    log,
		cfg:    config.ChainConfig{GRPCAddr: "node.example.invalid:12345", ChainID: "integration-localnet"},
		events: make(chan ChainEvent, 1),
		stopCh: make(chan struct{}),
	}

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := buf.String()
	for _, secret := range []string{"node.example.invalid", "12345", "23456", "integration-localnet"} {
		if strings.Contains(got, secret) {
			t.Fatalf("log exposed %q in %q", secret, got)
		}
	}
}

func TestBroadcastTxErrorDoesNotExposeEndpoint(t *testing.T) {
	fake := &recordTxService{err: errors.New("post http://node.example.invalid:12345: timeout")}
	c := &client{
		cfg: config.ChainConfig{GRPCAddr: "node.example.invalid:12345"},
		tx:  fake,
	}

	_, err := c.BroadcastTx(context.Background(), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected broadcast error")
	}
	got := err.Error()
	for _, secret := range []string{"node.example.invalid", "12345"} {
		if strings.Contains(got, secret) {
			t.Fatalf("error exposed %q in %q", secret, got)
		}
	}
}

func TestRedactSensitiveTextRemovesEndpointShapes(t *testing.T) {
	got := redactSensitiveText(`post http://node.example.invalid:12345 failed; dial tcp [::1]:26657; retry localhost:26657`)
	for _, secret := range []string{"node.example.invalid", "12345", "[::1]", "26657", "localhost"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted text exposed %q in %q", secret, got)
		}
	}
}

func TestLatestHeightUsesGRPC(t *testing.T) {
	latest := &recordLatestBlock{response: &cmtv1beta1.GetLatestBlockResponse{
		Block: &tmtypes.Block{Header: &tmtypes.Header{ChainId: "trueopen-localnet-1", Height: 1971}},
	}}
	c := &client{cfg: config.ChainConfig{ChainID: "trueopen-localnet-1"}, latestBlock: latest}

	height, err := c.LatestHeight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if height != 1971 || latest.calls != 1 {
		t.Fatalf("height=%d grpc_calls=%d", height, latest.calls)
	}
}

// The frozen contract's QueryTask queries by task_id only and returns
// TaskViewV1{active{core, assignment, verifier_assignment}}: infer receipt / settlement /
// failure class were split into separate RPCs, so those sections of OnChainTask stay zero
// (see the mapTask comment).
func TestQueryTaskUsesTaskIDAndMapsActiveBundle(t *testing.T) {
	fake := &recordTaskQuery{response: &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{
		Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core: &taskv1.TaskCoreState{
				TaskId: testTaskIDBytes, SessionId: testSessionIDBytes, UserAddress: "user-1",
				OrderSequence: 7, AcceptedTaskHash: mustHash32("55"),
				ModelId: "model-1", ProfileVersion: 2,
				TaskPhase: taskv1.TaskPhase_TASK_PHASE_VERIFIER_ASSIGNED,
			},
			Assignment: &taskv1.TaskAssignmentViewV1{
				TaskId: testTaskIDBytes, AssignAcceptHeight: 44, AssignmentRandomnessHeight: 45,
				WinnerConfirmHeight: proto.Uint64(46), InferDeadlineHeight: proto.Uint64(50),
				CandidatePoolSnapshotId: mustHash32("66"), AssignmentCandidateSetHash: mustHash32("77"),
				WinnerWorker: proto.String("worker-1"),
			},
			// Since wire v0.4.1 the bundle is split per round into round1 / round2; Phase 0 reads only round1.
			Round1VerifierAssignment: &taskv1.VerifierAssignmentState{
				TaskId: testTaskIDBytes, VerifyRound: 1, OpenVerifyHeight: 55,
				SelectedVerifiers: []*taskv1.SelectedVerifierV1{
					{OperatorAddress: "verifier-1", Slot: 1},
					{OperatorAddress: "verifier-2", Slot: 2},
					{OperatorAddress: "verifier-3", Slot: 3},
				},
				CommitDeadlineHeight: 60, RevealDeadlineHeight: 80, VerifyDeadlineHeight: 90,
			},
		}},
	}}}
	c := &client{taskQuery: fake}

	got, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.request.GetTaskId(), testTaskIDBytes) {
		t.Fatalf("request=%+v", fake.request)
	}
	if got.SessionID != testSessionIDHex || got.TaskID != testTaskIDHex || got.State != types.Verifying {
		t.Fatalf("task identity/state=%+v", got)
	}
	if got.Status != "VERIFIER_ASSIGNED" {
		t.Fatalf("status=%q", got.Status)
	}
	if got.Winner != "worker-1" || got.InferDeadline != 50 {
		t.Fatalf("assignment=%+v", got)
	}
	if len(got.Verifiers) != 3 || got.Verifiers[2] != "verifier-3" {
		t.Fatalf("verifiers=%v", got.Verifiers)
	}
	if got.Deadlines.Commit != 60 || got.Deadlines.Reveal != 80 || got.Deadlines.Verify != 90 {
		t.Fatalf("deadlines=%+v", got.Deadlines)
	}
	if got.Assignment.OrderSequence != 7 || got.Assignment.ModelID != "model-1" ||
		got.Assignment.AssignAcceptHeight != 44 || got.Assignment.WinnerConfirmHeight != 46 {
		t.Fatalf("assignment view=%+v", got.Assignment)
	}
	// Facts that disappeared from the QueryTask response must be zero; no substituting other fields.
	if got.InferReceipt != (InferReceiptState{}) || got.Settlement != (TaskSettlementState{}) ||
		got.TaskVerdict != types.VerdictUnspecified || got.FailureClass != "" ||
		len(got.SampleSeed) != 0 || len(got.AssignedSet) != 0 {
		t.Fatalf("facts not carried by QueryTask must stay zero: %+v", got)
	}
}

// VerifierRounds carries both round assignments for task data authorization, while the
// coordinator view (Verifiers, Deadlines) stays round 1.
func TestQueryTaskMapsBothVerifierRounds(t *testing.T) {
	round := func(n uint32, verifiers ...string) *taskv1.VerifierAssignmentState {
		state := &taskv1.VerifierAssignmentState{
			TaskId: testTaskIDBytes, VerifyRound: n, CommitDeadlineHeight: 60 * uint64(n),
		}
		for i, address := range verifiers {
			state.SelectedVerifiers = append(state.SelectedVerifiers,
				&taskv1.SelectedVerifierV1{OperatorAddress: address, Slot: uint32(i + 1)})
		}
		return state
	}
	response := func(round1, round2 *taskv1.VerifierAssignmentState) *taskv1.QueryTaskResponse {
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{
			Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
				Core: &taskv1.TaskCoreState{
					TaskId: testTaskIDBytes, SessionId: testSessionIDBytes,
					TaskPhase: taskv1.TaskPhase_TASK_PHASE_COMMITTING,
				},
				Round1VerifierAssignment: round1, Round2VerifierAssignment: round2,
			}},
		}}
	}
	round1 := round(1, "verifier-1", "verifier-2", "verifier-3")
	round1.RevealDeadlineHeight = 70
	c := &client{taskQuery: &recordTaskQuery{response: response(round1, round(2, "challenger-1", "challenger-2"))}}
	got, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if err != nil {
		t.Fatal(err)
	}
	want := []VerifierRound{
		{VerifyRound: 1, Verifiers: []string{"verifier-1", "verifier-2", "verifier-3"}, CommitDeadlineHeight: 60, RevealDeadlineHeight: 70},
		{VerifyRound: 2, Verifiers: []string{"challenger-1", "challenger-2"}, CommitDeadlineHeight: 120},
	}
	if !reflect.DeepEqual(got.VerifierRounds, want) {
		t.Fatalf("verifier rounds = %+v, want %+v", got.VerifierRounds, want)
	}
	if len(got.Verifiers) != 3 || got.Deadlines.Commit != 60 {
		t.Fatalf("coordinator view must stay round 1: verifiers=%v deadlines=%+v", got.Verifiers, got.Deadlines)
	}

	// An assignment published under the wrong round slot is rejected rather than trusted.
	c = &client{taskQuery: &recordTaskQuery{response: response(round1, round(1, "challenger-1"))}}
	if _, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err == nil {
		t.Fatal("round-2 slot carrying verify_round 1 was accepted")
	}
}

func TestVerifierRoundCommitsLocked(t *testing.T) {
	open := VerifierRound{CommitDeadlineHeight: 60}
	if open.CommitsLocked(60) {
		t.Fatal("commits locked at the commit deadline, which still accepts commits")
	}
	if !open.CommitsLocked(61) {
		t.Fatal("commits not locked after the commit deadline")
	}
	if !(VerifierRound{CommitDeadlineHeight: 60, RevealDeadlineHeight: 70}).CommitsLocked(10) {
		t.Fatal("commits not locked once reveal started")
	}
	// A missing commit deadline is an incomplete chain view, never an open door.
	if (VerifierRound{}).CommitsLocked(1000) || (VerifierRound{RevealDeadlineHeight: 70}).CommitsLocked(1000) {
		t.Fatal("commits reported locked without a commit deadline")
	}
}

func TestQueryTaskRejectsMismatchedScope(t *testing.T) {
	fake := &recordTaskQuery{response: &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{
		Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core: &taskv1.TaskCoreState{
				TaskId: testTaskIDBytes, SessionId: testOtherIDBytes,
				TaskPhase: taskv1.TaskPhase_TASK_PHASE_WORKER_ASSIGNED,
			},
		}},
	}}}
	c := &client{taskQuery: fake}
	if _, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err == nil {
		t.Fatal("a session mismatch must be rejected")
	}
}

// SettlementBuildFacts is deregistered in the frozen contract (§16 no longer registers
// any settlement-build/preview RPC) and must fail closed.
func TestQuerySettlementBuildFactsIsDeregistered(t *testing.T) {
	c := &client{}
	_, err := c.QuerySettlementBuildFacts(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if !errors.Is(err, ErrNotSupportedOnChain) {
		t.Fatalf("err = %v, want ErrNotSupportedOnChain", err)
	}
}

func TestMapTaskRejectsUnknownPhase(t *testing.T) {
	c := &client{}
	_, err := c.mapTask(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}, &taskv1.QueryTaskResponse{
		Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core: &taskv1.TaskCoreState{TaskId: testTaskIDBytes, SessionId: testSessionIDBytes, TaskPhase: taskv1.TaskPhase(99)},
		}}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown task phase") {
		t.Fatalf("err=%v", err)
	}
}

func TestMapTaskRejectsMissingActiveBundle(t *testing.T) {
	c := &client{}
	if _, err := c.mapTask(TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}, &taskv1.QueryTaskResponse{}); err == nil {
		t.Fatal("a compacted/empty TaskViewV1 must not map to a task")
	}
}

// Positive mapping: the request carries only the height selector, and the response is
// mapped field by field from BuilderSetViewV1. Since wire v0.4.1 the BuilderSet has only
// builder_set_version (mapped to Epoch) and effective_height (mapped to UpdatedHeight),
// no term / epoch range; the request selector is only height | builder_set_id.
func TestQueryBuilderSetAtHeightSendsHeightSelectorAndMapsView(t *testing.T) {
	setHash := bytes.Repeat([]byte{0x5a}, 32)
	fake := &recordHubQuery{builderSet: &hubv1.QueryBuilderSetResponse{Set: &hubv1.BuilderSetViewV1{
		BuilderSetVersion: 7, BuilderSetId: "7", BuilderSetHash: setHash,
		ActiveBuilders: []string{"builder-1", "builder-2", "builder-3"}, ActiveBuilderCount: 3,
		EffectiveHeight: 99,
		BodyStatus:      sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
	}}}
	c := &client{hubQuery: fake}

	got, err := c.QueryBuilderSetAtHeight(context.Background(), 4242)
	if err != nil {
		t.Fatal(err)
	}
	if fake.builderSetRequest.GetHeight() != 4242 {
		t.Fatalf("request height=%d want 4242 (selector=%T)", fake.builderSetRequest.GetHeight(), fake.builderSetRequest.GetSelector())
	}
	if fake.builderSetRequest.GetBuilderSetId() != "" {
		t.Fatalf("only the height selector may be set: %+v", fake.builderSetRequest)
	}
	if got.Epoch != 7 || got.BuilderSetID != "7" ||
		got.SetHash != hex.EncodeToString(setHash) || got.ActiveBuilderCount != 3 ||
		got.BodyStatus != "ACTIVE" || got.UpdatedHeight != 99 {
		t.Fatalf("builder set=%+v", got)
	}
	if len(got.Members) != 3 || got.Members[2].Address != "builder-3" || got.Members[2].Rank != 3 {
		t.Fatalf("members=%+v", got.Members)
	}
}

// Negative: every case must fail closed. The PRUNED case is the trap named in contract
// §16.5: members empty but count retained; reading it as an "empty BuilderSet" means
// starting with a nonexistent empty set.
func TestQueryBuilderSetAtHeightFailsClosed(t *testing.T) {
	validView := func() *hubv1.BuilderSetViewV1 {
		return &hubv1.BuilderSetViewV1{
			BuilderSetVersion: 7, BuilderSetId: "7", BuilderSetHash: bytes.Repeat([]byte{0x5a}, 32),
			ActiveBuilders:     []string{"builder-1", "builder-2"},
			ActiveBuilderCount: 2, EffectiveHeight: 99,
			BodyStatus: sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
		}
	}
	prunedHeight := uint64(50)
	tests := []struct {
		name   string
		height uint64
		mutate func(*hubv1.BuilderSetViewV1)
		want   string
	}{
		{name: "zero height", height: 0, want: "height must be greater than zero"},
		{name: "pruned body", height: 4242, want: "PRUNED", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.BodyStatus = sharedv1.StoredBodyStatus_STORED_BODY_STATUS_PRUNED
			v.ActiveBuilders = nil
			v.PrunedHeight = &prunedHeight
		}},
		{name: "unspecified body status", height: 4242, want: "invalid body_status", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.BodyStatus = sharedv1.StoredBodyStatus_STORED_BODY_STATUS_UNSPECIFIED
		}},
		{name: "short hash", height: 4242, want: "builder_set_hash is 31 bytes", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.BuilderSetHash = bytes.Repeat([]byte{0x5a}, 31)
		}},
		{name: "count mismatch", height: 4242, want: "active_builder_count is 3", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.ActiveBuilderCount = 3
		}},
		{name: "empty members on active body", height: 4242, want: "has no members", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.ActiveBuilders = nil
			v.ActiveBuilderCount = 0
		}},
		{name: "duplicate member", height: 4242, want: "duplicate member entry", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.ActiveBuilders = []string{"builder-1", "builder-1"}
		}},
		{name: "padded member", height: 4242, want: "member entry is empty or padded", mutate: func(v *hubv1.BuilderSetViewV1) {
			v.ActiveBuilders = []string{"builder-1", " builder-2"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := validView()
			if tt.mutate != nil {
				tt.mutate(view)
			}
			c := &client{hubQuery: &recordHubQuery{builderSet: &hubv1.QueryBuilderSetResponse{Set: view}}}
			_, err := c.QueryBuilderSetAtHeight(context.Background(), tt.height)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

// Settlement ordering comes from the frozen TaskBuilders query: in selected_task_builders
// order, task_id must match the request, and addresses must not repeat.
func TestQueryTaskBuildersReturnsFrozenOrder(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	raw, _ := hex.DecodeString(taskID)
	fake := &recordTaskQuery{builders: &taskv1.QueryTaskBuildersResponse{Selection: &taskv1.TaskBuilderSelectionViewV1{
		TaskId: raw, SelectedTaskBuilders: []string{"builder-1", "builder-2", "builder-3"},
		SelectedTaskBuilderCount: 3, CreatedHeight: 150, BodyStatus: sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
	}}}
	c := &client{taskQuery: fake}

	got, err := c.QueryTaskBuilders(context.Background(), TaskKey{SessionID: "session-1", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(fake.buildersRequest.GetTaskId()) != taskID {
		t.Fatalf("request=%+v", fake.buildersRequest)
	}
	if len(got.SelectedBuilders) != 3 || got.SelectedBuilders[0] != "builder-1" || got.SelectedBuilders[2] != "builder-3" ||
		got.CreatedHeight != 150 || got.SelectedCount != 3 || got.BodyStatus != "ACTIVE" {
		t.Fatalf("selection=%+v", got)
	}

	fake.builders.Selection.SelectedTaskBuilders = []string{"builder-1", "builder-1"}
	if _, err := c.QueryTaskBuilders(context.Background(), TaskKey{SessionID: "session-1", TaskID: taskID}); err == nil {
		t.Fatal("duplicate builders must be refused")
	}
	fake.builders.Selection.SelectedTaskBuilders = []string{"builder-1"}
	fake.builders.Selection.TaskId = bytes.Repeat([]byte{0xcd}, 32)
	if _, err := c.QueryTaskBuilders(context.Background(), TaskKey{SessionID: "session-1", TaskID: taskID}); err == nil {
		t.Fatal("task_id mismatch must be refused")
	}
}

func TestQuerySettlementBuilderGraceBlocksReadsHubParams(t *testing.T) {
	fake := &recordHubQuery{params: &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{
		Builder: &hubv1.BuilderParamsV1{SettlementBuilderGraceBlocks: 2},
	}}}
	c := &client{hubQuery: fake}
	got, err := c.QuerySettlementBuilderGraceBlocks(context.Background())
	if err != nil || got != 2 {
		t.Fatalf("grace=%d err=%v", got, err)
	}
	fake.params.Params.Builder.SettlementBuilderGraceBlocks = 0
	if _, err := c.QuerySettlementBuilderGraceBlocks(context.Background()); err == nil {
		t.Fatal("zero grace must be refused")
	}
}

// The timeout bucket query moved from task.v1.Query to hub.v1.Query and the
// response became the generic ParameterBucketVersionViewV1; height is no longer a query
// key, and the four per-stage timeout fields are not on the wire either.
func TestQueryTimeoutBucketUsesHubParameterBucket(t *testing.T) {
	fake := &recordHubQuery{timeoutBucket: &hubv1.QueryTimeoutBucketResponse{
		Bucket: &hubv1.ParameterBucketVersionViewV1{
			BucketKind: sharedv1.BucketKind_BUCKET_KIND_TIMEOUT, BucketKey: "standard",
			Version: 4, SchemaVersion: 1, EffectiveHeight: 100,
			TimeoutEntries: &hubv1.TimeoutBucketEntriesV1{Entries: []*hubv1.TimeoutBucketEntryV1{
				{UpperWorkUnitsInclusive: 1000, TimeoutBlocks: 20},
			}},
			EntryCount: 1,
		},
		CurrentVersion: 4,
	}}
	c := &client{hubQuery: fake}

	got, err := c.QueryTimeoutBucket(context.Background(), "standard", 4, 123)
	if err != nil {
		t.Fatal(err)
	}
	if fake.timeoutRequest.GetBucketKey() != "standard" || fake.timeoutRequest.GetVersion() != 4 {
		t.Fatalf("request=%+v", fake.timeoutRequest)
	}
	if got.BucketKey != "standard" || got.Version != 4 || got.EffectiveHeight != 100 {
		t.Fatalf("bucket=%+v", got)
	}
	if got.InferTimeoutBlocks != 0 || got.VerifyTimeoutBlocks != 0 ||
		got.RevealTimeoutBlocks != 0 || got.ChallengeTimeoutBlocks != 0 || got.Source != "" {
		t.Fatalf("deleted per-stage timeout facts must stay zero: %+v", got)
	}
}

// bucket_kind must be TIMEOUT: since wire v0.4.1 BucketKind has only the TIMEOUT family;
// a missing / zero (UNSPECIFIED) bucket must error rather than be used as timeout parameters.
func TestQueryTimeoutBucketRejectsWrongBucketKind(t *testing.T) {
	fake := &recordHubQuery{timeoutBucket: &hubv1.QueryTimeoutBucketResponse{
		Bucket: &hubv1.ParameterBucketVersionViewV1{
			BucketKind: sharedv1.BucketKind_BUCKET_KIND_UNSPECIFIED, BucketKey: "standard", Version: 4,
		},
	}}
	c := &client{hubQuery: fake}
	if _, err := c.QueryTimeoutBucket(context.Background(), "standard", 4, 0); err == nil {
		t.Fatal("an UNSPECIFIED bucket kind must not be accepted as a timeout bucket")
	}
}

func TestQueryProfileMapsChallengeWindow(t *testing.T) {
	fake := &recordHubQuery{profile: &hubv1.QueryProfileResponse{Profile: &hubv1.ProfileState{
		ModelId: "model-1", ProfileVersion: 2,
		Status:                    hubv1.ModelProfileStatus_MODEL_PROFILE_STATUS_ACTIVE,
		ChallengeOpenWindowBlocks: 120,
	}}}
	c := &client{hubQuery: fake}

	got, err := c.QueryProfile(context.Background(), "model-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if fake.profileRequest.GetModelId() != "model-1" || fake.profileRequest.GetProfileVersion() != 2 {
		t.Fatalf("request=%+v", fake.profileRequest)
	}
	if got.ModelID != "model-1" || got.ProfileVersion != 2 || got.Status != "MODEL_PROFILE_STATUS_ACTIVE" || got.ChallengeOpenWindowBlocks != 120 {
		t.Fatalf("profile=%+v", got)
	}
}

func TestQueryProfilePreservesUint32Range(t *testing.T) {
	const version = uint32(math.MaxUint32)
	fake := &recordHubQuery{profile: &hubv1.QueryProfileResponse{Profile: &hubv1.ProfileState{
		ModelId: "model-1", ProfileVersion: version,
		Status: hubv1.ModelProfileStatus_MODEL_PROFILE_STATUS_ACTIVE,
	}}}
	c := &client{hubQuery: fake}
	got, err := c.QueryProfile(context.Background(), "model-1", version)
	if err != nil {
		t.Fatal(err)
	}
	if fake.profileRequest.GetProfileVersion() != version || got.ProfileVersion != version {
		t.Fatalf("request=%d response=%d", fake.profileRequest.GetProfileVersion(), got.ProfileVersion)
	}
}

func TestQueryProfileRejectsZeroVersion(t *testing.T) {
	c := &client{}
	if _, err := c.QueryProfile(context.Background(), "model-1", 0); err == nil {
		t.Fatal("QueryProfile accepted profile_version 0")
	}
}

type recordTaskQuery struct {
	taskv1connect.QueryClient
	request         *taskv1.QueryTaskRequest
	response        *taskv1.QueryTaskResponse
	buildersRequest *taskv1.QueryTaskBuildersRequest
	builders        *taskv1.QueryTaskBuildersResponse
}

type recordLatestBlock struct {
	response *cmtv1beta1.GetLatestBlockResponse
	err      error
	calls    int
}

func (q *recordLatestBlock) GetLatestBlock(context.Context, *connect.Request[cmtv1beta1.GetLatestBlockRequest]) (*connect.Response[cmtv1beta1.GetLatestBlockResponse], error) {
	q.calls++
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.response), nil
}

func (q *recordTaskQuery) Task(_ context.Context, req *connect.Request[taskv1.QueryTaskRequest]) (*connect.Response[taskv1.QueryTaskResponse], error) {
	q.request = req.Msg
	return connect.NewResponse(q.response), nil
}

func (q *recordTaskQuery) TaskBuilders(_ context.Context, req *connect.Request[taskv1.QueryTaskBuildersRequest]) (*connect.Response[taskv1.QueryTaskBuildersResponse], error) {
	q.buildersRequest = req.Msg
	return connect.NewResponse(q.builders), nil
}

type recordHubQuery struct {
	hubv1connect.QueryClient
	builderSetRequest *hubv1.QueryBuilderSetRequest
	builderSet        *hubv1.QueryBuilderSetResponse
	params            *hubv1.QueryHubParamsResponse
	profileRequest    *hubv1.QueryProfileRequest
	profile           *hubv1.QueryProfileResponse
	timeoutRequest    *hubv1.QueryTimeoutBucketRequest
	timeoutBucket     *hubv1.QueryTimeoutBucketResponse
}

// QueryBuilderSetAtHeight also resolves each member's on-chain endpoint; this fake always
// returns an empty row, so endpoint resolution degrades while members and rank must stay intact.
func (q *recordHubQuery) Builder(context.Context, *connect.Request[hubv1.QueryBuilderRequest]) (*connect.Response[hubv1.QueryBuilderResponse], error) {
	return connect.NewResponse(&hubv1.QueryBuilderResponse{}), nil
}

func (q *recordHubQuery) ServiceDescriptor(context.Context, *connect.Request[hubv1.QueryServiceDescriptorRequest]) (*connect.Response[hubv1.QueryServiceDescriptorResponse], error) {
	return connect.NewResponse(&hubv1.QueryServiceDescriptorResponse{}), nil
}

func (q *recordHubQuery) TimeoutBucket(_ context.Context, req *connect.Request[hubv1.QueryTimeoutBucketRequest]) (*connect.Response[hubv1.QueryTimeoutBucketResponse], error) {
	q.timeoutRequest = req.Msg
	return connect.NewResponse(q.timeoutBucket), nil
}

func (q *recordHubQuery) Profile(_ context.Context, req *connect.Request[hubv1.QueryProfileRequest]) (*connect.Response[hubv1.QueryProfileResponse], error) {
	q.profileRequest = req.Msg
	return connect.NewResponse(q.profile), nil
}

func (q *recordHubQuery) Params(context.Context, *connect.Request[hubv1.QueryHubParamsRequest]) (*connect.Response[hubv1.QueryHubParamsResponse], error) {
	return connect.NewResponse(q.params), nil
}

func (q *recordHubQuery) BuilderSet(_ context.Context, req *connect.Request[hubv1.QueryBuilderSetRequest]) (*connect.Response[hubv1.QueryBuilderSetResponse], error) {
	q.builderSetRequest = req.Msg
	return connect.NewResponse(q.builderSet), nil
}

func TestGRPCTransportFollowsScheme(t *testing.T) {
	if tr := newGRPCTransport("https://node.example:9090"); tr.AllowHTTP || tr.TLSClientConfig == nil {
		t.Fatalf("https base must use a TLS transport, got AllowHTTP=%v tls=%v", tr.AllowHTTP, tr.TLSClientConfig != nil)
	}
	if tr := newGRPCTransport("http://127.0.0.1:9090"); !tr.AllowHTTP || tr.DialTLSContext == nil {
		t.Fatal("http base must keep the h2c transport")
	}
}

type recordEvidenceCleanup struct {
	taskv1connect.QueryClient
	request  *taskv1.QueryEvidenceCleanupRequest
	response *taskv1.QueryEvidenceCleanupResponse
	err      error
}

func (r *recordEvidenceCleanup) EvidenceCleanup(_ context.Context, req *connect.Request[taskv1.QueryEvidenceCleanupRequest]) (*connect.Response[taskv1.QueryEvidenceCleanupResponse], error) {
	r.request = req.Msg
	if r.err != nil {
		return nil, r.err
	}
	return connect.NewResponse(r.response), nil
}

func TestQueryEvidenceCleanupMapsStatus(t *testing.T) {
	respond := func(taskID []byte, status taskv1.TaskCleanupStatus) *taskv1.QueryEvidenceCleanupResponse {
		return &taskv1.QueryEvidenceCleanupResponse{Cleanup: &taskv1.TaskCleanupProgressViewV1{TaskId: taskID, Status: status}}
	}
	for status, want := range map[taskv1.TaskCleanupStatus]EvidenceCleanupStatus{
		taskv1.TaskCleanupStatus_TASK_CLEANUP_STATUS_NOT_SCHEDULED: EvidenceCleanupNotScheduled,
		taskv1.TaskCleanupStatus_TASK_CLEANUP_STATUS_RUNNING:       EvidenceCleanupRunning,
		taskv1.TaskCleanupStatus_TASK_CLEANUP_STATUS_COMPACTED:     EvidenceCleanupCompacted,
	} {
		fake := &recordEvidenceCleanup{response: respond(testTaskIDBytes, status)}
		got, err := (&client{taskQuery: fake}).QueryEvidenceCleanup(context.Background(), testTaskIDHex)
		if err != nil || got != want {
			t.Fatalf("%s -> %q, %v; want %q", status, got, err, want)
		}
		if !bytes.Equal(fake.request.GetTaskId(), testTaskIDBytes) {
			t.Fatalf("request task_id = %x", fake.request.GetTaskId())
		}
	}
	if !EvidenceCleanupRunning.Started() || !EvidenceCleanupCompacted.Started() || EvidenceCleanupNotScheduled.Started() {
		t.Fatal("Started must hold exactly for RUNNING and COMPACTED")
	}
	for name, fake := range map[string]*recordEvidenceCleanup{
		"unspecified status": {response: respond(testTaskIDBytes, taskv1.TaskCleanupStatus_TASK_CLEANUP_STATUS_UNSPECIFIED)},
		"other task":         {response: respond(mustHash32("99"), taskv1.TaskCleanupStatus_TASK_CLEANUP_STATUS_COMPACTED)},
		"transport error":    {err: connect.NewError(connect.CodeUnavailable, errors.New("down"))},
	} {
		if _, err := (&client{taskQuery: fake}).QueryEvidenceCleanup(context.Background(), testTaskIDHex); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: error = %v, want a non-NotFound failure", name, err)
		}
	}
	missing := &recordEvidenceCleanup{err: connect.NewError(connect.CodeNotFound, errors.New("no task"))}
	if _, err := (&client{taskQuery: missing}).QueryEvidenceCleanup(context.Background(), testTaskIDHex); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown task error = %v, want ErrNotFound", err)
	}
}

func terminalResponse(summary *taskv1.TaskTerminalSummaryState) *taskv1.QueryTaskResponse {
	return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{
		Value: &taskv1.TaskViewV1_Terminal{Terminal: summary},
	}}
}

// After evidence cleanup QueryTask returns the terminal summary; it maps to a final task
// instead of failing with "active bundle is missing".
func TestQueryTaskMapsCompactedTerminalSummary(t *testing.T) {
	summary := &taskv1.TaskTerminalSummaryState{
		TaskId: testTaskIDBytes, SessionId: testSessionIDBytes, OrderSequence: 7, TaskHash: mustHash32("55"),
		TerminalPhase: taskv1.TaskPhase_TASK_PHASE_SETTLED, Verdict: taskv1.TaskVerdict_TASK_VERDICT_PASS,
		SettlementStatus: taskv1.SettlementStatus_SETTLEMENT_STATUS_FINALIZED,
		FinalityStatus:   sharedv1.TaskFinalityStatusV1_TASK_FINALITY_STATUS_V1_FINAL,
		ModelId:          "model-1", ProfileVersion: 2, WinnerWorker: proto.String("worker-1"),
		SettlementHeight: 90, TaskFinalityHeight: 88,
	}
	c := &client{taskQuery: &recordTaskQuery{response: terminalResponse(summary)}}
	got, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Compacted || got.State != types.Settled || got.Status != "SETTLED" || got.TaskVerdict != types.VerdictPass ||
		got.Winner != "worker-1" || got.Assignment.AcceptedTaskHash != hex.EncodeToString(mustHash32("55")) {
		t.Fatalf("terminal task = %+v", got)
	}
	want := TaskSettlementState{SettlementStatus: "FINALIZED", FinalityStatus: "FINAL", SettlementHeight: 90, TaskFinalityHeight: 88}
	if got.Settlement != want {
		t.Fatalf("terminal settlement = %+v, want %+v", got.Settlement, want)
	}
	if len(got.Verifiers) != 0 || len(got.VerifierRounds) != 0 {
		t.Fatalf("a compacted task has no per-round view: %+v", got)
	}

	summary.TerminalPhase = taskv1.TaskPhase_TASK_PHASE_FAILED
	summary.FailureClass = taskv1.TaskFailureClass(1)
	failed, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if err != nil || failed.State != types.Failed || failed.FailureClass == "" {
		t.Fatalf("failed terminal task = %+v, %v", failed, err)
	}

	for name, mutate := range map[string]func(*taskv1.TaskTerminalSummaryState){
		"non-terminal phase": func(s *taskv1.TaskTerminalSummaryState) { s.TerminalPhase = taskv1.TaskPhase_TASK_PHASE_COMMITTING },
		"other task":         func(s *taskv1.TaskTerminalSummaryState) { s.TaskId = mustHash32("99") },
		"other session":      func(s *taskv1.TaskTerminalSummaryState) { s.SessionId = mustHash32("98") },
	} {
		bad := proto.CloneOf(summary)
		bad.TerminalPhase = taskv1.TaskPhase_TASK_PHASE_SETTLED
		mutate(bad)
		c := &client{taskQuery: &recordTaskQuery{response: terminalResponse(bad)}}
		if _, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex}); err == nil {
			t.Fatalf("%s: inconsistent terminal summary accepted", name)
		}
	}
}

// The active view carries the finality the coordinator closes settled tasks on.
func TestQueryTaskMapsCoreFinality(t *testing.T) {
	finality := uint64(88)
	c := &client{taskQuery: &recordTaskQuery{response: &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{
		Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{Core: &taskv1.TaskCoreState{
			TaskId: testTaskIDBytes, SessionId: testSessionIDBytes, TaskPhase: taskv1.TaskPhase_TASK_PHASE_SETTLED,
			SettlementStatus:   taskv1.SettlementStatus_SETTLEMENT_STATUS_FINALIZED,
			FinalityStatus:     sharedv1.TaskFinalityStatusV1_TASK_FINALITY_STATUS_V1_FINAL,
			TaskFinalityHeight: &finality,
		}}},
	}}}}
	got, err := c.QueryTask(context.Background(), TaskKey{SessionID: testSessionIDHex, TaskID: testTaskIDHex})
	if err != nil {
		t.Fatal(err)
	}
	if got.Compacted || got.Settlement.FinalityStatus != "FINAL" || got.Settlement.TaskFinalityHeight != 88 ||
		got.Settlement.SettlementStatus != "FINALIZED" {
		t.Fatalf("active task settlement = %+v", got.Settlement)
	}
}
