package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"   // test only
const workerKeyHex = "0000000000000000000000000000000000000000000000000000000000000001" // test only
const alternateKeyHex = "0000000000000000000000000000000000000000000000000000000000000002"

type fakeServiceKeyResolver struct {
	states map[string]chaincli.ServiceKeyState
	err    error
	calls  int
}

func (f *fakeServiceKeyResolver) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	f.calls++
	if f.err != nil {
		return chaincli.ServiceKeyState{}, f.err
	}
	state, ok := f.states[participantType+"|"+operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func activeServiceKey(participantType, operator string, service signer.Signer) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: participantType,
		OperatorAddress: operator,
		ServiceAddress:  service.Address(),
		ServicePubKey:   hex.EncodeToString(service.PubKeyCompressed()),
		Status:          "ACTIVE",
	}
}

func TestPlaintextOutputProtoContract(t *testing.T) {
	file := nexusv1.File_nexus_v1_ingress_proto
	svc := file.Services().ByName("IngressAPI")
	if svc == nil {
		t.Fatal("IngressAPI descriptor missing")
	}
	subscribe := svc.Methods().ByName("SubscribeOutput")
	if subscribe == nil || !subscribe.IsStreamingServer() || subscribe.IsStreamingClient() {
		t.Fatalf("SubscribeOutput descriptor = %v", subscribe)
	}
	ack := svc.Methods().ByName("AckOutput")
	if ack == nil || ack.IsStreamingServer() || ack.IsStreamingClient() {
		t.Fatalf("AckOutput descriptor = %v", ack)
	}
	// The Worker/Verifier surface removes SubmitOutputRef and the inline output_text:
	// the target state for plaintext delivery to the SDK is FetchTaskData(OUTPUT).
	for _, name := range []protoreflect.Name{"SubmitOutputRef", "FetchPayload", "UploadTaskData", "RefreshTaskDataAuthorization"} {
		if method := svc.Methods().ByName(name); method != nil {
			t.Fatalf("%s must be removed from the Worker/Verifier surface, got %v", name, method)
		}
	}
	for _, name := range []protoreflect.Name{
		"SubmitOutputRefRequest", "SubmitOutputRefResponse", "FetchPayloadRequest", "FetchPayloadResponse",
		"UploadTaskDataHeader", "UploadTaskDataRequest", "UploadTaskDataResponse",
		"RefreshTaskDataAuthorizationRequest", "RefreshTaskDataAuthorizationResponse",
		"OutputRef", "TaskDataAuthorizationV1",
	} {
		if message := file.Messages().ByName(name); message != nil {
			t.Fatalf("message %s must be removed from the Worker/Verifier surface", name)
		}
	}
	// No OutputRef-related field may remain on the nexus ingress surface.
	for _, entry := range []struct {
		message protoreflect.Name
		field   protoreflect.Name
	}{
		{"GetTaskDataMetadataResponse", "download_authorization"},
		{"FetchTaskDataRequest", "authorization"},
	} {
		message := file.Messages().ByName(entry.message)
		if message == nil {
			t.Fatalf("message %s descriptor missing", entry.message)
		}
		if field := message.Fields().ByName(entry.field); field != nil {
			t.Fatalf("%s.%s must be removed from the Worker/Verifier surface", entry.message, entry.field)
		}
	}
}

// TestWorkerVerifierContractSurface pins the Worker/Verifier method surface of the ingress API.
func TestWorkerVerifierContractSurface(t *testing.T) {
	file := nexusv1.File_nexus_v1_ingress_proto
	svc := file.Services().ByName("IngressAPI")
	if svc == nil {
		t.Fatal("IngressAPI descriptor missing")
	}
	methods := []struct {
		name           protoreflect.Name
		client, server bool
	}{
		{"UploadTaskResultObject", true, false},
		{"FinalizeTaskResult", false, false},
		{"FinalizeVerifierEvidence", false, false}, // client stream
		{"FetchTaskData", false, true},             // server stream
		{"GetTaskDataMetadata", false, false},
		{"SubmitInferReceipt", false, false},
		{"SubmitVerifyCommit", false, false},
		{"SubmitVerifyResult", false, false},
	}
	for _, want := range methods {
		method := svc.Methods().ByName(want.name)
		if method == nil || method.IsStreamingClient() != want.client || method.IsStreamingServer() != want.server {
			t.Fatalf("%s descriptor = %v", want.name, method)
		}
		if options, _ := method.Options().(*descriptorpb.MethodOptions); options.GetDeprecated() {
			t.Fatalf("API method %s must not be deprecated", want.name)
		}
	}
	// An upload commits to a single object only: object_ref + size + media_type, with the receipt not among them --
	// it is committed by FinalizeTaskResult's body domain.
	assertProtoFields(t, file.Messages().ByName("UploadTaskResultObjectHeaderV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"object_ref": 1, "size_bytes": 2, "media_type": 3, "request_auth": 4,
	})
	// The acknowledgement only states that the object is STORED and no longer carries a storage confirmation.
	assertProtoFields(t, file.Messages().ByName("UploadTaskResultObjectResponse"), map[protoreflect.Name]protoreflect.FieldNumber{
		"accepted": 1, "idempotent": 2, "metadata": 3,
	})
	// The storage confirmation converges on 9 fields, evidence is addressed by the three producer items of object_ref,
	// and there are no longer separate data_kind / evidence_type / evidence_hash fields.
	assertProtoFields(t, file.Messages().ByName("BuilderStorageConfirmationV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"schema_version": 1, "chain_id": 2, "builder_operator_address": 3,
		"service_authorization_nonce": 4, "object_ref": 5, "size_bytes": 6,
		"artifact_total_size_bytes": 7, "retention_until_height": 8, "service_signature": 9,
	})

	// The three relay requests carry only the on-chain message body: no session_id and no request_auth.
	// Authorization is the message's own service_signature; wrapping it in another envelope would add a second request identity.
	for _, tt := range []struct {
		message protoreflect.Name
		field   protoreflect.Name
	}{
		{"SubmitInferReceiptRequest", "receipt"},
		{"SubmitVerifyCommitRequest", "commit"},
		{"SubmitVerifyResultRequest", "receipt"},
	} {
		message := file.Messages().ByName(tt.message)
		if message == nil || message.Fields().Len() != 1 || message.Fields().ByName(tt.field) == nil {
			t.Fatalf("%s must carry exactly the chain message %q", tt.message, tt.field)
		}
		for _, forbidden := range []protoreflect.Name{"session_id", "task_id", "request_auth"} {
			if message.Fields().ByName(forbidden) != nil {
				t.Fatalf("%s must not carry %s", tt.message, forbidden)
			}
		}
	}

	// Both storage confirmation fields are reserved: a transport-layer acknowledgement must not state ahead of time that the whole Task Result is READY.
	for _, tt := range []struct {
		message protoreflect.Name
		field   protoreflect.Name
	}{
		{"SubmitInferReceiptResponse", "output_storage_confirmation"},
		{"OutputStreamResultV1", "storage_confirmation"},
	} {
		if file.Messages().ByName(tt.message).Fields().ByName(tt.field) != nil {
			t.Fatalf("%s.%s must stay reserved", tt.message, tt.field)
		}
	}

	// commit_key, metric_summary_hash and result_payload_hash are recomputed by the keeper,
	// so the request must not assert them.
	for _, name := range []protoreflect.Name{"SubmitVerifyCommitRequest", "SubmitVerifyResultRequest"} {
		if field := file.Messages().ByName(name).Fields().ByName("commit_key"); field != nil {
			t.Fatalf("%s must not carry commit_key: the Keeper recomputes it", name)
		}
	}
}

func TestTaskDataProtoContract(t *testing.T) {
	file := nexusv1.File_nexus_v1_ingress_proto
	svc := file.Services().ByName("IngressAPI")
	if svc == nil {
		t.Fatal("IngressAPI descriptor missing")
	}
	methods := []struct {
		name           protoreflect.Name
		client, server bool
	}{
		{"OpenTask", true, false},
		{"GetTaskDataMetadata", false, false},
		{"FetchTaskData", false, true},
		{"UploadTaskResultObject", true, false},
		{"FinalizeTaskResult", false, false},
		{"FinalizeVerifierEvidence", false, false},
	}
	for _, want := range methods {
		method := svc.Methods().ByName(want.name)
		if method == nil || method.IsStreamingClient() != want.client || method.IsStreamingServer() != want.server {
			t.Fatalf("%s descriptor = %v", want.name, method)
		}
	}

	// On the wire EVIDENCE splits into two values, manifest and artifact: their storage and authorization rules differ.
	kind := file.Enums().ByName("TaskDataObjectKind")
	if kind == nil || kind.Values().Len() != 5 ||
		kind.Values().ByName("TASK_DATA_OBJECT_KIND_INPUT").Number() != 1 ||
		kind.Values().ByName("TASK_DATA_OBJECT_KIND_OUTPUT").Number() != 2 ||
		kind.Values().ByName("TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST").Number() != 3 ||
		kind.Values().ByName("TASK_DATA_OBJECT_KIND_EVIDENCE_ARTIFACT").Number() != 4 {
		t.Fatalf("TaskDataObjectKind descriptor = %v", kind)
	}

	// An object is uniquely determined by these eight fields, which are also the first field of all four body domains.
	assertProtoFields(t, file.Messages().ByName("TaskDataObjectRefV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"task_hash": 1, "session_id": 2, "task_id": 3, "object_kind": 4, "content_hash": 5,
		"evidence_producer_kind": 6, "verify_round": 7, "producer_operator": 8,
	})
	// Fields 1..10 of the request authentication are exactly the ordered preimage of TRUEOPEN_TASK_DATA_REQUEST_V1;
	// the signature itself is not included.
	assertProtoFields(t, file.Messages().ByName("TaskDataRequestAuthV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"schema_version": 1, "chain_id": 2, "builder_operator_address": 3, "rpc_method": 4,
		"body_digest": 5, "requester_kind": 6, "requester_address": 7,
		"service_authorization_nonce": 8, "request_nonce": 9, "expiry_height": 10, "signature": 11,
	})
	assertProtoFields(t, file.Messages().ByName("TaskDataObjectMetadataV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"object_ref": 1, "size_bytes": 2, "media_type": 3, "readiness": 4,
		"chunk_lengths": 5, "output_leaf_count": 6,
	})
	// A whole-object read must sign range as absent, so range is optional; when present, length must be positive.
	assertProtoFields(t, file.Messages().ByName("ByteRangeV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"offset": 1, "length": 2,
	})
	// OpenTask is required to carry an idempotency_key (server-side deduplication is still to be implemented).
	assertProtoFields(t, file.Messages().ByName("OpenTaskHeader"), map[protoreflect.Name]protoreflect.FieldNumber{
		"input_size_bytes": 9, "input_hash": 10, "input_media_type": 11, "idempotency_key": 12,
	})
}

// TestSDKContractSurface pins the SDK method surface of the ingress API: every SDK method present
// with the right streaming shape, and the retired methods gone.
func TestSDKContractSurface(t *testing.T) {
	svc := nexusv1.File_nexus_v1_ingress_proto.Services().ByName("IngressAPI")
	if svc == nil {
		t.Fatal("IngressAPI descriptor missing")
	}
	contract := []struct {
		name           protoreflect.Name
		client, server bool
	}{
		{"OpenTask", true, false},
		{"GetTaskDataMetadata", false, false},
		{"FetchTaskData", false, true},
		{"SubscribeOutput", false, true},
		{"AckOutput", false, false},
		{"GetTaskStatus", false, false},
		{"GetTaskEvents", false, true},
		{"PrepareChallenge", false, false},
	}
	for _, want := range contract {
		method := svc.Methods().ByName(want.name)
		if method == nil || method.IsStreamingClient() != want.client || method.IsStreamingServer() != want.server {
			t.Fatalf("API method %s descriptor = %v", want.name, method)
		}
		if options, _ := method.Options().(*descriptorpb.MethodOptions); options.GetDeprecated() {
			t.Fatalf("API method %s must not be deprecated", want.name)
		}
	}
	for _, name := range []protoreflect.Name{
		"SubmitOrder", "FetchOutputRef", "RefreshCredential", "ConfirmOpenTask",
	} {
		if method := svc.Methods().ByName(name); method != nil {
			t.Fatalf("retired method %s must be removed, got %v", name, method)
		}
	}
}

func assertProtoFields(t *testing.T, message protoreflect.MessageDescriptor, fields map[protoreflect.Name]protoreflect.FieldNumber) {
	t.Helper()
	if message == nil {
		t.Fatal("message descriptor missing")
	}
	for name, number := range fields {
		field := message.Fields().ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("%s.%s descriptor = %v, want field %d", message.FullName(), name, field, number)
		}
	}
}

// TestOutputStreamContractSurface pins the wire shape of the streaming OUTPUT data plane
// (nexus/v1/ingress.proto): RPC shapes and field numbers. The implementation sits behind
// task_data.output_stream.enabled (another PR); this only guarantees the wire shape does not drift.
func TestOutputStreamContractSurface(t *testing.T) {
	file := nexusv1.File_nexus_v1_ingress_proto
	svc := file.Services().ByName("IngressAPI")
	method := svc.Methods().ByName("UploadTaskOutputStream")
	if method == nil || !method.IsStreamingClient() || !method.IsStreamingServer() {
		t.Fatalf("UploadTaskOutputStream descriptor = %v, want bidirectional stream", method)
	}
	msg := func(name protoreflect.Name) protoreflect.MessageDescriptor { return file.Messages().ByName(name) }
	assertProtoFields(t, msg("OutputStreamHeaderV2"), map[protoreflect.Name]protoreflect.FieldNumber{
		"session_id": 1, "task_id": 2, "task_hash": 3, "request_auth": 4, "stream_instance": 6,
		"user_recipient_pubkey": 7, "output_key_commitment": 8, "key_package_hash": 9, "worker_signature": 10,
		"dispatch_ticket_hash": 11,
	})
	if msg("OutputStreamHeaderV2").Fields().ByName("attempt") != nil {
		t.Fatal("OutputStreamHeaderV2.attempt must stay reserved: the dispatch ticket names the attempt")
	}
	assertProtoFields(t, msg("OutputChunkV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"seq": 1, "text": 2, "mmr_root": 3, "worker_signature": 4, "attachment": 5, "attachment_signature": 6,
		"cumulative_generated_tokens": 7, "dispatch_ticket_hash": 8,
	})
	assertProtoFields(t, msg("OutputFinV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"final_seq": 1, "output_mmr_root": 2, "dispatch_ticket_hash": 5,
	})
	assertProtoFields(t, msg("UploadTaskOutputStreamRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"header": 1, "chunk": 2, "fin": 3})
	assertProtoFields(t, msg("OutputStreamProgressV1"), map[protoreflect.Name]protoreflect.FieldNumber{"last_seq": 1, "mmr_root": 2, "last_frame_short": 3})
	if f := msg("OutputStreamProgressV1").Fields().ByName("last_seq"); f == nil || !f.HasPresence() {
		t.Fatal("OutputStreamProgressV1.last_seq must be optional: absent means nothing received")
	}
	assertProtoFields(t, msg("OutputStreamResultV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		// storage_confirmation (formerly field 5) is reserved: the confirmation is issued by FinalizeTaskResult.
		"accepted": 1, "last_seq": 2, "output_mmr_root": 3, "leaf_count": 4,
	})
	assertProtoFields(t, msg("UploadTaskOutputStreamResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"progress": 1, "result": 2})
	assertProtoFields(t, msg("SubscribeOutputRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"resume_after_seq": 4, "dispatch_ticket_hash": 5})
	assertProtoFields(t, msg("SubscribeOutputResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"chunk": 8, "fin": 9})
	if o := msg("SubscribeOutputResponse").Oneofs().ByName("frame"); o == nil || o.Fields().Len() != 2 {
		t.Fatalf("SubscribeOutputResponse.frame oneof = %v", o)
	}
	assertProtoFields(t, msg("AckOutputRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"last_seq": 5})
	assertProtoFields(t, msg("TaskDataObjectMetadataV1"), map[protoreflect.Name]protoreflect.FieldNumber{"chunk_lengths": 5, "output_leaf_count": 6})
	// SubmitInferReceiptResponse.output_storage_confirmation (formerly field 4) is reserved:
	// the storage confirmation is issued by FinalizeTaskResult instead, and a transport-layer acknowledgement does not state that the Task Result is READY.
	if msg("SubmitInferReceiptResponse").Fields().ByName("output_storage_confirmation") != nil {
		t.Fatal("output_storage_confirmation must stay reserved")
	}
	// Whole-text delivery is gone: output travels only as frames.
	for _, name := range []protoreflect.Name{"output_id", "session_id", "task_id", "output_text", "output_hash", "created_at", "expires_at"} {
		if f := msg("SubscribeOutputResponse").Fields().ByName(name); f != nil {
			t.Fatalf("SubscribeOutputResponse.%s must stay reserved", name)
		}
	}
}

func TestPrepareChallengeHeightProtoContract(t *testing.T) {
	message := nexusv1.File_nexus_v1_ingress_proto.Messages().ByName("PrepareChallengeResponse")
	field := message.Fields().ByName("challenge_close_height")
	if field == nil || field.Number() != 2 || field.Kind() != protoreflect.Uint64Kind {
		t.Fatalf("challenge_close_height descriptor = %v", field)
	}
}

// fakeHandler records calls and returns controllable results.
type fakeHandler struct {
	taskOwner           string
	taskTerminal        bool
	lastOrder           types.Order
	orderErr            error
	dispatchResult      *nexusv1.DispatchResultHeaderV1
	lastInferReceipt    types.InferReceiptSubmission
	inferReceiptErr     error
	lastVerifyCommit    *taskv1.VerifyCommitV1
	lastVerifyResult    *taskv1.ResultReceiptV3
	verifyRelayAck      types.VerifyRelayAck
	verifyRelayErr      error
	authorizedRequester string
	events              []types.TaskEvent
	live                chan types.TaskEvent
	onOrder             func(context.Context, types.Order) error
	checkOrder          func(context.Context, types.Order) error
	// sessionForTask is the lookup the wire relay path requires: the request carries only the on-chain message,
	// and the on-chain task_id does not contain the session.
	sessionForTask    string
	sessionForTaskErr error
}

func (f *fakeHandler) SessionForTask(_ context.Context, _ string) (string, error) {
	if f.sessionForTaskErr != nil {
		return "", f.sessionForTaskErr
	}
	if f.sessionForTask == "" {
		return "sess-relay", nil
	}
	return f.sessionForTask, nil
}

func (f *fakeHandler) CheckOrder(ctx context.Context, o types.Order) error {
	if f.checkOrder != nil {
		return f.checkOrder(ctx, o)
	}
	return nil
}

func (f *fakeHandler) OnOrder(ctx context.Context, o types.Order) error {
	f.lastOrder = o
	if f.onOrder != nil {
		return f.onOrder(ctx, o)
	}
	return f.orderErr
}
func (f *fakeHandler) DispatchResult(context.Context, string, string) (*nexusv1.DispatchResultHeaderV1, bool) {
	return f.dispatchResult, f.dispatchResult != nil
}

func (f *fakeHandler) OnInferReceipt(_ context.Context, receipt types.InferReceiptSubmission) error {
	f.lastInferReceipt = receipt
	return f.inferReceiptErr
}

func (f *fakeHandler) OnVerifyCommit(_ context.Context, _, _ string, commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error) {
	f.lastVerifyCommit = commit
	return f.verifyRelayAck, f.verifyRelayErr
}

func (f *fakeHandler) OnVerifyResult(_ context.Context, _, _ string, receipt *taskv1.ResultReceiptV3) (types.VerifyRelayAck, error) {
	f.lastVerifyResult = receipt
	return f.verifyRelayAck, f.verifyRelayErr
}

func (f *fakeHandler) TaskStatus(_ context.Context, _, _ string) (types.TaskStatus, error) {
	return types.TaskStatus{State: "VERIFYING", TaskPhase: "SAMPLE_READY"}, nil
}
func (f *fakeHandler) TaskEvents(_ context.Context, _, _ string, fromCursor uint64) ([]types.TaskEvent, <-chan types.TaskEvent, func(), error) {
	var replay []types.TaskEvent
	for _, e := range f.events {
		if e.Seq > fromCursor {
			replay = append(replay, e)
		}
	}
	return replay, f.live, func() {}, nil
}
func (f *fakeHandler) PrepareChallenge(_ context.Context, _, _, _ string) (types.ChallengePlan, error) {
	return types.ChallengePlan{ChallengeOpen: true, ChallengeCloseHeight: 42, RequiredEvidence: []string{"x"}}, nil
}

func newTestClient(t *testing.T, h Handler, auth AuthParams) nexusv1connect.IngressAPIClient {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := nexusv1connect.NewIngressAPIHandler(newService(h, auth))
	mux.Handle(path, handler)
	return nexusv1connect.NewIngressAPIClient(&http.Client{Transport: handlerRoundTripper{h: mux}}, "http://ingress.test")
}

// newStreamingTestClient serves the streaming OUTPUT data plane with an empty runtime: enough for
// requests refused before the runtime is used.
func newStreamingTestClient(t *testing.T, h Handler, auth AuthParams) nexusv1connect.IngressAPIClient {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := nexusv1connect.NewIngressAPIHandler(newService(h, auth, withOutputStream(&outputStreamRuntime{})))
	mux.Handle(path, handler)
	return nexusv1connect.NewIngressAPIClient(&http.Client{Transport: handlerRoundTripper{h: mux}}, "http://ingress.test")
}

// Without the streaming OUTPUT data plane there is no output delivery: SubscribeOutput and AckOutput
// answer Unimplemented before reading the request.
func TestOutputDeliveryNeedsOutputStream(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	result := <-receiveSubscribe(context.Background(), client, &nexusv1.SubscribeOutputRequest{
		SessionId: wireID(testSessionID("session")), TaskId: wireID(testSessionID("task")),
	})
	if connect.CodeOf(result.err) != connect.CodeUnimplemented {
		t.Fatalf("SubscribeOutput code = %v, err = %v", connect.CodeOf(result.err), result.err)
	}
	_, err := client.AckOutput(context.Background(), connect.NewRequest(&nexusv1.AckOutputRequest{
		SessionId: wireID(testSessionID("session")), TaskId: wireID(testSessionID("task")), LastSeq: 1,
	}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("AckOutput code = %v, err = %v", connect.CodeOf(err), err)
	}
}

func TestPrepareChallengeReturnsCloseHeight(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain})
	response, err := client.PrepareChallenge(context.Background(), connect.NewRequest(&nexusv1.PrepareChallengeRequest{
		SessionId: wireID(testSessionID("session-1")), TaskId: wireID(testSessionID("task-1")), ChallengeKind: "VERDICT_FRAUD_PROOF",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetChallengeCloseHeight() != 42 {
		t.Fatalf("height=%d", response.Msg.GetChallengeCloseHeight())
	}
}

func TestMapPrepareChallengeErr(t *testing.T) {
	tests := []struct {
		err  error
		code connect.Code
	}{
		{err: types.ErrTaskNotFound, code: connect.CodeNotFound},
		{err: types.ErrChainStateUnavailable, code: connect.CodeUnavailable},
		{err: errors.New("unexpected"), code: connect.CodeInternal},
	}
	for _, test := range tests {
		if got := connect.CodeOf(mapPrepareChallengeErr(test.err)); got != test.code {
			t.Fatalf("error=%v code=%v want=%v", test.err, got, test.code)
		}
	}
}

type handlerRoundTripper struct {
	h http.Handler
}

func (rt handlerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	rw := &pipeResponseWriter{
		header: make(http.Header),
		body:   pw,
		code:   http.StatusOK,
		ready:  make(chan struct{}),
	}
	go func() {
		rt.h.ServeHTTP(rw, req)
		rw.finish()
	}()
	<-rw.ready
	return &http.Response{
		StatusCode:    rw.code,
		Status:        http.StatusText(rw.code),
		Header:        rw.header.Clone(),
		Body:          pr,
		ContentLength: -1,
		Request:       req,
	}, nil
}

type pipeResponseWriter struct {
	header http.Header
	body   *io.PipeWriter
	code   int
	ready  chan struct{}
	wrote  bool
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.code = code
	w.wrote = true
	close(w.ready)
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

func (w *pipeResponseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
}

func (w *pipeResponseWriter) finish() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	_ = w.body.Close()
}

// testSignerKeys remembers the private key of every test signer for the places that need to sign a digest directly.
// The production path never does this -- there the private key is held only by Cortex.
var testSignerKeys = struct {
	byAddress map[string]string
}{byAddress: map[string]string{}}

func mustSigner(t *testing.T, hexKey string) signer.Signer {
	t.Helper()
	sg, err := signer.NewFromHex(hexKey, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	testSignerKeys.byAddress[sg.Address()] = hexKey
	return sg
}

func keyHexOf(t *testing.T, sg signer.Signer) string {
	t.Helper()
	hexKey, ok := testSignerKeys.byAddress[sg.Address()]
	if !ok {
		t.Fatalf("signer %s was not built by mustSigner, so its private key is unavailable", sg.Address())
	}
	return hexKey
}

// canonicalTestTaskID is a task_id in canonical lowercase 64-hex.
func canonicalTestTaskID(seed string) string {
	return hex.EncodeToString(relayTaskID(seed))
}

// validInferReceiptRequest builds a SubmitInferReceiptRequest in the frozen on-chain shape.
// The wire request carries only the receipt body: the session is looked up by task_id, and there is no request envelope.
func validInferReceiptRequest(
	t *testing.T, operator signer.Signer, _ string, taskID string, output []byte,
) *nexusv1.SubmitInferReceiptRequest {
	t.Helper()
	rawTaskID, err := hex.DecodeString(taskID)
	if err != nil {
		t.Fatal(err)
	}
	outputHash := sha256.Sum256(output)
	return &nexusv1.SubmitInferReceiptRequest{Receipt: &taskv1.InferReceiptV3{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV3, ChainId: "trueopen-localnet",
		TaskId: rawTaskID, TaskHash: bytes.Repeat([]byte{0x2a}, 32),
		WorkerOperatorAddress: operator.Address(), ServiceAuthorizationNonce: 7,
		DispatchTicketHash:     bytes.Repeat([]byte{0x7d}, 32),
		GenerationParamsDigest: bytes.Repeat([]byte{0x3b}, 32),
		OutputHash:             outputHash[:],
		OutputSizeBytes:        uint64(len(output)),
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind: 1, EvidenceHashOrRoot: bytes.Repeat([]byte{0x5d}, 32), EncodedSizeBytes: 4096,
		}, {
			EvidenceKind: 4, EvidenceHashOrRoot: bytes.Repeat([]byte{0x5e}, 32), EncodedSizeBytes: 520,
		}},
		ExpiryHeight: 1200, GeneratedTokenCount: 128, OutputLeafCount: 1,
		OutputKeyCommitment: make([]byte, 32), WorkerTokenKeyCommitment: make([]byte, 32),
		WorkerValueKeyCommitment: make([]byte, 32), CiphertextOutputRoot: make([]byte, 32),
	}}
}

// signInferReceiptRequest signs the receipt's on-chain digest with the given key. Authorization is that
// signature -- the request envelope no longer exists in wire.
func signInferReceiptRequest(t *testing.T, key signer.Signer, req *nexusv1.SubmitInferReceiptRequest) {
	t.Helper()
	// As above: a 64-byte placeholder lets the shape check pass, and the digest is unaffected by it.
	req.Receipt.ServiceSignature = make([]byte, 64)
	submission, err := inferReceiptFromPB(req, "trueopen-localnet")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	req.Receipt.ServiceSignature = mustSignDigest(t, keyHexOf(t, key), digest[:])
}

func mustSign(t *testing.T, sg signer.Signer, signBytes []byte) []byte {
	t.Helper()
	sig, err := sg.Sign(signBytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// mustSignDigest signs the 32-byte digest directly with no extra hashing layer -- this is the convention of both the
// strict on-chain verifier and the Cortex signer.
func mustSignDigest(t *testing.T, hexKey string, digest []byte) []byte {
	t.Helper()
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	sig := ecdsa.Sign(priv, digest)
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rb[:])
	copy(out[32:], sb[:])
	return out
}

// testSignatureChainID is the EIP-712 domain chainId the ingress tests sign under and carry as
// signature_chain_id.
const testSignatureChainID = uint64(4242)

// testUserChain answers the chain reads User request verification needs: the account key of every
// test signer (registered by mustSigner) and a fixed current height.
type fakeUserChain struct{ height uint64 }

var testUserChain = &fakeUserChain{height: 100}

func (c *fakeUserChain) CurrentHeight(context.Context) (uint64, error) { return c.height, nil }
func (c *fakeUserChain) AccountPubKey(_ context.Context, address string) ([]byte, error) {
	keyHex, ok := testSignerKeys.byAddress[address]
	if !ok {
		return nil, sdkauth.ErrNoAccountKey
	}
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(raw).PubKey().SerializeCompressed(), nil
}

// signEIP712 signs digest as a wallet does: 65 bytes R||S||V, V in {27, 28}.
func signEIP712(t *testing.T, sg signer.Signer, digest [32]byte) []byte {
	t.Helper()
	raw, err := hex.DecodeString(keyHexOf(t, sg))
	if err != nil {
		t.Fatal(err)
	}
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(raw), digest[:], false)
	return append(append([]byte{}, compact[1:]...), compact[0])
}

// testNonce stretches a label into the 32-byte request nonce the envelope requires.
func testNonce(label []byte) []byte {
	sum := sha256.Sum256(label)
	return sum[:]
}

// signedTaskEnvelope builds a wallet-signed SDKRequestEnvelopeV2 over body (the method's body digest).
func signedTaskEnvelope(
	t *testing.T,
	sg signer.Signer,
	method, endpoint, sessionID, taskID string,
	body, nonce []byte,
) *nexusv1.SDKRequestEnvelopeV2 {
	t.Helper()
	pb := &nexusv1.SDKRequestEnvelopeV2{
		RequestDomain: sdkauth.RequestDomain, ChainId: "trueopen-localnet", Method: method,
		Endpoint: endpoint, SessionId: sessionID, TaskId: taskID,
		RequestNonce: testNonce(nonce), ExpiryHeightOrTime: time.Now().Add(time.Hour).UnixMilli(),
		BodyDigest: append([]byte(nil), body...), SignerAddress: sg.Address(),
		SignatureChainId: testSignatureChainID,
	}
	resignTaskEnvelope(t, sg, pb)
	return pb
}

// resignTaskEnvelope re-signs pb (after a field changed) with sg's wallet key.
func resignTaskEnvelope(t *testing.T, sg signer.Signer, pb *nexusv1.SDKRequestEnvelopeV2) {
	t.Helper()
	e := envelopeFromPB(pb)
	var body [32]byte
	copy(body[:], pb.GetBodyDigest())
	digest, err := sdkauth.RequestDigest(e, body, [32]byte{})
	if err != nil {
		t.Fatalf("request digest: %v", err)
	}
	pb.Signature = signEIP712(t, sg, digest)
}

type subscribeStreamResult struct {
	response *nexusv1.SubscribeOutputResponse
	err      error
}

func receiveSubscribe(
	ctx context.Context,
	client nexusv1connect.IngressAPIClient,
	req *nexusv1.SubscribeOutputRequest,
) <-chan subscribeStreamResult {
	result := make(chan subscribeStreamResult, 1)
	go func() {
		stream, err := client.SubscribeOutput(ctx, connect.NewRequest(req))
		if err != nil {
			result <- subscribeStreamResult{err: err}
			return
		}
		if !stream.Receive() {
			result <- subscribeStreamResult{err: stream.Err()}
			return
		}
		response := stream.Msg()
		if stream.Receive() {
			result <- subscribeStreamResult{err: errors.New("SubscribeOutput returned more than one message")}
			return
		}
		result <- subscribeStreamResult{response: response, err: stream.Err()}
	}()
	return result
}

func TestWorkerServiceKeyAuthenticatesRoleRPCs(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	serviceKey := mustSigner(t, workerKeyHex)
	resolver := &fakeServiceKeyResolver{states: map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + operator.Address(): activeServiceKey(servicekey.ParticipantCortex, operator.Address(), serviceKey),
	}}
	auth := AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", BuilderAddress: "trueopen1builder", Bech32Prefix: "trueopen",
		RequireEnvelope: true, ServiceKeys: resolver,
	}

	t.Run("SubmitInferReceipt", func(t *testing.T) {
		client := newTestClient(t, &fakeHandler{}, auth)
		req := validInferReceiptRequest(t, operator, "service-session", canonicalTestTaskID("service"), []byte("output"))
		signInferReceiptRequest(t, serviceKey, req)
		if _, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(req)); err != nil {
			t.Fatalf("SubmitInferReceipt with Worker service key: %v", err)
		}
	})
}

func TestWorkerServiceKeyAuthenticationRejectsUnauthorizedKeys(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	serviceKey := mustSigner(t, workerKeyHex)
	alternateKey := mustSigner(t, alternateKeyHex)
	otherOperator := alternateKey.Address()

	tests := []struct {
		name      string
		presented signer.Signer
		states    map[string]chaincli.ServiceKeyState
	}{
		{
			name:      "revoked",
			presented: serviceKey,
			states: func() map[string]chaincli.ServiceKeyState {
				state := activeServiceKey(servicekey.ParticipantCortex, operator.Address(), serviceKey)
				state.Status = "REVOKED"
				return map[string]chaincli.ServiceKeyState{servicekey.ParticipantCortex + "|" + operator.Address(): state}
			}(),
		},
		{
			name: "belongs to another operator", presented: serviceKey,
			states: map[string]chaincli.ServiceKeyState{
				servicekey.ParticipantCortex + "|" + otherOperator: activeServiceKey(servicekey.ParticipantCortex, otherOperator, serviceKey),
			},
		},
		{
			name: "random", presented: alternateKey,
			states: map[string]chaincli.ServiceKeyState{
				servicekey.ParticipantCortex + "|" + operator.Address(): activeServiceKey(servicekey.ParticipantCortex, operator.Address(), serviceKey),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeServiceKeyResolver{states: tc.states}
			client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain,
				ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver,
			})
			req := validInferReceiptRequest(t, operator, "rejected-session", canonicalTestTaskID("rejected"), []byte("output"))
			signInferReceiptRequest(t, tc.presented, req)
			if _, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, err = %v; want Unauthenticated", connect.CodeOf(err), err)
			}
		})
	}
}

// "Chain lookup unavailable" must not degrade into "unauthorized".
//
// When the chain cannot be queried (including a malformed participant type domain: the "CORTEX_NODE" Cortex currently sends
// has no corresponding value in hub.v1.ParticipantType, so the request cannot even be issued), nexus has decided
// neither to authorize nor to reject. Reporting Unauthenticated would send Cortex and operators hunting for a signature/key error
// while the real failure is on the chain side or in how the query domain is built; it must report Unavailable -- consistent with the
// taskdata path (ErrAuthorityUnavailable -> CodeUnavailable) and semantically retryable.
func TestRoleSignatureAuthorityFailureIsUnavailableNotUnauthenticated(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	serviceKey := mustSigner(t, workerKeyHex)

	authorityFailures := map[string]error{
		"node unreachable":          errors.New("query current service key: endpoint unavailable"),
		"participant type not enum": errors.New(`query current service key: participant type "CORTEX_NODE" is not a hub.v1.ParticipantType value`),
		"keeper internal": connect.NewError(
			connect.CodeInternal, errors.New("query current service key: endpoint unavailable")),
	}

	for name, failure := range authorityFailures {
		t.Run(name, func(t *testing.T) {
			resolver := &fakeServiceKeyResolver{err: failure}
			auth := AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver}

			receipt := validInferReceiptRequest(t, operator, "authority-session", canonicalTestTaskID("authority"), []byte("output"))
			signInferReceiptRequest(t, serviceKey, receipt)
			if _, err := newTestClient(t, &fakeHandler{}, auth).SubmitInferReceipt(
				context.Background(), connect.NewRequest(receipt)); connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("SubmitInferReceipt code = %v, err = %v; want Unavailable", connect.CodeOf(err), err)
			}
			if resolver.calls == 0 {
				t.Fatal("service key authority was never consulted")
			}
		})
	}

	// Control group: the chain can be queried but this key is not the current service key -- that is a decided rejection.
	resolver := &fakeServiceKeyResolver{states: map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + operator.Address(): activeServiceKey(
			servicekey.ParticipantCortex, operator.Address(), mustSigner(t, alternateKeyHex)),
	}}
	receipt := validInferReceiptRequest(t, operator, "rejected-session", canonicalTestTaskID("rejected"), []byte("output"))
	signInferReceiptRequest(t, serviceKey, receipt)
	client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver,
	})
	if _, err := client.SubmitInferReceipt(
		context.Background(), connect.NewRequest(receipt)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong-key code = %v, err = %v; want Unauthenticated", connect.CodeOf(err), err)
	}
}

// There is no operator self-signing compatibility path: the CORTEX_SERVICE public key is read from the chain
// only by (CORTEX, requester_address). When the chain is unreachable it must fail closed and report chain lookup unavailable,
// never degrade into "no service key, so admit an operator self-signature".
func TestOperatorKeyFallbackIsGoneAndAuthorityFailureFailsClosed(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	resolver := &fakeServiceKeyResolver{err: errors.New("chain unavailable")}
	client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver,
	})
	req := validInferReceiptRequest(t, operator, "operator-session", canonicalTestTaskID("operator"), []byte("output"))
	signInferReceiptRequest(t, operator, req)
	_, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("code = %v, err = %v; want Unavailable", connect.CodeOf(err), err)
	}
	if resolver.calls == 0 {
		t.Fatal("service key must be queried: operator self-signing is no longer a valid path")
	}
}

func sha256Bytes(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

func TestSubscribeOutputRequiresEnvelopeEvenInDevMode(t *testing.T) {
	client := newStreamingTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: false})
	result := <-receiveSubscribe(context.Background(), client, &nexusv1.SubscribeOutputRequest{
		SessionId: wireID(testSessionID("session")), TaskId: wireID(testSessionID("task")),
	})
	if connect.CodeOf(result.err) != connect.CodeUnauthenticated {
		t.Fatalf("SubscribeOutput code = %v, err = %v", connect.CodeOf(result.err), result.err)
	}
}

func TestSubscribeOutputRejectsEnvelopeTaskMismatch(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	client := newStreamingTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	session, task := wireID(testSessionID("session")), wireID(testSessionID("task"))
	req := &nexusv1.SubscribeOutputRequest{SessionId: session, TaskId: task}
	req.RequestEnvelope = signedTaskEnvelope(
		t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
		session, wireID(testSessionID("other-task")), subscribeBody(t, session, task, nil), []byte("nonce-subscribe-mismatch"),
	)
	result := <-receiveSubscribe(context.Background(), client, req)
	if connect.CodeOf(result.err) != connect.CodeInvalidArgument {
		t.Fatalf("SubscribeOutput code = %v, err = %v", connect.CodeOf(result.err), result.err)
	}
}

// TestGetTaskEventsStream runs the event stream over a real connect server-streaming round trip: replay + live + cursor.
func TestGetTaskEventsStream(t *testing.T) {
	live := make(chan types.TaskEvent, 4)
	fake := &fakeHandler{
		events: []types.TaskEvent{
			{Seq: 1, EventCode: "ORDER_RECEIVED", State: "PENDING", TaskPhase: "UNSPECIFIED"},
			{Seq: 2, EventCode: "ASSIGN_ACCEPTED", State: "PENDING", TaskPhase: "ASSIGN_RANDOMNESS_PENDING", ChainHeight: 100},
		},
		live: live,
	}
	client := newTestClient(t, fake, AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.GetTaskEvents(ctx, connect.NewRequest(&nexusv1.GetTaskEventsRequest{
		SessionId: wireID(testSessionID("s")), TaskId: wireID(testSessionID("t")), FromCursor: "1", // resume from a cursor: skip seq 1
	}))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	live <- types.TaskEvent{Seq: 3, EventCode: "DISPATCH_RECORDED", State: "ASSIGNED", TaskPhase: "ASSIGNMENT_FINALIZED", ChainHeight: 101}
	close(live) // closing -> the stream ends normally

	var got []*nexusv1.GetTaskEventsResponse
	for stream.Receive() {
		got = append(got, stream.Msg())
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream err: %v", err)
	}
	if len(got) != 2 || got[0].GetCursor() != "2" || got[1].GetEventCode() != "DISPATCH_RECORDED" || got[1].GetChainHeight() != 101 {
		t.Fatalf("stream events mismatch: %+v", got)
	}
}

// session_id and task_id must be "0x" + 64 lowercase hex even in lenient mode (no envelope,
// RequireEnvelope off): a bare, uppercase or non-hex id is InvalidArgument, not a NotFound lookup.
func TestTaskIDsMustBePrefixedWithoutEnvelope(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: false})
	ctx := context.Background()
	session, task := testSessionID("session-lenient"), testSessionID("task-lenient")
	calls := map[string]func(sessionID, taskID string) error{
		"GetTaskEvents": func(sessionID, taskID string) error {
			stream, err := client.GetTaskEvents(ctx, connect.NewRequest(&nexusv1.GetTaskEventsRequest{SessionId: sessionID, TaskId: taskID}))
			if err != nil {
				return err
			}
			for stream.Receive() {
			}
			return stream.Err()
		},
		"GetTaskStatus": func(sessionID, taskID string) error {
			_, err := client.GetTaskStatus(ctx, connect.NewRequest(&nexusv1.GetTaskStatusRequest{SessionId: sessionID, TaskId: taskID}))
			return err
		},
		"PrepareChallenge": func(sessionID, taskID string) error {
			_, err := client.PrepareChallenge(ctx, connect.NewRequest(&nexusv1.PrepareChallengeRequest{
				SessionId: sessionID, TaskId: taskID, ChallengeKind: "VERDICT_FRAUD_PROOF",
			}))
			return err
		},
	}
	ids := map[string][2]string{
		"bare session_id":       {session, wireID(task)},
		"bare task_id":          {wireID(session), task},
		"uppercase 0X task_id":  {wireID(session), "0X" + task},
		"uppercase hex task_id": {wireID(session), "0x" + strings.ToUpper(task)},
		"text ids":              {"s", "t"},
	}
	for method, call := range calls {
		for name, id := range ids {
			t.Run(method+"/"+name, func(t *testing.T) {
				err := call(id[0], id[1])
				if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "NEXUS_INGRESS_MALFORMED") {
					t.Fatalf("code = %v, err = %v; want InvalidArgument NEXUS_INGRESS_MALFORMED", connect.CodeOf(err), err)
				}
			})
		}
	}
}

// SubscribeOutput and AckOutput refuse a bare session_id or task_id with InvalidArgument: the SDK body
// digest cannot be computed over it, so the request fails before its envelope is checked.
func TestSubscribeAndAckRejectBareIDs(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	session, task := testSessionID("session-bare-ids"), testSessionID("task-bare-ids")
	auth := AuthParams{Chain: testUserChain, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"}
	clients := map[string]nexusv1connect.IngressAPIClient{
		"streaming": newStreamingTestClient(t, &fakeHandler{}, auth),
	}
	ids := map[string][2]string{
		"bare session_id": {session, wireID(task)},
		"bare task_id":    {wireID(session), task},
	}
	nonce := 0
	for plane, client := range clients {
		for name, id := range ids {
			t.Run(plane+"/SubscribeOutput/"+name, func(t *testing.T) {
				nonce++
				// A well-formed envelope over the 0x ids: only the request's own ids are bare.
				env := signedTaskEnvelope(t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
					wireID(session), wireID(task), subscribeBody(t, wireID(session), wireID(task), nil), []byte("bare-sub-"+strconv.Itoa(nonce)))
				result := <-receiveSubscribe(context.Background(), client, &nexusv1.SubscribeOutputRequest{
					SessionId: id[0], TaskId: id[1], RequestEnvelope: env,
				})
				if connect.CodeOf(result.err) != connect.CodeInvalidArgument || !strings.Contains(result.err.Error(), "must be 0x") {
					t.Fatalf("code = %v, err = %v; want InvalidArgument naming the 0x spelling", connect.CodeOf(result.err), result.err)
				}
			})
			t.Run(plane+"/AckOutput/"+name, func(t *testing.T) {
				nonce++
				env := signedTaskEnvelope(t, sg, "AckOutput", nexusv1connect.IngressAPIAckOutputProcedure,
					wireID(session), wireID(task), ackBody(t, wireID(session), wireID(task), 1), []byte("bare-ack-"+strconv.Itoa(nonce)))
				_, err := client.AckOutput(context.Background(), connect.NewRequest(&nexusv1.AckOutputRequest{
					SessionId: id[0], TaskId: id[1], LastSeq: 1, RequestEnvelope: env,
				}))
				if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "must be 0x") {
					t.Fatalf("code = %v, err = %v; want InvalidArgument naming the 0x spelling", connect.CodeOf(err), err)
				}
			})
		}
	}
}

func (h *fakeHandler) IsTaskTerminal(_, _ string) bool { return h.taskTerminal }

func (h *fakeHandler) TaskOwner(_ context.Context, _, _ string) (string, error) {
	if h.taskOwner == "" {
		return "", types.ErrTaskNotFound
	}
	return h.taskOwner, nil
}

// subscribeBody is the TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1 digest of a SubscribeOutput request.
func subscribeBody(t *testing.T, sessionID, taskID string, resumeAfterSeq *uint64) []byte {
	t.Helper()
	body, err := sdkauth.SubscribeOutputBody(sessionID, taskID, resumeAfterSeq, nil)
	if err != nil {
		t.Fatalf("subscribe body: %v", err)
	}
	return body[:]
}

// ackBody is the TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1 digest of an AckOutput request.
func ackBody(t *testing.T, sessionID, taskID string, lastSeq uint64) []byte {
	t.Helper()
	body, err := sdkauth.AckOutputBody(sessionID, taskID, lastSeq)
	if err != nil {
		t.Fatalf("ack body: %v", err)
	}
	return body[:]
}

// GetTaskEvents and PrepareChallenge serve only the user who ordered the task: a request signed by
// anyone else, or an envelope bound to another task, is refused.
func TestTaskEventsAndChallengeRequireOrderUser(t *testing.T) {
	owner := mustSigner(t, testKeyHex)
	other := mustSigner(t, workerKeyHex)
	session, task := wireID(testSessionID("session-owner-only")), wireID(testSessionID("task-owner-only"))
	otherTask := wireID(testSessionID("task-owner-other"))
	live := make(chan types.TaskEvent)
	close(live)
	fake := &fakeHandler{taskOwner: owner.Address(), live: live}
	client := newTestClient(t, fake, AuthParams{Chain: testUserChain,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	nonce := 0
	events := func(sg signer.Signer, envelopeTask string) error {
		nonce++
		body, err := sdkauth.GetTaskEventsBody(session, envelopeTask, "")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := client.GetTaskEvents(context.Background(), connect.NewRequest(&nexusv1.GetTaskEventsRequest{
			SessionId: session, TaskId: task,
			RequestEnvelope: signedTaskEnvelope(t, sg, "GetTaskEvents", nexusv1connect.IngressAPIGetTaskEventsProcedure,
				session, envelopeTask, body[:], []byte("events-"+strconv.Itoa(nonce))),
		}))
		if err != nil {
			return err
		}
		for stream.Receive() {
		}
		return stream.Err()
	}
	challenge := func(sg signer.Signer, envelopeTask string) error {
		nonce++
		body, err := sdkauth.PrepareChallengeBody(session, envelopeTask, "VERDICT_FRAUD_PROOF", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.PrepareChallenge(context.Background(), connect.NewRequest(&nexusv1.PrepareChallengeRequest{
			SessionId: session, TaskId: task, ChallengeKind: "VERDICT_FRAUD_PROOF",
			RequestEnvelope: signedTaskEnvelope(t, sg, "PrepareChallenge", nexusv1connect.IngressAPIPrepareChallengeProcedure,
				session, envelopeTask, body[:], []byte("challenge-"+strconv.Itoa(nonce))),
		}))
		return err
	}
	for name, call := range map[string]func(signer.Signer, string) error{"GetTaskEvents": events, "PrepareChallenge": challenge} {
		t.Run(name, func(t *testing.T) {
			if err := call(owner, task); err != nil {
				t.Fatalf("order user: %v", err)
			}
			if err := call(other, task); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("another user: code %v (%v), want permission_denied", connect.CodeOf(err), err)
			}
			if err := call(owner, otherTask); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("envelope for another task: code %v (%v), want invalid_argument", connect.CodeOf(err), err)
			}
		})
	}
}
