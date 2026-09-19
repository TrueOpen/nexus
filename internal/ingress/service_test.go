package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/payloadstore"
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
	// The target-state baseline of the nexus<->Cortex contract removes SubmitOutputRef and the inline output_text:
	// the target state for plaintext delivery to the SDK is FetchTaskData(OUTPUT).
	for _, name := range []protoreflect.Name{"SubmitOutputRef", "FetchPayload", "UploadTaskData", "RefreshTaskDataAuthorization"} {
		if method := svc.Methods().ByName(name); method != nil {
			t.Fatalf("%s must be removed by the Cortex contract, got %v", name, method)
		}
	}
	for _, name := range []protoreflect.Name{
		"SubmitOutputRefRequest", "SubmitOutputRefResponse", "FetchPayloadRequest", "FetchPayloadResponse",
		"UploadTaskDataHeader", "UploadTaskDataRequest", "UploadTaskDataResponse",
		"RefreshTaskDataAuthorizationRequest", "RefreshTaskDataAuthorizationResponse",
		"OutputRef", "TaskDataAuthorizationV1",
	} {
		if message := file.Messages().ByName(name); message != nil {
			t.Fatalf("message %s must be removed by the Cortex contract", name)
		}
	}
	// §9 implementation alignment check: no OutputRef-related field may remain on the nexus ingress contract surface.
	for _, entry := range []struct {
		message protoreflect.Name
		field   protoreflect.Name
	}{
		{"FetchOutputRefResponse", "output_ref"},
		{"RefreshCredentialResponse", "output_ref"},
		{"GetTaskDataMetadataResponse", "download_authorization"},
		{"FetchTaskDataRequest", "authorization"},
	} {
		message := file.Messages().ByName(entry.message)
		if message == nil {
			t.Fatalf("message %s descriptor missing", entry.message)
		}
		if field := message.Fields().ByName(entry.field); field != nil {
			t.Fatalf("%s.%s must be removed by the Cortex contract", entry.message, entry.field)
		}
	}
}

// TestWorkerVerifierContractSurface pins the Worker/Verifier method surface of §2 of the nexus<->Cortex contract.
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
		{"FinalizeVerifierEvidence", false, false}, // §2.1 client stream
		{"FetchTaskData", false, true},             // §2.2 server stream
		{"GetTaskDataMetadata", false, false},      // §2.3
		{"SubmitInferReceipt", false, false},       // §2.4
		{"SubmitVerifyCommit", false, false},       // §2.5
		{"SubmitVerifyResult", false, false},       // §2.6
	}
	for _, want := range methods {
		method := svc.Methods().ByName(want.name)
		if method == nil || method.IsStreamingClient() != want.client || method.IsStreamingServer() != want.server {
			t.Fatalf("%s descriptor = %v", want.name, method)
		}
		if options, _ := method.Options().(*descriptorpb.MethodOptions); options.GetDeprecated() {
			t.Fatalf("contract method %s must not be deprecated", want.name)
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
		{"ConfirmOpenTask", false, false},
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
	// Contract §3.1 requires OpenTask to carry an idempotency_key (server-side deduplication is still to be implemented).
	assertProtoFields(t, file.Messages().ByName("OpenTaskHeader"), map[protoreflect.Name]protoreflect.FieldNumber{
		"input_size_bytes": 9, "input_hash": 10, "input_media_type": 11, "idempotency_key": 12,
	})
}

// TestSDKContractSurface pins the SDK method surface of §3 of the nexus<->SDK interface contract v0.1:
// all 9 contract methods present with the right streaming shape; the pre-existing SDK methods the contract supersedes stay deprecated
// until the members rule on a removal date (see docs/nexus-sdk-contract-migration.md).
func TestSDKContractSurface(t *testing.T) {
	svc := nexusv1.File_nexus_v1_ingress_proto.Services().ByName("IngressAPI")
	if svc == nil {
		t.Fatal("IngressAPI descriptor missing")
	}
	contract := []struct {
		name           protoreflect.Name
		client, server bool
	}{
		{"OpenTask", true, false},             // §3.1
		{"ConfirmOpenTask", false, false},     // §3.2
		{"GetTaskDataMetadata", false, false}, // §3.3
		{"FetchTaskData", false, true},        // §3.4
		{"SubscribeOutput", false, true},      // §3.5
		{"AckOutput", false, false},           // §3.6
		{"GetTaskStatus", false, false},       // §3.7
		{"GetTaskEvents", false, true},        // §3.8
		{"PrepareChallenge", false, false},    // §3.9
	}
	for _, want := range contract {
		method := svc.Methods().ByName(want.name)
		if method == nil || method.IsStreamingClient() != want.client || method.IsStreamingServer() != want.server {
			t.Fatalf("contract method %s descriptor = %v", want.name, method)
		}
		if options, _ := method.Options().(*descriptorpb.MethodOptions); options.GetDeprecated() {
			t.Fatalf("contract method %s must not be deprecated", want.name)
		}
	}
	for _, name := range []protoreflect.Name{
		"SubmitOrder", "FetchOutputRef", "RefreshCredential",
	} {
		method := svc.Methods().ByName(name)
		if method == nil {
			t.Fatalf("superseded method %s descriptor missing", name)
		}
		if options, _ := method.Options().(*descriptorpb.MethodOptions); !options.GetDeprecated() {
			t.Fatalf("superseded method %s must stay deprecated until removal is agreed", name)
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

// TestOutputStreamContractSurface pins the wire shape of the ADR-0017 streaming OUTPUT data plane
// (wire v0.4.0 nexus/v1/ingress.proto): RPC shapes and field numbers. The implementation sits behind
// task_data.output_stream.enabled (another PR); this only guarantees the contract does not drift.
func TestOutputStreamContractSurface(t *testing.T) {
	file := nexusv1.File_nexus_v1_ingress_proto
	svc := file.Services().ByName("IngressAPI")
	method := svc.Methods().ByName("UploadTaskOutputStream")
	if method == nil || !method.IsStreamingClient() || !method.IsStreamingServer() {
		t.Fatalf("UploadTaskOutputStream descriptor = %v, want bidirectional stream", method)
	}
	msg := func(name protoreflect.Name) protoreflect.MessageDescriptor { return file.Messages().ByName(name) }
	assertProtoFields(t, msg("OutputStreamHeaderV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"session_id": 1, "task_id": 2, "task_hash": 3, "request_auth": 4,
	})
	assertProtoFields(t, msg("OutputChunkV1"), map[protoreflect.Name]protoreflect.FieldNumber{
		"seq": 1, "text": 2, "mmr_root": 3, "worker_signature": 4, "attachment": 5, "attachment_signature": 6,
	})
	assertProtoFields(t, msg("OutputFinV1"), map[protoreflect.Name]protoreflect.FieldNumber{"final_seq": 1, "output_mmr_root": 2})
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
	assertProtoFields(t, msg("SubscribeOutputRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"resume_after_seq": 4})
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
	for _, name := range []protoreflect.Name{"output_id", "session_id", "task_id", "output_text", "output_hash", "created_at", "expires_at"} {
		f := msg("SubscribeOutputResponse").Fields().ByName(name)
		if opts, _ := f.Options().(*descriptorpb.FieldOptions); f == nil || !opts.GetDeprecated() {
			t.Fatalf("SubscribeOutputResponse.%s must be deprecated (whole-text delivery is superseded by frames)", name)
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
	lastOrder           types.Order
	orderErr            error
	lastInferReceipt    types.InferReceiptSubmission
	inferReceiptErr     error
	lastVerifyCommit    *taskv1.VerifyCommitV1
	lastVerifyResult    *taskv1.ResultReceiptV2
	verifyRelayAck      types.VerifyRelayAck
	verifyRelayErr      error
	authorizedRequester string
	events              []types.TaskEvent
	live                chan types.TaskEvent
	subscribeOutput     func(context.Context, string, string, string) (types.PlaintextOutput, error)
	ackOutput           func(context.Context, string, string, string, string) (types.OutputAck, error)
	onOrder             func(context.Context, types.Order) error
	// sessionForTask is the lookup the wire v0.4.1 relay path requires: the request carries only the on-chain message,
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

func (f *fakeHandler) OnOrder(ctx context.Context, o types.Order) error {
	f.lastOrder = o
	if f.onOrder != nil {
		return f.onOrder(ctx, o)
	}
	return f.orderErr
}
func (f *fakeHandler) OnInferReceipt(_ context.Context, receipt types.InferReceiptSubmission) error {
	f.lastInferReceipt = receipt
	return f.inferReceiptErr
}

func (f *fakeHandler) OnVerifyCommit(_ context.Context, _, _ string, commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error) {
	f.lastVerifyCommit = commit
	return f.verifyRelayAck, f.verifyRelayErr
}

func (f *fakeHandler) OnVerifyResult(_ context.Context, _, _ string, receipt *taskv1.ResultReceiptV2) (types.VerifyRelayAck, error) {
	f.lastVerifyResult = receipt
	return f.verifyRelayAck, f.verifyRelayErr
}

func (f *fakeHandler) SubscribeOutput(ctx context.Context, sessionID, taskID, requester string) (types.PlaintextOutput, error) {
	if f.subscribeOutput != nil {
		return f.subscribeOutput(ctx, sessionID, taskID, requester)
	}
	return types.PlaintextOutput{}, nil
}

func (f *fakeHandler) AckOutput(ctx context.Context, sessionID, taskID, outputID, requester string) (types.OutputAck, error) {
	if f.ackOutput != nil {
		return f.ackOutput(ctx, sessionID, taskID, outputID, requester)
	}
	return types.OutputAck{}, nil
}
func (f *fakeHandler) FetchOutputRef(_ context.Context, _, _, requester string, level types.AccessLevel, usage string) (types.Credential, error) {
	authorized := f.authorizedRequester
	if authorized == "" {
		authorized = "trueopen1authorized"
	}
	if level == types.AccessSealedKey && requester != authorized {
		return types.Credential{}, types.ErrUnauthorized
	}
	return types.Credential{ID: "cred-1", Recipient: requester, Usage: usage, AccessLevel: level}, nil
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
func (f *fakeHandler) RefreshCredential(_ context.Context, old types.Credential, _, _ string, _ int64) (types.Credential, error) {
	return old, nil
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

func TestPrepareChallengeReturnsCloseHeight(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{})
	response, err := client.PrepareChallenge(context.Background(), connect.NewRequest(&nexusv1.PrepareChallengeRequest{
		SessionId: "session-1", TaskId: "task-1", ChallengeKind: "VERDICT_FRAUD_PROOF",
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
// The wire v0.4.1 request carries only the receipt body: the session is looked up by task_id, and there is no request envelope.
func validInferReceiptRequest(
	t *testing.T, operator signer.Signer, _ string, taskID string, output []byte,
) *nexusv1.SubmitInferReceiptRequest {
	t.Helper()
	rawTaskID, err := hex.DecodeString(taskID)
	if err != nil {
		t.Fatal(err)
	}
	outputHash := sha256.Sum256(output)
	return &nexusv1.SubmitInferReceiptRequest{Receipt: &taskv1.InferReceiptV2{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainId: "trueopen-localnet",
		TaskId: rawTaskID, TaskHash: bytes.Repeat([]byte{0x2a}, 32),
		WorkerOperatorAddress: operator.Address(), ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: bytes.Repeat([]byte{0x3b}, 32),
		OutputHash:             outputHash[:],
		OutputSizeBytes:        uint64(len(output)),
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind: 1, EvidenceHashOrRoot: bytes.Repeat([]byte{0x5d}, 32), EncodedSizeBytes: 4096,
		}},
		ExpiryHeight: 1200, GeneratedTokenCount: 128, OutputLeafCount: 1,
	}}
}

// signInferReceiptRequest signs the receipt's on-chain digest with the given key. Authorization is that
// signature -- the request envelope no longer exists in wire v0.4.1.
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

// signedEnvelope builds a valid SDK envelope.
func signedEnvelope(t *testing.T, sg signer.Signer, method string, body []byte) *nexusv1.SDKRequestEnvelopeV1 {
	t.Helper()
	env := &sdkauth.Envelope{
		RequestDomain:      sdkauth.RequestDomain,
		ChainID:            "trueopen-localnet",
		Method:             method,
		ExpiryHeightOrTime: time.Now().Add(time.Hour).UnixMilli(),
		BodyDigest:         body,
		RequestNonce:       []byte("nonce-" + method),
		SignerAddress:      sg.Address(),
		SignerPubKey:       sg.PubKeyCompressed(),
	}
	sig := mustSign(t, sg, sdkauth.SignBytes(env))
	return &nexusv1.SDKRequestEnvelopeV1{
		RequestDomain:      env.RequestDomain,
		ChainId:            env.ChainID,
		Method:             env.Method,
		ExpiryHeightOrTime: env.ExpiryHeightOrTime,
		BodyDigest:         env.BodyDigest,
		RequestNonce:       env.RequestNonce,
		SignerAddress:      env.SignerAddress,
		Signature:          sig,
		SignerPubkey:       env.SignerPubKey,
	}
}

func signedTaskEnvelope(
	t *testing.T,
	sg signer.Signer,
	method, endpoint, sessionID, taskID string,
	body, nonce []byte,
) *nexusv1.SDKRequestEnvelopeV1 {
	t.Helper()
	env := &sdkauth.Envelope{
		RequestDomain: sdkauth.RequestDomain, ChainID: "trueopen-localnet",
		Method: method, Endpoint: endpoint, SessionID: sessionID, TaskID: taskID,
		RequestNonce: nonce, ExpiryHeightOrTime: time.Now().Add(time.Hour).UnixMilli(),
		BodyDigest: body, SignerAddress: sg.Address(), SignerPubKey: sg.PubKeyCompressed(),
	}
	signature := mustSign(t, sg, sdkauth.SignBytes(env))
	return &nexusv1.SDKRequestEnvelopeV1{
		RequestDomain: env.RequestDomain, ChainId: env.ChainID, Method: env.Method,
		Endpoint: env.Endpoint, SessionId: env.SessionID, TaskId: env.TaskID,
		RequestNonce: env.RequestNonce, ExpiryHeightOrTime: env.ExpiryHeightOrTime,
		BodyDigest: env.BodyDigest, SignerAddress: env.SignerAddress,
		Signature: signature, SignerPubkey: env.SignerPubKey,
	}
}

func resignTaskEnvelope(t *testing.T, sg signer.Signer, pb *nexusv1.SDKRequestEnvelopeV1) {
	t.Helper()
	env := &sdkauth.Envelope{
		RequestDomain: pb.GetRequestDomain(), ChainID: pb.GetChainId(), Method: pb.GetMethod(),
		Endpoint: pb.GetEndpoint(), SessionID: pb.GetSessionId(), TaskID: pb.GetTaskId(),
		RequestNonce: pb.GetRequestNonce(), ExpiryHeightOrTime: pb.GetExpiryHeightOrTime(),
		BodyDigest: pb.GetBodyDigest(), SignerAddress: pb.GetSignerAddress(), SignerPubKey: pb.GetSignerPubkey(),
	}
	pb.Signature = mustSign(t, sg, sdkauth.SignBytes(env))
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

// TestSubmitOrderEnvelopeEnforcement covers enforcing mode: no envelope is rejected; a valid envelope is admitted and Order.User is set.
func TestSubmitOrderEnvelopeEnforcement(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()
	req := canonicalOrderRequest(t, sg, testSessionID("sess-env"), 1, "model-test")

	// No envelope -> Unauthenticated.
	_, err := client.SubmitOrder(ctx, connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}

	// Valid envelope -> admitted, and the signer address becomes the order user.
	env := signedEnvelope(t, sg, "SubmitOrder", submitOrderBodyDigest(req))
	req.RequestEnvelope = env
	resp, err := client.SubmitOrder(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("submit with envelope: %v", err)
	}
	if !resp.Msg.GetAccepted() || fake.lastOrder.User != sg.Address() {
		t.Fatalf("order user not bound: %+v", fake.lastOrder)
	}

	// Tampered body (the envelope digest no longer matches) -> InvalidArgument.
	tampered := proto.Clone(req).(*nexusv1.SubmitOrderRequest)
	tampered.PayloadRef = "bafy-tampered"
	_, err = client.SubmitOrder(ctx, connect.NewRequest(tampered))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument on body mismatch, got %v", err)
	}
}

func TestSubmitOrderRejectsReplayEnvelope(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()

	req := canonicalOrderRequest(t, sg, testSessionID("sess-replay"), 1, "model-replay")
	req.RequestEnvelope = signedEnvelope(t, sg, "SubmitOrder", submitOrderBodyDigest(req))
	if _, err := client.SubmitOrder(ctx, connect.NewRequest(req)); err != nil {
		t.Fatalf("first SubmitOrder: %v", err)
	}
	if _, err := client.SubmitOrder(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated replay rejection, got %v", err)
	}
}

func TestSubmitOrderMapsStage1AdmissionErrors(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	tests := []struct {
		name    string
		err     error
		code    connect.Code
		message string
	}{
		{name: "not selected", err: coordinator.ErrNotSelectedBuilder, code: connect.CodePermissionDenied, message: "NEXUS_INGRESS_NOT_SELECTED_BUILDER"},
		{name: "authority unavailable", err: coordinator.ErrAdmissionUnavailable, code: connect.CodeUnavailable, message: "NEXUS_INGRESS_STAGE1_UNAVAILABLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeHandler{orderErr: tt.err}
			client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
			req := canonicalOrderRequest(t, user, testSessionID("sess-admission-"+tt.name), 1, "model-test")
			req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))

			_, err := client.SubmitOrder(context.Background(), connect.NewRequest(req))
			if connect.CodeOf(err) != tt.code || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("SubmitOrder error=%v code=%v want code=%v message=%q", err, connect.CodeOf(err), tt.code, tt.message)
			}
		})
	}
}

// TestSubmitOrderProductParameters covers the product parameters of a user-submitted task:
// order_envelope/payload_ref/signature/request_envelope all enter the digest, and the user address lands in Order.User.
func TestSubmitOrderProductParameters(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()

	wantSessionID := testSessionID("sess-product")
	req := canonicalOrderRequest(t, user, wantSessionID, 7, "model-qwen-72b")
	req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))

	resp, err := client.SubmitOrder(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("SubmitOrder: %v", err)
	}
	wantTaskID := mustDeriveTaskID(t, wantSessionID, 7)
	if !resp.Msg.GetAccepted() || resp.Msg.GetTaskId() != wantTaskID || resp.Msg.GetSessionId() != wantSessionID {
		t.Fatalf("submit order response mismatch: %+v want task=%s session=%s", resp.Msg, wantTaskID, wantSessionID)
	}
	if fake.lastOrder.User != user.Address() || fake.lastOrder.PayloadCID != req.GetPayloadRef() ||
		fake.lastOrder.TaskID != wantTaskID || fake.lastOrder.SessionID != wantSessionID ||
		fake.lastOrder.OrderSequence != 7 || fake.lastOrder.ModelID != "model-qwen-72b" ||
		fake.lastOrder.OrderEnvelope != string(req.GetOrderEnvelope()) || fake.lastOrder.SignatureScheme != "secp256k1" ||
		fake.lastOrder.UserSignature != hex.EncodeToString(req.GetSignature()) || fake.lastOrder.MaxFee != 1000 ||
		fake.lastOrder.InferTimeoutBlocks != 20 || fake.lastOrder.Deadline != 1000 {
		t.Fatalf("order not fully bound: %+v", fake.lastOrder)
	}

	tampered := proto.Clone(req).(*nexusv1.SubmitOrderRequest)
	tampered.PayloadRef = "bafy-input-tampered"
	_, err = client.SubmitOrder(ctx, connect.NewRequest(tampered))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("tampered payload_ref must be rejected, got %v", err)
	}
}

func TestSubmitOrderRejectsNonHash32SessionID(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	client := newTestClient(t, &fakeHandler{}, AuthParams{
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true,
	})
	req := canonicalOrderRequest(t, user, "session-text", 7, "model-test")
	req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))

	_, err := client.SubmitOrder(context.Background(), connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("SubmitOrder error=%v code=%v, want InvalidArgument for session_id", err, connect.CodeOf(err))
	}
}

func TestSubmitOrderBindsAndValidatesPayload(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()
	req := canonicalOrderRequest(t, user, testSessionID("sess-payload"), 1, "model-payload")
	req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))

	if _, err := client.SubmitOrder(ctx, connect.NewRequest(req)); err != nil {
		t.Fatalf("SubmitOrder: %v", err)
	}
	if !bytes.Equal(fake.lastOrder.Payload, req.GetPayload()) || fake.lastOrder.PayloadCID != req.GetPayloadRef() {
		t.Fatalf("payload not bound to order: order=%+v request_ref=%q", fake.lastOrder, req.GetPayloadRef())
	}

	tamperedPayload := proto.Clone(req).(*nexusv1.SubmitOrderRequest)
	tamperedPayload.Payload = []byte("different encrypted payload")
	tamperedPayload.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(tamperedPayload))
	client = newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	if _, err := client.SubmitOrder(ctx, connect.NewRequest(tamperedPayload)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("payload hash mismatch code = %v, want InvalidArgument: %v", connect.CodeOf(err), err)
	}

	tamperedRef := proto.Clone(req).(*nexusv1.SubmitOrderRequest)
	tamperedRef.PayloadRef = payloadstore.RefFor([]byte("different encrypted payload"))
	tamperedRef.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(tamperedRef))
	client = newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	if _, err := client.SubmitOrder(ctx, connect.NewRequest(tamperedRef)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("payload ref mismatch code = %v, want InvalidArgument: %v", connect.CodeOf(err), err)
	}
}

func TestWorkerServiceKeyAuthenticatesRoleRPCs(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	serviceKey := mustSigner(t, workerKeyHex)
	resolver := &fakeServiceKeyResolver{states: map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + operator.Address(): activeServiceKey(servicekey.ParticipantCortex, operator.Address(), serviceKey),
	}}
	auth := AuthParams{
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

	t.Run("FetchOutputRef", func(t *testing.T) {
		client := newTestClient(t, &fakeHandler{}, auth)
		req := &nexusv1.FetchOutputRefRequest{
			SessionId: "service-session", TaskId: "service-task", Requester: operator.Address(),
			RequesterPubkey: serviceKey.PubKeyCompressed(), Usage: "VERIFIER_FETCH",
			AccessLevel: nexusv1.AccessLevel_ACCESS_LEVEL_PACKAGE_UNSPECIFIED,
		}
		req.Signature = mustSign(t, serviceKey, fetchOutputRefSignBytes(req, types.AccessPackage))
		if _, err := client.FetchOutputRef(context.Background(), connect.NewRequest(req)); err != nil {
			t.Fatalf("FetchOutputRef with Worker service key: %v", err)
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
			client := newTestClient(t, &fakeHandler{}, AuthParams{
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

// "Chain lookup unavailable" must not degrade into "unauthorized" (gh #22 acceptance criterion 4).
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
			auth := AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver}

			receipt := validInferReceiptRequest(t, operator, "authority-session", canonicalTestTaskID("authority"), []byte("output"))
			signInferReceiptRequest(t, serviceKey, receipt)
			if _, err := newTestClient(t, &fakeHandler{}, auth).SubmitInferReceipt(
				context.Background(), connect.NewRequest(receipt)); connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("SubmitInferReceipt code = %v, err = %v; want Unavailable", connect.CodeOf(err), err)
			}

			fetch := &nexusv1.FetchOutputRefRequest{
				SessionId: "authority-session", TaskId: "authority-task", Requester: operator.Address(),
				RequesterPubkey: serviceKey.PubKeyCompressed(), Usage: "VERIFIER_FETCH",
			}
			fetch.Signature = mustSign(t, serviceKey, fetchOutputRefSignBytes(fetch, types.AccessPackage))
			if _, err := newTestClient(t, &fakeHandler{}, auth).FetchOutputRef(
				context.Background(), connect.NewRequest(fetch)); connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("FetchOutputRef code = %v, err = %v; want Unavailable", connect.CodeOf(err), err)
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
	client := newTestClient(t, &fakeHandler{}, AuthParams{
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", ServiceKeys: resolver,
	})
	if _, err := client.SubmitInferReceipt(
		context.Background(), connect.NewRequest(receipt)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong-key code = %v, err = %v; want Unauthenticated", connect.CodeOf(err), err)
	}
}

// From wire v0.4.1 on there is no operator self-signing compatibility path: the CORTEX_SERVICE public key is read from the chain
// only by (CORTEX, requester_address). When the chain is unreachable it must fail closed and report chain lookup unavailable,
// never degrade into "no service key, so admit an operator self-signature".
func TestOperatorKeyFallbackIsGoneAndAuthorityFailureFailsClosed(t *testing.T) {
	operator := mustSigner(t, testKeyHex)
	resolver := &fakeServiceKeyResolver{err: errors.New("chain unavailable")}
	client := newTestClient(t, &fakeHandler{}, AuthParams{
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

func TestSubmitOrderRejectsMalformedOrderEnvelope(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()

	req := canonicalOrderRequest(t, user, "sess-bad", 1, "model-bad")
	req.OrderEnvelope = []byte(`{"session_id":"sess-bad","order_sequence":1,"model_id":"model-bad"}`)
	req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))
	_, err := client.SubmitOrder(ctx, connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for missing model_id, got %v", err)
	}

	// A request-level order_sequence that differs from the one the user signature covers -> rejected.
	//
	// This section previously asserted "order_sequence == 0 -> InvalidArgument", and that criterion was itself
	// wrong: 0 is the valid first value for every session on chain (see order_sequence_zero_test.go),
	// so rejecting on it would keep the first order of any new session out.
	//
	// The invariant that actually needs guarding is this one: this request's signature covers sequence=1, so after changing it to 0
	// the signature no longer matches and order signature verification stops it -- `Unauthenticated`, not `InvalidArgument`.
	// That is stronger than the old zero check: it stops any value inconsistent with the user signature,
	// not just the single special case of 0.
	client = newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	req = canonicalOrderRequest(t, user, "sess-bad", 1, "model-bad")
	req.OrderSequence = 0
	req.RequestEnvelope = signedEnvelope(t, user, "SubmitOrder", submitOrderBodyDigest(req))
	_, err = client.SubmitOrder(ctx, connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated for an order_sequence the user did not sign, got %v", err)
	}
}

func canonicalOrderRequest(t *testing.T, user signer.Signer, sessionID string, sequence uint64, modelID string) *nexusv1.SubmitOrderRequest {
	t.Helper()
	payload := []byte("encrypted payload for " + sessionID + "/" + modelID)
	payloadHash := sha256.Sum256(payload)
	envelope := nodecontract.AssignmentOrderEnvelopeV1{
		SchemaVersion: nodecontract.OrderEnvelopeSchemaV1, ModelID: modelID, ProfileVersion: 1, TaskType: "inference",
		RewardBucket: 1, ProfileResourceTier: 2, InferInputUnitPriceBid: 2, InferOutputUnitPriceBid: 3, VerifyUnitPriceBid: 4,
		MaxFee: 1000, TxFeeReserve: 100, InferFeeCap: 600, VerifyFeeCap: 300, OrderValue: 900,
		ValidAfterHeight: 10, DeadlineHeight: 1000, PayloadHash: hex.EncodeToString(payloadHash[:]),
		InferTimeoutBlocks: 20, ReferenceBucketKey: "reference-v1", TimeoutBucketKey: "timeout-v1",
	}
	raw, err := nodecontract.CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return &nexusv1.SubmitOrderRequest{
		OrderEnvelope: []byte(raw), PayloadRef: payloadstore.RefFor(payload), Payload: payload, SessionId: sessionID, OrderSequence: sequence,
		UserAddress: user.Address(), SignatureScheme: "secp256k1",
		Signature: mustSign(t, user, nodecontract.OrderSigningBytes("trueopen-localnet", user.Address(), sessionID, sequence, raw)),
	}
}

func sha256Bytes(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

func TestSubscribeOutputWaitsAndStreamsOneResult(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	started := make(chan struct{})
	release := make(chan struct{})
	fake := &fakeHandler{subscribeOutput: func(ctx context.Context, sessionID, taskID, requester string) (types.PlaintextOutput, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return types.PlaintextOutput{}, ctx.Err()
		}
		return types.PlaintextOutput{
			OutputID: "output-1", SessionID: sessionID, TaskID: taskID,
			Text: "hello", Hash: []byte("hash"), CreatedAt: 10, ExpiresAt: 20,
		}, nil
	}}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	const session, task = "session-stream", "task-stream"
	body := sdkauth.BodyDigest([]byte(session), []byte(task))
	req := &nexusv1.SubscribeOutputRequest{SessionId: session, TaskId: task}
	req.RequestEnvelope = signedTaskEnvelope(
		t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
		session, task, body, []byte("nonce-subscribe-wait"),
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := receiveSubscribe(ctx, client, req)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("SubscribeOutput did not reach handler")
	}
	close(release)
	got := <-result
	if got.err != nil || got.response.GetOutputId() != "output-1" || got.response.GetOutputText() != "hello" ||
		got.response.GetSessionId() != session || got.response.GetTaskId() != task || got.response.GetCreatedAt() != 10 || got.response.GetExpiresAt() != 20 {
		t.Fatalf("SubscribeOutput = %+v/%v", got.response, got.err)
	}
}

func TestSubscribeOutputRequiresEnvelopeEvenInDevMode(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: false})
	result := <-receiveSubscribe(context.Background(), client, &nexusv1.SubscribeOutputRequest{
		SessionId: "session", TaskId: "task",
	})
	if connect.CodeOf(result.err) != connect.CodeUnauthenticated {
		t.Fatalf("SubscribeOutput code = %v, err = %v", connect.CodeOf(result.err), result.err)
	}
}

func TestSubscribeOutputRejectsEnvelopeTaskMismatch(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	client := newTestClient(t, &fakeHandler{}, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	const session, task = "session", "task"
	req := &nexusv1.SubscribeOutputRequest{SessionId: session, TaskId: task}
	req.RequestEnvelope = signedTaskEnvelope(
		t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
		session, "other-task", sdkauth.BodyDigest([]byte(session), []byte(task)), []byte("nonce-subscribe-mismatch"),
	)
	result := <-receiveSubscribe(context.Background(), client, req)
	if connect.CodeOf(result.err) != connect.CodeInvalidArgument {
		t.Fatalf("SubscribeOutput code = %v, err = %v", connect.CodeOf(result.err), result.err)
	}
}

func TestSubscribeOutputMapsUnauthorizedAndExpired(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code connect.Code
	}{
		{name: "unauthorized", err: outputdelivery.ErrUnauthorized, code: connect.CodePermissionDenied},
		{name: "expired", err: outputdelivery.ErrExpired, code: connect.CodeFailedPrecondition},
		{name: "shutdown", err: outputdelivery.ErrDeliveryFailure, code: connect.CodeUnavailable},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sg := mustSigner(t, testKeyHex)
			fake := &fakeHandler{subscribeOutput: func(context.Context, string, string, string) (types.PlaintextOutput, error) {
				return types.PlaintextOutput{}, tc.err
			}}
			client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			const session, task = "session", "task"
			req := &nexusv1.SubscribeOutputRequest{SessionId: session, TaskId: task}
			req.RequestEnvelope = signedTaskEnvelope(
				t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
				session, task, sdkauth.BodyDigest([]byte(session), []byte(task)), []byte{byte(index + 1)},
			)
			result := <-receiveSubscribe(context.Background(), client, req)
			if connect.CodeOf(result.err) != tc.code {
				t.Fatalf("code = %v, err = %v", connect.CodeOf(result.err), result.err)
			}
		})
	}
}

func TestSubscribeOutputAuthorizationMatrix(t *testing.T) {
	owner := mustSigner(t, testKeyHex)
	other := mustSigner(t, workerKeyHex)
	const session, task = "session-auth-matrix", "task-auth-matrix"
	fake := &fakeHandler{subscribeOutput: func(_ context.Context, sessionID, taskID, requester string) (types.PlaintextOutput, error) {
		if requester != owner.Address() {
			return types.PlaintextOutput{}, outputdelivery.ErrUnauthorized
		}
		return types.PlaintextOutput{
			OutputID: "output-auth", SessionID: sessionID, TaskID: taskID, Text: "authorized",
		}, nil
	}}
	client := newTestClient(t, fake, AuthParams{
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: false,
	})
	body := sdkauth.BodyDigest([]byte(session), []byte(task))
	request := func(sg signer.Signer, nonce string) *nexusv1.SubscribeOutputRequest {
		return &nexusv1.SubscribeOutputRequest{
			SessionId: session,
			TaskId:    task,
			RequestEnvelope: signedTaskEnvelope(
				t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure,
				session, task, body, []byte(nonce),
			),
		}
	}

	valid := request(owner, "nonce-auth-valid")
	result := <-receiveSubscribe(context.Background(), client, valid)
	if result.err != nil || result.response.GetOutputId() != "output-auth" {
		t.Fatalf("valid owner result = %+v/%v", result.response, result.err)
	}

	denied := <-receiveSubscribe(context.Background(), client, request(other, "nonce-auth-other"))
	if connect.CodeOf(denied.err) != connect.CodePermissionDenied || !strings.Contains(denied.err.Error(), outputdelivery.ErrUnauthorized.Error()) {
		t.Fatalf("other account code = %v, err = %v", connect.CodeOf(denied.err), denied.err)
	}

	replayed := <-receiveSubscribe(context.Background(), client, valid)
	if connect.CodeOf(replayed.err) != connect.CodeUnauthenticated || !strings.Contains(replayed.err.Error(), sdkauth.ErrReplay.Error()) {
		t.Fatalf("replay code = %v, err = %v", connect.CodeOf(replayed.err), replayed.err)
	}

	expired := request(owner, "nonce-auth-expired")
	expired.RequestEnvelope.ExpiryHeightOrTime = time.Now().Add(-time.Second).UnixMilli()
	resignTaskEnvelope(t, owner, expired.RequestEnvelope)
	expiredResult := <-receiveSubscribe(context.Background(), client, expired)
	if connect.CodeOf(expiredResult.err) != connect.CodeDeadlineExceeded || !strings.Contains(expiredResult.err.Error(), sdkauth.ErrExpired.Error()) {
		t.Fatalf("expired code = %v, err = %v", connect.CodeOf(expiredResult.err), expiredResult.err)
	}
}

func TestAckOutputSignsBodyAndReturnsIdempotentResult(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	var gotSession, gotTask, gotOutputID, gotRequester string
	fake := &fakeHandler{ackOutput: func(_ context.Context, sessionID, taskID, outputID, requester string) (types.OutputAck, error) {
		gotSession, gotTask, gotOutputID, gotRequester = sessionID, taskID, outputID, requester
		return types.OutputAck{Acked: true, AlreadyAcked: true, AckedAt: 42}, nil
	}}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	const session, task, outputID = "session-ack", "task-ack", "output-ack"
	req := &nexusv1.AckOutputRequest{SessionId: session, TaskId: task, OutputId: outputID}
	req.RequestEnvelope = signedTaskEnvelope(
		t, sg, "AckOutput", nexusv1connect.IngressAPIAckOutputProcedure,
		session, task,
		sdkauth.BodyDigest([]byte(session), []byte(task), []byte(outputID)),
		[]byte("nonce-ack-success"),
	)
	resp, err := client.AckOutput(context.Background(), connect.NewRequest(req))
	if err != nil || !resp.Msg.GetAcked() || !resp.Msg.GetAlreadyAcked() || resp.Msg.GetAckedAt() != 42 {
		t.Fatalf("AckOutput = %+v/%v", resp, err)
	}
	if gotSession != session || gotTask != task || gotOutputID != outputID || gotRequester != sg.Address() {
		t.Fatalf("handler args = %q/%q/%q/%q", gotSession, gotTask, gotOutputID, gotRequester)
	}

	tampered := proto.Clone(req).(*nexusv1.AckOutputRequest)
	tampered.OutputId = "other-output"
	if _, err := client.AckOutput(context.Background(), connect.NewRequest(tampered)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("tampered AckOutput code = %v, err = %v", connect.CodeOf(err), err)
	}
}

func TestAckOutputMapsStableErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code connect.Code
	}{
		{name: "unauthorized", err: outputdelivery.ErrUnauthorized, code: connect.CodePermissionDenied},
		{name: "conflict", err: outputdelivery.ErrConflict, code: connect.CodeFailedPrecondition},
		{name: "expired", err: outputdelivery.ErrExpired, code: connect.CodeFailedPrecondition},
		{name: "already acked", err: outputdelivery.ErrAlreadyAcked, code: connect.CodeFailedPrecondition},
		{name: "unavailable", err: outputdelivery.ErrUnavailable, code: connect.CodeFailedPrecondition},
		{name: "storage", err: outputdelivery.ErrDeliveryFailure, code: connect.CodeUnavailable},
		{name: "task missing", err: types.ErrTaskNotFound, code: connect.CodeNotFound},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sg := mustSigner(t, testKeyHex)
			fake := &fakeHandler{ackOutput: func(context.Context, string, string, string, string) (types.OutputAck, error) {
				return types.OutputAck{}, tc.err
			}}
			client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			const session, task, outputID = "session", "task", "output"
			req := &nexusv1.AckOutputRequest{SessionId: session, TaskId: task, OutputId: outputID}
			req.RequestEnvelope = signedTaskEnvelope(
				t, sg, "AckOutput", nexusv1connect.IngressAPIAckOutputProcedure,
				session, task,
				sdkauth.BodyDigest([]byte(session), []byte(task), []byte(outputID)),
				[]byte{byte(index + 20)},
			)
			if _, err := client.AckOutput(context.Background(), connect.NewRequest(req)); connect.CodeOf(err) != tc.code {
				t.Fatalf("code = %v, err = %v", connect.CodeOf(err), err)
			}
		})
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
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.GetTaskEvents(ctx, connect.NewRequest(&nexusv1.GetTaskEventsRequest{
		SessionId: "s", TaskId: "t", FromCursor: "1", // resume from a cursor: skip seq 1
	}))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	live <- types.TaskEvent{Seq: 3, EventCode: "ASSIGNMENT_FINALIZED", State: "ASSIGNED", TaskPhase: "ASSIGNMENT_FINALIZED", ChainHeight: 101}
	close(live) // closing -> the stream ends normally

	var got []*nexusv1.GetTaskEventsResponse
	for stream.Receive() {
		got = append(got, stream.Msg())
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream err: %v", err)
	}
	if len(got) != 2 || got[0].GetCursor() != "2" || got[1].GetEventCode() != "ASSIGNMENT_FINALIZED" || got[1].GetChainHeight() != 101 {
		t.Fatalf("stream events mismatch: %+v", got)
	}
}

// TestFetchOutputRefErrorMapping: an authorization failure -> PermissionDenied (CREDENTIAL_UNAUTHORIZED).
func TestFetchOutputRefErrorMapping(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	fake := &fakeHandler{authorizedRequester: sg.Address()}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	ctx := context.Background()

	_, err := client.FetchOutputRef(ctx, connect.NewRequest(&nexusv1.FetchOutputRefRequest{
		SessionId: "s", TaskId: "t", Requester: "trueopen1stranger",
		AccessLevel: nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY, Usage: "VERIFIER_FETCH",
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated without signature, got %v", err)
	}

	stranger := mustSigner(t, workerKeyHex)
	deniedReq := &nexusv1.FetchOutputRefRequest{
		SessionId:       "s",
		TaskId:          "t",
		Requester:       stranger.Address(),
		RequesterPubkey: stranger.PubKeyCompressed(),
		AccessLevel:     nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY,
		Usage:           "VERIFIER_FETCH",
	}
	deniedReq.Signature = mustSign(t, stranger, fetchOutputRefSignBytes(deniedReq, types.AccessSealedKey))
	_, err = client.FetchOutputRef(ctx, connect.NewRequest(deniedReq))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	allowedReq := &nexusv1.FetchOutputRefRequest{
		SessionId:       "s",
		TaskId:          "t",
		Requester:       sg.Address(),
		RequesterPubkey: sg.PubKeyCompressed(),
		AccessLevel:     nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY,
		Usage:           "VERIFIER_FETCH",
	}
	allowedReq.Signature = mustSign(t, sg, fetchOutputRefSignBytes(allowedReq, types.AccessSealedKey))
	resp, err := client.FetchOutputRef(ctx, connect.NewRequest(allowedReq))
	if err != nil {
		t.Fatalf("authorized fetch: %v", err)
	}
	// The contract's target-state baseline removes the OutputRef object: only the binding credential is returned.
	if resp.Msg.GetCredential().GetCredentialId() == "" {
		t.Fatalf("authorized fetch payload: %+v", resp.Msg)
	}
}

func (h *fakeHandler) TaskOwner(_ context.Context, _, _ string) (string, error) {
	if h.taskOwner == "" {
		return "", types.ErrTaskNotFound
	}
	return h.taskOwner, nil
}
