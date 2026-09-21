package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// End-to-end cases for the streaming OUTPUT data plane (sequence diagrams 1 / 2 / 3 / 5): real Connect round trips,
// the Worker signing every frame with its service key, and the user subscribing with an SDK envelope.

type streamTaskAuthority struct {
	mu     sync.RWMutex
	height uint64
	task   chaincli.OnChainTask
	keys   map[string]chaincli.ServiceKeyState
}

func (a *streamTaskAuthority) LatestHeight(context.Context) (uint64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.height, nil
}

func (a *streamTaskAuthority) QueryTask(_ context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.task.SessionID != key.SessionID || a.task.TaskID != key.TaskID {
		return chaincli.OnChainTask{}, chaincli.ErrNotFound
	}
	return a.task, nil
}

func (a *streamTaskAuthority) QueryProfile(context.Context, string, uint32) (chaincli.ProfileState, error) {
	return chaincli.ProfileState{}, chaincli.ErrNotFound
}

func (a *streamTaskAuthority) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	state, ok := a.keys[participantType+"|"+operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func streamServiceKey(participantType, operator string, sg signer.Signer) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: participantType, OperatorAddress: operator,
		ServiceAddress: sg.Address(), ServicePubKey: hex.EncodeToString(sg.PubKeyCompressed()),
		AuthorizationNonce: 1, UpdatedHeight: 100, Status: "ACTIVE",
	}
}

// signDigestRaw64 reproduces the Worker's direct-digest signature over the frozen digest (R||S, low-S).
func signDigestRaw64(t *testing.T, hexKey string, digest []byte) []byte {
	t.Helper()
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	sig := ecdsa.Sign(secp256k1.PrivKeyFromBytes(raw), digest)
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rb[:])
	copy(out[32:], sb[:])
	return out
}

// streamRequestAuth builds the request authentication for the CORTEX_SERVICE path. bodyDigest is computed by each call site
// under its own body domain and passed in -- body_digest inside the auth is the value the caller claims, and the
// server compares it byte for byte against the one it computes itself.
func streamRequestAuth(
	t *testing.T, worker signer.Signer, workerKey string, method taskdata.RequestMethod,
	key taskdata.ObjectKey, expires uint64, nonce []byte, bodyDigest [32]byte,
) *nexusv1.TaskDataRequestAuthV1 {
	t.Helper()
	requestNonce := make([]byte, 32)
	copy(requestNonce, nonce)
	request := taskdata.RequestAuth{
		SchemaVersion: 1, ChainID: "trueopen-localnet", BuilderOperatorAddress: integrationBuilderAddress,
		RPCMethod:     "/nexus.v1.IngressAPI/" + string(method),
		BodyDigest:    hex.EncodeToString(bodyDigest[:]),
		RequesterKind: taskdata.RequesterKindCortexService, RequesterAddress: worker.Address(),
		ServiceAuthorizationNonce: 1, RequestNonce: requestNonce, ExpiryHeight: expires, Key: key,
	}
	digest, err := taskdata.CortexTaskDataRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return &nexusv1.TaskDataRequestAuthV1{
		SchemaVersion: request.SchemaVersion, ChainId: request.ChainID,
		BuilderOperatorAddress: request.BuilderOperatorAddress, RpcMethod: request.RPCMethod,
		BodyDigest:                request.BodyDigest,
		RequesterKind:             nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_CORTEX_SERVICE,
		RequesterAddress:          request.RequesterAddress,
		ServiceAuthorizationNonce: request.ServiceAuthorizationNonce,
		RequestNonce:              request.RequestNonce,
		ExpiryHeight:              request.ExpiryHeight,
		Signature:                 mustSignDigest(t, workerKey, digest[:]),
	}
}

// mustMetadataBody is the body digest of a metadata request: the object ref itself.
func mustMetadataBody(t *testing.T, key taskdata.ObjectKey) [32]byte {
	t.Helper()
	digest, err := taskdata.TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func streamHeaderAuth(t *testing.T, worker signer.Signer, workerKey string, key taskdata.ObjectKey, expires uint64, nonce []byte) *nexusv1.TaskDataRequestAuthV1 {
	t.Helper()
	digest, err := taskdata.OutputStreamBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	return streamRequestAuth(t, worker, workerKey, taskdata.MethodUploadStream, key, expires, nonce, digest)
}

type streamFixture struct {
	client    nexusv1connect.IngressAPIClient
	user      signer.Signer
	worker    signer.Signer
	authority *streamTaskAuthority
	session   string
	taskID    string
	taskHash  []byte
	key       taskdata.ObjectKey
}

func newStreamFixture(t *testing.T, enabled bool) *streamFixture {
	t.Helper()
	user := mustSigner(t, testKeyHex)
	worker := mustSigner(t, workerKeyHex)
	builderService := mustSigner(t, "0000000000000000000000000000000000000000000000000000000000000002")
	backend := kv.NewMemStore()
	store, err := taskdata.NewStore(
		slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "task-data"), backend,
		taskdata.Config{
			InlineMaxBytes: 16, ChunkSizeBytes: 16, MaxRangeBytes: 64, MaxBlobBytes: 64,
			SpoolReservationBytes: 128, DiskAcceptWatermarkPercent: 99,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := &streamTaskAuthority{height: 100, keys: map[string]chaincli.ServiceKeyState{
		"BUILDER|" + integrationBuilderAddress: streamServiceKey("BUILDER", integrationBuilderAddress, builderService),
		"CORTEX|" + worker.Address():           streamServiceKey("CORTEX", worker.Address(), worker),
	}}
	authorizer, err := taskdata.NewAuthorizer(taskdata.AuthorizerConfig{
		ChainID: "trueopen-localnet", EVMChainID: 31337, BuilderAddress: integrationBuilderAddress, AddressPrefix: "trueopen",
		RequestTTLBlocks: 20, RetentionLeaseBlocks: 50,
	}, backend, authority, builderService)
	if err != nil {
		t.Fatal(err)
	}
	dataService, err := taskdata.NewService(store, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	options := []Option{WithPayloadMaxBytes(16), WithReadMaxBytes(16), WithTaskDataService(dataService)}
	if enabled {
		dataService.SetOutputStreamConfig(taskdata.OutputStreamConfig{MaxLeaves: 8, MinFrameBytes: 2, MaxFrameBytes: 16, MaxAttachmentBytes: 8})
		options = append(options, WithOutputStream(dataService, taskdata.NewOutputDispatcher(8), backend))
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{},
		AuthParams{ChainID: "trueopen-localnet", BuilderAddress: integrationBuilderAddress, Bech32Prefix: "trueopen"},
		&fakeHandler{taskOwner: user.Address()}, options...,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Bidirectional streaming needs HTTP/2: httptest defaults to HTTP/1.1, where the request body does not reach the server until it is closed,
	// so enable TLS + HTTP/2 (in production nexus has its own TLS, likewise h2).
	httpServer := httptest.NewUnstartedServer(server.handler())
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	session := testSessionID("session-stream")
	taskID := mustDeriveTaskID(t, session, 1)
	taskHash := sha256.Sum256([]byte("accepted-task-" + taskID))
	authority.task = chaincli.OnChainTask{
		SessionID: session, TaskID: taskID, State: types.Assigned,
		Assignment: chaincli.TaskAssignmentState{
			UserAddress: user.Address(), SelectedWorkerOperatorAddress: worker.Address(),
			AcceptedTaskHash: hex.EncodeToString(taskHash[:]),
		},
	}
	return &streamFixture{
		client: nexusv1connect.NewIngressAPIClient(httpServer.Client(), httpServer.URL),
		user:   user, worker: worker, authority: authority, session: session, taskID: taskID, taskHash: taskHash[:],
		key: taskdata.ObjectKey{
			TaskHash: hex.EncodeToString(taskHash[:]), SessionID: session, TaskID: taskID,
			Kind: taskdata.ObjectKindOutput, ContentHash: strings.Repeat("7", 64),
		},
	}
}

func (f *streamFixture) subscribe(t *testing.T, ctx context.Context, sg signer.Signer, resumeAfter uint64, nonce string) *connect.ServerStreamForClient[nexusv1.SubscribeOutputResponse] {
	t.Helper()
	body := sdkauth.BodyDigest([]byte(f.session), []byte(f.taskID))
	env := signedTaskEnvelope(t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure, f.session, f.taskID, body, []byte(nonce))
	stream, err := f.client.SubscribeOutput(ctx, connect.NewRequest(&nexusv1.SubscribeOutputRequest{
		SessionId: f.session, TaskId: f.taskID, RequestEnvelope: env, ResumeAfterSeq: resumeAfter,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

type subscribeResult struct {
	frames []*nexusv1.SubscribeOutputResponse
	err    error
}

// subscribeAsync subscribes before the stream starts: the SubscribeOutput call only returns at the first frame (HTTP streaming
// response headers are sent with the first message), so both the call and the frame reads run in a goroutine, with the envelope signed here up front.
func (f *streamFixture) subscribeAsync(t *testing.T, ctx context.Context, sg signer.Signer, resumeAfter uint64, nonce string) <-chan subscribeResult {
	t.Helper()
	body := sdkauth.BodyDigest([]byte(f.session), []byte(f.taskID))
	env := signedTaskEnvelope(t, sg, "SubscribeOutput", nexusv1connect.IngressAPISubscribeOutputProcedure, f.session, f.taskID, body, []byte(nonce))
	request := connect.NewRequest(&nexusv1.SubscribeOutputRequest{
		SessionId: f.session, TaskId: f.taskID, RequestEnvelope: env, ResumeAfterSeq: resumeAfter,
	})
	out := make(chan subscribeResult, 1)
	go func() {
		stream, err := f.client.SubscribeOutput(ctx, request)
		if err != nil {
			out <- subscribeResult{err: err}
			return
		}
		frames, err := collectFrames(stream)
		out <- subscribeResult{frames: frames, err: err}
	}()
	return out
}

func collectFrames(stream *connect.ServerStreamForClient[nexusv1.SubscribeOutputResponse]) ([]*nexusv1.SubscribeOutputResponse, error) {
	var frames []*nexusv1.SubscribeOutputResponse
	for stream.Receive() {
		frames = append(frames, stream.Msg())
	}
	return frames, stream.Err()
}

func (f *streamFixture) sendChunk(t *testing.T, up *connect.BidiStreamForClient[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse], acc *mmr.Accumulator, seq uint64, text string) {
	t.Helper()
	root := acc.Append([]byte(text))
	digest, err := nodecontract.OutputChunkSigningDigest("trueopen-localnet", f.taskHash, seq, root[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Chunk{Chunk: &nexusv1.OutputChunkV1{
		Seq: seq, Text: []byte(text), MmrRoot: root[:], WorkerSignature: signDigestRaw64(t, workerKeyHex, digest[:]),
	}}}); err != nil {
		t.Fatal(err)
	}
}

func TestOutputStreamIntegrationUploadSubscribeAck(t *testing.T) {
	f := newStreamFixture(t, true)
	ctx := context.Background()

	// Diagram 5: subscribe before the stream starts (resume_after_seq left unset).
	subCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	received := f.subscribeAsync(t, subCtx, f.user, 0, "nonce-subscribe-early-0001")

	// Diagram 1: Header -> progress (empty) -> three chunks -> receipt has arrived -> fin frame with the storage confirmation.
	up := f.client.UploadTaskOutputStream(ctx)
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte("nonce-stream-header-0001")),
	}}}); err != nil {
		t.Fatal(err)
	}
	first, err := up.Receive()
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if progress := first.GetProgress(); progress == nil || progress.LastSeq != nil || progress.GetLastFrameShort() {
		t.Fatalf("fresh progress = %v", first)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	texts := []string{"Hello, ", "stream", "!"}
	for i, text := range texts {
		f.sendChunk(t, up, acc, uint64(i), text)
	}
	final := acc.Root()
	// wire v0.1.1 OutputFinV1 carries finish_reason and worker_signature; the Builder stores the frame
	// and replays it byte-identically (TRUEOPEN_OUTPUT_FIN_V1 registry note). Not verified here yet.
	finSignature := bytes.Repeat([]byte{0xf1}, 64)
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Fin{Fin: &nexusv1.OutputFinV1{
		FinalSeq: 2, OutputMmrRoot: final[:], FinishReason: taskv1.FinishReasonV1_FINISH_REASON_V1_EOS_TOKEN, WorkerSignature: finSignature,
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := up.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	last, err := up.Receive()
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	result := last.GetResult()
	if result == nil || !result.GetAccepted() || result.GetLastSeq() != 2 || result.GetLeafCount() != 3 ||
		hex.EncodeToString(result.GetOutputMmrRoot()) != hex.EncodeToString(final[:]) {
		t.Fatalf("result = %v", last)
	}
	// wire v0.4.1 marks OutputStreamResultV1.storage_confirmation as reserved:
	// the fin frame only states that this stream has been fully persisted, and the storage confirmation is instead issued once by
	// FinalizeTaskResult after it checks the receipt, the STORED output and all required evidence (design §5.5).
	_ = up.CloseResponse()

	// The subscriber receives the three chunks and the fin frame, with the frames unchanged.
	early := <-received
	if early.err != nil {
		t.Fatalf("early subscriber: %v", early.err)
	}
	frames := early.frames
	if len(frames) != 4 || string(frames[0].GetChunk().GetText()) != "Hello, " || frames[2].GetChunk().GetSeq() != 2 ||
		frames[3].GetFin() == nil || hex.EncodeToString(frames[3].GetFin().GetOutputMmrRoot()) != hex.EncodeToString(final[:]) ||
		len(frames[1].GetChunk().GetWorkerSignature()) != 64 ||
		frames[3].GetFin().GetFinishReason() != taskv1.FinishReasonV1_FINISH_REASON_V1_EOS_TOKEN ||
		!bytes.Equal(frames[3].GetFin().GetWorkerSignature(), finSignature) {
		t.Fatalf("subscriber frames = %v", frames)
	}

	// Metadata: chunk boundaries and leaf count (from which the Verifier rebuilds the MMR).
	// Once sealed, the object is addressed by its full object ref: the OUTPUT content_hash is the output_hash,
	// i.e. the MMR root -- so the user can locate it with the output_hash from the on-chain receipt.
	objectKey := f.key
	objectKey.ContentHash = hex.EncodeToString(final[:])
	metadataAuth := streamRequestAuth(t, f.worker, workerKeyHex, taskdata.MethodGetMetadata, objectKey, 110, []byte("nonce-metadata-stream-01"), mustMetadataBody(t, objectKey))
	metadataResponse, err := f.client.GetTaskDataMetadata(ctx, connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: objectRefToPB(objectKey), RequestAuth: metadataAuth,
	}))
	if err != nil {
		t.Fatal(err)
	}
	metadata := metadataResponse.Msg.GetMetadata()
	// The new contract has no object_exists bit: when the object does not exist the whole metadata is absent.
	// The fin frame only reaches STORED: READY waits for FinalizeTaskResult (§5.5). chunk_lengths and
	// output_leaf_count are returned only for a READY streaming OUTPUT, so they are not visible yet.
	if metadata == nil || metadata.GetSizeBytes() != 14 ||
		metadata.GetReadiness() != nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_STORED {
		t.Fatalf("metadata = %v", metadata)
	}

	// Diagram 3 alt: opening a stream after it is sealed -> progress is returned first, then it ends with AlreadyExists.
	again := f.client.UploadTaskOutputStream(ctx)
	if err := again.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte("nonce-stream-header-0002")),
	}}}); err != nil {
		t.Fatal(err)
	}
	reply, err := again.Receive()
	if err != nil || reply.GetProgress() == nil || reply.GetProgress().GetLastSeq() != 2 {
		t.Fatalf("sealed progress = %v / %v", reply, err)
	}
	if _, err := again.Receive(); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("sealed stream must end with AlreadyExists, got %v", err)
	}

	// Diagram 5: resubscribe with resume_after_seq=1 and receive only seq 2 and the fin frame.
	late := f.subscribe(t, ctx, f.user, 1, "nonce-subscribe-late-0002")
	resumed, err := collectFrames(late)
	if err != nil || len(resumed) != 2 || resumed[0].GetChunk().GetSeq() != 2 || resumed[1].GetFin() == nil ||
		resumed[1].GetFin().GetFinishReason() != taskv1.FinishReasonV1_FINISH_REASON_V1_EOS_TOKEN ||
		!bytes.Equal(resumed[1].GetFin().GetWorkerSignature(), finSignature) {
		t.Fatalf("resumed frames = %v / %v", resumed, err)
	}

	// AckOutput only records local progress; the same last_seq is idempotent.
	ackBody := sdkauth.BodyDigest([]byte(f.session), []byte(f.taskID), []byte(""))
	ackEnv := signedTaskEnvelope(t, f.user, "AckOutput", nexusv1connect.IngressAPIAckOutputProcedure, f.session, f.taskID, ackBody, []byte("nonce-ack-0001"))
	ack, err := f.client.AckOutput(ctx, connect.NewRequest(&nexusv1.AckOutputRequest{SessionId: f.session, TaskId: f.taskID, RequestEnvelope: ackEnv, LastSeq: 2}))
	if err != nil || !ack.Msg.GetAcked() || ack.Msg.GetAlreadyAcked() {
		t.Fatalf("ack = %v / %v", ack, err)
	}
	ackEnv = signedTaskEnvelope(t, f.user, "AckOutput", nexusv1connect.IngressAPIAckOutputProcedure, f.session, f.taskID, ackBody, []byte("nonce-ack-0002"))
	ack, err = f.client.AckOutput(ctx, connect.NewRequest(&nexusv1.AckOutputRequest{SessionId: f.session, TaskId: f.taskID, RequestEnvelope: ackEnv, LastSeq: 2}))
	if err != nil || !ack.Msg.GetAcked() || !ack.Msg.GetAlreadyAcked() {
		t.Fatalf("repeated ack = %v / %v", ack, err)
	}

	// A user who did not place the order cannot subscribe.
	other := f.subscribe(t, ctx, f.worker, 0, "nonce-subscribe-worker-0003")
	if _, err := collectFrames(other); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-owner subscribe error = %v", err)
	}
}

// The fin frame is not compared against any local receipt: it only proves the bytes were persisted and the root could be computed;
// the object stays at STORED and is indexed with the MMR root as its content_hash. "OUTPUT matches the receipt" is
// FinalizeTaskResult's criterion -- it looks the object up by receipt.output_hash, and finding it is the comparison.
func TestOutputStreamFinStoresObjectUnderMMRRoot(t *testing.T) {
	f := newStreamFixture(t, true)
	ctx := context.Background()

	subCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	received := f.subscribeAsync(t, subCtx, f.user, 0, "nonce-subscribe-mismatch-01")

	up := f.client.UploadTaskOutputStream(ctx)
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte("nonce-stream-header-0003")),
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Receive(); err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	f.sendChunk(t, up, acc, 0, "only chunk")
	final := acc.Root()
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Fin{Fin: &nexusv1.OutputFinV1{FinalSeq: 0, OutputMmrRoot: final[:]}}}); err != nil {
		t.Fatal(err)
	}
	_ = up.CloseRequest()
	result, err := up.Receive()
	if err != nil {
		t.Fatalf("fin must succeed without any local receipt: %v", err)
	}
	if !result.GetResult().GetAccepted() || result.GetResult().GetLeafCount() != 1 {
		t.Fatalf("fin result = %v", result)
	}
	subscribed := <-received
	if subscribed.err != nil || len(subscribed.frames) != 2 || subscribed.frames[1].GetFin() == nil {
		t.Fatalf("subscriber must still get chunk and fin, got %v / %v", subscribed.frames, subscribed.err)
	}
	// After sealing, the object is addressed by its full object ref: content_hash is the MMR root, not the SHA-256 of the concatenated text.
	rootKey := f.key
	rootKey.ContentHash = hex.EncodeToString(final[:])
	metadataAuth := streamRequestAuth(t, f.worker, workerKeyHex, taskdata.MethodGetMetadata, rootKey, 110, []byte("nonce-metadata-mismatch-01"), mustMetadataBody(t, rootKey))
	metadataResponse, err := f.client.GetTaskDataMetadata(ctx, connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: objectRefToPB(rootKey), RequestAuth: metadataAuth,
	}))
	if err != nil || metadataResponse.Msg.GetMetadata().GetReadiness() !=
		nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_STORED {
		t.Fatalf("object must be STORED after fin: %v / %v", metadataResponse, err)
	}
	sha := sha256.Sum256([]byte("only chunk"))
	shaKey := f.key
	shaKey.ContentHash = hex.EncodeToString(sha[:])
	shaAuth := streamRequestAuth(t, f.worker, workerKeyHex, taskdata.MethodGetMetadata, shaKey, 110, []byte("nonce-metadata-mismatch-02"), mustMetadataBody(t, shaKey))
	shaResponse, err := f.client.GetTaskDataMetadata(ctx, connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: objectRefToPB(shaKey), RequestAuth: shaAuth,
	}))
	if err != nil || shaResponse.Msg.GetMetadata() != nil {
		t.Fatalf("object must not be addressable by sha256(text): %v / %v", shaResponse, err)
	}
}

// A per-frame validation failure closes the stream: bad signature -> PermissionDenied; bad root -> DataLoss; broken seq -> InvalidArgument.
func TestOutputStreamRejectsBadChunks(t *testing.T) {
	f := newStreamFixture(t, true)
	ctx := context.Background()
	openStream := func(nonce string) *connect.BidiStreamForClient[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse] {
		up := f.client.UploadTaskOutputStream(ctx)
		if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
			SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
			RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte(nonce)),
		}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := up.Receive(); err != nil {
			t.Fatal(err)
		}
		return up
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	root := acc.Append([]byte("abcd"))

	up := openStream("nonce-bad-signature-0001")
	_ = up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Chunk{Chunk: &nexusv1.OutputChunkV1{
		Seq: 0, Text: []byte("abcd"), MmrRoot: root[:], WorkerSignature: make([]byte, 64),
	}}})
	if _, err := up.Receive(); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("bad signature error = %v", err)
	}

	up = openStream("nonce-bad-root-000001")
	wrong := sha256.Sum256([]byte("x"))
	digest, _ := nodecontract.OutputChunkSigningDigest("trueopen-localnet", f.taskHash, 0, wrong[:])
	_ = up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Chunk{Chunk: &nexusv1.OutputChunkV1{
		Seq: 0, Text: []byte("abcd"), MmrRoot: wrong[:], WorkerSignature: signDigestRaw64(t, workerKeyHex, digest[:]),
	}}})
	if _, err := up.Receive(); connect.CodeOf(err) != connect.CodeDataLoss {
		t.Fatalf("bad root error = %v", err)
	}

	up = openStream("nonce-bad-seq-0000001")
	f.sendChunk(t, up, acc.Clone(), 3, "abcd")
	if _, err := up.Receive(); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad seq error = %v", err)
	}

	// A Worker that was not selected opening a stream: PermissionDenied.
	const strangerKeyHex = "0000000000000000000000000000000000000000000000000000000000000003"
	stranger := mustSigner(t, strangerKeyHex)
	up = f.client.UploadTaskOutputStream(ctx)
	_ = up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, stranger, strangerKeyHex, f.key, 110, []byte("nonce-stranger-000001")),
	}}})
	if _, err := up.Receive(); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("stranger header error = %v", err)
	}
}

func TestOutputStreamDisabledIsUnimplemented(t *testing.T) {
	f := newStreamFixture(t, false)
	up := f.client.UploadTaskOutputStream(context.Background())
	_ = up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte("nonce-disabled-000001")),
	}}})
	if _, err := up.Receive(); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("disabled stream error = %v", err)
	}
}
