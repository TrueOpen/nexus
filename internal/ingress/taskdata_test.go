package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

type fakeTaskDataAPI struct {
	openTaskRequester string
	openTaskNonce     []byte
	openTaskExpiry    uint64
	orderExpiry       uint64 // order_expire_height passed to AuthorizeOpenTaskRequest
	openTaskErr       error  // returned by AuthorizeOpenTaskRequest when set
	metadata          taskdata.Metadata
	exists            bool
	confirmation      taskdata.StorageConfirmation
	metadataReq       taskdata.RequestAuth
	reader            io.ReadCloser
	readLength        uint64
	chunkSize         uint64
	downloadKey       taskdata.ObjectKey
	fetchRequest      taskdata.RequestAuth
	fetchRange        *taskdata.ByteRange
	uploadHeader      taskdata.UploadHeader
	uploadRequest     taskdata.RequestAuth
	upload            *fakeTaskDataUpload
	err               error
	inputUpload       *fakeTaskDataUpload
	inputPrepared     taskdata.Metadata
	inputState        taskdata.State
	inputRolledBack   bool
	finalizeResult    taskdata.FinalizeResultRequest
	finalizeVerifier  taskdata.FinalizeVerifierRequest
	resultOutcome     taskdata.FinalizeResultOutcome
	verifierOutcome   taskdata.FinalizeVerifierOutcome
	fin               *taskdata.OutputFin
}

func (f *fakeTaskDataAPI) AuthorizeOpenTaskRequest(_ context.Context, requester string, nonce []byte, expiry, orderExpireHeight uint64) error {
	f.openTaskRequester = requester
	f.openTaskNonce = append([]byte(nil), nonce...)
	f.openTaskExpiry = expiry
	f.orderExpiry = orderExpireHeight
	if f.openTaskErr != nil {
		return f.openTaskErr
	}
	return f.err
}

type fakeTaskDataUpload struct {
	chunks     [][]byte
	aborted    bool
	idempotent bool
}

func (f *fakeTaskDataAPI) GetMetadata(_ context.Context, request taskdata.RequestAuth) (taskdata.Metadata, bool, error) {
	f.metadataReq = request
	return f.metadata, f.exists, f.err
}

func (f *fakeTaskDataAPI) OpenFetch(
	_ context.Context, request taskdata.RequestAuth, byteRange *taskdata.ByteRange,
) (io.ReadCloser, taskdata.ByteRange, taskdata.Metadata, error) {
	f.downloadKey = request.Key
	f.fetchRequest = request
	f.fetchRange = byteRange
	served := taskdata.ByteRange{Offset: 0, Length: f.readLength}
	if byteRange != nil {
		served = *byteRange
	}
	metadata := f.metadata
	metadata.SizeBytes = f.readLength
	return f.reader, served, metadata, f.err
}

func (f *fakeTaskDataAPI) BeginUpload(_ context.Context, request taskdata.RequestAuth, header taskdata.UploadHeader) (taskDataUpload, error) {
	f.uploadRequest = request
	f.uploadHeader = header
	if f.err != nil {
		return nil, f.err
	}
	if f.upload == nil {
		f.upload = &fakeTaskDataUpload{}
	}
	return f.upload, nil
}

func (f *fakeTaskDataAPI) CommitUpload(context.Context, taskDataUpload) (taskdata.Metadata, error) {
	return f.metadata, f.err
}

func (f *fakeTaskDataAPI) ChunkSize() uint64 {
	if f.chunkSize == 0 {
		return 2
	}
	return f.chunkSize
}

func (f *fakeTaskDataAPI) BeginInput(_ context.Context, header taskdata.UploadHeader) (taskDataUpload, error) {
	f.uploadHeader = header
	if f.err != nil {
		return nil, f.err
	}
	f.inputUpload = &fakeTaskDataUpload{}
	return f.inputUpload, nil
}

func (f *fakeTaskDataAPI) PrepareInput(context.Context, taskDataUpload) (taskdata.Metadata, error) {
	if f.err != nil {
		return taskdata.Metadata{}, f.err
	}
	f.inputState = taskdata.StatePrepared
	f.inputPrepared = taskdata.Metadata{
		Key: f.uploadHeader.Key, SemanticHash: f.uploadHeader.SemanticHash, SizeBytes: f.uploadHeader.SizeBytes,
		MediaType: f.uploadHeader.MediaType, State: taskdata.StatePrepared, RetentionStatus: taskdata.RetentionActive,
		RetainUntilHeight: f.uploadHeader.RetainUntilHeight,
	}
	return f.inputPrepared, nil
}

func (f *fakeTaskDataAPI) MarkInputReady(context.Context, taskdata.ObjectKey) (taskdata.Metadata, error) {
	f.inputState = taskdata.StateReady
	f.inputPrepared.State = taskdata.StateReady
	return f.inputPrepared, f.err
}

func (f *fakeTaskDataAPI) FinalizeTaskResult(
	_ context.Context, request taskdata.FinalizeResultRequest,
) (taskdata.FinalizeResultOutcome, error) {
	f.finalizeResult = request
	return f.resultOutcome, f.err
}

func (f *fakeTaskDataAPI) FinalizeVerifierEvidence(
	_ context.Context, request taskdata.FinalizeVerifierRequest,
) (taskdata.FinalizeVerifierOutcome, error) {
	f.finalizeVerifier = request
	return f.verifierOutcome, f.err
}

func (f *fakeTaskDataAPI) OutputFin(context.Context, taskdata.ObjectKey) (taskdata.OutputFin, bool, error) {
	if f.fin == nil {
		return taskdata.OutputFin{}, false, nil
	}
	return *f.fin, true, nil
}

func (f *fakeTaskDataAPI) RollbackInput(context.Context, taskdata.ObjectKey) error {
	f.inputRolledBack = true
	f.inputState = ""
	return nil
}

func (u *fakeTaskDataUpload) WriteChunk(chunk []byte) error {
	u.chunks = append(u.chunks, append([]byte(nil), chunk...))
	return nil
}
func (u *fakeTaskDataUpload) Abort() error     { u.aborted = true; return nil }
func (u *fakeTaskDataUpload) Idempotent() bool { return u.idempotent }

func newTaskDataClient(t *testing.T, api taskDataAPI) nexusv1connect.IngressAPIClient {
	t.Helper()
	return newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID})
}

func newTaskDataClientWithHandler(t *testing.T, handler Handler, api taskDataAPI, auth AuthParams) nexusv1connect.IngressAPIClient {
	t.Helper()
	mux := http.NewServeMux()
	path, connectHandler := nexusv1connect.NewIngressAPIHandler(newService(handler, auth, withTaskDataAPI(api)))
	mux.Handle(path, connectHandler)
	return nexusv1connect.NewIngressAPIClient(&http.Client{Transport: handlerRoundTripper{h: mux}}, "http://task-data.test")
}

func TestTaskDataMetadataOmitsLocatorAndAuthorization(t *testing.T) {
	api := &fakeTaskDataAPI{
		exists: true,
		metadata: taskdata.Metadata{
			Key:          testObjectKey(taskdata.ObjectKindOutput),
			SemanticHash: testPBContent, SizeBytes: 7, MediaType: "text/plain",
			State:           taskdata.StateReady,
			RetentionStatus: taskdata.RetentionActive, RetainUntilHeight: 99,
			Receipt:             &taskdata.SignedInferReceipt{TaskID: "task-1", WorkerOperatorAddress: "worker", OutputHash: strings.Repeat("a", 64)},
			AcceptedReceiptHash: "accepted",
		},
	}
	client := newTaskDataClient(t, api)
	response, err := client.GetTaskDataMetadata(context.Background(), connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef:   testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT),
		RequestAuth: testAuthPB("GetTaskDataMetadata", 2),
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := response.Msg.GetMetadata()
	// The current wire has no object_exists bit: when the object does not exist the whole metadata is absent.
	if got.GetSizeBytes() != 7 || got.GetObjectRef().GetContentHash() != testPBContent ||
		got.GetReadiness() != nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_READY {
		t.Fatalf("metadata = %#v", got)
	}
	// The body digest is recomputed by the server from the object ref; it is no longer an empty value the caller fills in at will.
	if api.metadataReq.RPCMethod != "/nexus.v1.IngressAPI/GetTaskDataMetadata" ||
		len(api.metadataReq.BodyDigest) != 64 {
		t.Fatalf("request conversion = %#v", api.metadataReq)
	}
}

// The convenience copy of infer_receipt for an OUTPUT: field for field identical to the InferReceiptV2
// FinalizeTaskResult received, with hex fields restored to raw bytes.
func TestTaskDataMetadataReturnsInferReceiptCopy(t *testing.T) {
	receipt := &taskdata.SignedInferReceipt{
		SchemaVersion: 3, ChainID: "trueopen-test", TaskID: testPBTask, TaskHash: testPBHash,
		WorkerOperatorAddress: "trueopen1worker", ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: strings.Repeat("7", 64), OutputHash: testPBContent, OutputSizeBytes: 88,
		EvidenceCommitments: []taskdata.EvidenceCommitment{{Kind: 1, HashOrRoot: strings.Repeat("8", 64), EncodedSizeBytes: 4096}},
		ExpiryHeight:        900, ServiceSignature: strings.Repeat("9", 128), GeneratedTokenCount: 12, OutputLeafCount: 18,
		OutputKeyCommitment: strings.Repeat("0", 64), WorkerTokenKeyCommitment: strings.Repeat("0", 64),
		WorkerValueKeyCommitment: strings.Repeat("0", 64), CiphertextOutputRoot: strings.Repeat("0", 64),
	}
	fin := &taskdata.OutputFin{
		FinalSeq: 17, OutputMMRRoot: bytes.Repeat([]byte{0x44}, 32), FinishReason: 5, WorkerSignature: bytes.Repeat([]byte{0x66}, 64),
	}
	api := &fakeTaskDataAPI{exists: true, fin: fin, metadata: taskdata.Metadata{
		Key: testObjectKey(taskdata.ObjectKindOutput), SemanticHash: testPBContent, SizeBytes: 88,
		State: taskdata.StateReady, RetentionStatus: taskdata.RetentionActive, Receipt: receipt,
	}}
	client := newTaskDataClient(t, api)
	response, err := client.GetTaskDataMetadata(context.Background(), connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT), RequestAuth: testAuthPB("GetTaskDataMetadata", 2),
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := response.Msg.GetInferReceipt()
	back, err := signedInferReceiptFromPB(got, "trueopen-test")
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(back, *receipt) {
		t.Fatalf("receipt round trip:\n got %+v\nwant %+v", back, *receipt)
	}
	// A stored OUTPUT carries the Worker's signed Fin as received, USER_STOP included.
	gotFin := response.Msg.GetMetadata().GetFin()
	if gotFin == nil || gotFin.GetFinalSeq() != 17 || gotFin.GetFinishReason() != taskv1.FinishReasonV1(5) ||
		!bytes.Equal(gotFin.GetOutputMmrRoot(), fin.OutputMMRRoot) || !bytes.Equal(gotFin.GetWorkerSignature(), fin.WorkerSignature) {
		t.Fatalf("metadata fin = %v", gotFin)
	}

	api.metadata.Receipt = nil
	response, err = client.GetTaskDataMetadata(context.Background(), connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT), RequestAuth: testAuthPB("GetTaskDataMetadata", 3),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetInferReceipt() != nil {
		t.Fatal("an OUTPUT that has not been finalized must not carry an infer_receipt")
	}
}

// Querying an EVIDENCE_MANIFEST returns the bundle summary: evidence_bundle_hash is the H_V1 of the manifest
// bytes, which is not the same value as the ref content_hash of the Worker manifest (the receipt's evidence_hash_or_root);
// after fetching the bytes the Verifier checks them against the value in the summary. An OUTPUT returns no summary.
func TestTaskDataMetadataReturnsEvidenceBundleSummary(t *testing.T) {
	bundleHash := strings.Repeat("5", 64)
	api := &fakeTaskDataAPI{
		exists: true,
		metadata: taskdata.Metadata{
			Key:          testObjectKey(taskdata.ObjectKindEvidenceManifest),
			SemanticHash: testPBContent, SizeBytes: 321, MediaType: "application/json",
			State: taskdata.StateStored, RetentionStatus: taskdata.RetentionActive,
			ArtifactTotalSizeBytes: 4096, EvidenceSchemaHash: strings.Repeat("6", 64),
			Artifacts:          []taskdata.EvidenceArtifact{{ArtifactID: "trace"}, {ArtifactID: "checkpoint"}},
			EvidenceBundleHash: bundleHash,
		},
	}
	client := newTaskDataClient(t, api)
	response, err := client.GetTaskDataMetadata(context.Background(), connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef:   testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST),
		RequestAuth: testAuthPB("GetTaskDataMetadata", 2),
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := response.Msg.GetEvidenceBundle()
	if got.GetEvidenceManifestHash() != bundleHash || got.GetEvidenceSchemaHash() != strings.Repeat("6", 64) ||
		got.GetArtifactCount() != 2 || got.GetArtifactTotalSizeBytes() != 4096 || got.GetManifestSizeBytes() != 321 {
		t.Fatalf("evidence bundle summary = %#v", got)
	}
	if response.Msg.GetMetadata().GetObjectRef().GetContentHash() != testPBContent {
		t.Fatalf("ref content_hash must stay the locator, got %s", response.Msg.GetMetadata().GetObjectRef().GetContentHash())
	}

	api.metadata = taskdata.Metadata{Key: testObjectKey(taskdata.ObjectKindOutput), SemanticHash: testPBContent, SizeBytes: 7, State: taskdata.StateReady, RetentionStatus: taskdata.RetentionActive}
	response, err = client.GetTaskDataMetadata(context.Background(), connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef:   testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT),
		RequestAuth: testAuthPB("GetTaskDataMetadata", 3),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetEvidenceBundle() != nil {
		t.Fatalf("OUTPUT must not carry an evidence bundle summary")
	}
}

// ConfirmOpenTask is a skeleton: it accepts no calls until its field table and the storage
// confirmation encoding are frozen, so that no wire structure that will later be overturned gets committed.
//
// It must be FailedPrecondition rather than Unimplemented: an unfrozen interface is a deterministic unmet precondition,
// whereas callers read Unimplemented as "the server is too old" and blindly retry.
// Object addressing and request authentication fixtures for the current wire. A Hash32 must be canonical lowercase 64-hex --
// these cases do not verify real signatures, but the shape check runs in the conversion layer.
const (
	testPBSession = "1111111111111111111111111111111111111111111111111111111111111111"
	testPBTask    = "2222222222222222222222222222222222222222222222222222222222222222"
	testPBHash    = "3333333333333333333333333333333333333333333333333333333333333333"
	testPBContent = "4444444444444444444444444444444444444444444444444444444444444444"
	testPBBuilder = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	testPBCaller  = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
)

func testRefPB(kind nexusv1.TaskDataObjectKind) *nexusv1.TaskDataObjectRefV1 {
	ref := &nexusv1.TaskDataObjectRefV1{
		TaskHash: testPBHash, SessionId: testPBSession, TaskId: testPBTask,
		ObjectKind: kind, ContentHash: testPBContent,
	}
	if kind == nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST ||
		kind == nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_ARTIFACT {
		ref.EvidenceProducerKind = nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_WORKER
		ref.EvidenceKind = sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING
		ref.VerifyRound = 1
	}
	return ref
}

func testAuthPB(method string, nonce byte) *nexusv1.TaskDataRequestAuthV1 {
	return &nexusv1.TaskDataRequestAuthV1{
		SchemaVersion: 1, ChainId: "chain", BuilderOperatorAddress: testPBBuilder,
		RpcMethod:        "/nexus.v1.IngressAPI/" + method,
		BodyDigest:       strings.Repeat("5", 64),
		RequesterKind:    nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_CORTEX_SERVICE,
		RequesterAddress: testPBCaller, ServiceAuthorizationNonce: 7,
		RequestNonce: bytes.Repeat([]byte{nonce}, 32), ExpiryHeight: 10,
		Signature: bytes.Repeat([]byte{8}, 64),
	}
}

func testObjectKey(kind taskdata.ObjectKind) taskdata.ObjectKey {
	key := taskdata.ObjectKey{
		TaskHash: testPBHash, SessionID: testPBSession, TaskID: testPBTask,
		Kind: kind, ContentHash: testPBContent,
	}
	if kind.IsEvidence() {
		key.EvidenceProducerKind = taskdata.EvidenceProducerWorker
		key.EvidenceKind = taskdata.EvidenceKindWorkerValueOpening
		key.VerifyRound = 1
	}
	return key
}

func TestConfirmOpenTaskFailsPreconditionUntilContractFreeze(t *testing.T) {
	client := newTaskDataClient(t, &fakeTaskDataAPI{})
	_, err := client.ConfirmOpenTask(context.Background(), connect.NewRequest(&nexusv1.ConfirmOpenTaskRequest{
		SessionId: "session-1", TaskId: "task-1",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("ConfirmOpenTask error = %v, want failed_precondition", err)
	}
	if !strings.Contains(err.Error(), "NEXUS_INGRESS_CONTRACT_NOT_FROZEN") {
		t.Fatalf("ConfirmOpenTask error = %v, want NEXUS_INGRESS_CONTRACT_NOT_FROZEN", err)
	}
}

func TestTaskDataFetchStreamsExactChunks(t *testing.T) {
	api := &fakeTaskDataAPI{reader: io.NopCloser(bytes.NewReader([]byte("abcdef"))), readLength: 6, chunkSize: 2}
	client := newTaskDataClient(t, api)
	stream, err := client.FetchTaskData(context.Background(), connect.NewRequest(&nexusv1.FetchTaskDataRequest{
		ObjectRef:   testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_INPUT),
		Range:       &nexusv1.ByteRangeV1{Offset: 4, Length: 6},
		RequestAuth: testAuthPB("FetchTaskData", 4),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var chunks [][]byte
	var offsets []uint64
	var eof []bool
	var header *nexusv1.FetchTaskDataHeaderV1
	for stream.Receive() {
		// The first frame must be the header, chunks only after it.
		if h := stream.Msg().GetHeader(); h != nil {
			if header != nil || len(chunks) != 0 {
				t.Fatal("header must be the first frame and appear once")
			}
			header = h
			continue
		}
		chunk := stream.Msg().GetChunk()
		chunks = append(chunks, append([]byte(nil), chunk.GetData()...))
		offsets = append(offsets, chunk.GetOffset())
		eof = append(eof, chunk.GetEof())
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	if got := bytes.Join(chunks, nil); !bytes.Equal(got, []byte("abcdef")) ||
		fmtSlice(offsets) != "[4 6 8]" || fmtSlice(eof) != "[false false true]" {
		t.Fatalf("chunks=%q offsets=%v eof=%v", got, offsets, eof)
	}
	if header == nil || header.GetServedRange().GetOffset() != 4 || header.GetServedRange().GetLength() != 6 {
		t.Fatalf("fetch header = %#v", header)
	}
	// Authorization is decided over the object ref + range, both of which enter the request signature via the body digest; there is no pre-signed credential.
	if api.downloadKey != testObjectKey(taskdata.ObjectKindInput) ||
		api.fetchRange == nil || api.fetchRange.Offset != 4 || api.fetchRange.Length != 6 ||
		api.fetchRequest.RequesterAddress != testPBCaller {
		t.Fatalf("download key/range = %#v %#v", api.downloadKey, api.fetchRange)
	}
}

func TestTaskResultUploadFramesAndConfirmation(t *testing.T) {
	api := &fakeTaskDataAPI{metadata: taskdata.Metadata{
		Key:          testObjectKey(taskdata.ObjectKindEvidenceManifest),
		SemanticHash: testPBContent, SizeBytes: 4, MediaType: "application/octet-stream",
		State: taskdata.StateReady, RetentionStatus: taskdata.RetentionActive,
	}, confirmation: taskdata.StorageConfirmation{
		SchemaVersion: taskdata.StorageConfirmationSchemaVersionV1, ChainID: "chain",
		BuilderOperator: "builder", ServiceAuthorizationNonce: 7,
		Ref:       testObjectKey(taskdata.ObjectKindEvidenceManifest),
		SizeBytes: 4, ArtifactTotalSizeBytes: 512, RetentionUntilHeight: 99,
		Signature: bytes.Repeat([]byte{1}, 64),
	}}
	client := newTaskDataClient(t, api)
	stream := client.UploadTaskResultObject(context.Background())
	header := &nexusv1.UploadTaskResultObjectHeaderV1{
		ObjectRef:   testRefPB(nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST),
		SizeBytes:   4,
		MediaType:   api.metadata.MediaType,
		RequestAuth: testAuthPB("UploadTaskResultObject", 7),
	}
	if err := stream.Send(&nexusv1.UploadTaskResultObjectRequest{Frame: &nexusv1.UploadTaskResultObjectRequest_Header{Header: header}}); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{[]byte("ab"), []byte("cd")} {
		if err := stream.Send(&nexusv1.UploadTaskResultObjectRequest{Frame: &nexusv1.UploadTaskResultObjectRequest_Chunk{Chunk: chunk}}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := stream.CloseAndReceive()
	if err != nil {
		t.Fatal(err)
	}
	if !response.Msg.GetAccepted() || !bytes.Equal(bytes.Join(api.upload.chunks, nil), []byte("abcd")) ||
		api.uploadHeader.Key.EvidenceProducerKind != taskdata.EvidenceProducerWorker ||
		api.uploadHeader.Key.VerifyRound != 1 ||
		api.uploadRequest.RPCMethod != "/nexus.v1.IngressAPI/UploadTaskResultObject" {
		t.Fatalf("response/header/request = %#v %#v %#v", response.Msg, api.uploadHeader, api.uploadRequest)
	}
	// The body digest is recomputed by the server from object ref + size + media type and is canonical 64-hex.
	if len(api.uploadRequest.BodyDigest) != 64 {
		t.Fatalf("upload body digest = %q", api.uploadRequest.BodyDigest)
	}
	// The upload acknowledgement only states that the single object is STORED and no longer carries a storage confirmation --
	// the confirmation is issued once by FinalizeTaskResult after it checks the receipt, the output and all evidence.
	if response.Msg.GetMetadata().GetReadiness() ==
		nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_UNSPECIFIED {
		t.Fatal("upload response must report object readiness")
	}
}

func TestTaskResultUploadRejectsChunkBeforeHeader(t *testing.T) {
	client := newTaskDataClient(t, &fakeTaskDataAPI{})
	stream := client.UploadTaskResultObject(context.Background())
	_ = stream.Send(&nexusv1.UploadTaskResultObjectRequest{Frame: &nexusv1.UploadTaskResultObjectRequest_Chunk{Chunk: []byte("bad")}})
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, err = %v", connect.CodeOf(err), err)
	}
}

// The wire upload header carries no receipt: uploading a single object only commits to object_ref, size
// and media_type, while the receipt is committed by FinalizeTaskResult's body domain
// (TRUEOPEN_TASK_DATA_FINALIZE_RESULT_BODY_V1). The former
// TestTaskResultOutputUploadPropagatesCompleteReceipt here covered "the receipt passes through the upload header
// intact", and that path no longer exists; the equivalent coverage belongs to FinalizeTaskResult and will be added with it.

func TestTaskDataErrorMapping(t *testing.T) {
	tests := []struct {
		err  error
		code connect.Code
	}{
		{taskdata.ErrMalformed, connect.CodeInvalidArgument},
		{taskdata.ErrUnauthorized, connect.CodePermissionDenied},
		{taskdata.ErrNotFound, connect.CodeNotFound},
		{taskdata.ErrConflict, connect.CodeAlreadyExists},
		{taskdata.ErrExpired, connect.CodeDeadlineExceeded},
		{taskdata.ErrCapacity, connect.CodeResourceExhausted},
		{taskdata.ErrHashMismatch, connect.CodeDataLoss},
		{taskdata.ErrRangeInvalid, connect.CodeOutOfRange},
		{taskdata.ErrServiceKeyUnavailable, connect.CodeUnavailable},
		{taskdata.ErrAuthorityUnavailable, connect.CodeUnavailable},
		{taskdata.ErrNotReady, connect.CodeUnavailable},
		{taskdata.ErrStorage, connect.CodeInternal},
		{errors.New("other"), connect.CodeInternal},
	}
	for _, tt := range tests {
		if got := connect.CodeOf(mapTaskDataError(tt.err)); got != tt.code {
			t.Errorf("%v maps to %v, want %v", tt.err, got, tt.code)
		}
	}
}

func TestOpenTaskPreparesBeforeCoordinatorAndMarksReadyAfter(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 4}
	handler := &fakeHandler{}
	handler.onOrder = func(_ context.Context, order types.Order) error {
		if api.inputState != taskdata.StatePrepared {
			t.Fatalf("input state during OnOrder = %s", api.inputState)
		}
		if len(order.Payload) != 0 || order.PayloadCID != payloadstore.RefFor([]byte("abcdefgh")) {
			t.Fatalf("order payload boundary = %#v", order)
		}
		return nil
	}
	client := newTaskDataClientWithHandler(t, handler, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	header := openTaskHeader(t, user, testSessionID("session-open"), 9, []byte("abcdefgh"))
	stream := client.OpenTask(context.Background())
	if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}}); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range [][]byte{[]byte("abcd"), []byte("efgh")} {
		if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: chunk}}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := stream.CloseAndReceive()
	if err != nil {
		t.Fatal(err)
	}
	if !response.Msg.GetAccepted() || api.inputState != taskdata.StateReady || (response.Msg.GetInputMetadata() != nil) != true ||
		!bytes.Equal(bytes.Join(api.inputUpload.chunks, nil), []byte("abcdefgh")) {
		t.Fatalf("response/input = %#v state=%s chunks=%q", response.Msg, api.inputState, bytes.Join(api.inputUpload.chunks, nil))
	}
}

func TestOpenTaskRejectsNonHash32SessionID(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 64}
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID,
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen",
	})
	header := openTaskHeader(t, user, testSessionID("session-text"), 9, []byte("input"))
	header.SessionId = "session-text"
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})

	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("OpenTask error=%v code=%v, want InvalidArgument for session_id", err, connect.CodeOf(err))
	}
}

func TestOpenTaskRollsBackPreparedInputOnCoordinatorFailure(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 64}
	handler := &fakeHandler{orderErr: errors.New("order rejected")}
	client := newTaskDataClientWithHandler(t, handler, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	header := openTaskHeader(t, user, testSessionID("session-reject"), 10, []byte("input"))
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: []byte("input")}})
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInternal || !api.inputRolledBack {
		t.Fatalf("error=%v code=%v rolled_back=%t", err, connect.CodeOf(err), api.inputRolledBack)
	}
}

func TestOpenTaskRequiresChainHeightExpiry(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 64}
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	header := openTaskHeader(t, user, testSessionID("session-expiry"), 11, []byte("input"))
	header.RequestEnvelope.ExpiryHeightOrTime = time.Now().Add(time.Minute).UnixMilli()
	resignTaskEnvelope(t, user, header.RequestEnvelope)
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "NEXUS_INGRESS_MALFORMED") ||
		api.openTaskExpiry != 0 {
		t.Fatalf("time expiry error=%v code=%v forwarded=%d, want NEXUS_INGRESS_MALFORMED", err, connect.CodeOf(err), api.openTaskExpiry)
	}
}

func TestOpenTaskForwardsChainHeightReplayFields(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 64}
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	header := openTaskHeader(t, user, testSessionID("session-height"), 12, []byte("input"))
	stream := client.OpenTask(context.Background())
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
	_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: []byte("input")}})
	if _, err := stream.CloseAndReceive(); err != nil {
		t.Fatal(err)
	}
	if api.openTaskRequester != user.Address() || api.openTaskExpiry != 110 ||
		!bytes.Equal(api.openTaskNonce, header.GetRequestEnvelope().GetRequestNonce()) {
		t.Fatalf("OpenTask replay fields = %q/%x/%d", api.openTaskRequester, api.openTaskNonce, api.openTaskExpiry)
	}
}

// openTaskHeader builds a valid OpenTask header: order_envelope is a SignedOrderV2 for user, and the
// request envelope is wallet-signed by user with a chain-height expiry. There is no outer signature.
func openTaskHeader(t *testing.T, user signer.Signer, sessionID string, sequence uint64, payload []byte) *nexusv1.OpenTaskHeader {
	t.Helper()
	digest := sha256.Sum256(payload)
	session, err := hex.DecodeString(sessionID)
	if err != nil || len(session) != 32 {
		session = make([]byte, 32) // a malformed session_id is what some tests exercise
	}
	signed := testFrozenSignedOrder()
	signed.Order.UserAddress = user.Address()
	signed.Order.SessionId = session
	signed.Order.OrderSequence = sequence
	signed.Order.InputHash = digest[:]
	signed.Order.InputSizeBytes = uint64(len(payload))
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustDeriveTaskID(t, sessionID, sequence)
	header := &nexusv1.OpenTaskHeader{
		OrderEnvelope: raw, PayloadRef: payloadstore.RefFor(payload), SessionId: sessionID,
		OrderSequence: sequence, UserAddress: user.Address(),
		InputSizeBytes: uint64(len(payload)), InputHash: hex.EncodeToString(digest[:]), InputMediaType: "application/octet-stream",
		IdempotencyKey: "idem-" + sessionID,
	}
	header.RequestEnvelope = signedTaskEnvelope(
		t, user, "OpenTask", nexusv1connect.IngressAPIOpenTaskProcedure, sessionID, taskID,
		openTaskBodyDigest(header), []byte("nonce-open-task-"+sessionID),
	)
	header.RequestEnvelope.ExpiryHeightOrTime = 110
	resignTaskEnvelope(t, user, header.RequestEnvelope)
	return header
}

func fmtSlice(value any) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toString(value)), "  ", " "))
}

func toString(value any) string {
	switch value := value.(type) {
	case []uint64:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = fmt.Sprintf("%d", item)
		}
		return "[" + strings.Join(parts, " ") + "]"
	case []bool:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = fmt.Sprintf("%t", item)
		}
		return "[" + strings.Join(parts, " ") + "]"
	default:
		return ""
	}
}

// reEnvelopeOpenTask signs a fresh request envelope over the header as it stands now, with sg.
func reEnvelopeOpenTask(t *testing.T, sg signer.Signer, header *nexusv1.OpenTaskHeader) {
	t.Helper()
	taskID := mustDeriveTaskID(t, header.GetSessionId(), header.GetOrderSequence())
	header.RequestEnvelope = signedTaskEnvelope(
		t, sg, "OpenTask", nexusv1connect.IngressAPIOpenTaskProcedure, header.GetSessionId(), taskID,
		openTaskBodyDigest(header), []byte("nonce-open-task-"+header.GetSessionId()),
	)
	header.RequestEnvelope.ExpiryHeightOrTime = 110
	resignTaskEnvelope(t, sg, header.RequestEnvelope)
}

// An OpenTask must be signed by the order user's wallet, and carries no outer order signature.
func TestOpenTaskRejectsOtherSignerAndOuterSignature(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	other := mustSigner(t, strings.Repeat("22", 32))
	tests := []struct {
		name string
		edit func(*nexusv1.OpenTaskHeader)
		code connect.Code
		want string
	}{
		{name: "envelope signed by someone else", edit: func(h *nexusv1.OpenTaskHeader) { reEnvelopeOpenTask(t, other, h) },
			code: connect.CodeUnauthenticated, want: sdkauth.ErrInvalidSignature.Error()},
		{name: "outer signature present", edit: func(h *nexusv1.OpenTaskHeader) {
			h.Signature = bytes.Repeat([]byte{1}, 64) //nolint:staticcheck // the deprecated field must be empty
			h.SignatureScheme = "secp256k1"           //nolint:staticcheck
			reEnvelopeOpenTask(t, user, h)
		}, code: connect.CodeInvalidArgument, want: "must be empty"},
		{name: "session key signs OpenTask", edit: func(h *nexusv1.OpenTaskHeader) {
			h.RequestEnvelope.SessionGrant = &nexusv1.SessionGrantV1{ChainId: "trueopen-localnet", User: user.Address(),
				SessionKey: make([]byte, 20), ExpiryHeight: 150, GrantNonce: make([]byte, 32), UserSignature: make([]byte, 65)}
		}, code: connect.CodePermissionDenied, want: sdkauth.ErrSessionMethodNotAllowed.Error()},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeTaskDataAPI{chunkSize: 64}
			client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain, EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			header := openTaskHeader(t, user, testSessionID(fmt.Sprintf("session-deny-%d", index)), 13, []byte("input"))
			tt.edit(header)
			stream := client.OpenTask(context.Background())
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
			_, err := stream.CloseAndReceive()
			if connect.CodeOf(err) != tt.code || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v code=%v, want %v naming %q", err, connect.CodeOf(err), tt.code, tt.want)
			}
		})
	}
}

// openTaskBodyDigest is the TRUEOPEN_SDK_BODY_OPEN_TASK_V1 digest of header, with task_hash
// recomputed from the signed order it carries.
func openTaskBodyDigest(header *nexusv1.OpenTaskHeader) []byte {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(header.GetOrderEnvelope(), &signed); err != nil {
		return make([]byte, 32)
	}
	taskHashHex, err := nodecontract.TaskOrderHashHexV3(signed.GetOrder())
	if err != nil {
		return make([]byte, 32)
	}
	taskHash, err := sdkauth.Hash32Hex("task_hash", taskHashHex)
	if err != nil {
		return make([]byte, 32)
	}
	body, err := sdkauth.OpenTaskBody(taskHash, header.GetSessionId(), header.GetOrderSequence(), header.GetUserAddress(),
		header.GetInputSizeBytes(), header.GetInputHash(), header.GetInputMediaType(), header.GetIdempotencyKey())
	if err != nil {
		return make([]byte, 32)
	}
	return body[:]
}

// Stage-1 admission failures reach the OpenTask caller under their stable codes.
func TestOpenTaskMapsStage1AdmissionErrors(t *testing.T) {
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
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeTaskDataAPI{chunkSize: 64}
			client := newTaskDataClientWithHandler(t, &fakeHandler{orderErr: tt.err}, api, AuthParams{Chain: testUserChain,
				EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
			header := openTaskHeader(t, user, testSessionID(fmt.Sprintf("session-admission-%d", index)), 3, []byte("input"))
			stream := client.OpenTask(context.Background())
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
			_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: []byte("input")}})
			_, err := stream.CloseAndReceive()
			if connect.CodeOf(err) != tt.code || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("OpenTask error=%v code=%v want code=%v message=%q", err, connect.CodeOf(err), tt.code, tt.message)
			}
		})
	}
}

// OpenTask step 5 uses the SDK request codes: a height outside the request_ttl_blocks window is
// SDK_AUTH_EXPIRED and a used nonce SDK_AUTH_REPLAY.
func TestOpenTaskExpiryAndReplayCodes(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	for index, tc := range []struct {
		err  error
		code connect.Code
		want string
	}{
		{taskdata.ErrExpired, connect.CodeDeadlineExceeded, sdkauth.ErrExpired.Error()},
		{taskdata.ErrReplay, connect.CodeUnauthenticated, sdkauth.ErrReplay.Error()},
	} {
		api := &fakeTaskDataAPI{chunkSize: 64, err: tc.err}
		client := newTaskDataClientWithHandler(t, &fakeHandler{}, api, AuthParams{Chain: testUserChain,
			EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
		header := openTaskHeader(t, user, testSessionID(fmt.Sprintf("session-step5-%d", index)), 5, []byte("input"))
		stream := client.OpenTask(context.Background())
		_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}})
		_, err := stream.CloseAndReceive()
		if connect.CodeOf(err) != tc.code || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: error=%v code=%v, want %v %s", tc.err, err, connect.CodeOf(err), tc.code, tc.want)
		}
	}
}
