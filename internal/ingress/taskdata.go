package ingress

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io"
	"math"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

type taskDataUpload interface {
	WriteChunk([]byte) error
	Abort() error
	Idempotent() bool
}

type taskDataAPI interface {
	AuthorizeOpenTaskRequest(context.Context, string, []byte, uint64) error
	GetMetadata(context.Context, taskdata.RequestAuth) (taskdata.Metadata, bool, error)
	OpenFetch(context.Context, taskdata.RequestAuth, *taskdata.ByteRange) (io.ReadCloser, taskdata.ByteRange, taskdata.Metadata, error)
	BeginUpload(context.Context, taskdata.RequestAuth, taskdata.UploadHeader) (taskDataUpload, error)
	CommitUpload(context.Context, taskDataUpload) (taskdata.Metadata, error)
	ChunkSize() uint64
	BeginInput(context.Context, taskdata.UploadHeader) (taskDataUpload, error)
	PrepareInput(context.Context, taskDataUpload) (taskdata.Metadata, error)
	MarkInputReady(context.Context, taskdata.ObjectKey) (taskdata.Metadata, error)
	RollbackInput(context.Context, taskdata.ObjectKey) error
	FinalizeTaskResult(context.Context, taskdata.FinalizeResultRequest) (taskdata.FinalizeResultOutcome, error)
	FinalizeVerifierEvidence(context.Context, taskdata.FinalizeVerifierRequest) (taskdata.FinalizeVerifierOutcome, error)
	OutputFin(context.Context, taskdata.ObjectKey) (taskdata.OutputFin, bool, error)
}

type taskDataRuntime struct{ service *taskdata.Service }

func (r taskDataRuntime) AuthorizeOpenTaskRequest(ctx context.Context, requester string, nonce []byte, expiry uint64) error {
	return r.service.AuthorizeOpenTaskRequest(ctx, requester, nonce, expiry)
}

func (r taskDataRuntime) GetMetadata(ctx context.Context, request taskdata.RequestAuth) (taskdata.Metadata, bool, error) {
	return r.service.GetMetadata(ctx, request)
}

func (r taskDataRuntime) OpenFetch(
	ctx context.Context, request taskdata.RequestAuth, byteRange *taskdata.ByteRange,
) (io.ReadCloser, taskdata.ByteRange, taskdata.Metadata, error) {
	return r.service.OpenFetch(ctx, request, byteRange)
}

func (r taskDataRuntime) BeginUpload(ctx context.Context, request taskdata.RequestAuth, header taskdata.UploadHeader) (taskDataUpload, error) {
	return r.service.BeginUpload(ctx, request, header)
}

func (r taskDataRuntime) CommitUpload(ctx context.Context, upload taskDataUpload) (taskdata.Metadata, error) {
	concrete, ok := upload.(*taskdata.Upload)
	if !ok {
		return taskdata.Metadata{}, taskdata.ErrMalformed
	}
	return r.service.CommitUpload(ctx, concrete)
}

func (r taskDataRuntime) ChunkSize() uint64 { return r.service.ChunkSize() }

func (r taskDataRuntime) BeginInput(ctx context.Context, header taskdata.UploadHeader) (taskDataUpload, error) {
	return r.service.BeginInput(ctx, header)
}

func (r taskDataRuntime) PrepareInput(ctx context.Context, upload taskDataUpload) (taskdata.Metadata, error) {
	concrete, ok := upload.(*taskdata.Upload)
	if !ok {
		return taskdata.Metadata{}, taskdata.ErrMalformed
	}
	return r.service.PrepareInput(ctx, concrete)
}

func (r taskDataRuntime) MarkInputReady(ctx context.Context, key taskdata.ObjectKey) (taskdata.Metadata, error) {
	return r.service.MarkInputReady(ctx, key)
}

func (r taskDataRuntime) RollbackInput(ctx context.Context, key taskdata.ObjectKey) error {
	return r.service.RollbackInput(ctx, key)
}

func (r taskDataRuntime) OutputFin(ctx context.Context, key taskdata.ObjectKey) (taskdata.OutputFin, bool, error) {
	return r.service.OutputFin(ctx, key)
}

func (r taskDataRuntime) FinalizeTaskResult(
	ctx context.Context, request taskdata.FinalizeResultRequest,
) (taskdata.FinalizeResultOutcome, error) {
	return r.service.FinalizeTaskResult(ctx, request)
}

func (r taskDataRuntime) FinalizeVerifierEvidence(
	ctx context.Context, request taskdata.FinalizeVerifierRequest,
) (taskdata.FinalizeVerifierOutcome, error) {
	return r.service.FinalizeVerifierEvidence(ctx, request)
}

func (s *service) OpenTask(ctx context.Context, stream *connect.ClientStream[nexusv1.OpenTaskRequest]) (*connect.Response[nexusv1.OpenTaskResponse], error) {
	if s.taskData == nil {
		return nil, mapTaskDataError(taskdata.ErrServiceKeyUnavailable)
	}
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, mapTaskDataError(fmt.Errorf("%w: OpenTask header required", taskdata.ErrMalformed))
	}
	headerPB := stream.Msg().GetHeader()
	if headerPB == nil {
		return nil, mapTaskDataError(fmt.Errorf("%w: first OpenTask frame must be header", taskdata.ErrMalformed))
	}
	order, uploadHeader, err := s.validateOpenTaskHeader(ctx, headerPB)
	if err != nil {
		// Even with an invalid header, drain the remaining client frames before returning: leaving without
		// reading may block the peer's Send forever on a stream nobody receives.
		for stream.Receive() {
		}
		return nil, err
	}
	// Step 5 (expiry window, then the nonce) comes before any storage, so a replayed OpenTask is
	// SDK_AUTH_REPLAY rather than a conflict with the stored input.
	envelope := headerPB.GetRequestEnvelope()
	if err := s.taskData.AuthorizeOpenTaskRequest(
		ctx, envelope.GetSignerAddress(), envelope.GetRequestNonce(), uint64(envelope.GetExpiryHeightOrTime()),
	); err != nil {
		for stream.Receive() {
		}
		return nil, mapOpenTaskRequestErr(err)
	}
	// Refuse another version of a known task before storing anything, so the refused input never
	// replaces the stored version's index. OnOrder repeats the check after the upload.
	if err := s.h.CheckOrder(ctx, order); err != nil {
		for stream.Receive() {
		}
		return nil, mapOrderErr(err)
	}
	upload, err := s.taskData.BeginInput(ctx, uploadHeader)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	prepared := false
	coordinatorAccepted := false
	defer func() {
		if !prepared {
			_ = upload.Abort()
		} else if !coordinatorAccepted {
			_ = s.taskData.RollbackInput(context.Background(), uploadHeader.Key)
		}
	}()
	chunks := 0
	for stream.Receive() {
		chunkFrame, ok := stream.Msg().GetFrame().(*nexusv1.OpenTaskRequest_Chunk)
		if !ok || len(chunkFrame.Chunk) == 0 || uint64(len(chunkFrame.Chunk)) > s.taskData.ChunkSize() {
			return nil, mapTaskDataError(fmt.Errorf("%w: OpenTask chunk frame", taskdata.ErrMalformed))
		}
		if err := upload.WriteChunk(chunkFrame.Chunk); err != nil {
			return nil, mapTaskDataError(err)
		}
		chunks++
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	if chunks == 0 {
		return nil, mapTaskDataError(fmt.Errorf("%w: OpenTask chunks required", taskdata.ErrMalformed))
	}
	if _, err := s.taskData.PrepareInput(ctx, upload); err != nil {
		return nil, mapTaskDataError(err)
	}
	prepared = true
	if err := s.h.OnOrder(ctx, order); err != nil {
		return nil, mapOrderErr(err)
	}
	coordinatorAccepted = true
	ready, err := s.taskData.MarkInputReady(ctx, uploadHeader.Key)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	return connect.NewResponse(&nexusv1.OpenTaskResponse{
		SessionId: order.SessionID, TaskId: order.TaskID, Accepted: true, InputMetadata: metadataToPB(ready, true),
	}), nil
}

// errConfirmOpenTaskContractNotFrozen is the deterministic rejection of ConfirmOpenTask.
//
// This method's request/response field table is not frozen yet, and neither are the proto
// name, field numbers and encoding order of the storage confirmation itself, so the confirmation list cannot be defined
// and the server has nothing to validate against; shipping a wire structure that will be overturned is worse than rejecting.
//
// But "interface not frozen" is an unmet deterministic precondition, not a transient fault: Unimplemented would make
// callers assume the server is too old and retry repeatedly, so FailedPrecondition is used here.
// No freeze date has been set yet; once decided, update the open items in README.md.
var errConfirmOpenTaskContractNotFrozen = errors.New(
	"NEXUS_INGRESS_CONTRACT_NOT_FROZEN: ConfirmOpenTask stays closed until its field table " +
		"and the storage-confirmation proto are frozen; do not retry")

// ConfirmOpenTask records the cross-Builder input storage confirmations collected by the SDK.
// Not a precondition for Open Task progress; the V1 baseline does not require the SDK to call it.
func (s *service) ConfirmOpenTask(
	_ context.Context,
	_ *connect.Request[nexusv1.ConfirmOpenTaskRequest],
) (*connect.Response[nexusv1.ConfirmOpenTaskResponse], error) {
	return nil, connect.NewError(connect.CodeFailedPrecondition, errConfirmOpenTaskContractNotFrozen)
}

func (s *service) validateOpenTaskHeader(ctx context.Context, header *nexusv1.OpenTaskHeader) (types.Order, taskdata.UploadHeader, error) {
	// OpenTask is a user request: a header that fails the format step is NEXUS_INGRESS_MALFORMED.
	malformed := func(format string, args ...any) error {
		return mapTaskDataError(fmt.Errorf("%w: %s", taskdata.ErrRequestMalformed, fmt.Sprintf(format, args...)))
	}
	// order_sequence is not among the required-field checks: 0 is the valid first value of every
	// on-chain session, not "unset".
	if header == nil || header.GetSessionId() == "" || header.GetUserAddress() == "" ||
		header.GetInputSizeBytes() == 0 || header.GetInputHash() == "" || header.GetInputMediaType() == "" ||
		header.GetPayloadRef() == "" || len(header.GetOrderEnvelope()) == 0 {
		return types.Order{}, taskdata.UploadHeader{}, malformed("OpenTask header")
	}
	if err := sdkauth.CheckUserAddress("user_address", header.GetUserAddress(), s.auth.Bech32Prefix); err != nil {
		return types.Order{}, taskdata.UploadHeader{}, bodyErr(err)
	}
	// There is no outer order signature: the order is authorized only by the SignedOrder's EIP-712
	// user signature, which the chain verifies.
	if len(header.GetSignature()) != 0 || header.GetSignatureScheme() != "" { //nolint:staticcheck // deprecated fields must be empty
		return types.Order{}, taskdata.UploadHeader{}, malformed("OpenTask signature and signature_scheme must be empty")
	}
	// order_envelope carries the SignedOrderV2 protobuf bytes; the legacy JSON envelope is not accepted.
	order, err := parseSignedOrderEnvelope(header.GetOrderEnvelope())
	if err != nil {
		return types.Order{}, taskdata.UploadHeader{}, malformed("%v", err)
	}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(header.GetOrderEnvelope(), &signed); err != nil {
		return types.Order{}, taskdata.UploadHeader{}, malformed("order_envelope: %v", err)
	}
	signedOrder := signed.GetOrder()
	if signedOrder.GetUserAddress() != header.GetUserAddress() ||
		signedOrder.GetInputSizeBytes() != header.GetInputSizeBytes() ||
		hex.EncodeToString(signedOrder.GetSessionId()) != header.GetSessionId() ||
		signedOrder.GetOrderSequence() != header.GetOrderSequence() {
		return types.Order{}, taskdata.UploadHeader{}, malformed(
			"OpenTask user_address, input_size_bytes, session_id and order_sequence must equal the signed order's")
	}
	order.SessionID = header.GetSessionId()
	order.OrderSequence = header.GetOrderSequence()
	order.TaskID, err = deriveTaskID(order.SessionID, order.OrderSequence)
	if err != nil {
		return types.Order{}, taskdata.UploadHeader{}, malformed("%v", err)
	}
	order.User = header.GetUserAddress()
	if order.PayloadHash != header.GetInputHash() {
		return types.Order{}, taskdata.UploadHeader{}, malformed("OpenTask input hash")
	}
	// payload_ref is not in the signed body; it is a transport check against input_hash.
	order.PayloadCID = payloadstore.RefForHash(header.GetInputHash())
	if order.PayloadCID == "" || header.GetPayloadRef() != order.PayloadCID || order.DeadlineHeight == 0 {
		return types.Order{}, taskdata.UploadHeader{}, malformed("OpenTask input commitment")
	}
	// task_hash enters the body recomputed from the order, never from the caller.
	taskHash, err := sdkauth.Hash32Hex("task_hash", order.TaskHash)
	if err != nil {
		return types.Order{}, taskdata.UploadHeader{}, malformed("order task_hash: %v", err)
	}
	body, err := sdkauth.OpenTaskBody(taskHash, order.SessionID, order.OrderSequence, order.User,
		header.GetInputSizeBytes(), header.GetInputHash(), header.GetInputMediaType(), header.GetIdempotencyKey())
	if err != nil {
		return types.Order{}, taskdata.UploadHeader{}, bodyErr(err)
	}
	// The wallet signs OpenTask directly (no session grant). Its height expiry and nonce are checked
	// by the taskdata Authorizer against the chain, so no replay cache here.
	requester, err := s.checkTaskEnvelope(ctx, header.GetRequestEnvelope(), order.SessionID, order.TaskID, envelopeCheck{
		method: "OpenTask", body: body, heightExpiry: true,
	})
	if err != nil {
		return types.Order{}, taskdata.UploadHeader{}, err
	}
	if requester != order.User {
		return types.Order{}, taskdata.UploadHeader{}, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf(
			"%w: request envelope signer %q is not the order user %q", sdkauth.ErrInvalidSignature, requester, order.User))
	}
	// Full object ref for INPUT: task_hash is the order identity, content_hash is input_hash itself --
	// the same bytes can have only one identity.
	key := taskdata.ObjectKey{
		TaskHash: order.TaskHash, SessionID: order.SessionID, TaskID: order.TaskID,
		Kind: taskdata.ObjectKindInput, ContentHash: header.GetInputHash(),
	}
	uploadHeader := taskdata.UploadHeader{
		Key: key, SizeBytes: header.GetInputSizeBytes(), SemanticHash: header.GetInputHash(),
		MediaType: header.GetInputMediaType(), RetainUntilHeight: order.DeadlineHeight,
	}
	return order, uploadHeader, nil
}

func (s *service) GetTaskDataMetadata(ctx context.Context, req *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error) {
	if s.taskData == nil {
		return nil, mapTaskDataError(taskdata.ErrServiceKeyUnavailable)
	}
	ref, err := objectRefFromPB(req.Msg.GetObjectRef())
	if err != nil {
		return nil, mapTaskDataError(userFormatErr(req.Msg.GetRequestAuth(), err))
	}
	request, err := requestAuthFromPB(req.Msg.GetRequestAuth(), ref)
	if err != nil {
		return nil, mapTaskDataError(userFormatErr(req.Msg.GetRequestAuth(), err))
	}
	metadata, exists, err := s.taskData.GetMetadata(ctx, request)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	// Return only boundary metadata, never content, Builder-internal locators or download authorization.
	// metadata is nil when the object does not exist: the current wire expresses this via field absence, there is no object_exists bit.
	response := &nexusv1.GetTaskDataMetadataResponse{
		Metadata:          metadataToPB(metadata, exists),
		EvidenceBundle:    evidenceBundleToPB(metadata, exists),
		RetainUntilHeight: metadata.RetainUntilHeight,
	}
	// infer_receipt is only a convenience copy, persisted alongside OUTPUT at FinalizeTaskResult;
	// callers must compare it with the on-chain accepted receipt before trusting it.
	if exists && metadata.Key.Kind == taskdata.ObjectKindOutput && metadata.Receipt != nil {
		response.InferReceipt = signedInferReceiptToPB(*metadata.Receipt)
	}
	// A stored OUTPUT carries the Worker's signed Fin, the same frame subscribers get, so a caller that
	// only fetches can still tell a finished generation from one cut off by its budget.
	if exists && metadata.Key.Kind == taskdata.ObjectKindOutput &&
		(metadata.State == taskdata.StateStored || metadata.State == taskdata.StateReady) {
		fin, found, err := s.taskData.OutputFin(ctx, metadata.Key)
		if err != nil {
			return nil, mapTaskDataError(err)
		}
		if found {
			response.Metadata.Fin = outputFinToPB(fin)
		}
	}
	return connect.NewResponse(response), nil
}

// FetchTaskData streams Task data by signed range (SDK and Cortex callers,
// formerly DownloadTaskData). Authorization looks only at on-chain duties
// (internal/taskdata.rolePermissions.canDownload); the requester signature over the range binds
// requester, Task, data_kind, range, validity and anti-replay nonce; there are no pre-signed download credentials anymore.
func (s *service) FetchTaskData(
	ctx context.Context,
	req *connect.Request[nexusv1.FetchTaskDataRequest],
	stream *connect.ServerStream[nexusv1.FetchTaskDataResponse],
) error {
	if s.taskData == nil {
		return mapTaskDataError(taskdata.ErrServiceKeyUnavailable)
	}
	ref, err := objectRefFromPB(req.Msg.GetObjectRef())
	if err != nil {
		return mapTaskDataError(userFormatErr(req.Msg.GetRequestAuth(), err))
	}
	byteRange, err := rangeFromPB(req.Msg.GetRange())
	if err != nil {
		return mapTaskDataError(err)
	}
	request, err := requestAuthFromPB(req.Msg.GetRequestAuth(), ref)
	if err != nil {
		return mapTaskDataError(userFormatErr(req.Msg.GetRequestAuth(), err))
	}
	reader, served, stored, err := s.taskData.OpenFetch(ctx, request, byteRange)
	if err != nil {
		return mapTaskDataError(err)
	}
	length := served.Length
	defer reader.Close()
	if length == 0 || s.taskData.ChunkSize() == 0 || s.taskData.ChunkSize() > uint64(math.MaxInt) {
		return mapTaskDataError(taskdata.ErrRangeInvalid)
	}
	// The first frame must be the header: binds object ref, total size, media type and the actual returned range.
	// The codec of EVIDENCE_ARTIFACT is defined solely by the evidence schema; media_type must be empty.
	mediaType := stored.MediaType
	if ref.Kind == taskdata.ObjectKindEvidenceArtifact {
		mediaType = ""
	}
	if err := stream.Send(&nexusv1.FetchTaskDataResponse{Frame: &nexusv1.FetchTaskDataResponse_Header{
		Header: &nexusv1.FetchTaskDataHeaderV1{
			ObjectRef: objectRefToPB(ref), TotalSizeBytes: stored.SizeBytes, MediaType: mediaType,
			ServedRange: &nexusv1.ByteRangeV1{Offset: served.Offset, Length: served.Length},
		},
	}}); err != nil {
		return err
	}
	chunkSize := s.taskData.ChunkSize()
	remaining := length
	offset := served.Offset
	for remaining > 0 {
		want := chunkSize
		if remaining < want {
			want = remaining
		}
		chunk := make([]byte, int(want))
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return mapTaskDataError(fmt.Errorf("%w: read authorized range", taskdata.ErrStorage))
		}
		remaining -= want
		if err := stream.Send(&nexusv1.FetchTaskDataResponse{
			Frame: &nexusv1.FetchTaskDataResponse_Chunk{Chunk: &nexusv1.FetchTaskDataChunkV1{
				// offset is the absolute offset from the start of the full object, not relative to this range.
				Offset: offset, Data: chunk, Eof: remaining == 0,
			}},
		}); err != nil {
			return err
		}
		offset += want
	}
	return nil
}

// UploadTaskResultData: the selected Worker uploads OUTPUT or EVIDENCE in chunks.
// OUTPUT / EVIDENCE are uploaded and stored separately; only after the complete data is persisted and size,
// hash/root and the Worker role signature all verify is the current Builder's signed storage confirmation returned.
// A single RPC represents only the current Builder and cannot claim a cross-Builder 2/3 confirmation.
func (s *service) UploadTaskResultObject(
	ctx context.Context, stream *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest],
) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
	if s.taskData == nil {
		return nil, mapTaskDataError(taskdata.ErrServiceKeyUnavailable)
	}
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, mapTaskDataError(fmt.Errorf("%w: upload header required", taskdata.ErrMalformed))
	}
	headerPB := stream.Msg().GetHeader()
	if headerPB == nil {
		return nil, mapTaskDataError(fmt.Errorf("%w: first upload frame must be header", taskdata.ErrMalformed))
	}
	header, request, err := uploadHeaderFromPB(headerPB)
	if err != nil {
		return nil, mapTaskDataError(userFormatErr(headerPB.GetRequestAuth(), err))
	}
	upload, err := s.taskData.BeginUpload(ctx, request, header)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = upload.Abort()
		}
	}()
	chunks := 0
	for stream.Receive() {
		frame := stream.Msg()
		chunkFrame, ok := frame.GetFrame().(*nexusv1.UploadTaskResultObjectRequest_Chunk)
		if !ok || len(chunkFrame.Chunk) == 0 || uint64(len(chunkFrame.Chunk)) > s.taskData.ChunkSize() {
			return nil, mapTaskDataError(fmt.Errorf("%w: upload chunk frame", taskdata.ErrMalformed))
		}
		if err := upload.WriteChunk(chunkFrame.Chunk); err != nil {
			return nil, mapTaskDataError(err)
		}
		chunks++
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	if chunks == 0 {
		return nil, mapTaskDataError(fmt.Errorf("%w: upload chunks required", taskdata.ErrMalformed))
	}
	metadata, err := s.taskData.CommitUpload(ctx, upload)
	if err != nil {
		return nil, mapTaskDataError(err)
	}
	committed = true
	// The receipt only proves a single object is fully stored as STORED, not that the whole Task Result is complete,
	// and it does not issue the final StorageConfirmation -- that is FinalizeTaskResult's job.
	return connect.NewResponse(&nexusv1.UploadTaskResultObjectResponse{
		Accepted: true, Idempotent: upload.Idempotent(), Metadata: metadataToPB(metadata, true),
	}), nil
}

// objectRefFromPB converts the wire TaskDataObjectRefV1 to the internal ref. All shape rules live in
// taskdata.CanonicalObjectRefFrame (non-evidence must not carry the producer fields or an evidence
// kind, evidence must carry a producer kind and one of its bundle kinds); this only converts encoding and lets it validate once.
func objectRefFromPB(pb *nexusv1.TaskDataObjectRefV1) (taskdata.ObjectRef, error) {
	if pb == nil {
		return taskdata.ObjectRef{}, fmt.Errorf("%w: object_ref required", taskdata.ErrMalformed)
	}
	kind, err := objectKindFromPB(pb.GetObjectKind())
	if err != nil {
		return taskdata.ObjectRef{}, err
	}
	producerKind, err := producerKindFromPB(pb.GetEvidenceProducerKind())
	if err != nil {
		return taskdata.ObjectRef{}, err
	}
	ref := taskdata.ObjectRef{
		TaskHash: pb.GetTaskHash(), SessionID: pb.GetSessionId(), TaskID: pb.GetTaskId(),
		Kind: kind, ContentHash: pb.GetContentHash(),
		EvidenceProducerKind: producerKind, VerifyRound: pb.GetVerifyRound(),
		ProducerOperator: pb.GetProducerOperator(), EvidenceKind: taskdata.EvidenceKind(pb.GetEvidenceKind()),
	}
	if _, err := taskdata.CanonicalObjectRefFrame(ref); err != nil {
		return taskdata.ObjectRef{}, err
	}
	return ref, nil
}

func objectRefToPB(ref taskdata.ObjectRef) *nexusv1.TaskDataObjectRefV1 {
	pb := &nexusv1.TaskDataObjectRefV1{
		TaskHash: ref.TaskHash, SessionId: ref.SessionID, TaskId: ref.TaskID,
		ObjectKind: objectKindToPB(ref.Kind), ContentHash: ref.ContentHash,
		EvidenceProducerKind: producerKindToPB(ref.EvidenceProducerKind),
		VerifyRound:          ref.VerifyRound,
		EvidenceKind:         sharedv1.EvidenceKind(ref.EvidenceKind),
	}
	if ref.ProducerOperator != "" {
		operator := ref.ProducerOperator
		pb.ProducerOperator = &operator
	}
	return pb
}

func objectKindFromPB(kind nexusv1.TaskDataObjectKind) (taskdata.ObjectKind, error) {
	switch kind {
	case nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_INPUT:
		return taskdata.ObjectKindInput, nil
	case nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT:
		return taskdata.ObjectKindOutput, nil
	case nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST:
		return taskdata.ObjectKindEvidenceManifest, nil
	case nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_ARTIFACT:
		return taskdata.ObjectKindEvidenceArtifact, nil
	default:
		return 0, fmt.Errorf("%w: object_kind", taskdata.ErrMalformed)
	}
}

func objectKindToPB(kind taskdata.ObjectKind) nexusv1.TaskDataObjectKind {
	switch kind {
	case taskdata.ObjectKindInput:
		return nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_INPUT
	case taskdata.ObjectKindOutput:
		return nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT
	case taskdata.ObjectKindEvidenceManifest:
		return nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST
	case taskdata.ObjectKindEvidenceArtifact:
		return nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_EVIDENCE_ARTIFACT
	default:
		return nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_UNSPECIFIED
	}
}

func producerKindFromPB(kind nexusv1.EvidenceProducerKindV1) (taskdata.EvidenceProducerKind, error) {
	switch kind {
	case nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_UNSPECIFIED:
		return taskdata.EvidenceProducerUnspecified, nil
	case nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_WORKER:
		return taskdata.EvidenceProducerWorker, nil
	case nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_VERIFIER:
		return taskdata.EvidenceProducerVerifier, nil
	default:
		return 0, fmt.Errorf("%w: evidence_producer_kind", taskdata.ErrMalformed)
	}
}

func producerKindToPB(kind taskdata.EvidenceProducerKind) nexusv1.EvidenceProducerKindV1 {
	switch kind {
	case taskdata.EvidenceProducerWorker:
		return nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_WORKER
	case taskdata.EvidenceProducerVerifier:
		return nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_VERIFIER
	default:
		return nexusv1.EvidenceProducerKindV1_EVIDENCE_PRODUCER_KIND_V1_UNSPECIFIED
	}
}

func requesterKindFromPB(kind nexusv1.TaskDataRequesterKindV1) (taskdata.RequesterKind, error) {
	switch kind {
	case nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_USER:
		return taskdata.RequesterKindUser, nil
	case nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_CORTEX_SERVICE:
		return taskdata.RequesterKindCortexService, nil
	default:
		return 0, fmt.Errorf("%w: requester_kind", taskdata.ErrMalformed)
	}
}

// userFormatErr reports a malformed USER Task data request under NEXUS_INGRESS_MALFORMED, the code of
// the format step; CORTEX_SERVICE requests keep NEXUS_DATA_MALFORMED.
func userFormatErr(auth *nexusv1.TaskDataRequestAuthV1, err error) error {
	return taskdata.UserFormatErr(
		auth.GetRequesterKind() == nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_USER, err)
}

// requestAuthFromPB converts the wire TaskDataRequestAuthV1 to the internal form. The body digest is computed
// by the caller for its own body domain -- the body_digest in auth is what the caller claims and must equal
// ours byte for byte; that comparison happens in the authorizer.
// requestAuthFromPB only converts encoding. body_digest is carried through as is -- taskdata recomputes it per
// request and compares; nothing is filled in or altered here.
func requestAuthFromPB(
	pb *nexusv1.TaskDataRequestAuthV1, ref taskdata.ObjectRef,
) (taskdata.RequestAuth, error) {
	if pb == nil {
		return taskdata.RequestAuth{}, fmt.Errorf("%w: request_auth required", taskdata.ErrMalformed)
	}
	kind, err := requesterKindFromPB(pb.GetRequesterKind())
	if err != nil {
		return taskdata.RequestAuth{}, err
	}
	return taskdata.RequestAuth{
		SchemaVersion:             pb.GetSchemaVersion(),
		ChainID:                   pb.GetChainId(),
		BuilderOperatorAddress:    pb.GetBuilderOperatorAddress(),
		RPCMethod:                 pb.GetRpcMethod(),
		BodyDigest:                pb.GetBodyDigest(),
		RequesterKind:             kind,
		RequesterAddress:          pb.GetRequesterAddress(),
		ServiceAuthorizationNonce: pb.GetServiceAuthorizationNonce(),
		RequestNonce:              append([]byte(nil), pb.GetRequestNonce()...),
		ExpiryHeight:              pb.GetExpiryHeight(),
		Signature:                 append([]byte(nil), pb.GetSignature()...),
		SessionGrant:              sessionGrantFromPB(pb.GetSessionGrant()),
		Key:                       ref,
	}, nil
}

// rangeFromPB preserves the distinction between "whole read" and "range read": an absent range and a present range
// with offset/length both zero are two different signed commitments and must not be rewritten into each other.
func rangeFromPB(pb *nexusv1.ByteRangeV1) (*taskdata.ByteRange, error) {
	if pb == nil {
		return nil, nil
	}
	if pb.GetLength() == 0 {
		return nil, fmt.Errorf("%w: present range must have a positive length", taskdata.ErrRangeInvalid)
	}
	return &taskdata.ByteRange{Offset: pb.GetOffset(), Length: pb.GetLength()}, nil
}

func uploadHeaderFromPB(pb *nexusv1.UploadTaskResultObjectHeaderV1) (taskdata.UploadHeader, taskdata.RequestAuth, error) {
	ref, err := objectRefFromPB(pb.GetObjectRef())
	if err != nil {
		return taskdata.UploadHeader{}, taskdata.RequestAuth{}, err
	}
	header := taskdata.UploadHeader{
		Key: ref, SizeBytes: pb.GetSizeBytes(), SemanticHash: ref.ContentHash, MediaType: pb.GetMediaType(),
	}
	request, err := requestAuthFromPB(pb.GetRequestAuth(), ref)
	return header, request, err
}

func metadataToPB(metadata taskdata.Metadata, exists bool) *nexusv1.TaskDataObjectMetadataV1 {
	if !exists {
		return nil
	}
	pb := &nexusv1.TaskDataObjectMetadataV1{
		ObjectRef: objectRefToPB(metadata.Key),
		SizeBytes: metadata.SizeBytes,
		MediaType: metadata.MediaType,
		Readiness: readinessToPB(metadata.State),
	}
	if metadata.Key.Kind == taskdata.ObjectKindOutput && metadata.OutputLeafCount > 0 &&
		metadata.State == taskdata.StateReady {
		// Return chunk boundaries and leaf count only for READY streaming OUTPUT.
		pb.ChunkLengths = append([]uint32(nil), metadata.ChunkLengths...)
		pb.OutputLeafCount = metadata.OutputLeafCount
	}
	// The codec of EVIDENCE_ARTIFACT is defined solely by the evidence schema; media_type must be empty.
	if metadata.Key.Kind == taskdata.ObjectKindEvidenceArtifact {
		pb.MediaType = ""
	}
	return pb
}

// signedInferReceiptToPB is the inverse of finalize.go signedInferReceiptFromPB: hex fields are
// restored to raw 32/64 bytes. Invalid hex can only come from a locally corrupted record; it is returned as empty
// bytes, and the caller's comparison against the chain naturally rejects it.
func signedInferReceiptToPB(r taskdata.SignedInferReceipt) *taskv1.InferReceiptV3 {
	fromHex := func(v string) []byte { raw, _ := hex.DecodeString(v); return raw }
	commitments := make([]*taskv1.EvidenceCommitmentV1, 0, len(r.EvidenceCommitments))
	for _, c := range r.EvidenceCommitments {
		commitments = append(commitments, &taskv1.EvidenceCommitmentV1{
			EvidenceKind: sharedv1.EvidenceKind(c.Kind), EvidenceHashOrRoot: fromHex(c.HashOrRoot), EncodedSizeBytes: c.EncodedSizeBytes,
		})
	}
	return &taskv1.InferReceiptV3{
		SchemaVersion: r.SchemaVersion, ChainId: r.ChainID,
		TaskId: fromHex(r.TaskID), TaskHash: fromHex(r.TaskHash),
		WorkerOperatorAddress:       r.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   r.ServiceAuthorizationNonce,
		GenerationParamsDigest:      fromHex(r.GenerationParamsDigest),
		OutputHash:                  fromHex(r.OutputHash),
		OutputSizeBytes:             r.OutputSizeBytes,
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                r.ExpiryHeight,
		ServiceSignature:            fromHex(r.ServiceSignature),
		GeneratedTokenCount:         r.GeneratedTokenCount,
		OutputLeafCount:             r.OutputLeafCount,
		OutputKeyCommitment:         fromHex(r.OutputKeyCommitment),
		WorkerTokenKeyCommitment:    fromHex(r.WorkerTokenKeyCommitment),
		WorkerValueKeyCommitment:    fromHex(r.WorkerValueKeyCommitment),
		CiphertextOutputRoot:        fromHex(r.CiphertextOutputRoot),
	}
}

// evidenceBundleToPB returns the bundle summary only for EVIDENCE_MANIFEST.
// evidence_bundle_hash is the H_V1 of the manifest bytes; the Worker manifest's ref content_hash is the
// receipt's evidence_hash_or_root, and the Verifier checks the fetched bytes against the value here.
func evidenceBundleToPB(metadata taskdata.Metadata, exists bool) *nexusv1.EvidenceBundleSummaryV1 {
	if !exists || metadata.Key.Kind != taskdata.ObjectKindEvidenceManifest {
		return nil
	}
	bundleHash := metadata.EvidenceBundleHash
	if bundleHash == "" {
		// Record persisted before EvidenceBundleHash existed: back then content_hash was the byte hash.
		bundleHash = metadata.Key.ContentHash
	}
	return &nexusv1.EvidenceBundleSummaryV1{
		EvidenceManifestHash:   bundleHash,
		EvidenceSchemaHash:     metadata.EvidenceSchemaHash,
		ArtifactCount:          uint32(len(metadata.Artifacts)),
		ArtifactTotalSizeBytes: metadata.ArtifactTotalSizeBytes,
		ManifestSizeBytes:      metadata.SizeBytes,
	}
}

func readinessToPB(state taskdata.State) nexusv1.TaskDataObjectReadinessV1 {
	switch state {
	case taskdata.StateReady:
		return nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_READY
	case taskdata.StateStored:
		return nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_STORED
	default:
		// PREPARED is STAGING (bytes still being written) and QUARANTINED is a bad object; neither should be
		// visible externally. Only STORED and READY are externally visible.
		return nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_UNSPECIFIED
	}
}

// mapOpenTaskRequestErr reports step 5 of OpenTask under the SDK request codes: a height expiry
// outside [current_height, current_height + request_ttl_blocks] is SDK_AUTH_EXPIRED and a used nonce
// SDK_AUTH_REPLAY.
func mapOpenTaskRequestErr(err error) error {
	switch {
	case errors.Is(err, taskdata.ErrExpired):
		return mapEnvelopeErr(fmt.Errorf("%w: %v", sdkauth.ErrExpired, err))
	case errors.Is(err, taskdata.ErrReplay):
		return mapEnvelopeErr(fmt.Errorf("%w: %v", sdkauth.ErrReplay, err))
	default:
		return mapTaskDataError(err)
	}
}

func mapTaskDataError(err error) error {
	var code connect.Code
	switch {
	case errors.Is(err, taskdata.ErrMalformed), errors.Is(err, taskdata.ErrRequestMalformed):
		code = connect.CodeInvalidArgument
	case errors.Is(err, taskdata.ErrReplay):
		code = connect.CodeUnauthenticated
	case errors.Is(err, taskdata.ErrRetentionExpired):
		code = connect.CodeNotFound
	case errors.Is(err, taskdata.ErrSessionMethodNotAllowed):
		code = connect.CodePermissionDenied
	case errors.Is(err, taskdata.ErrSessionGrantInvalid), errors.Is(err, taskdata.ErrInvalidSignature):
		code = connect.CodeUnauthenticated
	case errors.Is(err, taskdata.ErrDenied):
		code = connect.CodePermissionDenied
	case errors.Is(err, taskdata.ErrSessionGrantExpired):
		code = connect.CodeDeadlineExceeded
	case errors.Is(err, taskdata.ErrUnauthorized):
		code = connect.CodePermissionDenied
	case errors.Is(err, taskdata.ErrNotFound):
		code = connect.CodeNotFound
	case errors.Is(err, taskdata.ErrConflict):
		code = connect.CodeAlreadyExists
	case errors.Is(err, taskdata.ErrExpired):
		code = connect.CodeDeadlineExceeded
	case errors.Is(err, taskdata.ErrCapacity):
		code = connect.CodeResourceExhausted
	case errors.Is(err, taskdata.ErrHashMismatch):
		code = connect.CodeDataLoss
	case errors.Is(err, taskdata.ErrRangeInvalid):
		code = connect.CodeOutOfRange
	case errors.Is(err, taskdata.ErrServiceKeyUnavailable):
		code = connect.CodeUnavailable
	case errors.Is(err, taskdata.ErrAuthorityUnavailable):
		code = connect.CodeUnavailable
	case errors.Is(err, taskdata.ErrNotReady):
		// Retryable against the same Builder; the message keeps the NEXUS_DATA_NOT_READY prefix.
		code = connect.CodeUnavailable
	default:
		code = connect.CodeInternal
	}
	return connect.NewError(code, err)
}
