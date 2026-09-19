package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// Connect handlers for the ADR-0017 streaming OUTPUT data plane (streaming output delivery design §5; sequence
// diagrams 1-5 in "Nexus streaming output sequence"). When task_data.output_stream.enabled is off, the three RPCs
// in this file go Unimplemented / legacy path, behaving exactly as before the change.

// outputStreamAPI is the streaming part of taskdata.Service (replaceable in tests).
type outputStreamAPI interface {
	OpenOutputStream(context.Context, taskdata.RequestAuth, taskdata.OutputStreamHeader) (*taskdata.OutputStreamSession, taskdata.OutputStreamProgress, error)
	OutputFrames(context.Context, taskdata.ObjectKey, *uint64) ([]taskdata.OutputFrame, error)
}

// outputStreamRuntime wires the streaming data plane into ingress: storage and authorization (service), per-task
// fan-out (dispatcher), the user's local delivery progress (acks, kv NSOutputAck).
type outputStreamRuntime struct {
	service    outputStreamAPI
	dispatcher *taskdata.OutputDispatcher
	acks       kv.Store
}

func withOutputStream(runtime *outputStreamRuntime) serviceOption {
	return func(s *service) { s.outputStream = runtime }
}

// WithOutputStream enables the streaming OUTPUT data plane (task_data.output_stream.enabled).
func WithOutputStream(service *taskdata.Service, dispatcher *taskdata.OutputDispatcher, acks kv.Store) Option {
	return func(s *Server) {
		if service != nil && dispatcher != nil && acks != nil {
			s.outputStream = &outputStreamRuntime{service: service, dispatcher: dispatcher, acks: acks}
		}
	}
}

var errOutputStreamDisabled = connect.NewError(connect.CodeUnimplemented,
	errors.New("NEXUS_OUTPUT_STREAM_DISABLED: task_data.output_stream.enabled is false"))

// UploadTaskOutputStream, diagrams 1 / 3: authorize on Header and return progress; verify, validate, persist and
// forward each chunk; Fin finalizes, compares against the local receipt and returns the result. Any error closes the
// stream and the reason travels only as the status code (mapping in the proto comments); persisted chunks are not rolled back.
func (s *service) UploadTaskOutputStream(
	ctx context.Context,
	stream *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse],
) error {
	if s.outputStream == nil {
		return errOutputStreamDisabled
	}
	first, err := stream.Receive()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_DATA_MALFORMED: output stream header required"))
		}
		return err
	}
	headerPB := first.GetHeader()
	if headerPB == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_DATA_MALFORMED: first frame must be header"))
	}
	// A streaming Header carries no object ref: the content hash is unknown when the stream opens and only computable at Fin.
	// An in-flight stream is located by (session, task, OUTPUT) with content_hash empty, filled in at Fin.
	key := taskdata.ObjectRef{
		TaskHash: headerPB.GetTaskHash(), SessionID: headerPB.GetSessionId(),
		TaskID: headerPB.GetTaskId(), Kind: taskdata.ObjectKindOutput,
	}
	request, err := requestAuthFromPB(headerPB.GetRequestAuth(), key)
	if err != nil {
		return mapTaskDataError(err)
	}
	session, progress, err := s.outputStream.service.OpenOutputStream(ctx, request, taskdata.OutputStreamHeader{
		Key: key, TaskHash: headerPB.GetTaskHash(),
	})
	if err != nil {
		// Stream already finalized or a complete object already exists: return progress first, then end with AlreadyExists;
		// the Worker uses the root to decide between "already delivered" and "switch provider" (alt branch of diagrams 1 / 3).
		if errors.Is(err, taskdata.ErrConflict) && session == nil && progress.Sealed {
			_ = stream.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: progressToPB(progress)}})
		}
		return mapTaskDataError(err)
	}
	defer session.Close()
	if err := stream.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: progressToPB(progress)}}); err != nil {
		return err
	}
	for {
		msg, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Worker disconnected without sending Fin: progress is persisted, reconnect resumes per diagram 3.
				return connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_DATA_STREAM_INTERRUPTED: stream closed before fin"))
			}
			return err
		}
		switch frame := msg.GetFrame().(type) {
		case *nexusv1.UploadTaskOutputStreamRequest_Chunk:
			chunk := chunkFromPB(frame.Chunk)
			if _, err := session.Append(ctx, chunk); err != nil {
				return mapTaskDataError(err)
			}
			s.outputStream.dispatcher.Publish(key, taskdata.OutputFrame{Chunk: &chunk})
		case *nexusv1.UploadTaskOutputStreamRequest_Fin:
			fin := taskdata.OutputFin{FinalSeq: frame.Fin.GetFinalSeq(), OutputMMRRoot: append([]byte(nil), frame.Fin.GetOutputMmrRoot()...)}
			metadata, err := session.Finish(ctx, fin)
			if err != nil {
				return mapTaskDataError(err)
			}
			s.outputStream.dispatcher.Publish(key, taskdata.OutputFrame{Fin: &fin})
			// Fin only means this stream is fully persisted, not that the whole Task Result is READY:
			// wire v0.4.1 removed the storage_confirmation here; the confirmation is now issued by
			// FinalizeTaskResult after checking the receipt, output and all evidence (design §5.5).
			result := &nexusv1.OutputStreamResultV1{
				Accepted: true, LastSeq: fin.FinalSeq, OutputMmrRoot: fin.OutputMMRRoot, LeafCount: metadata.OutputLeafCount,
			}
			return stream.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Result{Result: result}})
		default:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_DATA_MALFORMED: only chunk or fin may follow the header"))
		}
	}
}

// subscribeOutputStream, diagram 5: verify the envelope, allow only the ordering user; first replay persisted frames with
// seq > resume_after_seq, then live frames (the subscriber is registered before replay, live frames are buffered, and only those with seq above the highest replayed are sent).
// If the stream has ended, only historical frames and Fin are sent. When disconnected due to a full buffer, ResourceExhausted is returned and the SDK resubscribes with last_seq.
func (s *service) subscribeOutputStream(
	ctx context.Context,
	req *connect.Request[nexusv1.SubscribeOutputRequest],
	stream *connect.ServerStream[nexusv1.SubscribeOutputResponse],
) error {
	m := req.Msg
	if m.GetSessionId() == "" || m.GetTaskId() == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_INGRESS_MALFORMED: session_id and task_id are required"))
	}
	body := sdkauth.BodyDigest([]byte(m.GetSessionId()), []byte(m.GetTaskId()))
	requester, err := s.checkRequiredTaskEnvelope(m.GetRequestEnvelope(), "SubscribeOutput",
		nexusv1connect.IngressAPISubscribeOutputProcedure, m.GetSessionId(), m.GetTaskId(), body)
	if err != nil {
		return err
	}
	if err := s.requireTaskOwner(ctx, m.GetSessionId(), m.GetTaskId(), requester); err != nil {
		return err
	}
	key := taskdata.ObjectKey{SessionID: m.GetSessionId(), TaskID: m.GetTaskId(), Kind: taskdata.ObjectKindOutput}
	sub := s.outputStream.dispatcher.Subscribe(key)
	defer sub.Close()

	// In proto3, 0 and "unset" are indistinguishable: 0 means replay from seq = 0; n > 0 replays only seq > n.
	var after *uint64
	if resume := m.GetResumeAfterSeq(); resume > 0 {
		after = &resume
	}
	frames, err := s.outputStream.service.OutputFrames(ctx, key, after)
	if err != nil {
		return mapTaskDataError(err)
	}
	sent := false
	var lastSent uint64
	for _, frame := range frames {
		if err := stream.Send(outputFrameToPB(frame)); err != nil {
			return err
		}
		if frame.Fin != nil {
			return nil
		}
		sent, lastSent = true, frame.Chunk.Seq
	}
	for {
		select {
		case frame, ok := <-sub.Frames:
			if !ok {
				if sub.Overflowed() {
					return connect.NewError(connect.CodeResourceExhausted,
						errors.New("NEXUS_OUTPUT_SUBSCRIBER_OVERFLOW: subscriber buffer full, re-subscribe with resume_after_seq"))
				}
				return connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_OUTPUT_STREAM_STOPPED: builder is shutting down"))
			}
			if frame.Chunk != nil {
				if sent && frame.Chunk.Seq <= lastSent {
					continue
				}
				sent, lastSent = true, frame.Chunk.Seq
			}
			if err := stream.Send(outputFrameToPB(frame)); err != nil {
				return err
			}
			if frame.Fin != nil {
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// outputAckRecord is the user's local delivery progress (task, last_seq): not an on-chain fact, not part of settlement / retention / attribution.
type outputAckRecord struct {
	LastSeq int64 `json:"last_seq"`
	AckedAt int64 `json:"acked_at"`
}

// ackOutputStream, end of diagram 5: record local progress. Repeated ACK with the same last_seq is idempotent.
func (s *service) ackOutputStream(
	ctx context.Context,
	req *connect.Request[nexusv1.AckOutputRequest],
) (*connect.Response[nexusv1.AckOutputResponse], error) {
	m := req.Msg
	if m.GetSessionId() == "" || m.GetTaskId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_INGRESS_MALFORMED: session_id and task_id are required"))
	}
	body := sdkauth.BodyDigest([]byte(m.GetSessionId()), []byte(m.GetTaskId()), []byte(m.GetOutputId()))
	requester, err := s.checkRequiredTaskEnvelope(m.GetRequestEnvelope(), "AckOutput",
		nexusv1connect.IngressAPIAckOutputProcedure, m.GetSessionId(), m.GetTaskId(), body)
	if err != nil {
		return nil, err
	}
	if err := s.requireTaskOwner(ctx, m.GetSessionId(), m.GetTaskId(), requester); err != nil {
		return nil, err
	}
	key := m.GetSessionId() + "|" + m.GetTaskId()
	now := time.Now().UnixMilli()
	if raw, found := s.outputStream.acks.Get(kv.NSOutputAck, key); found {
		var existing outputAckRecord
		if json.Unmarshal(raw, &existing) == nil && existing.LastSeq == int64(m.GetLastSeq()) {
			return connect.NewResponse(&nexusv1.AckOutputResponse{Acked: true, AlreadyAcked: true, AckedAt: existing.AckedAt}), nil
		}
	}
	raw, err := json.Marshal(outputAckRecord{LastSeq: int64(m.GetLastSeq()), AckedAt: now})
	if err == nil {
		err = s.outputStream.acks.Set(kv.NSOutputAck, key, raw)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("NEXUS_OUTPUT_ACK_STORAGE: %v", err))
	}
	return connect.NewResponse(&nexusv1.AckOutputResponse{Acked: true, AckedAt: now}), nil
}

// requireTaskOwner: streaming subscribe and ACK are allowed only for the ordering user (design §5.6).
func (s *service) requireTaskOwner(ctx context.Context, sessionID, taskID, requester string) error {
	owner, err := s.h.TaskOwner(ctx, sessionID, taskID)
	if err != nil {
		if errors.Is(err, types.ErrTaskNotFound) {
			return connect.NewError(connect.CodeNotFound, errors.New("task not found"))
		}
		return connect.NewError(connect.CodeUnavailable, err)
	}
	if owner == "" || owner != requester {
		return connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_OUTPUT_UNAUTHORIZED: only the order user may subscribe"))
	}
	return nil
}

func chunkFromPB(pb *nexusv1.OutputChunkV1) taskdata.OutputChunk {
	return taskdata.OutputChunk{
		Seq: pb.GetSeq(), Text: append([]byte(nil), pb.GetText()...), MMRRoot: append([]byte(nil), pb.GetMmrRoot()...),
		WorkerSignature: append([]byte(nil), pb.GetWorkerSignature()...),
		Attachment:      append([]byte(nil), pb.GetAttachment()...), AttachmentSignature: append([]byte(nil), pb.GetAttachmentSignature()...),
	}
}

func chunkToPB(chunk *taskdata.OutputChunk) *nexusv1.OutputChunkV1 {
	return &nexusv1.OutputChunkV1{
		Seq: chunk.Seq, Text: chunk.Text, MmrRoot: chunk.MMRRoot, WorkerSignature: chunk.WorkerSignature,
		Attachment: chunk.Attachment, AttachmentSignature: chunk.AttachmentSignature,
	}
}

func outputFrameToPB(frame taskdata.OutputFrame) *nexusv1.SubscribeOutputResponse {
	if frame.Fin != nil {
		return &nexusv1.SubscribeOutputResponse{Frame: &nexusv1.SubscribeOutputResponse_Fin{Fin: &nexusv1.OutputFinV1{
			FinalSeq: frame.Fin.FinalSeq, OutputMmrRoot: frame.Fin.OutputMMRRoot,
		}}}
	}
	return &nexusv1.SubscribeOutputResponse{Frame: &nexusv1.SubscribeOutputResponse_Chunk{Chunk: chunkToPB(frame.Chunk)}}
}

func progressToPB(progress taskdata.OutputStreamProgress) *nexusv1.OutputStreamProgressV1 {
	pb := &nexusv1.OutputStreamProgressV1{MmrRoot: progress.MMRRoot, LastFrameShort: progress.LastFrameShort}
	if progress.Received {
		last := progress.LastSeq
		pb.LastSeq = &last
	}
	return pb
}
