package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/credential"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// Handler is the application-level implementation behind IngressAPI, satisfied by the Coordinator.
// Every task-level entry point carries the composite key session_id + task_id.
type Handler interface {
	OnOrder(ctx context.Context, o types.Order) error
	// OnInferReceipt accepts the selected Worker's signed InferReceipt (Cortex contract §2.4).
	// Acceptance means the Builder commits to relaying it; it does not wait for output/evidence upload and does not mean on-chain accepted.
	// SessionForTask looks up session_id by task_id: wire v0.4.1 relay requests carry only the on-chain
	// message body, and the on-chain task_id contains no session.
	SessionForTask(ctx context.Context, taskID string) (string, error)
	OnInferReceipt(ctx context.Context, receipt types.InferReceiptSubmission) error
	// OnVerifyCommit / OnVerifyResult relay the selected Verifier's signed commit / result
	// (Cortex contract §2.5 / §2.6; the initial relay implementation trusts the Builder). Return only means broadcast, not on-chain accepted.
	OnVerifyCommit(ctx context.Context, sessionID, taskID string, commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error)
	OnVerifyResult(ctx context.Context, sessionID, taskID string, receipt *taskv1.ResultReceiptV2) (types.VerifyRelayAck, error)
	SubscribeOutput(ctx context.Context, sessionID, taskID, requester string) (types.PlaintextOutput, error)
	AckOutput(ctx context.Context, sessionID, taskID, outputID, requester string) (types.OutputAck, error)
	// TaskOwner returns the ordering user's address (authorization for ADR-0017 streaming subscribe / ACK);
	// returns types.ErrTaskNotFound for an unknown task.
	TaskOwner(ctx context.Context, sessionID, taskID string) (string, error)
	// FetchOutputRef issues bound credentials tiered by access_level only (deprecated):
	// the Cortex contract "target-state baseline" removed the OutputRef object, so there is no reference left to return.
	FetchOutputRef(ctx context.Context, sessionID, taskID, requester string, level types.AccessLevel, usage string) (types.Credential, error)
	TaskStatus(ctx context.Context, sessionID, taskID string) (types.TaskStatus, error)
	// TaskEvents subscribes to the event stream (v1.5 §3.4): replay after cursor + live channel + unsubscribe.
	TaskEvents(ctx context.Context, sessionID, taskID string, fromCursor uint64) ([]types.TaskEvent, <-chan types.TaskEvent, func(), error)
	// RefreshCredential exchanges an old credential for a new one (v1.5 §3.5, deprecated).
	RefreshCredential(ctx context.Context, old types.Credential, recipient, usage string, requestedValidUntil int64) (types.Credential, error)
	// PrepareChallenge assembles challenge inputs (v1.5 §3.6) without submitting a verdict.
	PrepareChallenge(ctx context.Context, sessionID, taskID, kind string) (types.ChallengePlan, error)
}

type ServiceKeyResolver interface {
	QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error)
}

// AuthParams is the SDK envelope verification environment (v1.5 §3.0).
// RequireEnvelope=false (default lenient, devnet): an envelope, if present, must verify; absent ones pass;
// RequireEnvelope=true (production): every SDK request must carry a valid envelope.
type AuthParams struct {
	ChainID         string
	BuilderAddress  string
	Bech32Prefix    string
	RequireEnvelope bool
	ServiceKeys     ServiceKeyResolver
}

// service implements nexusv1connect.IngressAPIHandler, forwarding Connect requests to Handler.
type service struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	h        Handler
	auth     AuthParams
	replay   sdkauth.ReplayCache
	taskData taskDataAPI
	// outputStream non-nil means the streaming OUTPUT data plane is enabled (task_data.output_stream.enabled).
	outputStream *outputStreamRuntime
}

type serviceOption func(*service)

func withTaskDataAPI(api taskDataAPI) serviceOption {
	return func(s *service) { s.taskData = api }
}

func newService(h Handler, auth AuthParams, options ...serviceOption) *service {
	s := &service{
		h:      h,
		auth:   auth,
		replay: sdkauth.NewMemoryReplayCache(),
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// checkEnvelope verifies the request envelope and returns the signer address (empty when the envelope is absent in lenient mode).
func (s *service) checkEnvelope(pb *nexusv1.SDKRequestEnvelopeV1, method string, wantBody []byte) (string, error) {
	return s.checkEnvelopeWithReplay(pb, method, wantBody, s.replay)
}

func (s *service) checkEnvelopeWithReplay(pb *nexusv1.SDKRequestEnvelopeV1, method string, wantBody []byte, replay sdkauth.ReplayCache) (string, error) {
	if pb == nil {
		if s.auth.RequireEnvelope {
			return "", connect.NewError(connect.CodeUnauthenticated,
				errors.New("SDK_AUTH_INVALID_SIGNATURE: request_envelope required"))
		}
		return "", nil
	}
	env := &sdkauth.Envelope{
		RequestDomain:      pb.GetRequestDomain(),
		ChainID:            pb.GetChainId(),
		Method:             pb.GetMethod(),
		Endpoint:           pb.GetEndpoint(),
		SessionID:          pb.GetSessionId(),
		TaskID:             pb.GetTaskId(),
		RequestNonce:       pb.GetRequestNonce(),
		ExpiryHeightOrTime: pb.GetExpiryHeightOrTime(),
		BodyDigest:         pb.GetBodyDigest(),
		SignerAddress:      pb.GetSignerAddress(),
		Signature:          pb.GetSignature(),
		SignerPubKey:       pb.GetSignerPubkey(),
	}
	err := sdkauth.Verify(env, sdkauth.VerifyOpts{
		ChainID:      s.auth.ChainID,
		Method:       method,
		NowMS:        time.Now().UnixMilli(),
		WantBody:     wantBody,
		Bech32Prefix: s.auth.Bech32Prefix,
		ReplayCache:  replay,
	})
	switch {
	case err == nil:
		return env.SignerAddress, nil
	case errors.Is(err, sdkauth.ErrExpired):
		return "", connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.Is(err, sdkauth.ErrMalformed):
		return "", connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return "", connect.NewError(connect.CodeUnauthenticated, err)
	}
}

func (s *service) checkRequiredTaskEnvelopeWithoutReplay(
	pb *nexusv1.SDKRequestEnvelopeV1,
	method, endpoint, sessionID, taskID string,
	wantBody []byte,
) (string, error) {
	if pb == nil {
		return "", connect.NewError(connect.CodeUnauthenticated,
			errors.New("SDK_AUTH_INVALID_SIGNATURE: request_envelope required"))
	}
	signerAddress, err := s.checkEnvelopeWithReplay(pb, method, wantBody, nil)
	if err != nil {
		return "", err
	}
	if signerAddress == "" || pb.GetEndpoint() != endpoint ||
		pb.GetSessionId() != sessionID || pb.GetTaskId() != taskID {
		return "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("NEXUS_INGRESS_MALFORMED: envelope binding mismatch"))
	}
	return signerAddress, nil
}

func (s *service) checkRequiredTaskEnvelope(
	pb *nexusv1.SDKRequestEnvelopeV1,
	method, endpoint, sessionID, taskID string,
	wantBody []byte,
) (string, error) {
	if pb == nil {
		return "", connect.NewError(connect.CodeUnauthenticated,
			errors.New("SDK_AUTH_INVALID_SIGNATURE: request_envelope required"))
	}
	signerAddress, err := s.checkEnvelope(pb, method, wantBody)
	if err != nil {
		return "", err
	}
	if signerAddress == "" || pb.GetEndpoint() != endpoint ||
		pb.GetSessionId() != sessionID || pb.GetTaskId() != taskID {
		return "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("NEXUS_INGRESS_MALFORMED: envelope binding mismatch"))
	}
	return signerAddress, nil
}

func (s *service) SubmitOrder(ctx context.Context, req *connect.Request[nexusv1.SubmitOrderRequest]) (*connect.Response[nexusv1.SubmitOrderResponse], error) {
	m := req.Msg
	if len(m.GetOrderEnvelope()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty order_envelope"))
	}
	if m.GetPayloadRef() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty payload_ref"))
	}
	if len(m.GetPayload()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty payload"))
	}
	if len(m.GetSignature()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty order signature"))
	}
	// order_sequence must **not** use `== 0` as the "unset" check: the first order of every on-chain session
	// is 0. The Keeper does not assign NextExpectedSequence when creating StreamState (Go zero value 0), and
	// consumeOrderSequence requires order_sequence to equal it exactly, so 0 is the only valid first value.
	// Rejecting it as unset means the first order of any new session can never get in.
	//
	// uint64 has no "unset" state to test anyway -- proto3 scalars carry no presence. The real safeguard is the
	// SDKRequestEnvelope signature check below: order_sequence enters the body digest, and a mismatching signature is rejected.
	if m.GetSessionId() == "" || m.GetUserAddress() == "" || m.GetSignatureScheme() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("session_id, user_address, and signature_scheme are required"))
	}
	user, err := s.checkEnvelope(m.GetRequestEnvelope(), "SubmitOrder", submitOrderBodyDigest(m))
	if err != nil {
		return nil, err
	}
	order, err := parseOrderEnvelope(m.GetOrderEnvelope(), m.GetSignatureScheme(), hex.EncodeToString(m.GetSignature()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if user != "" && m.GetUserAddress() != user {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("order user does not match request signer"))
	}
	if envelope := m.GetRequestEnvelope(); envelope != nil {
		if envelope.GetSessionId() != "" && envelope.GetSessionId() != m.GetSessionId() {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request envelope session_id mismatch"))
		}
	}
	order.SessionID = m.GetSessionId()
	order.OrderSequence = m.GetOrderSequence()
	order.User = m.GetUserAddress()
	if envelope := m.GetRequestEnvelope(); envelope != nil && len(envelope.GetSignerPubkey()) > 0 &&
		!s.verifyRoleSignature(order.User, envelope.GetSignerPubkey(), nodecontract.OrderSigningBytes(
			s.auth.ChainID, order.User, order.SessionID, order.OrderSequence, order.OrderEnvelope,
		), m.GetSignature()) {
		return nil, connect.NewError(connect.CodeUnauthenticated, types.ErrInvalidSignature)
	}
	order.TaskID, err = deriveTaskID(order.SessionID, order.OrderSequence)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if envelope := m.GetRequestEnvelope(); envelope != nil && envelope.GetTaskId() != "" && envelope.GetTaskId() != order.TaskID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request envelope task_id mismatch"))
	}
	order.PayloadCID = m.GetPayloadRef()
	if err := validateOrderPayload(order.PayloadHash, order.PayloadCID, m.GetPayload()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	order.Payload = append([]byte(nil), m.GetPayload()...)
	if err := s.h.OnOrder(ctx, order); err != nil {
		return nil, mapOrderErr(err)
	}
	// accepted=true only means ingress accepted it into the local queue, not on-chain accepted (v1.5 §3.1).
	return connect.NewResponse(&nexusv1.SubmitOrderResponse{SessionId: order.SessionID, TaskId: order.TaskID, Accepted: true}), nil
}

func (s *service) FetchOutputRef(ctx context.Context, req *connect.Request[nexusv1.FetchOutputRefRequest]) (*connect.Response[nexusv1.FetchOutputRefResponse], error) {
	m := req.Msg
	if err := validateFetchOutputRef(m); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	level := types.AccessPackage // default minimum authorization
	if m.GetAccessLevel() == nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY {
		level = types.AccessSealedKey
	}
	var signerAddr string
	if m.GetRequestEnvelope() != nil {
		var err error
		signerAddr, err = s.checkEnvelope(m.GetRequestEnvelope(), "FetchOutputRef", fetchOutputRefBodyDigest(m, level))
		if err != nil {
			return nil, err
		}
	}
	switch {
	case signerAddr != "":
		if signerAddr != m.GetRequester() {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("CREDENTIAL_UNAUTHORIZED: requester mismatch"))
		}
	case len(m.GetSignature()) > 0:
		if err := s.verifyParticipantRoleSignature(ctx, servicekey.ParticipantCortex, m.GetRequester(),
			m.GetRequesterPubkey(), fetchOutputRefSignBytes(m, level), m.GetSignature()); err != nil {
			return nil, mapRoleSignatureErr(err)
		}
	default:
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("SDK_AUTH_INVALID_SIGNATURE: request_envelope or role signature required"))
	}
	cred, err := s.h.FetchOutputRef(ctx, m.GetSessionId(), m.GetTaskId(), m.GetRequester(), level, m.GetUsage())
	if err != nil {
		return nil, mapFetchErr(err)
	}
	return connect.NewResponse(&nexusv1.FetchOutputRefResponse{Credential: credToPB(cred)}), nil
}

func (s *service) GetTaskStatus(ctx context.Context, req *connect.Request[nexusv1.GetTaskStatusRequest]) (*connect.Response[nexusv1.GetTaskStatusResponse], error) {
	st, err := s.h.TaskStatus(ctx, req.Msg.GetSessionId(), req.Msg.GetTaskId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&nexusv1.GetTaskStatusResponse{
		State:     st.State,
		TaskPhase: st.TaskPhase,
		Stage:     st.Stage,
		SetId:     st.SetID,
		UpdatedAt: st.UpdatedAt,
	}), nil
}

func (s *service) SubscribeOutput(
	ctx context.Context,
	req *connect.Request[nexusv1.SubscribeOutputRequest],
	stream *connect.ServerStream[nexusv1.SubscribeOutputResponse],
) error {
	if s.outputStream != nil {
		return s.subscribeOutputStream(ctx, req, stream)
	}
	m := req.Msg
	if m.GetSessionId() == "" || m.GetTaskId() == "" {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("NEXUS_INGRESS_MALFORMED: session_id and task_id are required"))
	}
	body := sdkauth.BodyDigest([]byte(m.GetSessionId()), []byte(m.GetTaskId()))
	requester, err := s.checkRequiredTaskEnvelope(
		m.GetRequestEnvelope(),
		"SubscribeOutput",
		nexusv1connect.IngressAPISubscribeOutputProcedure,
		m.GetSessionId(),
		m.GetTaskId(),
		body,
	)
	if err != nil {
		return err
	}
	output, err := s.h.SubscribeOutput(ctx, m.GetSessionId(), m.GetTaskId(), requester)
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return nil
		}
		return mapOutputDeliveryErr(err)
	}
	return stream.Send(&nexusv1.SubscribeOutputResponse{
		OutputId: output.OutputID, SessionId: output.SessionID, TaskId: output.TaskID,
		OutputText: output.Text, OutputHash: output.Hash,
		CreatedAt: output.CreatedAt, ExpiresAt: output.ExpiresAt,
	})
}

func (s *service) AckOutput(
	ctx context.Context,
	req *connect.Request[nexusv1.AckOutputRequest],
) (*connect.Response[nexusv1.AckOutputResponse], error) {
	if s.outputStream != nil {
		return s.ackOutputStream(ctx, req)
	}
	m := req.Msg
	if m.GetSessionId() == "" || m.GetTaskId() == "" || m.GetOutputId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("NEXUS_INGRESS_MALFORMED: session_id, task_id, and output_id are required"))
	}
	body := sdkauth.BodyDigest(
		[]byte(m.GetSessionId()),
		[]byte(m.GetTaskId()),
		[]byte(m.GetOutputId()),
	)
	requester, err := s.checkRequiredTaskEnvelope(
		m.GetRequestEnvelope(),
		"AckOutput",
		nexusv1connect.IngressAPIAckOutputProcedure,
		m.GetSessionId(),
		m.GetTaskId(),
		body,
	)
	if err != nil {
		return nil, err
	}
	ack, err := s.h.AckOutput(ctx, m.GetSessionId(), m.GetTaskId(), m.GetOutputId(), requester)
	if err != nil {
		return nil, mapOutputDeliveryErr(err)
	}
	return connect.NewResponse(&nexusv1.AckOutputResponse{
		Acked: ack.Acked, AlreadyAcked: ack.AlreadyAcked, AckedAt: ack.AckedAt,
	}), nil
}

// GetTaskEvents is the SDK event stream (server streaming): replays history after cursor, then pushes live events
// until the client disconnects. The event stream is only for UX hints; on-chain state is authoritative via chain query (v1.5 §3.4).
func (s *service) GetTaskEvents(ctx context.Context, req *connect.Request[nexusv1.GetTaskEventsRequest], stream *connect.ServerStream[nexusv1.GetTaskEventsResponse]) error {
	m := req.Msg
	if _, err := s.checkEnvelope(m.GetRequestEnvelope(), "GetTaskEvents", sdkauth.BodyDigest(
		[]byte(m.GetSessionId()), []byte(m.GetTaskId()), []byte(m.GetFromCursor()))); err != nil {
		return err
	}
	var fromCursor uint64
	if c := m.GetFromCursor(); c != "" {
		v, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad from_cursor"))
		}
		fromCursor = v
	}
	replay, live, cancel, err := s.h.TaskEvents(ctx, m.GetSessionId(), m.GetTaskId(), fromCursor)
	if err != nil {
		return connect.NewError(connect.CodeNotFound, err)
	}
	defer cancel()

	for _, ev := range replay {
		if err := stream.Send(eventToPB(ev)); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil // client disconnected: normal end; reconnect with cursor to resume
		case ev, ok := <-live:
			if !ok {
				return nil
			}
			if err := stream.Send(eventToPB(ev)); err != nil {
				return err
			}
		}
	}
}

func (s *service) RefreshCredential(ctx context.Context, req *connect.Request[nexusv1.RefreshCredentialRequest]) (*connect.Response[nexusv1.RefreshCredentialResponse], error) {
	m := req.Msg
	if m.GetCredential() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("missing credential"))
	}
	if _, err := s.checkEnvelope(m.GetRequestEnvelope(), "RefreshCredential", sdkauth.BodyDigest(
		[]byte(m.GetCredential().GetCredentialId()), []byte(m.GetSessionId()), []byte(m.GetTaskId()),
		[]byte(m.GetRecipient()), []byte(m.GetUsage()), i64be(m.GetRequestedValidUntil()))); err != nil {
		return nil, err
	}
	cred, err := s.h.RefreshCredential(ctx, credFromPB(m.GetCredential()), m.GetRecipient(), m.GetUsage(), m.GetRequestedValidUntil())
	if err != nil {
		return nil, mapCredentialErr(err)
	}
	return connect.NewResponse(&nexusv1.RefreshCredentialResponse{Credential: credToPB(cred)}), nil
}

func (s *service) PrepareChallenge(ctx context.Context, req *connect.Request[nexusv1.PrepareChallengeRequest]) (*connect.Response[nexusv1.PrepareChallengeResponse], error) {
	m := req.Msg
	if _, err := s.checkEnvelope(m.GetRequestEnvelope(), "PrepareChallenge", sdkauth.BodyDigest(
		[]byte(m.GetSessionId()), []byte(m.GetTaskId()), []byte(m.GetChallengeKind()), m.GetLocalEvidenceDigest())); err != nil {
		return nil, err
	}
	plan, err := s.h.PrepareChallenge(ctx, m.GetSessionId(), m.GetTaskId(), m.GetChallengeKind())
	if err != nil {
		return nil, mapPrepareChallengeErr(err)
	}
	return connect.NewResponse(&nexusv1.PrepareChallengeResponse{
		ChallengeOpen:        plan.ChallengeOpen,
		ChallengeCloseHeight: plan.ChallengeCloseHeight,
		RequiredEvidence:     plan.RequiredEvidence,
		EstimatedBond:        &nexusv1.Coin{Denom: plan.EstimatedBond.Denom, Amount: plan.EstimatedBond.Amount},
		EstimatedGas:         plan.EstimatedGas,
	}), nil
}

func mapPrepareChallengeErr(err error) error {
	switch {
	case errors.Is(err, types.ErrTaskNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, types.ErrChainStateUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ---- error mapping (aligned with v1.5 §3 error code semantics) ----

func mapFetchErr(err error) error {
	switch {
	case errors.Is(err, relay.ErrNotInCustody):
		return connect.NewError(connect.CodeNotFound, errors.New("CREDENTIAL_NOT_IN_CUSTODY"))
	case errors.Is(err, relay.ErrExpired):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("CREDENTIAL_EXPIRED"))
	case errors.Is(err, types.ErrTaskNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, types.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, errors.New("CREDENTIAL_UNAUTHORIZED"))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func mapOutputDeliveryErr(err error) error {
	switch {
	case errors.Is(err, outputdelivery.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, outputdelivery.ErrInvalidUTF8),
		errors.Is(err, outputdelivery.ErrHashMismatch),
		errors.Is(err, outputdelivery.ErrPlaintextRequired):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, outputdelivery.ErrTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, outputdelivery.ErrConflict),
		errors.Is(err, outputdelivery.ErrExpired),
		errors.Is(err, outputdelivery.ErrAlreadyAcked),
		errors.Is(err, outputdelivery.ErrUnavailable):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, outputdelivery.ErrDeliveryFailure):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, types.ErrTaskNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func mapCredentialErr(err error) error {
	switch {
	case errors.Is(err, credential.ErrExpired):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, credential.ErrWrongRecipient), errors.Is(err, credential.ErrWrongUsage),
		errors.Is(err, credential.ErrInvalidSignature):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, relay.ErrNotInCustody), errors.Is(err, relay.ErrExpired):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("CREDENTIAL_REFRESH_DENIED: custody released"))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ---- pb <-> types conversion ----

func credToPB(c types.Credential) *nexusv1.CredentialV1 {
	level := nexusv1.AccessLevel_ACCESS_LEVEL_PACKAGE_UNSPECIFIED
	if c.AccessLevel == types.AccessSealedKey {
		level = nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY
	}
	return &nexusv1.CredentialV1{
		CredentialId: c.ID,
		SessionId:    c.SessionID,
		TaskId:       c.TaskID,
		Recipient:    c.Recipient,
		Usage:        c.Usage,
		AccessLevel:  level,
		ValidUntil:   c.ValidUntil,
		Issuer:       c.Issuer,
		IssuerSig:    c.IssuerSig,
	}
}

func credFromPB(pb *nexusv1.CredentialV1) types.Credential {
	level := types.AccessPackage
	if pb.GetAccessLevel() == nexusv1.AccessLevel_ACCESS_LEVEL_SEALED_KEY {
		level = types.AccessSealedKey
	}
	return types.Credential{
		ID:          pb.GetCredentialId(),
		SessionID:   pb.GetSessionId(),
		TaskID:      pb.GetTaskId(),
		Recipient:   pb.GetRecipient(),
		Usage:       pb.GetUsage(),
		AccessLevel: level,
		ValidUntil:  pb.GetValidUntil(),
		Issuer:      pb.GetIssuer(),
		IssuerSig:   pb.GetIssuerSig(),
	}
}

func eventToPB(ev types.TaskEvent) *nexusv1.GetTaskEventsResponse {
	return &nexusv1.GetTaskEventsResponse{
		Cursor:      strconv.FormatUint(ev.Seq, 10),
		State:       ev.State,
		TaskPhase:   ev.TaskPhase,
		EventCode:   ev.EventCode,
		ChainHeight: ev.ChainHeight,
	}
}

func i64be(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

func submitOrderBodyDigest(m *nexusv1.SubmitOrderRequest) []byte {
	return sdkauth.BodyDigest(
		m.GetOrderEnvelope(),
		[]byte(m.GetPayloadRef()),
		m.GetSignature(),
		[]byte(m.GetSessionId()),
		u64be(m.GetOrderSequence()),
		[]byte(m.GetUserAddress()),
		[]byte(m.GetSignatureScheme()),
		m.GetPayload(),
	)
}

func validateOrderPayload(payloadHash, payloadRef string, payload []byte) error {
	sum := sha256.Sum256(payload)
	if payloadHash != hex.EncodeToString(sum[:]) {
		return payloadstore.ErrHashMismatch
	}
	if payloadRef != payloadstore.RefFor(payload) {
		return payloadstore.ErrRefMismatch
	}
	return nil
}

// isLegacyOrderEnvelope distinguishes the two order_envelope encodings: the legacy canonical JSON always
// starts with '{', while proto-encoded task.v1.SignedOrderV2 starts with the tag of field 1,
// 0x0a; they cannot be confused. SubmitOrderRequest.order_envelope is already bytes, so the
// new carrier needs no new proto field and the SDK request envelope's body digest is unchanged.
func isLegacyOrderEnvelope(raw []byte) bool {
	return len(raw) > 0 && raw[0] == '{'
}

// parseSignedOrderEnvelope parses the SignedOrderV2 carrier of frozen contract §5.13.
// It is the only valid input for the first-proposal scope branch of MsgSubmitWorkerHandraises: the user signature
// covers the order-domain EIP-712 digest of TaskOrderV2; Nexus only validates structure and shape and forwards as is,
// never reconstructs the order and never verifies the signature (the Keeper verifies with the on-chain account public key).
func parseSignedOrderEnvelope(raw []byte) (types.Order, error) {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return types.Order{}, fmt.Errorf("order_envelope is neither canonical json nor a SignedOrderV2: %w", err)
	}
	order := signed.GetOrder()
	if order == nil || order.GetModelId() == "" || order.GetProfileVersion() == 0 {
		return types.Order{}, errors.New("signed_order requires order.model_id and order.profile_version")
	}
	// 08 §7.3/§7.5: scheme is byte-for-byte "eip712"; signature is 65 bytes R||S||V, V in {27,28}, low-S.
	// The legacy "secp256k1" + 64 bytes is the V1 envelope and is not accepted for V2.
	if err := nodecontract.ValidateSignedOrderEnvelopeV2(signed.GetSignatureScheme(), signed.GetUserSignature()); err != nil {
		return types.Order{}, err
	}
	// Reject unknown fields at any level. Before submitting on-chain Nexus re-encodes this message with its own mirror,
	// and unknown fields would be silently dropped -- what gets forwarded would no longer be the order the SDK sent. Better to
	// fail at the entry point than silently rewrite what the user signed.
	var pruned taskv1.SignedOrderV2
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &pruned); err != nil {
		return types.Order{}, fmt.Errorf("signed_order re-decode: %w", err)
	}
	if !proto.Equal(&signed, &pruned) {
		return types.Order{}, errors.New("signed_order carries unknown fields; SDK and nexus mirrors are out of sync")
	}
	// task_hash is derived from the TaskOrderV2 the user actually signed (gh #42): it is the taskHash field of the
	// order-domain EIP-712 typed data, and the Keeper verifies it with the on-chain account public key at admission.
	// An order it cannot be computed for is certain to be rejected on-chain too, so it is rejected here outright
	// rather than carried on with an empty identity.
	//
	// Note that sha256(order_envelope) is **no longer** computed here. That value changes with the envelope encoding (the same
	// order re-signed gives a different value); using it as the Task identity is exactly the mistake gh #42 eradicates.
	taskHash, err := nodecontract.TaskOrderHashHexV2(order)
	if err != nil {
		return types.Order{}, fmt.Errorf("signed_order has no canonical task_hash: %w", err)
	}
	return types.Order{
		ModelID: order.GetModelId(), ProfileVersion: order.GetProfileVersion(),
		TaskType: enumTaskType(order.GetTaskType()),
		Deadline: int64(order.GetOrderExpireHeight()),
		// OrderEnvelope keeps the hex form only for readable logs and snapshots; the authoritative carrier is SignedOrder.
		OrderEnvelope: hex.EncodeToString(raw), TaskHash: taskHash,
		SignatureScheme:  signed.GetSignatureScheme(),
		UserSignature:    hex.EncodeToString(signed.GetUserSignature()),
		ValidAfterHeight: order.GetEarliestSubmitHeight(), DeadlineHeight: order.GetOrderExpireHeight(),
		PayloadHash: hex.EncodeToString(order.GetInputHash()),
		SignedOrder: append([]byte(nil), raw...),
	}, nil
}

func enumTaskType(t sharedv1.TaskType) string {
	return strings.ToLower(strings.TrimPrefix(t.String(), "TASK_TYPE_"))
}

func parseOrderEnvelope(raw []byte, signatureScheme, userSignature string) (types.Order, error) {
	if signatureScheme != "secp256k1" {
		return types.Order{}, fmt.Errorf("unsupported signature_scheme %q", signatureScheme)
	}
	signature, err := hex.DecodeString(userSignature)
	if err != nil || len(signature) != 64 || hex.EncodeToString(signature) != userSignature {
		return types.Order{}, errors.New("user_signature must be 64-byte lowercase hex")
	}
	if !isLegacyOrderEnvelope(raw) {
		return parseSignedOrderEnvelope(raw)
	}
	env, err := nodecontract.ParseAssignmentOrderEnvelope(string(raw))
	if err != nil {
		return types.Order{}, err
	}
	// The legacy JSON envelope has no TaskHash: it lacks chain_id / session_anchor_* / builder_set_* /
	// generation_params, so the TRUEOPEN_TASK_ORDER_V2 preimage cannot be built and **no**
	// canonical task_hash exists to fill in. The sha256(order_envelope) formerly filled in here was not a
	// substitute but an alias, removed with gh #42.
	//
	// The consequence is explicit: an order with an empty task_hash is not broadcast (taskfsm.onOrder rejects it outright),
	// which matches its original situation -- the first-proposal scope branch accepts only the frozen SignedOrderV2, and
	// legacy-envelope orders could never be submitted on-chain anyway. The only difference is that it now fails before broadcast
	// instead of in workerHandraiseScope after enough hand-raises were collected.
	return types.Order{
		ModelID: env.ModelID, ProfileVersion: env.ProfileVersion, TaskType: env.TaskType,
		Deadline: int64(env.DeadlineHeight), OrderEnvelope: string(raw),
		SignatureScheme: signatureScheme, UserSignature: userSignature,
		RewardBucket: env.RewardBucket, ProfileResourceTier: env.ProfileResourceTier,
		InferInputUnitPriceBid: env.InferInputUnitPriceBid, InferOutputUnitPriceBid: env.InferOutputUnitPriceBid,
		VerifyUnitPriceBid: env.VerifyUnitPriceBid, MaxFee: env.MaxFee, TxFeeReserve: env.TxFeeReserve,
		InferFeeCap: env.InferFeeCap, VerifyFeeCap: env.VerifyFeeCap, OrderValue: env.OrderValue,
		ValidAfterHeight: env.ValidAfterHeight, DeadlineHeight: env.DeadlineHeight,
		PayloadHash: env.PayloadHash, InferTimeoutBlocks: env.InferTimeoutBlocks,
		ReferenceBucketKey: env.ReferenceBucketKey, TimeoutBucketKey: env.TimeoutBucketKey,
	}, nil
}

func validateFetchOutputRef(m *nexusv1.FetchOutputRefRequest) error {
	switch {
	case m.GetSessionId() == "":
		return fmt.Errorf("%w: empty session_id", types.ErrInvalidArgument)
	case m.GetTaskId() == "":
		return fmt.Errorf("%w: empty task_id", types.ErrInvalidArgument)
	case m.GetRequester() == "":
		return fmt.Errorf("%w: empty requester", types.ErrInvalidArgument)
	case m.GetUsage() == "":
		return fmt.Errorf("%w: empty usage", types.ErrInvalidArgument)
	default:
		return nil
	}
}

func (s *service) verifyRoleSignature(address string, pubKey, signBytes, sig []byte) bool {
	if address == "" || len(pubKey) == 0 || len(sig) == 0 {
		return false
	}
	derived, err := signer.AddressFromPubKey(s.auth.Bech32Prefix, pubKey)
	if err != nil || derived != address {
		return false
	}
	return signer.VerifySig(pubKey, signBytes, sig)
}

// verifyParticipantRoleSignature verifies Cortex's role signature. The presented key may be the
// operator key self-signing, or that operator's current service key under the CORTEX domain --
// the latter is the norm; a Cortex Node need not keep the operator private key online.
//
// participantType accepts only the current service key query domain (CORTEX); do not pass
// sender_role's WORKER / VERIFIER: that is the Task duty in the message, not a query domain,
// and passing it never finds a key.
//
// nil means pass; an error wrapping errServiceKeyAuthority means **undecidable**
// (chain query failed, malformed query domain) and the caller must report Unavailable; any other error is a
// decided invalid signature. Collapsing both into one boolean would misreport a chain-side fault as an auth failure.
// verifyParticipantRoleDigest verifies the on-chain message's own service_signature: wire v0.4.1
// relay requests no longer wrap a request envelope, so this signature is the authorization. The public key is not presented
// by the caller but fetched from the chain as the current service key by (participantType, operator) -- an old key is invalid immediately after rotation.
func (s *service) verifyParticipantRoleDigest(
	ctx context.Context, participantType, operatorAddress string, digest, sig []byte,
) error {
	if operatorAddress == "" || len(sig) != 64 {
		return types.ErrInvalidSignature
	}
	publicKey, _, err := servicekey.Current(
		ctx, s.auth.ServiceKeys, s.auth.Bech32Prefix, participantType, operatorAddress)
	if err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return fmt.Errorf("%w: %v", errServiceKeyAuthority, err)
		}
		return types.ErrInvalidSignature
	}
	if !signer.VerifyDigestSig(publicKey, digest, sig) {
		return types.ErrInvalidSignature
	}
	return nil
}

func (s *service) verifyParticipantRoleSignature(
	ctx context.Context, participantType, operatorAddress string, pubKey, signBytes, sig []byte,
) error {
	if operatorAddress == "" || len(pubKey) == 0 || len(sig) == 0 || !signer.VerifySig(pubKey, signBytes, sig) {
		return types.ErrInvalidSignature
	}
	derivedAddress, err := signer.AddressFromPubKey(s.auth.Bech32Prefix, pubKey)
	if err != nil {
		return types.ErrInvalidSignature
	}
	if derivedAddress == operatorAddress {
		return nil
	}
	if _, err := servicekey.VerifyPresented(
		ctx, s.auth.ServiceKeys, s.auth.Bech32Prefix, participantType, operatorAddress, pubKey); err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return fmt.Errorf("%w: %v", errServiceKeyAuthority, err)
		}
		return types.ErrInvalidSignature
	}
	return nil
}

// errServiceKeyAuthority is synonymous with taskdata.ErrAuthorityUnavailable, only raised on the ingress
// role signature path: the on-chain current service key cannot be looked up, so neither authorized nor
// unauthorized can be decided; it must map to Unavailable (retryable), not Unauthenticated (decided rejection).
var errServiceKeyAuthority = errors.New("NEXUS_INGRESS_SERVICE_KEY_AUTHORITY_UNAVAILABLE")

// mapRoleSignatureErr maps role signature verification failures to Connect error codes.
func mapRoleSignatureErr(err error) error {
	if errors.Is(err, errServiceKeyAuthority) {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewError(connect.CodeUnauthenticated, types.ErrInvalidSignature)
}

func u64be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func u32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func fetchOutputRefBodyDigest(m *nexusv1.FetchOutputRefRequest, level types.AccessLevel) []byte {
	return sdkauth.BodyDigest(
		[]byte(m.GetSessionId()), []byte(m.GetTaskId()), []byte(m.GetRequester()),
		[]byte(level.String()), []byte(m.GetUsage()))
}

func fetchOutputRefSignBytes(m *nexusv1.FetchOutputRefRequest, level types.AccessLevel) []byte {
	return sdkauth.BodyDigest(
		[]byte("TRUEOPEN_FETCH_OUTPUT_REF_V1"),
		[]byte(m.GetSessionId()), []byte(m.GetTaskId()), []byte(m.GetRequester()),
		[]byte(level.String()), []byte(m.GetUsage()))
}

func mapPayloadErr(err error) error {
	switch {
	case errors.Is(err, types.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, types.ErrTaskNotFound), errors.Is(err, payloadstore.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, payloadstore.ErrExpired):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.Is(err, payloadstore.ErrTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, payloadstore.ErrInvalid), errors.Is(err, payloadstore.ErrHashMismatch),
		errors.Is(err, payloadstore.ErrRefMismatch), errors.Is(err, payloadstore.ErrConflict):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func mapOrderErr(err error) error {
	switch {
	case errors.Is(err, coordinator.ErrNotSelectedBuilder):
		return connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_INGRESS_NOT_SELECTED_BUILDER"))
	case errors.Is(err, coordinator.ErrAdmissionUnavailable):
		return connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_INGRESS_STAGE1_UNAVAILABLE"))
	default:
		return mapPayloadErr(err)
	}
}
