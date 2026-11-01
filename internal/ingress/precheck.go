package ingress

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/hash32text"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/takeover"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// orderAdmission is how the precheck admitted an OpenTask order: dispatched here (Result), or,
// for a session bound to another Builder, taken over (Takeover set; Existing when it is held
// already).
type orderAdmission struct {
	inflight.Result
	Takeover *takeover.Admission
}

// precheckOrder runs the dispatching Builder's precheck on an authenticated OpenTask order, before
// the request nonce is used or the input stored, and reserves an admitted new order in the
// in-flight ledger (Result.Reservation; the caller releases it if the order fails later). signer
// says who signed the order: its wallet or the session's registered key.
//
// A session bound to another Builder goes to AuthParams.Takeovers, which reserves a takeover of
// it for the order (the caller releases it if the order fails later); without takeovers it is
// refused with NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE naming that Builder. An exact resend of an
// order held for a takeover is answered with it before the precheck runs: once the takeover took
// effect the session is bound here, and the held order is not judged as a new one.
func (s *service) precheckOrder(
	ctx context.Context, order types.Order, signed *taskv1.TaskOrderV3, signer sdkauth.OrderPrecheck,
) (orderAdmission, error) {
	maxFee, err := strconv.ParseUint(signed.GetMaxFee().GetAtomicUnits(), 10, 64)
	if err != nil {
		return orderAdmission{}, mapTaskDataError(fmt.Errorf("%w: order max_fee is not a uint64 amount", taskdata.ErrRequestMalformed))
	}
	o := inflight.Order{
		SessionID: order.SessionID, Sequence: order.OrderSequence, TaskID: order.TaskID, TaskHash: order.TaskHash,
		User: order.User, MaxFee: maxFee, EarliestSubmitHeight: signed.GetEarliestSubmitHeight(),
		ExpireHeight: signed.GetOrderExpireHeight(), SessionAnchorHeight: signed.GetSessionAnchorHeight(),
	}
	if !signer.Wallet {
		key := signer.Recovered
		o.SessionKey = &key
	}
	takeovers := s.auth.Takeovers
	if takeovers != nil {
		if held, ok := takeovers.Held(order.SessionID, order.OrderSequence, order.TaskHash); ok {
			return orderAdmission{Takeover: &held}, nil
		}
	}
	result, err := s.auth.Precheck.Reserve(ctx, o)
	if err != nil {
		return orderAdmission{}, mapPrecheckErr(err)
	}
	if result.Binding != inflight.BoundElsewhere {
		return orderAdmission{Result: result}, nil
	}
	if takeovers == nil {
		return orderAdmission{}, mapPrecheckErr(&inflight.SessionBoundElsewhereError{Builder: result.Session.BoundBuilder})
	}
	admission, err := takeovers.Admit(ctx, order, o)
	if err != nil {
		return orderAdmission{}, mapPrecheckErr(err)
	}
	return orderAdmission{Result: result, Takeover: &admission}, nil
}

// mapPrecheckErr maps a precheck failure: session key verdicts as the SDK codes, a state that
// could not be read and an order still uploading on another stream Unavailable, every other code
// FailedPrecondition (the order cannot pass as sent; the code says what the SDK changes). A
// refusal that names where the session went carries it as an OpenTaskResponse detail:
// bound_builder and task_id of the Builder that recorded the order, or bound_builder and
// takeover_activation_height of the registered takeover candidate.
func mapPrecheckErr(err error) error {
	var elsewhere *inflight.SessionBoundElsewhereError
	var pending *inflight.TakeoverPendingError
	switch {
	case errors.Is(err, registeredkey.ErrKeyInvalid), errors.Is(err, registeredkey.ErrKeyExpired),
		errors.Is(err, registeredkey.ErrSpendCapExceeded), errors.Is(err, registeredkey.ErrChainUnreadable):
		return mapEnvelopeErr(sdkauth.OrderKeyErr(err))
	case errors.Is(err, inflight.ErrUnavailable), errors.Is(err, inflight.ErrOrderUploading):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, inflight.ErrBuilderKeyRotating):
		return mapKeyRotating(err)
	case errors.As(err, &elsewhere):
		detail := &nexusv1.OpenTaskResponse{BoundBuilder: &elsewhere.Builder}
		if elsewhere.TaskID != "" {
			detail.TaskId = hash32text.FromInternal(elsewhere.TaskID)
		}
		return withOpenTaskDetail(connect.NewError(connect.CodeFailedPrecondition, err), detail)
	case errors.As(err, &pending):
		detail := &nexusv1.OpenTaskResponse{BoundBuilder: &pending.Candidate}
		if pending.ActivationHeight != 0 {
			detail.TakeoverActivationHeight = &pending.ActivationHeight
		}
		return withOpenTaskDetail(connect.NewError(connect.CodeFailedPrecondition, err), detail)
	default:
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
}

// mapKeyRotating maps NEXUS_INGRESS_BUILDER_KEY_ROTATING: Unavailable, with the rotation's
// effective height, from which this Builder takes new orders again, as the OpenTaskResponse
// detail's dispatch_available_height (the message ends with it too). The SDK handles it as
// NO_CAPACITY: the order goes to another Builder by takeover, and orders already in flight here
// are followed here to their end.
func mapKeyRotating(err error) error {
	ce := connect.NewError(connect.CodeUnavailable, err)
	var rotating *inflight.BuilderKeyRotatingError
	if errors.As(err, &rotating) && rotating.EffectiveHeight != 0 {
		height := rotating.EffectiveHeight
		return withOpenTaskDetail(ce, &nexusv1.OpenTaskResponse{DispatchAvailableHeight: &height})
	}
	return ce
}

func withOpenTaskDetail(ce *connect.Error, detail *nexusv1.OpenTaskResponse) *connect.Error {
	if d, err := connect.NewErrorDetail(detail); err == nil {
		ce.AddDetail(d)
	}
	return ce
}

// takeoverResponse is the OpenTask answer for an order taken over: TAKEOVER_PENDING, naming this
// Builder as the one the session is moving to, with the activation height once registered.
func (s *service) takeoverResponse(order types.Order, admission *takeover.Admission) *nexusv1.OpenTaskResponse {
	builder := s.auth.BuilderAddress
	resp := &nexusv1.OpenTaskResponse{
		SessionId: hash32text.FromInternal(order.SessionID), TaskId: hash32text.FromInternal(order.TaskID), Accepted: true,
		Status: nexusv1.OpenTaskStatusV1_OPEN_TASK_STATUS_V1_TAKEOVER_PENDING, BoundBuilder: &builder,
	}
	if h := admission.ActivationHeight; h != 0 {
		resp.TakeoverActivationHeight = &h
	}
	return resp
}
