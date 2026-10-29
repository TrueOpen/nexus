package ingress

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// precheckOrder runs the dispatching Builder's precheck on an authenticated OpenTask order, before
// the request nonce is used or the input stored. signer says who signed the order: its wallet or
// the session's registered key. A session bound to another Builder is refused with
// NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE naming it: this Builder does not take sessions over.
func (s *service) precheckOrder(
	ctx context.Context, order types.Order, signed *taskv1.TaskOrderV3, signer sdkauth.OrderPrecheck,
) (inflight.Result, error) {
	maxFee, err := strconv.ParseUint(signed.GetMaxFee().GetAtomicUnits(), 10, 64)
	if err != nil {
		return inflight.Result{}, mapTaskDataError(fmt.Errorf("%w: order max_fee is not a uint64 amount", taskdata.ErrRequestMalformed))
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
	result, err := s.auth.Precheck.Check(ctx, o)
	if err != nil {
		return inflight.Result{}, mapPrecheckErr(err)
	}
	if result.Binding == inflight.BoundElsewhere {
		return inflight.Result{}, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"%w: session %s is bound to Builder %s", inflight.ErrSessionBoundElsewhere, order.SessionID, result.Session.BoundBuilder))
	}
	return result, nil
}

// mapPrecheckErr maps a precheck failure: session key verdicts as the SDK codes, a state that
// could not be read Unavailable, every other code FailedPrecondition (the order cannot pass as
// sent; the code says what the SDK changes).
func mapPrecheckErr(err error) error {
	switch {
	case errors.Is(err, registeredkey.ErrKeyInvalid), errors.Is(err, registeredkey.ErrKeyExpired),
		errors.Is(err, registeredkey.ErrSpendCapExceeded), errors.Is(err, registeredkey.ErrChainUnreadable):
		return mapEnvelopeErr(sdkauth.OrderKeyErr(err))
	case errors.Is(err, inflight.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
}
