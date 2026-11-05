package ingress

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/hash32text"
	"github.com/TrueOpen/nexus/internal/supportrelay"
)

// SupportRelay accepts Cortex model support confirmations for fee-paid relay (supportrelay.Relay).
type SupportRelay interface {
	Submit(ctx context.Context, epoch uint64, confirmation []byte) (supportrelay.Ack, error)
}

// WithSupportRelay serves IngressAPI.SubmitModelSupportConfirmation from relay.
func WithSupportRelay(relay SupportRelay) Option {
	return func(s *Server) { s.supportRelay = relay }
}

func withSupportRelay(relay SupportRelay) serviceOption {
	return func(s *service) { s.supportRelay = relay }
}

// SubmitModelSupportConfirmation queues a Cortex-signed support refresh for this Builder to batch
// into MsgBatchConfirmModelSupport. The confirmation's own service signature authenticates it; no
// SDK envelope, Task or dispatch stream is involved. A successful answer acknowledges local relay
// acceptance, or an existing chain acceptance of the same material, never an on-chain refresh;
// every refusal is an error and acknowledges nothing.
func (s *service) SubmitModelSupportConfirmation(
	ctx context.Context,
	req *connect.Request[nexusv1.SubmitModelSupportConfirmationRequest],
) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error) {
	if s.supportRelay == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("model support confirmations are not relayed by this Builder"))
	}
	ack, err := s.supportRelay.Submit(ctx, req.Msg.GetEpochIndex(), req.Msg.GetConfirmation())
	if err != nil {
		return nil, mapSupportRelayErr(err)
	}
	return connect.NewResponse(&nexusv1.SubmitModelSupportConfirmationResponse{
		RelayAccepted: true, ConfirmationSigningDigest: hash32text.Encode(ack.Digest[:]), Idempotent: ack.Idempotent,
	}), nil
}

func mapSupportRelayErr(err error) error {
	switch {
	case errors.Is(err, supportrelay.ErrMalformed):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, supportrelay.ErrInvalidSignature):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, supportrelay.ErrStale):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, supportrelay.ErrConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, supportrelay.ErrLimit):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, supportrelay.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
