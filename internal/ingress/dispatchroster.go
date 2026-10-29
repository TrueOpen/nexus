package ingress

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

const rosterRequestName = "nexus.v1.DispatchRosterRequestV1"

// DispatchRosters serves the rosters of this Builder's recorded tasks (dispatchevidence.Rosters).
type DispatchRosters interface {
	// DispatchRoster returns the rounds and record hash of a recorded task (internal hex spelling
	// of the ids); dispatchevidence.ErrRosterNotFound when none is held.
	DispatchRoster(ctx context.Context, sessionID, taskID string) (*nexusv1.GetDispatchRosterResponse, error)
}

// WithDispatchRosters serves IngressAPI.GetDispatchRoster from rosters.
func WithDispatchRosters(rosters DispatchRosters) Option {
	return func(s *Server) { s.dispatchRosters = rosters }
}

func withDispatchRosters(rosters DispatchRosters) serviceOption {
	return func(s *service) { s.dispatchRosters = rosters }
}

// GetDispatchRoster returns every round's roster of a recorded task with the handraise root it
// binds, and the record's dispatch_record_hash. The roster holds no input or order signature, so
// any pool Cortex may read it: the request is authenticated either by a Cortex's current service
// key (DispatchRosterRequestV1, bound to this chain, this Builder and the task, unexpired) or by
// an SDK envelope of the user who ordered the task.
func (s *service) GetDispatchRoster(ctx context.Context, req *connect.Request[nexusv1.GetDispatchRosterRequest]) (*connect.Response[nexusv1.GetDispatchRosterResponse], error) {
	if s.dispatchRosters == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("dispatch rosters are not served by this Builder"))
	}
	m := req.Msg
	ids, err := parseTaskIDs(m.GetSessionId(), m.GetTaskId())
	if err != nil {
		return nil, err
	}
	switch auth := m.GetAuthentication().(type) {
	case *nexusv1.GetDispatchRosterRequest_RosterRequest:
		if err := s.checkRosterRequest(ctx, auth.RosterRequest, ids); err != nil {
			return nil, err
		}
	case *nexusv1.GetDispatchRosterRequest_RequestEnvelope:
		body, err := sdkauth.GetDispatchRosterBody(m.GetSessionId(), m.GetTaskId())
		if err != nil {
			return nil, bodyErr(err)
		}
		requester, err := s.checkTaskEnvelope(ctx, auth.RequestEnvelope, ids.wireSession, ids.wireTask, envelopeCheck{
			method: "GetDispatchRoster", body: body, sessionAllowed: true, replay: s.replay,
		})
		if err != nil {
			return nil, err
		}
		if err := s.requireTaskOwner(ctx, ids.session, ids.task, requester); err != nil {
			return nil, err
		}
	default:
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("SDK_AUTH_INVALID_SIGNATURE: roster_request or request_envelope required"))
	}
	resp, err := s.dispatchRosters.DispatchRoster(ctx, ids.session, ids.task)
	switch {
	case errors.Is(err, dispatchevidence.ErrRosterNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(resp), nil
}

// checkRosterRequest verifies a Cortex's DispatchRosterRequestV1: it names this chain, this
// Builder and the task asked for, it is signed by the requester's current CORTEX service key over
// its wire signing projection, and its expiry_height is not below the current height. The
// request reads nothing secret, so its nonce is not tracked.
func (s *service) checkRosterRequest(ctx context.Context, r *nexusv1.DispatchRosterRequestV1, ids taskIDs) error {
	if r.GetChainId() != s.auth.ChainID || r.GetBuilderOperator() != s.auth.BuilderAddress || hex.EncodeToString(r.GetTaskId()) != ids.task {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("NEXUS_INGRESS_MALFORMED: roster request is for another chain, Builder or task"))
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	digest, err := dispatch.SigningDigest(rosterRequestName, raw)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("NEXUS_INGRESS_MALFORMED: roster request: %w", err))
	}
	// The signature is checked before the height is read: a request whose signature fails costs
	// no height read (the key lookup itself reads the chain when the key is not cached).
	if err := s.verifyParticipantRoleDigest(ctx, servicekey.ParticipantCortex, r.GetRequester(), digest[:], r.GetServiceSignature()); err != nil {
		return mapRoleSignatureErr(err)
	}
	if s.auth.Chain == nil {
		return connect.NewError(connect.CodeInternal, errors.New("roster request expiry cannot be checked: no chain height"))
	}
	height, err := s.auth.Chain.CurrentHeight(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, fmt.Errorf("current height: %w", err))
	}
	if r.GetExpiryHeight() < height {
		return connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("roster request expired at height %d (current %d)", r.GetExpiryHeight(), height))
	}
	return nil
}
