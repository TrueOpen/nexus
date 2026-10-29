package dispatchstream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

const (
	standingHandraiseMessage = "task.v1.StandingHandraiseV1"
	verifierHandraiseMessage = "task.v1.VerifierHandraiseV1"
)

// handraiseKeyWarnInterval spaces the warnings about standing handraises dropped because the
// CORTEX key could not be read: during an outage every heartbeat fails the same way.
const handraiseKeyWarnInterval = time.Minute

// errUplinkRefused marks an uplink business message that failed verification. The stream goes on;
// the message is dropped.
var errUplinkRefused = errors.New("uplink message refused")

// uplinkClaims are the signer facts of one uplink business message: the fields its signature binds
// that the stream must check against the bound Cortex.
type uplinkClaims struct {
	name      string // wire message name, selects the signing projection
	msg       proto.Message
	hasChain  bool
	chainID   string
	builder   string // StandingHandraiseV1 only: the Builder the handraise is addressed to
	operator  string
	nonce     uint64
	signature []byte
}

// claimsOf maps an uplink frame to its signer facts; ok is false for a message a Cortex may not
// send.
func claimsOf(frame *nexusv1.DispatchStreamFrameV1) (uplinkClaims, bool) {
	switch m := frame.GetMessage().(type) {
	case *nexusv1.DispatchStreamFrameV1_Handraise:
		h := m.Handraise
		return uplinkClaims{standingHandraiseMessage, h, true, h.GetChainId(), h.GetBuilderAddress(),
			h.GetMember().GetOperatorAddress(), h.GetServiceAuthorizationNonce(), h.GetServiceSignature()}, true
	case *nexusv1.DispatchStreamFrameV1_Accept:
		a := m.Accept
		return uplinkClaims{"task.v1.DispatchAcceptV1", a, true, a.GetChainId(), "",
			a.GetMember().GetOperatorAddress(), a.GetServiceAuthorizationNonce(), a.GetServiceSignature()}, true
	case *nexusv1.DispatchStreamFrameV1_Reject:
		r := m.Reject
		return uplinkClaims{"task.v1.DispatchRejectV1", r, true, r.GetChainId(), "",
			r.GetMember().GetOperatorAddress(), r.GetServiceAuthorizationNonce(), r.GetServiceSignature()}, true
	case *nexusv1.DispatchStreamFrameV1_InputRequest:
		r := m.InputRequest
		return uplinkClaims{"nexus.v1.DispatchInputRequestV1", r, false, "", "",
			r.GetMember().GetOperatorAddress(), r.GetServiceAuthorizationNonce(), r.GetServiceSignature()}, true
	case *nexusv1.DispatchStreamFrameV1_VerifierHandraise:
		v := m.VerifierHandraise
		return uplinkClaims{verifierHandraiseMessage, v, true, v.GetChainId(), "",
			v.GetMember().GetOperatorAddress(), v.GetServiceAuthorizationNonce(), v.GetServiceSignature()}, true
	case *nexusv1.DispatchStreamFrameV1_VerifyResultSubmitted:
		n := m.VerifyResultSubmitted
		return uplinkClaims{"nexus.v1.VerifyResultSubmittedNoticeV1", n, false, "", "",
			n.GetOperatorAddress(), n.GetServiceAuthorizationNonce(), n.GetServiceSignature()}, true
	default:
		return uplinkClaims{}, false
	}
}

// handleUplink verifies one uplink business message and routes it. A message is verified on its
// own, whatever the binding proved: its signer must be the stream's Cortex, its chain (where it
// names one) this chain, and its service signature must verify over its wire signing digest under
// that Cortex's current CORTEX key with that key's authorization nonce.
func (h *Hub) handleUplink(ctx context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error {
	claims, ok := claimsOf(frame)
	if !ok {
		return fmt.Errorf("%w: a Cortex may not send this message kind", ErrProtocol)
	}
	from, err := h.verifyUplink(ctx, operator, claims)
	if err != nil {
		// A standing handraise is soft state the Cortex re-signs every heartbeat: one whose key
		// cannot be read now is dropped and the stream goes on. Any other message ends the stream
		// unacknowledged so the Cortex sends it again.
		if errors.Is(err, ErrTransient) && claims.name == standingHandraiseMessage {
			if suppressed, ok := h.handraiseKeyWarn.Allow(h.now()); ok {
				h.log.Warn("standing handraise dropped: CORTEX key read failed", "operator", operator, "suppressed", suppressed, "err", err)
			}
			return nil
		}
		return err
	}
	sinks := h.sinks.Load()
	var routeErr error
	dropped := false
	switch m := claims.msg.(type) {
	case *taskv1.StandingHandraiseV1:
		if dropped = sinks.Handraise == nil; !dropped {
			routeErr = sinks.Handraise.HandleStandingHandraise(ctx, from, m)
		}
	case *taskv1.DispatchAcceptV1:
		if dropped = sinks.Dispatch == nil; !dropped {
			routeErr = sinks.Dispatch.HandleDispatchAccept(ctx, from, m)
		}
	case *taskv1.DispatchRejectV1:
		if dropped = sinks.Dispatch == nil; !dropped {
			routeErr = sinks.Dispatch.HandleDispatchReject(ctx, from, m)
		}
	case *nexusv1.DispatchInputRequestV1:
		if dropped = sinks.Dispatch == nil; !dropped {
			routeErr = sinks.Dispatch.HandleDispatchInputRequest(ctx, from, m)
		}
	case *taskv1.VerifierHandraiseV1:
		if dropped = sinks.Verifier == nil; !dropped {
			routeErr = sinks.Verifier.HandleVerifierHandraise(ctx, operator, m)
		}
	case *nexusv1.VerifyResultSubmittedNoticeV1:
		if dropped = sinks.Verifier == nil; !dropped {
			routeErr = sinks.Verifier.HandleVerifyResultSubmitted(ctx, operator, m)
		}
	}
	if dropped {
		h.log.Debug("no receiver for verified cortex dispatch stream message", "operator", operator, "message", claims.name)
	}
	return routeErr
}

func (h *Hub) verifyUplink(ctx context.Context, operator string, c uplinkClaims) (Origin, error) {
	switch {
	case c.operator != operator:
		return Origin{}, fmt.Errorf("%w: %s signer is not the stream's Cortex", errUplinkRefused, c.name)
	case c.hasChain && c.chainID != h.cfg.ChainID:
		return Origin{}, fmt.Errorf("%w: %s chain_id %q is not this chain", errUplinkRefused, c.name, c.chainID)
	case c.name == standingHandraiseMessage && c.builder != h.cfg.BuilderOperator:
		return Origin{}, fmt.Errorf("%w: standing handraise is addressed to another Builder", errUplinkRefused)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(c.msg)
	if err != nil {
		return Origin{}, fmt.Errorf("%w: encode %s: %v", errUplinkRefused, c.name, err)
	}
	var digest [32]byte
	if c.name == verifierHandraiseMessage {
		err = dispatch.ValidateMessage(c.name, raw)
	} else {
		digest, err = dispatch.SigningDigest(c.name, raw)
	}
	if err != nil {
		return Origin{}, fmt.Errorf("%w: %s: %v", errUplinkRefused, c.name, err)
	}
	key, err := h.keys.CurrentCortexKey(ctx, operator)
	if err != nil {
		if errors.Is(err, ErrTransient) {
			return Origin{}, err
		}
		return Origin{}, fmt.Errorf("%w: %v", errUplinkRefused, err)
	}
	if c.nonce != key.AuthorizationNonce {
		return Origin{}, fmt.Errorf("%w: %s service_authorization_nonce %d is not the current %d",
			errUplinkRefused, c.name, c.nonce, key.AuthorizationNonce)
	}
	if c.name == verifierHandraiseMessage {
		// The wire dispatch package registers no signing projection for VerifierHandraiseV1, so its
		// signature is left to the chain, which checks it when the handraise is proposed.
		return Origin{Operator: operator, Raw: raw}, nil
	}
	if err := dispatch.VerifyDigestSignature(key.PubKey, digest[:], c.signature); err != nil {
		return Origin{}, fmt.Errorf("%w: %s service_signature: %v", errUplinkRefused, c.name, err)
	}
	return Origin{Operator: operator, Raw: raw, Digest: digest}, nil
}
