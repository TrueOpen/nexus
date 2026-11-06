package takeover

import (
	"context"
	"errors"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
)

func rotationRegistered(participant sharedv1.ParticipantType, operator string, effective uint64) chaincli.ChainEvent {
	return chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATION_REGISTERED", Height: 41,
		Typed: chaincli.ServiceKeyRotationRegistered{ParticipantType: participant, Operator: operator, EffectiveHeight: effective}}
}

// Once this Builder's own key rotation is registered, the takeovers whose entry no transaction
// carries yet end with their input dropped, as on a revocation: a Builder whose rotation is
// pending takes no new order. One whose entry went out stays and finishes on chain. Rotations of
// other operators or of Cortex keys end nothing.
func TestKeyRotationEndsUnsentTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.m.ObserveKeyEvent(rotationRegistered(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, other, 90))
	e.m.ObserveKeyEvent(rotationRegistered(sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, self, 90))
	if e.m.Pending() != 1 {
		t.Fatal("another operator's rotation ended a takeover")
	}
	e.m.ObserveKeyEvent(rotationRegistered(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, self, 90))
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
	if e.m.Pending() != 0 || e.stored() != 0 {
		t.Fatalf("pending %d, stored %d", e.m.Pending(), e.stored())
	}

	sent := newEnv(t)
	sent.rec.sent = map[string]bool{session: true}
	sent.submit(5)
	sent.m.KeyRotating(90)
	if sent.m.Pending() != 1 {
		t.Fatal("a takeover whose entry went out was ended")
	}
	sent.registerAt(70)
	sent.m.TakeoverRegistered(session, 5, 60)
	sent.bindHere(70)
	sent.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 70})
	sent.wantCalls("held task5", "registered task5 70", "activated task5 70", "dispatch task5")
}

// A takeover the chain already registered is not touched by the rotation.
func TestKeyRotationKeepsRegisteredTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.registerAt(70)
	e.m.TakeoverRegistered(session, 5, 60)
	e.m.KeyRotating(90)
	e.wantCalls("held task5", "registered task5 70")
	if e.m.Pending() != 1 {
		t.Fatal("a registered takeover was ended")
	}
}

// An order admitted before the rotation but submitted while it is pending is refused with
// BUILDER_KEY_ROTATING and the effective height: nothing is held or sent.
func TestSubmitWhileTheKeyRotatesIsRefused(t *testing.T) {
	e := newEnv(t)
	o, pre := takeoverOrder(5, 1)
	if _, err := e.m.Admit(context.Background(), o, pre); err != nil {
		t.Fatal(err)
	}
	e.keys.err = &handraise.RotationPendingError{NextNonce: 2, RegisteredHeight: 40, EffectiveHeight: 90}
	err := e.m.Submit(context.Background(), o)
	var rotating *inflight.BuilderKeyRotatingError
	if !errors.As(err, &rotating) || rotating.EffectiveHeight != 90 {
		t.Fatalf("Submit = %v, want BUILDER_KEY_ROTATING at 90", err)
	}
	if e.m.Pending() != 0 || e.stored() != 0 || len(e.rec.bundles) != 0 {
		t.Fatalf("pending %d, stored %d, bundles %d", e.m.Pending(), e.stored(), len(e.rec.bundles))
	}
	e.wantCalls()
}

// A takeover whose entry the chain refused SEQUENCE_NOT_NEXT holds no entry any more: while this
// Builder's rotation is pending it is not sent again once the earlier sequences are recorded, but
// ends like an unsent one.
func TestKeyRotationEndsATakeoverAheadOfItsSequence(t *testing.T) {
	e := newEnv(t)
	e.rec.sent = map[string]bool{session: true}
	e.submit(5)
	e.keys.err = &handraise.RotationPendingError{NextNonce: 2, RegisteredHeight: 40, EffectiveHeight: 90}
	e.rec.resolved = map[string]bool{session: true}
	e.m.TakeoverRefused(session, 5, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_NOT_NEXT)
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
	if len(e.rec.bundles) != 1 || e.m.Pending() != 0 || e.stored() != 0 {
		t.Fatalf("bundles %d, pending %d, stored %d", len(e.rec.bundles), e.m.Pending(), e.stored())
	}
}
