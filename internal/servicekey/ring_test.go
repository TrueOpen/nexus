package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

const ringOperator = "trueopen1builder"

func builderState(current signer.Signer, nonce uint64) chaincli.ServiceKeyState {
	state := activeState(ParticipantBuilder, ringOperator, current)
	state.AuthorizationNonce = nonce
	return state
}

func setBuilderState(r *fakeResolver, state chaincli.ServiceKeyState) {
	r.states = map[string]chaincli.ServiceKeyState{ParticipantBuilder + "|" + ringOperator: state}
}

// The ring signs with its first key until it read the chain, then with the local key the chain
// holds current, with that binding's nonce.
func TestRingSignsWithTheChainsCurrentLocalKey(t *testing.T) {
	first, second := testSigner(t, 1), testSigner(t, 2)
	resolver := &fakeResolver{}
	setBuilderState(resolver, builderState(second, 7))
	var switches []Key
	ring, err := NewRing(resolver, testPrefix, ringOperator, func(_, current Key) { switches = append(switches, current) }, first, second)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is signed before the chain was read: the first local key may be a retired one.
	if k := ring.Key(); k.Nonce != 0 || k.Signer == nil {
		t.Fatalf("key before a read = nonce %d", k.Nonce)
	}
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, ErrNotRefreshed) {
		t.Fatalf("Sign before a read = %v, want ErrNotRefreshed", err)
	}
	if _, err := ring.Key().Signer.SignDigest([32]byte{1}); !errors.Is(err, ErrNotRefreshed) {
		t.Fatalf("SignDigest before a read = %v, want ErrNotRefreshed", err)
	}
	if _, ok := ring.View(); ok {
		t.Fatal("a view before a read")
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := ring.Key(); k.Signer != second || k.Nonce != 7 || ring.Address() != second.Address() {
		t.Fatalf("key after a read = %s nonce %d", k.Signer.Address(), k.Nonce)
	}
	if _, err := ring.Sign([]byte("m")); err != nil {
		t.Fatalf("Sign after a read = %v", err)
	}
	if len(switches) != 0 {
		t.Fatal("the first read is no switch")
	}

	// A cutover the chain made: the other local key is current, the old one previous.
	state := builderState(first, 8)
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(second.PubKeyCompressed()), AuthorizationNonce: 7, RetiredHeight: 120}
	setBuilderState(resolver, state)
	view, err := ring.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.Current.Signer != first || view.Current.Nonce != 8 || view.Previous.Signer != second || view.Previous.Nonce != 7 || view.PreviousRetiredHeight != 120 {
		t.Fatalf("view after the cutover = %+v", view)
	}
	if len(switches) != 1 || switches[0].Signer != first {
		t.Fatalf("switches = %v", switches)
	}
}

// A pending replacement is matched against the local keys; one not held has no signer.
func TestRingMatchesThePendingReplacement(t *testing.T) {
	current, next, foreign := testSigner(t, 1), testSigner(t, 2), testSigner(t, 3)
	resolver := &fakeResolver{}
	state := builderState(current, 4)
	state.PendingRotation = &chaincli.PendingServiceKeyRotation{NextServicePubKey: hex.EncodeToString(next.PubKeyCompressed()),
		NextAuthorizationNonce: 5, RegisteredHeight: 105, EffectiveHeight: 120}
	setBuilderState(resolver, state)
	ring, err := NewRing(resolver, testPrefix, ringOperator, nil, current, next)
	if err != nil {
		t.Fatal(err)
	}
	view, err := ring.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !view.Pending() || view.Next.Signer != next || view.Next.Nonce != 5 || view.NextEffectiveHeight != 120 || view.NextRegisteredHeight != 105 {
		t.Fatalf("view = %+v", view)
	}

	if !ring.Holds(hex.EncodeToString(next.PubKeyCompressed())) || ring.Holds(hex.EncodeToString(foreign.PubKeyCompressed())) {
		t.Fatal("Holds does not follow the local keys")
	}
	state.PendingRotation.NextServicePubKey = hex.EncodeToString(foreign.PubKeyCompressed())
	setBuilderState(resolver, state)
	if view, err = ring.Refresh(context.Background()); err != nil || view.Next.Signer != nil || !view.Pending() {
		t.Fatalf("view with a foreign replacement = %+v, %v", view, err)
	}
}

// A chain whose current key is not local, or that cannot be read, fails the refresh and keeps
// the last view.
func TestRingRefreshFailuresKeepTheLastView(t *testing.T) {
	local, foreign := testSigner(t, 1), testSigner(t, 2)
	resolver := &fakeResolver{}
	setBuilderState(resolver, builderState(local, 3))
	ring, err := NewRing(resolver, testPrefix, ringOperator, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	setBuilderState(resolver, builderState(foreign, 4))
	if _, err := ring.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign current key = %v, want ErrUnavailable", err)
	}
	resolver.err = errors.New("node offline")
	if _, err := ring.Refresh(context.Background()); !errors.Is(err, ErrAuthority) {
		t.Fatalf("outage = %v, want ErrAuthority", err)
	}
	if k := ring.Key(); k.Signer != local || k.Nonce != 3 {
		t.Fatalf("key after failed reads = %s nonce %d", k.Signer.Address(), k.Nonce)
	}
}

func TestNewRingRefusesRepeatedKeys(t *testing.T) {
	key := testSigner(t, 1)
	if _, err := NewRing(&fakeResolver{}, testPrefix, ringOperator, nil, key, testSigner(t, 1)); err == nil {
		t.Fatal("a repeated key was accepted")
	}
	if _, err := NewRing(&fakeResolver{}, testPrefix, ringOperator, nil); err == nil {
		t.Fatal("a ring without keys was accepted")
	}
}

// Await reads until the chain answers: then the ring signs. A context that ends first returns the
// last error.
func TestRingAwaitWaitsForTheFirstRead(t *testing.T) {
	local := testSigner(t, 1)
	resolver := &fakeResolver{err: errors.New("node offline")}
	ring, err := NewRing(resolver, testPrefix, ringOperator, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := ring.Await(ctx, time.Millisecond); !errors.Is(err, ErrAuthority) {
		t.Fatalf("Await on an unreadable chain = %v, want ErrAuthority", err)
	}
	resolver.err = nil
	setBuilderState(resolver, builderState(local, 2))
	if err := ring.Await(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Sign([]byte("m")); err != nil || ring.Key().Nonce != 2 {
		t.Fatalf("after Await: Sign %v, nonce %d", err, ring.Key().Nonce)
	}
}

func revokedState(current signer.Signer, nonce uint64) chaincli.ServiceKeyState {
	state := builderState(current, nonce)
	state.Status = StatusRevoked
	return state
}

func revokedEvent(participant sharedv1.ParticipantType, operator string, nonce uint64) chaincli.ChainEvent {
	return chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_REVOKED",
		Typed: chaincli.ServiceKeyRevoked{ParticipantType: participant, Operator: operator, AuthorizationNonce: nonce}}
}

// expectRevoked checks that the ring refuses every signature while it names the revoked
// generation: its key and nonce stay readable for what that generation signed before.
func expectRevoked(t *testing.T, ring *Ring, local signer.Signer, nonce uint64) {
	t.Helper()
	k := ring.Key()
	if !k.Revoked || k.Nonce != nonce || !bytes.Equal(k.Signer.PubKeyCompressed(), local.PubKeyCompressed()) || ring.Address() != local.Address() {
		t.Fatalf("key while revoked = %+v", k)
	}
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Sign while revoked = %v, want ErrRevoked", err)
	}
	if _, err := k.Signer.SignDigest([32]byte{1}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("SignDigest while revoked = %v, want ErrRevoked", err)
	}
	if view, ok := ring.View(); !ok || !view.Current.Revoked || view.Current.Nonce != nonce {
		t.Fatalf("view while revoked = %+v, %v", view, ok)
	}
}

// A chain that answers with this Builder's current key REVOKED is told apart from one that does
// not answer: the ring keeps that generation in its view, signs nothing until a replacement it
// holds becomes current ACTIVE, and then signs with it without a restart.
func TestRingFollowsARevocationToTheReplacement(t *testing.T) {
	local, next := testSigner(t, 1), testSigner(t, 2)
	resolver := &fakeResolver{}
	setBuilderState(resolver, builderState(local, 3))
	var switches []Key
	ring, err := NewRing(resolver, testPrefix, ringOperator, func(_, current Key) { switches = append(switches, current) }, local, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	setBuilderState(resolver, revokedState(local, 3))
	view, err := ring.Refresh(context.Background())
	var revoked *RevokedError
	if !errors.As(err, &revoked) || !errors.Is(err, ErrRevoked) || !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAuthority) {
		t.Fatalf("revoked current key = %v, want a RevokedError", err)
	}
	if revoked.Nonce != 3 || revoked.NextEffectiveHeight != 0 || !view.Current.Revoked || view.Current.Nonce != 3 {
		t.Fatalf("revocation = %+v, view %+v", revoked, view)
	}
	expectRevoked(t, ring, local, 3)
	if len(switches) != 1 || !switches[0].Revoked || switches[0].Nonce != 3 {
		t.Fatalf("switches = %+v", switches)
	}

	// An outage while revoked changes nothing.
	resolver.err = errors.New("node offline")
	if _, err := ring.Refresh(context.Background()); !errors.Is(err, ErrAuthority) {
		t.Fatalf("outage = %v, want ErrAuthority", err)
	}
	expectRevoked(t, ring, local, 3)
	resolver.err = nil

	// The operator registers a replacement: the revocation names its activation height.
	state := revokedState(local, 3)
	state.PendingRotation = &chaincli.PendingServiceKeyRotation{NextServicePubKey: hex.EncodeToString(next.PubKeyCompressed()),
		NextAuthorizationNonce: 4, RegisteredHeight: 150, EffectiveHeight: 200}
	setBuilderState(resolver, state)
	view, err = ring.Refresh(context.Background())
	if !errors.As(err, &revoked) || revoked.NextNonce != 4 || revoked.NextEffectiveHeight != 200 || view.Next.Signer != next || !view.Pending() {
		t.Fatalf("revoked with a replacement = %v, view %+v", err, view)
	}
	expectRevoked(t, ring, local, 3)

	// At the cutover the replacement signs; the revoked generation is the previous one.
	state = builderState(next, 4)
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(local.PubKeyCompressed()), AuthorizationNonce: 3, RetiredHeight: 200}
	setBuilderState(resolver, state)
	if view, err = ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := ring.Key(); k.Revoked || k.Signer != next || k.Nonce != 4 || view.Previous.Signer != local {
		t.Fatalf("key after the cutover = %+v, view %+v", k, view)
	}
	if _, err := ring.Sign([]byte("m")); err != nil {
		t.Fatalf("Sign after the cutover = %v", err)
	}
	if len(switches) != 2 || switches[1].Revoked || switches[1].Nonce != 4 {
		t.Fatalf("switches = %+v", switches)
	}
}

// This Builder's own SERVICE_KEY_REVOKED stops signing at once, before any read: the pending
// rotation it cancelled is dropped, and a read of the revoked generation still ACTIVE (a cache or
// node that lags the event) does not bring it back. Events of other operators, of Cortex keys
// or of an older generation change nothing.
func TestRingObservesItsOwnRevocation(t *testing.T) {
	local, next := testSigner(t, 1), testSigner(t, 2)
	resolver := &fakeResolver{}
	state := builderState(local, 3)
	state.PendingRotation = &chaincli.PendingServiceKeyRotation{NextServicePubKey: hex.EncodeToString(next.PubKeyCompressed()),
		NextAuthorizationNonce: 4, RegisteredHeight: 150, EffectiveHeight: 200}
	setBuilderState(resolver, state)
	var switches []Key
	ring, err := NewRing(resolver, testPrefix, ringOperator, func(_, current Key) { switches = append(switches, current) }, local, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, ev := range []chaincli.ChainEvent{
		revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, "trueopen1other", 3),
		revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, ringOperator, 3),
		revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, ringOperator, 2),
		{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATED", Typed: chaincli.ServiceKeyRotated{Operator: ringOperator}},
	} {
		ring.ObserveEvent(ev)
		if k := ring.Key(); k.Revoked || k.Signer != local {
			t.Fatalf("event %+v revoked the ring", ev)
		}
	}

	ring.ObserveEvent(revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, ringOperator, 3))
	expectRevoked(t, ring, local, 3)
	if view, _ := ring.View(); view.Pending() || view.Next.Signer != nil {
		t.Fatalf("the revocation kept the pending rotation: %+v", view)
	}
	if len(switches) != 1 || !switches[0].Revoked {
		t.Fatalf("switches = %+v", switches)
	}
	var revoked *RevokedError
	if _, err := ring.Refresh(context.Background()); !errors.As(err, &revoked) || revoked.NextEffectiveHeight != 0 {
		t.Fatalf("stale ACTIVE read after the event = %v, want a RevokedError without replacement", err)
	}
	expectRevoked(t, ring, local, 3)
	if len(switches) != 1 {
		t.Fatalf("switches = %+v", switches)
	}
}

// A revocation without a readable nonce revokes the generation the ring signs with; one that
// arrives before the first read is applied by that read.
func TestRingRevocationWithoutNonceOrBeforeTheFirstRead(t *testing.T) {
	local := testSigner(t, 1)
	resolver := &fakeResolver{}
	setBuilderState(resolver, builderState(local, 3))
	ring, err := NewRing(resolver, testPrefix, ringOperator, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	ring.ObserveEvent(revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, ringOperator, 3))
	if _, err := ring.Sign([]byte("m")); !errors.Is(err, ErrNotRefreshed) {
		t.Fatalf("Sign before a read = %v, want ErrNotRefreshed", err)
	}
	if _, err := ring.Refresh(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("first read after the event = %v, want ErrRevoked", err)
	}
	expectRevoked(t, ring, local, 3)

	setBuilderState(resolver, builderState(local, 5))
	other, err := NewRing(resolver, testPrefix, ringOperator, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	other.ObserveEvent(revokedEvent(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, ringOperator, 0))
	expectRevoked(t, other, local, 5)
}

// Await ends on a revoked binding as on a read: the chain answered, and waiting does not bring a
// replacement sooner.
func TestRingAwaitEndsOnARevokedBinding(t *testing.T) {
	local := testSigner(t, 1)
	resolver := &fakeResolver{}
	setBuilderState(resolver, revokedState(local, 2))
	ring, err := NewRing(resolver, testPrefix, ringOperator, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Await(context.Background(), time.Hour); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Await on a revoked binding = %v, want ErrRevoked", err)
	}
	expectRevoked(t, ring, local, 2)
}
