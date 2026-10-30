package servicekey

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

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
	if k := ring.Key(); k.Signer != first || k.Nonce != 0 {
		t.Fatalf("key before a read = %v nonce %d", k.Signer.Address(), k.Nonce)
	}
	if _, err := ring.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := ring.Key(); k.Signer != second || k.Nonce != 7 || ring.Address() != second.Address() {
		t.Fatalf("key after a read = %s nonce %d", k.Signer.Address(), k.Nonce)
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
