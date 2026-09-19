package servicekey

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

const testPrefix = "trueopen"

type fakeResolver struct {
	states map[string]chaincli.ServiceKeyState
	err    error
}

func (f *fakeResolver) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	if f.err != nil {
		return chaincli.ServiceKeyState{}, f.err
	}
	// Same gate as the real chaincli client: participantType must be constructible as a
	// hub.v1.ParticipantType enum, otherwise the request cannot be sent and what comes back is a query failure, not
	// ErrNotFound. If the fake were lax here it would test "cannot query" as "not found".
	if participantType != ParticipantCortex && participantType != ParticipantBuilder {
		return chaincli.ServiceKeyState{}, errors.New("participant type is not a hub.v1.ParticipantType value")
	}
	state, found := f.states[participantType+"|"+operator]
	if !found {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func testSigner(t *testing.T, value byte) signer.Signer {
	t.Helper()
	raw := make([]byte, 32)
	raw[31] = value
	s, err := signer.NewFromBytes(raw, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func activeState(participantType, operator string, service signer.Signer) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: participantType, OperatorAddress: operator, ServiceAddress: service.Address(),
		ServicePubKey: hex.EncodeToString(service.PubKeyCompressed()), AuthorizationNonce: 1,
		UpdatedHeight: 100, Status: StatusActive,
	}
}

func TestCurrentAcceptsActiveSelfConsistentKey(t *testing.T) {
	service := testSigner(t, 1)
	resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{
		ParticipantCortex + "|trueopen1operator": activeState(ParticipantCortex, "trueopen1operator", service),
	}}
	publicKey, state, err := Current(context.Background(), resolver, testPrefix, ParticipantCortex, "trueopen1operator")
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if hex.EncodeToString(publicKey) != state.ServicePubKey || state.ServiceAddress != service.Address() {
		t.Fatalf("unexpected state: %#v", state)
	}
}

func TestCurrentRejectsUnusableKeys(t *testing.T) {
	service := testSigner(t, 2)
	other := testSigner(t, 3)
	const operator = "trueopen1operator"

	tests := []struct {
		name     string
		state    chaincli.ServiceKeyState
		lookupAs string
	}{
		{
			name: "not ACTIVE",
			state: func() chaincli.ServiceKeyState {
				state := activeState(ParticipantCortex, operator, service)
				state.Status = "REVOKED"
				return state
			}(),
		},
		{
			name: "participant type mismatch",
			state: func() chaincli.ServiceKeyState {
				state := activeState(ParticipantCortex, operator, service)
				state.ParticipantType = ParticipantBuilder
				return state
			}(),
		},
		{
			name: "operator mismatch",
			state: func() chaincli.ServiceKeyState {
				state := activeState(ParticipantCortex, operator, service)
				state.OperatorAddress = "trueopen1other"
				return state
			}(),
		},
		{
			name: "pubkey is not lowercase 33-byte hex",
			state: func() chaincli.ServiceKeyState {
				state := activeState(ParticipantCortex, operator, service)
				state.ServicePubKey = strings.ToUpper(state.ServicePubKey)
				return state
			}(),
		},
		{
			name: "derived address differs from ServiceAddress",
			state: func() chaincli.ServiceKeyState {
				state := activeState(ParticipantCortex, operator, service)
				state.ServiceAddress = other.Address()
				return state
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{
				ParticipantCortex + "|" + operator: tt.state,
			}}
			if _, _, err := Current(context.Background(), resolver, testPrefix, ParticipantCortex, operator); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// "Not found" and "cannot query" are two different things: the former may be decided as "no usable key", the latter must report the chain lookup as unavailable.
func TestCurrentDistinguishesNotFoundFromQueryFailure(t *testing.T) {
	empty := &fakeResolver{}
	if _, _, err := Current(context.Background(), empty, testPrefix, ParticipantCortex, "trueopen1operator"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("not-found error = %v, want ErrUnavailable", err)
	}
	offline := &fakeResolver{err: errors.New("node offline")}
	if _, _, err := Current(context.Background(), offline, testPrefix, ParticipantCortex, "trueopen1operator"); !errors.Is(err, ErrAuthority) {
		t.Fatalf("outage error = %v, want ErrAuthority", err)
	}
	if _, _, err := Current(context.Background(), nil, testPrefix, ParticipantCortex, "trueopen1operator"); !errors.Is(err, ErrAuthority) {
		t.Fatalf("nil resolver error = %v, want ErrAuthority", err)
	}
}

func TestVerifyPresentedRequiresExactPubKeyMatch(t *testing.T) {
	service := testSigner(t, 4)
	other := testSigner(t, 5)
	const operator = "trueopen1operator"
	resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{
		ParticipantCortex + "|" + operator: activeState(ParticipantCortex, operator, service),
	}}
	if _, err := VerifyPresented(context.Background(), resolver, testPrefix, ParticipantCortex, operator, service.PubKeyCompressed()); err != nil {
		t.Fatalf("matching pubkey: %v", err)
	}
	if _, err := VerifyPresented(context.Background(), resolver, testPrefix, ParticipantCortex, operator, other.PubKeyCompressed()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mismatched pubkey error = %v, want ErrUnavailable", err)
	}
	// sender_role is not a lookup domain: WORKER / VERIFIER have no corresponding enum value in
	// hub.v1.ParticipantType, so the request cannot even be constructed -- that is "cannot determine" (ErrAuthority),
	// not "determined that no usable key exists" (ErrUnavailable). End-to-end evidence is in
	// internal/chaincli/servicekey_wire_test.go.
	for _, senderRole := range []string{"WORKER", "VERIFIER", "CORTEX_NODE"} {
		_, err := VerifyPresented(context.Background(), resolver, testPrefix, senderRole, operator, service.PubKeyCompressed())
		if !errors.Is(err, ErrAuthority) {
			t.Fatalf("%s domain error = %v, want ErrAuthority", senderRole, err)
		}
		if errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s domain error = %v, must not be downgraded to ErrUnavailable", senderRole, err)
		}
	}
}
