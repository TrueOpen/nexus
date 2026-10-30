package dispatchstream

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

type resolverFunc func(participantType, operator string) (chaincli.ServiceKeyState, error)

func (f resolverFunc) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	return f(participantType, operator)
}

func TestServiceKeyLookupReadsTheCurrentCortexKey(t *testing.T) {
	sg := testAccount("service|" + cortexA)
	state := chaincli.ServiceKeyState{
		ParticipantType: servicekey.ParticipantCortex, OperatorAddress: cortexA, ServiceAddress: sg.Address(),
		ServicePubKey: hex.EncodeToString(sg.PubKeyCompressed()), AuthorizationNonce: 4, Status: servicekey.StatusActive,
	}
	var asked string
	lookup := ServiceKeyLookup{AddressPrefix: testPrefix, Resolver: resolverFunc(func(p, op string) (chaincli.ServiceKeyState, error) {
		asked = p
		return state, nil
	})}
	key, err := lookup.CurrentCortexKey(context.Background(), cortexA)
	if err != nil || key.AuthorizationNonce != 4 || hex.EncodeToString(key.PubKey) != state.ServicePubKey {
		t.Fatalf("key = %+v, %v", key, err)
	}
	if asked != servicekey.ParticipantCortex {
		t.Fatalf("looked up the %s domain", asked)
	}

	lookup.Resolver = resolverFunc(func(string, string) (chaincli.ServiceKeyState, error) {
		return chaincli.ServiceKeyState{}, errors.New("connection refused")
	})
	if _, err := lookup.CurrentCortexKey(context.Background(), cortexA); !errors.Is(err, ErrTransient) {
		t.Fatalf("unreadable chain = %v, want ErrTransient", err)
	}
	lookup.Resolver = resolverFunc(func(string, string) (chaincli.ServiceKeyState, error) {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	})
	if _, err := lookup.CurrentCortexKey(context.Background(), cortexA); err == nil || errors.Is(err, ErrTransient) {
		t.Fatalf("missing key = %v, want a final refusal", err)
	}
	// A revocation keeps the nonce: the binding check and the uplink compare only the nonce, so a
	// revoked current key must be refused here.
	revoked := state
	revoked.Status = "REVOKED"
	lookup.Resolver = resolverFunc(func(string, string) (chaincli.ServiceKeyState, error) { return revoked, nil })
	if _, err := lookup.CurrentCortexKey(context.Background(), cortexA); err == nil || errors.Is(err, ErrTransient) {
		t.Fatalf("revoked key = %v, want a final refusal", err)
	}
}
