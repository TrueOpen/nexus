package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const proofChainID = "trueopen-proof-1"

// rotationVectors is the part of wire's service-key rotation vectors the Builder consumes.
type rotationVectors struct {
	Schedules []struct {
		Name             string `json:"name"`
		RegisteredHeight uint64 `json:"registered_height"`
		EffectiveHeight  uint64 `json:"effective_height"`
	} `json:"schedules"`
	ProofCases []struct {
		Name                  string `json:"name"`
		EarliestSubmitHeight  uint64 `json:"earliest_submit_height"`
		PreviousRetiredHeight uint64 `json:"previous_retired_height"`
		Allowed               bool   `json:"allowed"`
	} `json:"proof_cases"`
}

// signedAccept is a DispatchAcceptV1 of operator signed by key under nonce.
func signedAccept(t *testing.T, operator string, key signer.Signer, nonce uint64) []byte {
	t.Helper()
	accept := &taskv1.DispatchAcceptV1{
		SchemaVersion: 1, ChainId: proofChainID, TaskId: bytes.Repeat([]byte{1}, 32), TaskHash: bytes.Repeat([]byte{2}, 32),
		DispatchTicketHash:        bytes.Repeat([]byte{3}, 32),
		Member:                    &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: bytes.Repeat([]byte{4}, 32), Slot: 1, SlotVersion: 1, OperatorAddress: operator},
		ServiceAuthorizationNonce: nonce,
	}
	unsigned, err := proto.MarshalOptions{Deterministic: true}.Marshal(accept)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest("task.v1.DispatchAcceptV1", unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if accept.ServiceSignature, err = key.SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(accept)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Wire's cutover vectors: a key registered in the last block of an epoch is retired at the second
// epoch start after it; material it signed proves an order only when the order's
// earliest_submit_height is below that height, while the current key proves any order.
func TestProofKeysFollowTheCutoverVectors(t *testing.T) {
	var vectors rotationVectors
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/service_key_rotation_v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	var retired uint64
	for _, s := range vectors.Schedules {
		if s.Name == "last_block" {
			if s.RegisteredHeight != 109 || s.EffectiveHeight != 120 {
				t.Fatalf("last_block schedule = %+v", s)
			}
			retired = s.EffectiveHeight
		}
	}
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	state := activeState(ParticipantCortex, operator, current)
	state.AuthorizationNonce = 5
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(previous.PubKeyCompressed()), AuthorizationNonce: 4, RetiredHeight: retired}
	resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{ParticipantCortex + "|" + operator: state}}
	oldAccept, newAccept := signedAccept(t, operator, previous, 4), signedAccept(t, operator, current, 5)
	if len(vectors.ProofCases) == 0 {
		t.Fatal("no proof cases")
	}
	for _, c := range vectors.ProofCases {
		if c.PreviousRetiredHeight != retired {
			t.Fatalf("%s: previous_retired_height %d, want %d", c.Name, c.PreviousRetiredHeight, retired)
		}
		esh := c.EarliestSubmitHeight
		err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", oldAccept, ProofOptions(context.Background(), resolver, &esh))
		if (err == nil) != c.Allowed {
			t.Fatalf("%s: previous-key accept at esh %d = %v, allowed %v", c.Name, esh, err, c.Allowed)
		}
		if err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", newAccept, ProofOptions(context.Background(), resolver, &esh)); err != nil {
			t.Fatalf("%s: current-key accept at esh %d = %v", c.Name, esh, err)
		}
	}
	// Without the order's height only the current key proves.
	if err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", oldAccept, ProofOptions(context.Background(), resolver, nil)); err == nil {
		t.Fatal("a previous-key accept proved without its order height")
	}
}

func TestProofKeysResolveGenerations(t *testing.T) {
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	state := activeState(ParticipantBuilder, operator, current)
	state.AuthorizationNonce = 5
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(previous.PubKeyCompressed()), AuthorizationNonce: 4, RetiredHeight: 120}
	resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{ParticipantBuilder + "|" + operator: state}}
	lookup := ProofKeys(context.Background(), resolver)
	at := func(nonce uint64) (dispatch.ProofKeyBinding, error) {
		return lookup(dispatch.ServiceProofSigner{ParticipantType: dispatch.ProofParticipantBuilder, OperatorAddress: operator, ServiceAuthorizationNonce: nonce})
	}
	for _, nonce := range []uint64{0, 5} {
		key, err := at(nonce)
		if err != nil || key.Status != dispatch.ProofKeyActive || key.ServiceAuthorizationNonce != 5 || !bytes.Equal(key.PublicKey, current.PubKeyCompressed()) {
			t.Fatalf("nonce %d = %+v, %v", nonce, key, err)
		}
	}
	if key, err := at(4); err != nil || key.Status != dispatch.ProofKeyPrevious || key.PreviousRetiredHeight != 120 || !bytes.Equal(key.PublicKey, previous.PubKeyCompressed()) {
		t.Fatalf("previous = %+v, %v", key, err)
	}
	if _, err := at(3); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown generation = %v, want ErrUnavailable", err)
	}
	// The current key must derive the binding's service address.
	forged := state
	forged.ServiceAddress = previous.Address()
	resolver.states[ParticipantBuilder+"|"+operator] = forged
	if _, err := at(5); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("current key of another service address = %v, want ErrUnavailable", err)
	}
	state.Status = StatusRevoked
	resolver.states[ParticipantBuilder+"|"+operator] = state
	if key, err := at(5); err != nil || key.Status != dispatch.ProofKeyRevoked {
		t.Fatalf("revoked current = %+v, %v", key, err)
	}
	resolver.err = errors.New("node offline")
	if _, err := at(5); !errors.Is(err, ErrAuthority) {
		t.Fatalf("outage = %v, want ErrAuthority", err)
	}
	// A binding the chain answers malformed stays so: it is unavailable, not an outage to retry.
	resolver.err = fmt.Errorf("query current service key: %w", chaincli.ErrMalformedBinding)
	if _, err := at(5); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed binding = %v, want ErrUnavailable", err)
	}
	if _, _, err := Current(context.Background(), resolver, testPrefix, ParticipantBuilder, operator); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Current of a malformed binding = %v, want ErrUnavailable", err)
	}
}
