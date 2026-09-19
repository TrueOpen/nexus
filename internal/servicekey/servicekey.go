// Package servicekey is the single entry point for looking up and verifying the current service key.
//
// Every participant registers one current service key on chain under a participant type domain; the service side uses it
// to sign requests in place of the operator private key, so the operator private key need not be online. ingress and taskdata
// each used to carry their own lookup + verification logic, and the two implementations drifted into two defects --
// "taskdata only accepts operator self-signatures" and "participant type written as WORKER" -- so this package collapses that logic into one place.
package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

// participant type is the lookup domain of the current service key (Nexus<->Cortex contract §3.2 field 5).
//
// It and sender_role are two distinct value domains and must not be mixed: sender_role (BUILDER / WORKER /
// VERIFIER) is the Task duty carried in the message, whereas one and the same Cortex Node registers its
// current service key under the CORTEX domain whether it acts as Worker or Verifier. Looking up a service key
// with "WORKER" / "VERIFIER" never finds anything.
const (
	ParticipantBuilder = "BUILDER"
	ParticipantCortex  = "CORTEX"
)

// StatusActive is the only usable status of an on-chain service key.
const StatusActive = "ACTIVE"

const compressedPubKeyLen = 33

var (
	// ErrUnavailable means it has been determined that no usable current service key exists on chain: missing, not ACTIVE,
	// domain or operator mismatch, malformed encoding, inconsistent identity, or not equal to the presented pubkey.
	ErrUnavailable = errors.New("service key unavailable")
	// ErrAuthority means no determination could be made -- the on-chain query itself failed. Callers must be fail-closed
	// and must not degrade this into "there is no service key".
	ErrAuthority = errors.New("service key authority unavailable")
)

// Resolver is the on-chain lookup port for the current service key (participant type, operator address).
type Resolver interface {
	QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error)
}

// Current looks up the operator's current service key under the participantType domain and, before returning,
// verifies: the status is ACTIVE, the lookup domain and operator are consistent, ServicePubKey is 33-byte lowercase hex,
// and the address derived from that pubkey equals state.ServiceAddress.
//
// Only the current key is queried, with no historical-key fallback: an old key becomes invalid the moment it is rotated.
func Current(
	ctx context.Context, resolver Resolver, addressPrefix, participantType, operator string,
) ([]byte, chaincli.ServiceKeyState, error) {
	if resolver == nil {
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("current %s service key: %w", participantType, ErrAuthority)
	}
	state, err := resolver.QueryCurrentServiceKey(ctx, participantType, operator)
	if err != nil {
		if errors.Is(err, chaincli.ErrNotFound) {
			return nil, chaincli.ServiceKeyState{}, fmt.Errorf("current %s service key: %w", participantType, ErrUnavailable)
		}
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("current %s service key: %w", participantType, ErrAuthority)
	}
	if state.ParticipantType != participantType || state.OperatorAddress != operator || state.Status != StatusActive {
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("inactive or mismatched %s service key: %w", participantType, ErrUnavailable)
	}
	publicKey, err := hex.DecodeString(state.ServicePubKey)
	if err != nil || len(publicKey) != compressedPubKeyLen || hex.EncodeToString(publicKey) != state.ServicePubKey {
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("malformed %s service key: %w", participantType, ErrUnavailable)
	}
	address, err := signer.AddressFromPubKey(addressPrefix, publicKey)
	if err != nil || address != state.ServiceAddress {
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("%s service identity: %w", participantType, ErrUnavailable)
	}
	return publicKey, state, nil
}

// VerifyPresented adds to Current the assertion that the presented pubkey is byte-for-byte equal to the on-chain ServicePubKey.
// If any of the three checks (service address, service pubkey, status) fails it returns an error; nothing is relaxed.
// The signature itself is verified by the caller against its own sign bytes.
func VerifyPresented(
	ctx context.Context, resolver Resolver, addressPrefix, participantType, operator string, presented []byte,
) (chaincli.ServiceKeyState, error) {
	publicKey, state, err := Current(ctx, resolver, addressPrefix, participantType, operator)
	if err != nil {
		return chaincli.ServiceKeyState{}, err
	}
	if !bytes.Equal(publicKey, presented) {
		return chaincli.ServiceKeyState{}, fmt.Errorf("presented key is not the current %s service key: %w", participantType, ErrUnavailable)
	}
	return state, nil
}
