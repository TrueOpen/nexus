package servicekey

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

// StatusRevoked is the status of a current binding that grants no live permission; it still
// proves facts of its own generation, below its explicit revoke height when it has one.
const StatusRevoked = "REVOKED"

// ProofKeys returns the wire proof-key lookup over the chain bindings: a signed nonce selects the
// current generation (ACTIVE or REVOKED) or the one previous generation the last cutover retained;
// nonce 0, which only the nonce-free Builder sync request uses, selects the current one. An unknown
// generation fails with ErrUnavailable, a chain that cannot answer with ErrAuthority. Resolution
// grants no live permission: the wire verifiers refuse previous and explicitly revoked keys outside
// their order window and require current ACTIVE authority where live traffic needs it.
func ProofKeys(ctx context.Context, resolver Resolver, addressPrefix string) func(dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
	return func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		var participantType string
		switch s.ParticipantType {
		case dispatch.ProofParticipantBuilder:
			participantType = ParticipantBuilder
		case dispatch.ProofParticipantCortex:
			participantType = ParticipantCortex
		default:
			return dispatch.ProofKeyBinding{}, fmt.Errorf("proof participant type %d: %w", s.ParticipantType, ErrUnavailable)
		}
		return proofKey(ctx, resolver, addressPrefix, participantType, s.OperatorAddress, s.ServiceAuthorizationNonce)
	}
}

// ProofOptions are the wire ProofKeyOptions over ProofKeys. earliestSubmitHeight is the
// earliest_submit_height of the signed order (or accepted record, or the claim's frozen original
// order) the proof belongs to; ticketBoundChangeHeight the bound_change_height of the ticket a
// record, accept or reject answers, read from that verified ticket, accepted state or frozen claim,
// never from the record's own signed field. A key with a cutoff (previous, or an explicitly revoked
// current one) proves only when the larger of the two is below it; either one nil leaves only keys
// without a cutoff able to prove. Tickets and ticket-bound messages take the binding height from
// the actual ticket, handraise roots compare their own root_height.
func ProofOptions(ctx context.Context, resolver Resolver, addressPrefix string, earliestSubmitHeight, ticketBoundChangeHeight *uint64) dispatch.ProofKeyOptions {
	return dispatch.ProofKeyOptions{LookupProofKey: ProofKeys(ctx, resolver, addressPrefix),
		OrderEarliestSubmitHeight: earliestSubmitHeight, TicketBoundChangeHeight: ticketBoundChangeHeight}
}

func proofKey(ctx context.Context, resolver Resolver, addressPrefix, participantType, operator string, nonce uint64) (dispatch.ProofKeyBinding, error) {
	if resolver == nil {
		return dispatch.ProofKeyBinding{}, fmt.Errorf("%s proof key: %w", participantType, ErrAuthority)
	}
	state, err := resolver.QueryCurrentServiceKey(ctx, participantType, operator)
	if err != nil {
		if errors.Is(err, chaincli.ErrNotFound) || errors.Is(err, chaincli.ErrMalformedBinding) {
			return dispatch.ProofKeyBinding{}, fmt.Errorf("%s proof key: %w: %w", participantType, err, ErrUnavailable)
		}
		return dispatch.ProofKeyBinding{}, fmt.Errorf("%s proof key: %w", participantType, ErrAuthority)
	}
	if state.ParticipantType != participantType || state.OperatorAddress != operator {
		return dispatch.ProofKeyBinding{}, fmt.Errorf("mismatched %s binding: %w", participantType, ErrUnavailable)
	}
	if nonce == 0 || nonce == state.AuthorizationNonce {
		status := dispatch.ProofKeyActive
		switch state.Status {
		case StatusActive:
		case StatusRevoked:
			status = dispatch.ProofKeyRevoked
		default:
			return dispatch.ProofKeyBinding{}, fmt.Errorf("%s binding status %q: %w", participantType, state.Status, ErrUnavailable)
		}
		publicKey, err := decodePubKey(state.ServicePubKey)
		if err != nil || state.AuthorizationNonce == 0 || !derivesAddress(addressPrefix, publicKey, state.ServiceAddress) {
			return dispatch.ProofKeyBinding{}, fmt.Errorf("malformed %s binding: %w", participantType, ErrUnavailable)
		}
		return dispatch.ProofKeyBinding{PublicKey: publicKey, ServiceAuthorizationNonce: state.AuthorizationNonce, Status: status,
			RevokedHeight: state.RevokedHeight}, nil
	}
	if p := state.Previous; p != nil && nonce == p.AuthorizationNonce {
		publicKey, err := decodePubKey(p.ServicePubKey)
		if err != nil || p.RetiredHeight == 0 {
			return dispatch.ProofKeyBinding{}, fmt.Errorf("malformed previous %s binding: %w", participantType, ErrUnavailable)
		}
		return dispatch.ProofKeyBinding{PublicKey: publicKey, ServiceAuthorizationNonce: nonce, Status: dispatch.ProofKeyPrevious,
			PreviousRetiredHeight: p.RetiredHeight}, nil
	}
	return dispatch.ProofKeyBinding{}, fmt.Errorf("%s generation %d is neither current nor previous: %w", participantType, nonce, ErrUnavailable)
}

// derivesAddress reports whether publicKey derives the service address under the configured
// address prefix, as Current checks. The previous generation carries no service address to check.
func derivesAddress(addressPrefix string, publicKey []byte, address string) bool {
	derived, err := signer.AddressFromPubKey(addressPrefix, publicKey)
	return err == nil && derived == address
}

func decodePubKey(text string) ([]byte, error) {
	publicKey, err := hex.DecodeString(text)
	if err != nil || len(publicKey) != compressedPubKeyLen || hex.EncodeToString(publicKey) != text {
		return nil, fmt.Errorf("public key is not 33-byte lowercase hex")
	}
	return publicKey, nil
}
