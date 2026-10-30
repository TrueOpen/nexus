package handraise

import (
	"context"
	"fmt"

	"github.com/TrueOpen/nexus/internal/servicekey"
)

// ChainServiceKeys implements ServiceKeys with on-chain current service key lookups.
type ChainServiceKeys struct {
	Resolver      servicekey.Resolver
	AddressPrefix string
	// Ring holds this Builder's local service keys; the on-chain current BUILDER key must be one
	// of them.
	Ring *servicekey.Ring
}

func (k ChainServiceKeys) CurrentCortexKey(ctx context.Context, operator string) ([]byte, uint64, error) {
	pub, state, err := servicekey.Current(ctx, k.Resolver, k.AddressPrefix, servicekey.ParticipantCortex, operator)
	if err != nil {
		return nil, 0, err
	}
	if state.AuthorizationNonce == 0 {
		return nil, 0, fmt.Errorf("CORTEX service binding has no authorization nonce: %w", servicekey.ErrUnavailable)
	}
	return pub, state.AuthorizationNonce, nil
}

// CortexRotationPending reports whether operator registered a CORTEX service key replacement that
// has not activated yet. Its current key still verifies the messages it owes, but it may take no
// new Worker duty: the chain refuses a dispatch entry whose winner is pending.
func (k ChainServiceKeys) CortexRotationPending(ctx context.Context, operator string) (bool, error) {
	_, state, err := servicekey.Current(ctx, k.Resolver, k.AddressPrefix, servicekey.ParticipantCortex, operator)
	if err != nil {
		return false, err
	}
	return state.PendingRotation != nil, nil
}

func (k ChainServiceKeys) CheckBuilderKey(ctx context.Context) error {
	if k.Ring == nil {
		return fmt.Errorf("no local BUILDER service key: %w", servicekey.ErrUnavailable)
	}
	view, err := k.Ring.Refresh(ctx)
	if err != nil {
		return err
	}
	if view.Pending() {
		return fmt.Errorf("%w: nonce %d effective at height %d", ErrBuilderRotationPending, view.Next.Nonce, view.NextEffectiveHeight)
	}
	return nil
}
