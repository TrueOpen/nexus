package handraise

import (
	"bytes"
	"context"
	"fmt"

	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// ChainServiceKeys implements ServiceKeys with on-chain current service key lookups.
type ChainServiceKeys struct {
	Resolver       servicekey.Resolver
	AddressPrefix  string
	BuilderAddress string
	// Signer is this Builder's local service key; the on-chain current BUILDER key must be it.
	Signer signer.Signer
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

func (k ChainServiceKeys) CheckBuilderKey(ctx context.Context) error {
	pub, _, err := servicekey.Current(ctx, k.Resolver, k.AddressPrefix, servicekey.ParticipantBuilder, k.BuilderAddress)
	if err != nil {
		return err
	}
	if k.Signer == nil || !bytes.Equal(pub, k.Signer.PubKeyCompressed()) {
		return fmt.Errorf("on-chain BUILDER service key does not match the local signer")
	}
	return nil
}
