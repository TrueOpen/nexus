package dispatchstream

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/nexus/internal/servicekey"
)

// CortexKey is the current CORTEX service key binding of one operator.
type CortexKey struct {
	PubKey             []byte // compressed secp256k1
	AuthorizationNonce uint64
}

// CortexKeys looks up the current CORTEX service key of an operator. An error wrapping
// ErrTransient means the chain could not answer; any other error means there is no usable key.
type CortexKeys interface {
	CurrentCortexKey(ctx context.Context, operator string) (CortexKey, error)
}

// ServiceKeyLookup reads the current CORTEX key from the chain through servicekey.Current. There is
// no fallback to an older key or a key the message presents.
type ServiceKeyLookup struct {
	Resolver      servicekey.Resolver
	AddressPrefix string
}

// CurrentCortexKey implements CortexKeys.
func (l ServiceKeyLookup) CurrentCortexKey(ctx context.Context, operator string) (CortexKey, error) {
	publicKey, state, err := servicekey.Current(ctx, l.Resolver, l.AddressPrefix, servicekey.ParticipantCortex, operator)
	if err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return CortexKey{}, fmt.Errorf("%w: %v", ErrTransient, err)
		}
		return CortexKey{}, err
	}
	if state.AuthorizationNonce == 0 {
		return CortexKey{}, fmt.Errorf("current CORTEX service key of %s has no authorization nonce: %w", operator, servicekey.ErrUnavailable)
	}
	return CortexKey{PubKey: publicKey, AuthorizationNonce: state.AuthorizationNonce}, nil
}
