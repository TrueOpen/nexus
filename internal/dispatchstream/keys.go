package dispatchstream

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/nexus/internal/servicekey"
)

// CortexKey is the current CORTEX service key binding of one operator. It is always ACTIVE: a
// lookup never returns a revoked (or otherwise not ACTIVE) current key, so it carries no status.
type CortexKey struct {
	PubKey             []byte // compressed secp256k1
	AuthorizationNonce uint64
}

// CortexKeys looks up the current CORTEX service key of an operator. An error wrapping
// ErrTransient means the chain could not answer; any other error means there is no usable key,
// which includes a current key that is not ACTIVE (revoked): callers that compare only the nonce
// (a binding check, an uplink nonce) rely on that, since revocation keeps the nonce.
type CortexKeys interface {
	CurrentCortexKey(ctx context.Context, operator string) (CortexKey, error)
	// ProofOptions resolves proof keys by signed nonce for the wire dispatch proof verifier: the
	// current generation, or the previous one for an order whose earliest_submit_height (nil when
	// unknown) is below its retirement. A lookup failure wraps ErrTransient when the chain could
	// not answer.
	ProofOptions(ctx context.Context, earliestSubmitHeight *uint64) dispatch.ProofKeyOptions
}

// ServiceKeyLookup reads the current CORTEX key from the chain through servicekey.Current, which
// refuses a current key that is not ACTIVE. There is no fallback to an older key or a key the
// message presents.
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

// ProofOptions implements CortexKeys through servicekey.ProofOptions.
func (l ServiceKeyLookup) ProofOptions(ctx context.Context, earliestSubmitHeight *uint64) dispatch.ProofKeyOptions {
	opts := servicekey.ProofOptions(ctx, l.Resolver, l.AddressPrefix, earliestSubmitHeight)
	lookup := opts.LookupProofKey
	opts.LookupProofKey = func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		key, err := lookup(s)
		if errors.Is(err, servicekey.ErrAuthority) {
			err = fmt.Errorf("%w: %v", ErrTransient, err)
		}
		return key, err
	}
	return opts
}
