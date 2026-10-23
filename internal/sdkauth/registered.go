package sdkauth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/registeredkey"
)

// ErrSessionKeySpendCapExceeded: an OpenTask order signed by the session's registered key would
// take the key past its spend cap.
var ErrSessionKeySpendCapExceeded = errors.New("SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED")

// SessionKeys reads the registered-key state of a session (lowercase hex session_id, no 0x) as of
// no earlier than height. registeredkey.Cache implements it.
type SessionKeys interface {
	Lookup(ctx context.Context, sessionID string, height uint64) (registeredkey.State, error)
}

// verifyRegisteredKey is the registered-key branch of step 4: a request without a grant whose
// signature recovers to an address other than signer_address. In order: the envelope's session
// exists, is not CLOSED, is owned by signer_address and has recovered as its current key, else
// SDK_AUTH_INVALID_SIGNATURE (not saying which); current_height <= the key's expiry, else
// SDK_AUTH_SESSION_GRANT_EXPIRED; the method is in the session set, else
// SDK_AUTH_SESSION_METHOD_NOT_ALLOWED.
func verifyRegisteredKey(ctx context.Context, e *Envelope, opts VerifyOpts, recovered [20]byte) error {
	if opts.SessionKeys == nil {
		return fmt.Errorf("%w: the request does not recover to signer_address", ErrInvalidSignature)
	}
	session, err := Hash32Hex("session_id", e.SessionID) // checked in checkFormat
	if err != nil {
		return err
	}
	height := opts.Height
	if height == 0 {
		if opts.Chain == nil {
			return fmt.Errorf("%w: no chain to read the current height from", ErrUnavailable)
		}
		if height, err = opts.Chain.CurrentHeight(ctx); err != nil || height == 0 {
			return fmt.Errorf("%w: current height unavailable", ErrUnavailable)
		}
	}
	state, err := opts.SessionKeys.Lookup(ctx, hex.EncodeToString(session[:]), height)
	if err != nil {
		return fmt.Errorf("%w: session state", ErrUnavailable)
	}
	switch err := registeredkey.CheckRequest(state, e.SignerAddress, recovered, height); {
	case errors.Is(err, registeredkey.ErrKeyExpired):
		return fmt.Errorf("%w: the session's registered key has expired", ErrSessionGrantExpired)
	case err != nil:
		return fmt.Errorf("%w: the request does not recover to signer_address or the session's registered key", ErrInvalidSignature)
	}
	if !opts.SessionAllowed {
		return fmt.Errorf("%w: %s must be signed by the wallet, not a session key", ErrSessionMethodNotAllowed, opts.Method)
	}
	return nil
}

// OrderPrecheck is the OpenTask precheck of a SignedOrderV2 whose signature recovers to an address
// other than the order user's: only the session's registered key may have signed it, and the
// order must fit that key's current state. A wallet order is left to the Keeper as before.
type OrderPrecheck struct {
	// Wallet is true when the order recovers to its user; nothing more is checked.
	Wallet    bool
	Recovered [20]byte
	// Height is the current height a registered-key order is judged at, read once; pass it on as
	// VerifyOpts.Height so the request envelope is judged at the same height.
	Height uint64
}

// BeginOrderPrecheck recovers the order's signer (feeDenom is the chain's business_denom) and, for
// a registered-key order, reads the current height. A signature that does not recover is
// SDK_AUTH_INVALID_SIGNATURE.
func BeginOrderPrecheck(ctx context.Context, signed *taskv1.SignedOrderV2, feeDenom string, chain Chain) (OrderPrecheck, error) {
	recovered, wallet, err := registeredkey.OrderSigner(signed, feeDenom)
	if err != nil {
		return OrderPrecheck{}, fmt.Errorf("%w: the order signature does not recover", ErrInvalidSignature)
	}
	p := OrderPrecheck{Wallet: wallet, Recovered: recovered}
	if wallet {
		return p, nil
	}
	if chain == nil {
		return OrderPrecheck{}, fmt.Errorf("%w: no chain to read the current height from", ErrUnavailable)
	}
	if p.Height, err = chain.CurrentHeight(ctx); err != nil || p.Height == 0 {
		return OrderPrecheck{}, fmt.Errorf("%w: current height unavailable", ErrUnavailable)
	}
	return p, nil
}

// Check judges a registered-key order against its session's state (sessionID lowercase hex, no
// 0x) at p.Height: the current key, owned by the order user, registered at or before the signed
// anchor height, else SDK_AUTH_INVALID_SIGNATURE; not expired, else SDK_AUTH_SESSION_GRANT_EXPIRED;
// a nonzero cap holding the committed spent amount plus max_fee, else
// SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED. The Keeper remains the final authority.
func (p OrderPrecheck) Check(ctx context.Context, keys SessionKeys, sessionID string, order *taskv1.TaskOrderV3) error {
	if p.Wallet {
		return nil
	}
	if keys == nil {
		return fmt.Errorf("%w: the order does not recover to its user", ErrInvalidSignature)
	}
	state, err := keys.Lookup(ctx, sessionID, p.Height)
	if err != nil {
		return fmt.Errorf("%w: session state", ErrUnavailable)
	}
	err = registeredkey.CheckOrder(state, order.GetUserAddress(), p.Recovered, order.GetSessionAnchorHeight(),
		order.GetMaxFee().GetAtomicUnits(), p.Height)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, registeredkey.ErrKeyExpired):
		return fmt.Errorf("%w: the session's registered key has expired", ErrSessionGrantExpired)
	case errors.Is(err, registeredkey.ErrSpendCapExceeded):
		return fmt.Errorf("%w: the order's max_fee does not fit the registered key's spend cap", ErrSessionKeySpendCapExceeded)
	case errors.Is(err, registeredkey.ErrUnavailable):
		return fmt.Errorf("%w: session state", ErrUnavailable)
	default:
		return fmt.Errorf("%w: the order recovers to neither its user nor the session's registered key", ErrInvalidSignature)
	}
}
