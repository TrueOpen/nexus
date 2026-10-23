// Package registeredkey answers whether a key registered on a session may sign for it.
//
// A session owner may register one signing key on the session's on-chain StreamState
// (MsgCreateSession or MsgUpdateSessionKey). That key may then sign the session's orders and its
// closed set of User requests without a SessionGrant. The Keeper decides orders at admission;
// this package gives the Builder Ingress the same answer earlier, from chain state that may be a
// few blocks old:
//
//   - CheckRequest is the registered-key branch of request authentication: the session exists, is
//     not CLOSED, its owner is the request signer and its current key is the recovered address,
//     else ErrKeyInvalid; then current_height <= expiry, else ErrKeyExpired. The caller checks the
//     method set last.
//   - CheckOrder is the OpenTask precheck of an order the registered key signed: the request
//     checks, and the order's signed session_anchor_height must be at or after the key's
//     registration height (else ErrKeyInvalid), and a nonzero spend cap must hold the committed
//     spent amount plus the order's max_fee (else ErrSpendCapExceeded, also when the sum would
//     overflow the chain's uint64 counter). In-flight orders are not counted. Passing is no
//     admission: the Keeper remains the final authority. OrderSigner tells a registered-key order
//     from a wallet order.
//
// Requests never consume the spend cap.
package registeredkey

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

var (
	// ErrKeyInvalid: no such session, CLOSED, no registered key, another owner, another key, or
	// (orders) an anchor before the key's registration. Callers report it as an invalid signature
	// without saying which.
	ErrKeyInvalid = errors.New("registered key: not the session's registered key")
	// ErrKeyExpired: the registered key is past its expiry height.
	ErrKeyExpired = errors.New("registered key: expired")
	// ErrSpendCapExceeded: the order's max_fee would take the key past its nonzero spend cap.
	ErrSpendCapExceeded = errors.New("registered key: spend cap exceeded")
	// ErrUnavailable: chain state could not be read (or the read budget is spent); retryable,
	// never a verdict on the request.
	ErrUnavailable = errors.New("registered key: chain state unavailable")
)

// State is the part of one session's StreamState that governs its registered key.
type State struct {
	// Found is false when the chain has no such session (never created, or compacted after close).
	Found  bool
	Owner  string // canonical bech32 owner_user_address
	Closed bool
	// Key is the registered key address; nil when none is registered.
	Key          *[20]byte
	ExpiryHeight uint64 // inclusive
	SetHeight    uint64
	SpendCap     string // decimal atomic units; "0" or empty is unlimited
	Spent        string // decimal atomic units
}

// CheckRequest is the registered-key branch for a request on this session, signed by recovered
// for signer, at the current height.
func CheckRequest(s State, signer string, recovered [20]byte, height uint64) error {
	if !s.Found || s.Closed || s.Key == nil || s.Owner != signer || *s.Key != recovered {
		return ErrKeyInvalid
	}
	if height > s.ExpiryHeight {
		return fmt.Errorf("%w: expiry height %d is below the current height %d", ErrKeyExpired, s.ExpiryHeight, height)
	}
	return nil
}

// CheckOrder prechecks an order of orderUser on this session whose signature recovered to an
// address other than orderUser's: anchorHeight is its signed session_anchor_height, maxFee its
// max_fee in decimal atomic units.
func CheckOrder(s State, orderUser string, recovered [20]byte, anchorHeight uint64, maxFee string, height uint64) error {
	if err := CheckRequest(s, orderUser, recovered, height); err != nil {
		return err
	}
	if anchorHeight < s.SetHeight {
		return fmt.Errorf("%w: order anchor height %d is before the key's registration at %d", ErrKeyInvalid, anchorHeight, s.SetHeight)
	}
	limit, err := amount("spend_cap", s.SpendCap)
	if err != nil {
		return err
	}
	spent, err := amount("spent", s.Spent)
	if err != nil {
		return err
	}
	fee, ok := new(big.Int).SetString(maxFee, 10)
	if !ok || fee.Sign() < 0 {
		return fmt.Errorf("%w: order max_fee %q is not a decimal amount", ErrKeyInvalid, maxFee)
	}
	// The Keeper adds max_fee to spent with checked uint64 arithmetic even without a cap, so an
	// order that would overflow the counter is refused either way; it is reported as over the cap.
	total := new(big.Int).Add(spent, fee)
	if total.Cmp(maxAmount) > 0 {
		return fmt.Errorf("%w: spent %s plus max_fee %s overflows", ErrSpendCapExceeded, s.Spent, maxFee)
	}
	if limit.Sign() != 0 && total.Cmp(limit) > 0 {
		return fmt.Errorf("%w: spent %s plus max_fee %s exceeds the cap %s", ErrSpendCapExceeded, s.Spent, maxFee, s.SpendCap)
	}
	return nil
}

var maxAmount = new(big.Int).SetUint64(math.MaxUint64)

// OrderSigner recovers the signer of a SignedOrderV2 over the order domain digest (feeDenom is
// the chain's business_denom) and reports whether it is the order user's wallet. Any other signer
// must be the session's registered key (CheckOrder). A signature that does not recover is
// ErrKeyInvalid.
func OrderSigner(signed *taskv1.SignedOrderV2, feeDenom string) ([20]byte, bool, error) {
	var none [20]byte
	order := signed.GetOrder()
	digest, err := nodecontract.TaskOrderDigestV3(order, feeDenom, signed.GetSignatureChainId())
	if err != nil {
		return none, false, fmt.Errorf("%w: order digest: %v", ErrKeyInvalid, err)
	}
	recovered, err := eip712.Recover(digest, signed.GetUserSignature())
	if err != nil {
		return none, false, fmt.Errorf("%w: order signature: %v", ErrKeyInvalid, err)
	}
	user, err := nodecontract.CanonicalOperatorAddressBytes("user_address", order.GetUserAddress())
	if err != nil || len(user) != 20 {
		return none, false, fmt.Errorf("%w: order user_address is not a canonical address", ErrKeyInvalid)
	}
	return recovered.Address, bytes.Equal(recovered.Address[:], user), nil
}

// amount parses a chain amount; empty is zero. A malformed chain value makes the state unusable.
func amount(field, value string) (*big.Int, error) {
	if value == "" {
		return new(big.Int), nil
	}
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("%w: session %s %q is not a decimal amount", ErrUnavailable, field, value)
	}
	return n, nil
}
