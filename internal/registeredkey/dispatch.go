package registeredkey

import (
	"fmt"
	"math/big"
)

// PendingChange is a registered session key change that is not effective yet: a CLEAR, or a SET of
// a key with its expiry and spend cap. The Keeper keeps judging orders by the current fields until
// EffectiveHeight.
type PendingChange struct {
	Clear           bool
	Key             *[20]byte // the key a SET installs; nil for CLEAR
	ExpiryHeight    uint64
	SpendCap        string // decimal atomic units; "0" or empty is unlimited
	EffectiveHeight uint64
}

// DispatchOrder is an order signed by a session's registered key, as the dispatching Builder
// judges it before dispatch.
type DispatchOrder struct {
	User         string   // the order's user_address
	Recovered    [20]byte // the address the order signature recovers to
	AnchorHeight uint64   // the signed session_anchor_height
	MaxFee       string   // decimal atomic units
	Height       uint64   // the current height
	// Deadline is the last height the order's dispatch entry can be recorded at:
	// max(earliest_submit_height, bound_change_height) + record_deadline_blocks.
	Deadline uint64
	// InFlight is the sum of max_fee, in decimal atomic units, of this Builder's in-flight orders of
	// the session that the registered key signed: dispatched but not yet admitted by the chain.
	// Empty is zero.
	InFlight string
}

// CheckDispatchOrder is the precheck of an order the session's registered key signed, made by the
// Builder about to dispatch it. It must be at least as strict as the Keeper at record time, which
// may be as late as o.Deadline, and it cannot know which of the Builder's in-flight orders the
// Keeper admits first:
//
//   - CheckOrder's checks, with the key valid through o.Deadline (expiry >= Deadline), else
//     ErrKeyExpired;
//   - a nonzero spend cap must hold spent + InFlight + max_fee, else ErrSpendCapExceeded: the Keeper
//     adds max_fee to spent for every admitted entry, so in-flight orders count;
//   - a pending CLEAR, a lower cap or a shorter expiry is treated as already effective, so a
//     revocation takes effect at the Builder at once (a CLEAR is ErrKeyInvalid). A pending SET of
//     another key ends the current one at its effective height: the current key may sign only
//     orders whose deadline is before it. A pending key signs nothing until it is effective.
func CheckDispatchOrder(s State, o DispatchOrder) error {
	if err := CheckOrder(s, o.User, o.Recovered, o.AnchorHeight, o.MaxFee, o.Height); err != nil {
		return err
	}
	if o.Deadline > s.ExpiryHeight {
		return fmt.Errorf("%w: expiry height %d is before the record deadline %d", ErrKeyExpired, s.ExpiryHeight, o.Deadline)
	}
	inFlight, err := amount("in-flight max_fee", o.InFlight)
	if err != nil {
		return err
	}
	spent, err := amount("spent", s.Spent)
	if err != nil {
		return err
	}
	fee, _ := new(big.Int).SetString(o.MaxFee, 10) // checked by CheckOrder
	committed := new(big.Int).Add(spent, inFlight)
	if err := withinCap("spend_cap", s.SpendCap, committed, fee); err != nil {
		return err
	}
	p := s.Pending
	if p == nil {
		return nil
	}
	switch {
	case p.Clear:
		return fmt.Errorf("%w: a clear of the registered key is pending", ErrKeyInvalid)
	case p.Key == nil || *p.Key != o.Recovered:
		if p.EffectiveHeight <= o.Deadline {
			return fmt.Errorf("%w: the key is replaced at height %d, by the record deadline %d", ErrKeyInvalid, p.EffectiveHeight, o.Deadline)
		}
		return nil
	}
	if o.Deadline > p.ExpiryHeight {
		return fmt.Errorf("%w: pending expiry height %d is before the record deadline %d", ErrKeyExpired, p.ExpiryHeight, o.Deadline)
	}
	return withinCap("pending spend_cap", p.SpendCap, committed, fee)
}

// withinCap requires committed + fee to fit a nonzero cap; a zero or empty cap is unlimited.
func withinCap(field, capText string, committed, fee *big.Int) error {
	limit, err := amount(field, capText)
	if err != nil {
		return err
	}
	total := new(big.Int).Add(committed, fee)
	if total.Cmp(maxAmount) > 0 {
		return fmt.Errorf("%w: committed %s plus max_fee %s overflows", ErrSpendCapExceeded, committed, fee)
	}
	if limit.Sign() != 0 && total.Cmp(limit) > 0 {
		return fmt.Errorf("%w: committed %s plus max_fee %s exceeds the %s %s", ErrSpendCapExceeded, committed, fee, field, capText)
	}
	return nil
}
