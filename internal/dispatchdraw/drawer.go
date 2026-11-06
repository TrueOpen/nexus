package dispatchdraw

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
)

// Drawer computes the randomness and full-pool order of orders.
type Drawer struct {
	chainID string
	epochs  EpochSource
	keys    *VRFKeys
	pools   *PoolCache
}

// NewDrawer draws on chainID with the given chain readers and VRF keys.
func NewDrawer(chainID string, epochs EpochSource, keys *VRFKeys, pools *PoolCache) (*Drawer, error) {
	if chainID == "" || epochs == nil || keys == nil || pools == nil {
		return nil, fmt.Errorf("drawer needs the chain id, epoch source, VRF keys and pool cache")
	}
	return &Drawer{chainID: chainID, epochs: epochs, keys: keys, pools: pools}, nil
}

// EpochOf resolves the epoch of earliestSubmitHeight as Draw does; an epoch that cannot dispatch
// yet fails with a *NotReadyError.
func (d *Drawer) EpochOf(ctx context.Context, earliestSubmitHeight uint64) (Epoch, error) {
	return d.epochs.EpochOf(ctx, earliestSubmitHeight)
}

// Ready reports whether orders of ep can be dispatched with this Builder's VRF key
// (VRFKeys.Ready). While the chain holds only a pending key that a local key matches, it is a
// *NotReadyError: dispatchable from the first height of the pending key's epoch when that epoch is
// still ahead, with no known height once it has begun and the activation is not visible yet.
// Without any key the error wraps ErrNoVRFKey, without a matching local key ErrVRFKeyMismatch; any
// other error is a failed chain read.
func (d *Drawer) Ready(ctx context.Context, ep Epoch) error {
	err := d.keys.Ready(ctx, ep.Number)
	var pending *PendingVRFKeyError
	if !errors.As(err, &pending) {
		return err
	}
	notReady := &NotReadyError{Epoch: ep.Number, Reason: fmt.Sprintf(
		"this Builder's VRF key is pending and becomes active from epoch %d", pending.FromEpoch)}
	if pending.FromEpoch > ep.Number {
		start, err := d.epochs.StartHeight(ctx, pending.FromEpoch)
		if err != nil {
			return fmt.Errorf("first height of epoch %d: %w", pending.FromEpoch, err)
		}
		notReady.DispatchableHeight = start
	}
	return notReady
}

// CachedPool returns the dispatch pool of profile at ep when a draw already read it
// (PoolCache.Cached).
func (d *Drawer) CachedPool(ep Epoch, profile Profile) (*Pool, bool) {
	return d.pools.Cached(ep, profile)
}

// Draw is the randomness context and full-pool order of one order, shared by all its tickets.
type Draw struct {
	Epoch Epoch
	VRF   VRFProof
	Pool  *Pool
	// Drawn is the whole pool in draw order, before any sticky promotion.
	Drawn []dispatch.RosterMember
}

// Draw resolves the epoch of earliestSubmitHeight, proves the order's randomness and draws the
// whole dispatch pool of profile once, with at most maxAttempts hashes per selection
// (max_weighted_draw_attempts_per_selection).
func (d *Drawer) Draw(ctx context.Context, sessionID [32]byte, sequence, earliestSubmitHeight uint64, profile Profile, maxAttempts uint32) (*Draw, error) {
	ep, err := d.epochs.EpochOf(ctx, earliestSubmitHeight)
	if err != nil {
		return nil, fmt.Errorf("epoch of height %d: %w", earliestSubmitHeight, err)
	}
	proof, err := d.keys.Prove(ctx, d.chainID, ep, sessionID, sequence)
	if err != nil {
		return nil, err
	}
	pool, err := d.pools.Pool(ctx, ep, profile)
	if err != nil {
		return nil, err
	}
	drawn, err := pool.Draw(d.chainID, proof.Output, maxAttempts)
	if err != nil {
		return nil, err
	}
	return &Draw{Epoch: ep, VRF: proof, Pool: pool, Drawn: drawn}, nil
}
