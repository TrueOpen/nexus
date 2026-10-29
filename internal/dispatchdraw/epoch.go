// Package dispatchdraw computes the deterministic Worker dispatch order of an order.
//
// The order's randomness is a Builder VRF proof over (chain, epoch, epoch seed, session, order
// sequence); the epoch is the one containing the order's signed earliest_submit_height, so
// nothing the Builder chooses enters it. The randomness draws the whole eligible pool of the
// order's profile, frozen at the epoch's start, without replacement and with the chain's frozen
// candidate weights. Availability rosters built from the latest signed handraise root only filter
// that order; session stickiness may move the previous recorded winner to the front, decided once
// from the first round's roster.
//
// The package reads the chain only through small interfaces and keeps no dispatch state: the
// dispatcher persists the order, its cursor and the rosters.
package dispatchdraw

import "context"

// Epoch is the randomness and weight context of every order whose earliest_submit_height falls
// in one epoch.
type Epoch struct {
	// Number is the ticket's vrf_epoch: the epoch containing earliest_submit_height.
	Number uint64
	// ReferenceHeight is the first height of the epoch; weights and eligibility are frozen there.
	ReferenceHeight uint64
	// Seed is epoch_seed: the verified beacon randomness at ReferenceHeight.
	Seed [32]byte
	// SnapshotID is the epoch's ACTIVE candidate pool snapshot (candidate_pool_snapshot_id).
	SnapshotID [32]byte
}

// EpochSource resolves the epoch of an order from the chain.
type EpochSource interface {
	// EpochOf returns the epoch containing an order's signed earliest_submit_height.
	EpochOf(ctx context.Context, earliestSubmitHeight uint64) (Epoch, error)
}
