package dispatchdraw

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
)

// ErrNoCapacity is returned to the user when no candidate can take the order. Its text is the
// ingress status code.
var ErrNoCapacity = errors.New("NEXUS_INGRESS_NO_CAPACITY")

// Profile is the (model_id, profile_version) an order runs.
type Profile struct {
	ModelID [32]byte
	Version uint32
}

// PoolSource reads a candidate pool snapshot from the chain. Both reads return the snapshot's
// frozen state, never the current one.
type PoolSource interface {
	// SnapshotMembers returns every member of the snapshot in ascending slot order.
	SnapshotMembers(ctx context.Context, snapshotID [32]byte) ([]*hubv1.CandidatePoolMemberViewV1, error)
	// SnapshotMember returns operator's frozen membership, eligibility inputs and candidate_weight
	// for profile (QueryCandidatePoolSnapshotMember with model_id and profile_version).
	SnapshotMember(ctx context.Context, snapshotID [32]byte, operator string, profile Profile) (*hubv1.CandidatePoolSnapshotMemberViewV1, error)
}

// Pool is the dispatch pool of one profile in one epoch: every snapshot member eligible for the
// profile at the reference height, in slot order, weighted by the chain's frozen candidate_weight.
// It is the domain of the draw and is shared read-only.
type Pool struct {
	Epoch   Epoch
	Profile Profile
	Members []dispatch.RosterMember
	// Digest is dispatch_pool_hash.
	Digest [32]byte

	byOperator map[string]int
}

// Member returns the pool member of operator.
func (p *Pool) Member(operator string) (dispatch.RosterMember, bool) {
	i, ok := p.byOperator[operator]
	if !ok {
		return dispatch.RosterMember{}, false
	}
	return p.Members[i], true
}

// Draw returns the full dispatch order of randomness r: the whole pool drawn without replacement,
// weighted, with at most maxAttempts rejection-sampling hashes per selection. Availability does
// not enter it.
func (p *Pool) Draw(chainID string, r [32]byte, maxAttempts uint32) ([]dispatch.RosterMember, error) {
	if len(p.Members) == 0 {
		return nil, ErrNoCapacity
	}
	weighted := make([]dispatch.WeightedMember, len(p.Members))
	bySlot := make(map[uint32]dispatch.RosterMember, len(p.Members))
	for i, m := range p.Members {
		weighted[i] = dispatch.WeightedMember{Slot: m.Slot, Weight: m.CandidateWeight}
		bySlot[m.Slot] = m
	}
	order, err := dispatch.DrawOrder(chainID, r, weighted, maxAttempts)
	if err != nil {
		return nil, fmt.Errorf("draw dispatch order: %w", err)
	}
	out := make([]dispatch.RosterMember, len(order))
	for i, slot := range order {
		out[i] = bySlot[slot]
	}
	return out, nil
}

// BuildPool reads the dispatch pool of profile at ep from the chain. A member is in the pool when
// the snapshot froze it with fresh declared support for the profile, inference capability, no
// tombstone or unbonding, a nonzero jail factor, an available bond of at least the profile's
// minimum stake, and a positive candidate_weight. Weights are taken as frozen, never computed.
func BuildPool(ctx context.Context, chainID string, src PoolSource, ep Epoch, profile Profile) (*Pool, error) {
	listed, err := src.SnapshotMembers(ctx, ep.SnapshotID)
	if err != nil {
		return nil, fmt.Errorf("read candidate pool snapshot %x: %w", ep.SnapshotID, err)
	}
	pool := &Pool{Epoch: ep, Profile: profile, byOperator: map[string]int{}}
	for i, m := range listed {
		if i > 0 && listed[i-1].GetCandidateSlot() >= m.GetCandidateSlot() {
			return nil, fmt.Errorf("candidate pool snapshot %x members are not in ascending slot order", ep.SnapshotID)
		}
		view, err := src.SnapshotMember(ctx, ep.SnapshotID, m.GetOperatorAddress(), profile)
		if err != nil {
			return nil, fmt.Errorf("read candidate pool member %s: %w", m.GetOperatorAddress(), err)
		}
		if !view.GetInPool() || view.GetSlot() != m.GetCandidateSlot() || view.GetSlotVersion() != m.GetSlotVersion() {
			return nil, fmt.Errorf("candidate pool member %s: snapshot views disagree on its slot", m.GetOperatorAddress())
		}
		eligible, err := eligibleForProfile(view)
		if err != nil {
			return nil, fmt.Errorf("candidate pool member %s: %w", m.GetOperatorAddress(), err)
		}
		if !eligible {
			continue
		}
		pool.byOperator[m.GetOperatorAddress()] = len(pool.Members)
		pool.Members = append(pool.Members, dispatch.RosterMember{
			Slot:            m.GetCandidateSlot(),
			SlotVersion:     m.GetSlotVersion(),
			OperatorAddress: m.GetOperatorAddress(),
			CandidateWeight: view.GetCandidateWeight(),
		})
	}
	pool.Digest, err = dispatch.PoolDigest(chainID, ep.SnapshotID, ep.ReferenceHeight, profile.ModelID, profile.Version, pool.Members)
	if err != nil {
		return nil, fmt.Errorf("dispatch pool digest: %w", err)
	}
	return pool, nil
}

func eligibleForProfile(view *hubv1.CandidatePoolSnapshotMemberViewV1) (bool, error) {
	in := view.GetWeightInputs()
	if in == nil || !view.GetProfileSupportFresh() || view.GetCandidateWeight() == 0 ||
		!in.GetInferenceCapable() || in.GetUnbonding() || in.GetTombstoned() || in.GetCandidateJailFactorPpm() == 0 {
		return false, nil
	}
	available, err := atomicUnits(in.GetAvailableBond())
	if err != nil {
		return false, fmt.Errorf("available bond: %w", err)
	}
	minStake, err := atomicUnits(view.GetMinStakeSnapshot())
	if err != nil {
		return false, fmt.Errorf("min stake: %w", err)
	}
	return available.Cmp(minStake) >= 0, nil
}

// atomicUnits parses a canonical unsigned decimal amount: digits only, no leading zero.
func atomicUnits(a *sharedv1.Amount) (*big.Int, error) {
	s := a.GetAtomicUnits()
	if s == "" || len(s) > 1 && s[0] == '0' {
		return nil, fmt.Errorf("amount %q is not canonical", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("amount %q is not canonical", s)
		}
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n, nil
}

// PoolCache keeps built pools per (epoch, profile); a pool never changes once its snapshot is
// active.
type PoolCache struct {
	chainID string
	src     PoolSource

	mu    sync.Mutex
	pools map[poolKey]*Pool
}

type poolKey struct {
	epoch    uint64
	snapshot [32]byte
	profile  Profile
}

// NewPoolCache builds pools from src on first use.
func NewPoolCache(chainID string, src PoolSource) *PoolCache {
	return &PoolCache{chainID: chainID, src: src, pools: map[poolKey]*Pool{}}
}

// Pool returns the dispatch pool of profile at ep.
func (c *PoolCache) Pool(ctx context.Context, ep Epoch, profile Profile) (*Pool, error) {
	key := poolKey{epoch: ep.Number, snapshot: ep.SnapshotID, profile: profile}
	c.mu.Lock()
	pool, ok := c.pools[key]
	c.mu.Unlock()
	if ok {
		return pool, nil
	}
	pool, err := BuildPool(ctx, c.chainID, c.src, ep, profile)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.pools[key]; ok {
		return prev, nil
	}
	c.pools[key] = pool
	return pool, nil
}

// DropBefore forgets the pools of epochs before epoch, once no unexpired order can reference them.
func (c *PoolCache) DropBefore(epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.pools {
		if key.epoch < epoch {
			delete(c.pools, key)
		}
	}
}
