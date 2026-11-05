package dispatchdraw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
)

// ErrNoCapacity is returned to the user when no candidate can take the order. Its text is the
// ingress status code.
var ErrNoCapacity = errors.New("NEXUS_INGRESS_NO_CAPACITY")

// ErrInvalidSnapshot means a candidate pool snapshot lists an in-pool member without the frozen
// weight inputs every member must carry. No pool is built from it and nothing is read from live
// state instead; orders of the epoch have no capacity, so it wraps ErrNoCapacity.
var ErrInvalidSnapshot = fmt.Errorf("%w: invalid candidate pool snapshot", ErrNoCapacity)

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
	// Listed is how many members the snapshot lists and Excluded how many of them BuildPool left
	// out, by the first pool condition each fails; they explain an empty pool or roster. Both are
	// empty in a pool not read from the chain (NewPool).
	Listed   int
	Excluded map[string]int

	byOperator map[string]int
}

// Summary describes the pool for a NO_CAPACITY answer: its profile and epoch, how many snapshot
// members it holds and why the others were left out.
func (p *Pool) Summary() string {
	s := fmt.Sprintf("pool of model %x profile %d at epoch %d: %d", p.Profile.ModelID[:], p.Profile.Version, p.Epoch.Number, len(p.Members))
	if p.Listed > 0 {
		s += fmt.Sprintf(" of %d snapshot members", p.Listed)
	} else {
		s += " members"
	}
	if len(p.Excluded) == 0 {
		return s
	}
	reasons := slices.Sorted(maps.Keys(p.Excluded))
	for i, r := range reasons {
		reasons[i] = fmt.Sprintf("%d %s", p.Excluded[r], r)
	}
	return s + " (left out: " + strings.Join(reasons, ", ") + ")"
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
		return nil, fmt.Errorf("%w: empty dispatch %s", ErrNoCapacity, p.Summary())
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
// the snapshot froze, in its weight_inputs.profiles entry for the profile, fresh declared support
// and inference capability, and froze for the member no tombstone or unbonding, a nonzero jail
// factor, an available bond of at least the entry's minimum stake, and a positive candidate_weight.
// Weights are taken as frozen, never computed: the chain derives candidate_weight from the same
// entry, the frozen member inputs and the Worker coefficients frozen on the snapshot header, never
// from current Task params. An in-pool member without weight inputs is ErrInvalidSnapshot.
func BuildPool(ctx context.Context, chainID string, src PoolSource, ep Epoch, profile Profile) (*Pool, error) {
	listed, err := src.SnapshotMembers(ctx, ep.SnapshotID)
	if err != nil {
		return nil, fmt.Errorf("read candidate pool snapshot %x: %w", ep.SnapshotID, err)
	}
	pool := &Pool{Epoch: ep, Profile: profile, Listed: len(listed), Excluded: map[string]int{}, byOperator: map[string]int{}}
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
		excluded, err := poolExclusion(view, profile)
		if err != nil {
			return nil, fmt.Errorf("candidate pool member %s: %w", m.GetOperatorAddress(), err)
		}
		if excluded != "" {
			pool.Excluded[excluded]++
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
	return pool, nil
}

// poolExclusion applies the pool conditions for one (model_id, profile_version): it names the
// first condition the member fails, empty when it is in the pool. A member the chain gave no
// candidate_weight is left out whatever its inputs show; the condition they fail, when they show
// one, is named after it.
func poolExclusion(view *hubv1.CandidatePoolSnapshotMemberViewV1, profile Profile) (string, error) {
	in := view.GetWeightInputs()
	if in == nil {
		return "", fmt.Errorf("%w: in-pool member without weight inputs", ErrInvalidSnapshot)
	}
	if view.GetCandidateWeight() == 0 {
		if failed, err := profileExclusion(view, in, profile); err == nil && failed != "" {
			return "zero candidate_weight: " + failed, nil
		}
		return "zero candidate_weight", nil
	}
	return profileExclusion(view, in, profile)
}

// profileExclusion names the first pool condition other than the weight the member fails for the
// profile, empty when it meets them all. Support, minimum stake and inference capability are facts
// of that profile, so they are read from its weight_inputs.profiles entry, matched on both
// model_id and profile_version; a member without an entry is not in the pool. The member-wide
// inference_capable is only a summary and is not read. The view's top-level copies, when present,
// must agree with the entry: a pool built from contradicting facts could differ from the chain's
// by one member, and either direction fails a challenge.
func profileExclusion(view *hubv1.CandidatePoolSnapshotMemberViewV1, in *hubv1.CandidateWeightInputsV1, profile Profile) (string, error) {
	entry, err := profileEntry(in, profile)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "no weight inputs for the profile", nil
	}
	if view.ProfileSupportFresh != nil && view.GetProfileSupportFresh() != entry.GetProfileSupportFresh() {
		return "", fmt.Errorf("profile_support_fresh disagrees with the profile entry")
	}
	minStake, err := atomicUnits(entry.GetMinStakeSnapshot())
	if err != nil {
		return "", fmt.Errorf("min stake: %w", err)
	}
	if view.MinStakeSnapshot != nil {
		top, err := atomicUnits(view.GetMinStakeSnapshot())
		if err != nil {
			return "", fmt.Errorf("min stake: %w", err)
		}
		if top.Cmp(minStake) != 0 {
			return "", fmt.Errorf("min_stake_snapshot disagrees with the profile entry")
		}
	}
	switch {
	case !entry.GetProfileSupportFresh():
		return "profile support not fresh", nil
	case !entry.GetInferenceCapable():
		return "not inference capable for the profile", nil
	case in.GetUnbonding():
		return "unbonding", nil
	case in.GetTombstoned():
		return "tombstoned", nil
	case in.GetCandidateJailFactorPpm() == 0:
		return "jailed", nil
	}
	available, err := atomicUnits(in.GetAvailableBond())
	if err != nil {
		return "", fmt.Errorf("available bond: %w", err)
	}
	if available.Cmp(minStake) < 0 {
		return "available bond below min stake", nil
	}
	return "", nil
}

// profileEntry returns the weight inputs of profile, or nil when the member has none. Two entries
// for one profile are a malformed view.
func profileEntry(in *hubv1.CandidateWeightInputsV1, profile Profile) (*hubv1.CandidateProfileWeightInputV1, error) {
	var found *hubv1.CandidateProfileWeightInputV1
	for _, e := range in.GetProfiles() {
		if e.GetProfileVersion() != profile.Version || !bytes.Equal(e.GetModelId(), profile.ModelID[:]) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("duplicate weight inputs for the profile")
		}
		found = e
	}
	return found, nil
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

// Cached returns the dispatch pool of profile at ep when it was built already, without reading the
// chain.
func (c *PoolCache) Cached(ep Epoch, profile Profile) (*Pool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pool, ok := c.pools[poolKey{epoch: ep.Number, snapshot: ep.SnapshotID, profile: profile}]
	return pool, ok
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
