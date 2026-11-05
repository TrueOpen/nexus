package handraise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

// currentPoolTTL is how long ChainPool reuses the current candidate pool pointer. The pointer
// moves once per epoch. A handraise naming another snapshot than the cached one reads the pointer
// again at once, so one naming the new snapshot is not refused after the boundary; one naming the
// old snapshot is accepted for at most this long after the boundary and refused once the pointer
// is read again.
const currentPoolTTL = 2 * time.Second

// PoolQuerier is the chain reads ChainPool makes.
type PoolQuerier interface {
	QueryCurrentCandidatePool(ctx context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error)
	QueryCandidatePoolSnapshotMember(ctx context.Context, key chaincli.CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error)
}

// ChainPool implements CandidatePool on the chain's current candidate pool snapshot. A handraise
// must name the current snapshot; membership, eligibility inputs and per-profile support are the
// snapshot's frozen views, so they are cached for as long as the snapshot stays current. Every
// heartbeat then costs no chain read.
type ChainPool struct {
	chain PoolQuerier
	now   func() time.Time

	mu        sync.Mutex
	current   []byte
	currentAt time.Time
	views     map[memberViewKey]*hubv1.CandidatePoolSnapshotMemberViewV1
}

type memberViewKey struct {
	operator string
	model    string
	version  uint32
}

// NewChainPool reads the candidate pool through chain.
func NewChainPool(chain PoolQuerier) *ChainPool {
	return &ChainPool{chain: chain, now: time.Now, views: map[memberViewKey]*hubv1.CandidatePoolSnapshotMemberViewV1{}}
}

// IsEligibleMember implements CandidatePool: member names the current snapshot, the snapshot
// holds the operator at that slot and slot version with its frozen weight inputs, and those do not
// exclude it from dispatch (unbonding, tombstoned, jail factor zero). A member without weight
// inputs is an invalid snapshot row: not eligible, with ErrInvalidSnapshot so the refusal says
// why. Inference capability is a per-profile fact
// the dispatch pool decides; the member-wide inference_capable summary is not read. No current
// pool is not eligible.
func (p *ChainPool) IsEligibleMember(ctx context.Context, member *taskv1.CandidateMemberRefV1) (bool, error) {
	snapshot, err := p.currentSnapshot(ctx, member.GetCandidatePoolSnapshotId())
	if errors.Is(err, chaincli.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(snapshot, member.GetCandidatePoolSnapshotId()) {
		return false, nil
	}
	view, err := p.memberView(ctx, snapshot, member.GetOperatorAddress(), nil, 0)
	if err != nil || view == nil {
		return false, err
	}
	if !view.GetInPool() || view.GetSlot() != member.GetSlot() || view.GetSlotVersion() != member.GetSlotVersion() {
		return false, nil
	}
	in := view.GetWeightInputs()
	if in == nil {
		return false, fmt.Errorf("%w: in-pool member %s without weight inputs", ErrInvalidSnapshot, member.GetOperatorAddress())
	}
	if in.GetUnbonding() || in.GetTombstoned() || in.GetCandidateJailFactorPpm() == 0 {
		return false, nil
	}
	return true, nil
}

// HasFreshSupport implements CandidatePool with the current snapshot's frozen support of profile.
// It names no snapshot of its own: the registry asks it after IsEligibleMember, which has already
// read the pointer again for a handraise naming another snapshot.
func (p *ChainPool) HasFreshSupport(ctx context.Context, operator string, profile *taskv1.DispatchProfileV1) (bool, error) {
	snapshot, err := p.currentSnapshot(ctx, nil)
	if errors.Is(err, chaincli.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	view, err := p.memberView(ctx, snapshot, operator, profile.GetModelId(), profile.GetProfileVersion())
	if err != nil || view == nil {
		return false, err
	}
	return view.GetInPool() && view.GetProfileSupportFresh(), nil
}

// currentSnapshot returns the current pool's snapshot id, read again after currentPoolTTL or, when
// want is set and is not the cached id, at once. A new snapshot drops every cached member view.
func (p *ChainPool) currentSnapshot(ctx context.Context, want []byte) ([]byte, error) {
	p.mu.Lock()
	if p.current != nil && p.now().Sub(p.currentAt) < currentPoolTTL && (want == nil || bytes.Equal(p.current, want)) {
		snapshot := p.current
		p.mu.Unlock()
		return snapshot, nil
	}
	p.mu.Unlock()
	view, err := p.chain.QueryCurrentCandidatePool(ctx)
	if err != nil {
		return nil, fmt.Errorf("read current candidate pool: %w", err)
	}
	snapshot := bytes.Clone(view.GetSnapshotId())
	p.mu.Lock()
	defer p.mu.Unlock()
	if !bytes.Equal(p.current, snapshot) {
		p.views = map[memberViewKey]*hubv1.CandidatePoolSnapshotMemberViewV1{}
	}
	p.current, p.currentAt = snapshot, p.now()
	return snapshot, nil
}

// memberView reads operator's frozen view in snapshot, for profile when model is set; nil when the
// chain has no row for it.
func (p *ChainPool) memberView(ctx context.Context, snapshot []byte, operator string, model []byte, version uint32) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	key := memberViewKey{operator: operator, model: string(model), version: version}
	p.mu.Lock()
	view, ok := p.views[key]
	p.mu.Unlock()
	if ok {
		return view, nil
	}
	view, err := p.chain.QueryCandidatePoolSnapshotMember(ctx, chaincli.CandidatePoolMemberKey{
		SnapshotID: snapshot, Operator: operator, ModelID: model, ProfileVersion: version,
	})
	if errors.Is(err, chaincli.ErrNotFound) {
		view, err = nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read candidate pool member %s: %w", operator, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if bytes.Equal(p.current, snapshot) {
		p.views[key] = view
	}
	return view, nil
}
