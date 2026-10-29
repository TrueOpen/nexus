package handraise

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

type poolChain struct {
	current     *hubv1.CandidatePoolSnapshotViewV1
	currentErr  error
	views       map[string]*hubv1.CandidatePoolSnapshotMemberViewV1 // operator/model -> view
	keys        []chaincli.CandidatePoolMemberKey
	currentHits int
}

func (c *poolChain) QueryCurrentCandidatePool(context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	c.currentHits++
	return c.current, c.currentErr
}

func (c *poolChain) QueryCandidatePoolSnapshotMember(_ context.Context, key chaincli.CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	c.keys = append(c.keys, key)
	if !bytes.Equal(key.SnapshotID, c.current.GetSnapshotId()) {
		return nil, errors.New("asked about another snapshot")
	}
	view, ok := c.views[key.Operator+"/"+string(key.ModelID)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return view, nil
}

func eligibleInputs() *hubv1.CandidateWeightInputsV1 {
	return &hubv1.CandidateWeightInputsV1{InferenceCapable: true, CandidateJailFactorPpm: 1_000_000}
}

func TestChainPoolChecksTheCurrentSnapshot(t *testing.T) {
	fresh := true
	chain := &poolChain{
		current: &hubv1.CandidatePoolSnapshotViewV1{Epoch: 3, SnapshotId: testSnapshot},
		views: map[string]*hubv1.CandidatePoolSnapshotMemberViewV1{
			"op1/":                     {InPool: true, Slot: 4, SlotVersion: 1, WeightInputs: eligibleInputs()},
			"op1/" + string(testModel): {InPool: true, Slot: 4, SlotVersion: 1, ProfileSupportFresh: &fresh},
			"jailed/":                  {InPool: true, Slot: 5, SlotVersion: 1, WeightInputs: &hubv1.CandidateWeightInputsV1{InferenceCapable: true}},
			"noinputs/":                {InPool: true, Slot: 6, SlotVersion: 1},
			"summary/":                 {InPool: true, Slot: 7, SlotVersion: 1, WeightInputs: &hubv1.CandidateWeightInputsV1{CandidateJailFactorPpm: 1_000_000}},
		},
	}
	now := time.Unix(1_800_000_000, 0)
	pool := NewChainPool(chain)
	pool.now = func() time.Time { return now }
	member := func(op string, slot uint32, version uint64, snapshot []byte) *taskv1.CandidateMemberRefV1 {
		return &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: snapshot, Slot: slot, SlotVersion: version, OperatorAddress: op}
	}
	for name, tc := range map[string]struct {
		member *taskv1.CandidateMemberRefV1
		want   bool
	}{
		"eligible":       {member("op1", 4, 1, testSnapshot), true},
		"other snapshot": {member("op1", 4, 1, bytes.Repeat([]byte{9}, 32)), false},
		"other slot":     {member("op1", 5, 1, testSnapshot), false},
		"old version":    {member("op1", 4, 0, testSnapshot), false},
		"not a member":   {member("op2", 4, 1, testSnapshot), false},
		"jailed":         {member("jailed", 5, 1, testSnapshot), false},
		// The member-wide inference_capable is a summary; capability is decided per profile.
		"member-wide summary false": {member("summary", 7, 1, testSnapshot), true},
	} {
		got, err := pool.IsEligibleMember(context.Background(), tc.member)
		if err != nil || got != tc.want {
			t.Fatalf("%s: eligible = %v, %v", name, got, err)
		}
	}
	// An in-pool member without weight inputs is an invalid snapshot row: never eligible, and said.
	if got, err := pool.IsEligibleMember(context.Background(), member("noinputs", 6, 1, testSnapshot)); got || !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("member without weight inputs: eligible = %v, %v; want ErrInvalidSnapshot", got, err)
	}
	if fresh, err := pool.HasFreshSupport(context.Background(), "op1", testProfile()); err != nil || !fresh {
		t.Fatalf("support = %v, %v", fresh, err)
	}
	if fresh, err := pool.HasFreshSupport(context.Background(), "op2", testProfile()); err != nil || fresh {
		t.Fatalf("support without a row = %v, %v", fresh, err)
	}
	last := chain.keys[len(chain.keys)-1]
	if string(last.ModelID) != string(testModel) || last.ProfileVersion != 1 {
		t.Fatalf("support query = %+v", last)
	}

	// Views are reused while the snapshot stays current.
	queries, hits := len(chain.keys), chain.currentHits
	for i := 0; i < 3; i++ {
		_, _ = pool.IsEligibleMember(context.Background(), member("op1", 4, 1, testSnapshot))
		_, _ = pool.HasFreshSupport(context.Background(), "op1", testProfile())
	}
	if len(chain.keys) != queries || chain.currentHits != hits {
		t.Fatalf("heartbeats read the chain: %d member and %d pool reads", len(chain.keys)-queries, chain.currentHits-hits)
	}

	// A new snapshot drops the cached views and refuses handraises naming the old one.
	now = now.Add(currentPoolTTL)
	chain.current = &hubv1.CandidatePoolSnapshotViewV1{Epoch: 4, SnapshotId: bytes.Repeat([]byte{0x54}, 32)}
	if got, err := pool.IsEligibleMember(context.Background(), member("op1", 4, 1, testSnapshot)); err != nil || got {
		t.Fatalf("old snapshot after the boundary = %v, %v", got, err)
	}

	now = now.Add(currentPoolTTL)
	chain.currentErr = chaincli.ErrNotFound
	if got, err := pool.IsEligibleMember(context.Background(), member("op1", 4, 1, testSnapshot)); err != nil || got {
		t.Fatalf("no current pool = %v, %v", got, err)
	}
	now = now.Add(currentPoolTTL)
	chain.currentErr = errors.New("unreachable")
	if _, err := pool.IsEligibleMember(context.Background(), member("op1", 4, 1, testSnapshot)); err == nil {
		t.Fatal("a failed read was taken as a verdict")
	}
}
