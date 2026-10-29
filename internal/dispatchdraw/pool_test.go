package dispatchdraw

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// The wire weighted order vector: pool {1:1, 3:5, 7:2} drawn with its randomness gives [7, 3, 1].
func TestPoolDrawMatchesWireWeightedOrder(t *testing.T) {
	file := wirefixture.Load(t, dispatchVectors)
	var vec struct {
		Order struct {
			ChainID     string                    `json:"chain_id"`
			MaxAttempts uint32                    `json:"max_attempts"`
			Members     []dispatch.WeightedMember `json:"members"`
			Order       []uint32                  `json:"order"`
			Randomness  string                    `json:"randomness"`
		} `json:"weighted_order"`
	}
	if err := json.Unmarshal(file.Raw, &vec); err != nil {
		t.Fatal(err)
	}
	pool := vectorPool(t)
	want := []dispatch.RosterMember{
		{Slot: 1, SlotVersion: 1, OperatorAddress: vectorOp1, CandidateWeight: 1},
		{Slot: 3, SlotVersion: 1, OperatorAddress: vectorOp3, CandidateWeight: 5},
		{Slot: 7, SlotVersion: 1, OperatorAddress: vectorOp7, CandidateWeight: 2},
	}
	if !reflect.DeepEqual(pool.Members, want) {
		t.Fatalf("members = %+v", pool.Members)
	}
	weighted := make([]dispatch.WeightedMember, len(pool.Members))
	for i, m := range pool.Members {
		weighted[i] = dispatch.WeightedMember{Slot: m.Slot, Weight: m.CandidateWeight}
	}
	if vec.Order.ChainID != vectorChainID || !reflect.DeepEqual(weighted, vec.Order.Members) {
		t.Fatalf("weighted order vector is not over the pool fixture: %s %+v", vec.Order.ChainID, vec.Order.Members)
	}
	drawn, err := pool.Draw(vec.Order.ChainID, mustHex32(t, vec.Order.Randomness), vec.Order.MaxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	if got := slots(drawn); !reflect.DeepEqual(got, vec.Order.Order) {
		t.Fatalf("order = %v, want %v", got, vec.Order.Order)
	}
	if drawn[0].OperatorAddress != vectorOp7 || drawn[0].CandidateWeight != 2 {
		t.Fatalf("drawn member = %+v", drawn[0])
	}
}

// Only members meeting every pool condition at the reference height are in the pool, and their
// weight is the chain's frozen candidate_weight.
func TestPoolExcludesIneligibleMembers(t *testing.T) {
	type edit func(v *hubv1.CandidatePoolSnapshotMemberViewV1)
	no := false
	cases := map[string]edit{
		"support not fresh": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			v.ProfileSupportFresh = &no
			v.WeightInputs.Profiles[0].ProfileSupportFresh = false
		},
		"support not fresh without top-level copy": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			v.ProfileSupportFresh = nil
			v.WeightInputs.Profiles[0].ProfileSupportFresh = false
		},
		"no entry for the profile": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			v.ProfileSupportFresh, v.MinStakeSnapshot = nil, nil
			v.WeightInputs.Profiles[0].ProfileVersion++
		},
		"profile not inference capable": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			v.WeightInputs.Profiles[0].InferenceCapable = false
		},
		"available below profile stake": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			v.MinStakeSnapshot = amount("501")
			v.WeightInputs.Profiles[0].MinStakeSnapshot = amount("501")
		},
		"unbonding":               func(v *hubv1.CandidatePoolSnapshotMemberViewV1) { v.WeightInputs.Unbonding = true },
		"tombstoned":              func(v *hubv1.CandidatePoolSnapshotMemberViewV1) { v.WeightInputs.Tombstoned = true },
		"jail factor zero":        func(v *hubv1.CandidatePoolSnapshotMemberViewV1) { v.WeightInputs.CandidateJailFactorPpm = 0 },
		"available below stake":   func(v *hubv1.CandidatePoolSnapshotMemberViewV1) { v.WeightInputs.AvailableBond = amount("499") },
		"candidate weight absent": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) { v.CandidateWeight = nil },
		"candidate weight zero": func(v *hubv1.CandidatePoolSnapshotMemberViewV1) {
			zero := uint64(0)
			v.CandidateWeight = &zero
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			src := vectorPoolSource()
			change(src.members[1].views[vectorProfile])
			pool, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile)
			if err != nil {
				t.Fatal(err)
			}
			if got := slots(pool.Members); !reflect.DeepEqual(got, []uint32{1, 7}) {
				t.Fatalf("pool slots = %v, want [1 7]", got)
			}
			if _, ok := pool.Member(vectorOp3); ok {
				t.Fatal("ineligible member must not be found")
			}
		})
	}
}

// Eligibility is the matching profile entry's: the member-wide inference_capable summary neither
// grants nor withdraws it.
func TestPoolIgnoresTheMemberWideInferenceSummary(t *testing.T) {
	src := vectorPoolSource()
	src.members[1].views[vectorProfile].WeightInputs.InferenceCapable = false
	pool, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Member(vectorOp3); !ok {
		t.Fatal("a member whose profile entry is capable was left out for the member-wide summary")
	}
}

// An in-pool member without weight inputs is an invalid snapshot, not a member to skip: the pool
// is not built and the order has no capacity.
func TestPoolRefusesAnInPoolMemberWithoutWeightInputs(t *testing.T) {
	src := vectorPoolSource()
	src.members[1].views[vectorProfile].WeightInputs = nil
	_, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile)
	if !errors.Is(err, ErrInvalidSnapshot) || !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("BuildPool = %v, want ErrInvalidSnapshot and ErrNoCapacity", err)
	}
}

func TestPoolKeepsMembersAtTheStakeBoundaryAndUsesFrozenWeight(t *testing.T) {
	src := vectorPoolSource()
	view := src.members[1].views[vectorProfile]
	view.WeightInputs.AvailableBond = amount("500") // equal to min stake
	pool, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := pool.Member(vectorOp3)
	if !ok || m.CandidateWeight != 5 {
		t.Fatalf("member = %+v %v; want frozen weight 5", m, ok)
	}
}

func TestPoolIsPerProfile(t *testing.T) {
	src := vectorPoolSource()
	// Only slot 3 is eligible for the other model; slots 1 and 7 report no fresh support.
	other := Profile{ModelID: otherModel, Version: 1}
	src.members[1].views[other] = eligibleViewFor(other, 3, 1, 9, true)
	pool, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, other)
	if err != nil {
		t.Fatal(err)
	}
	if got := slots(pool.Members); !reflect.DeepEqual(got, []uint32{3}) || pool.Members[0].CandidateWeight != 9 {
		t.Fatalf("pool = %+v", pool.Members)
	}
}

func TestPoolRejectsInconsistentChainViews(t *testing.T) {
	cases := map[string]func(src *fakePoolSource){
		"slot differs":         func(src *fakePoolSource) { src.members[1].views[vectorProfile].Slot = 4 },
		"slot version differs": func(src *fakePoolSource) { src.members[1].views[vectorProfile].SlotVersion = 2 },
		"listed but not in pool": func(src *fakePoolSource) {
			src.members[1].views[vectorProfile] = &hubv1.CandidatePoolSnapshotMemberViewV1{InPool: false}
		},
		"members out of slot order": func(src *fakePoolSource) {
			src.members[0], src.members[1] = src.members[1], src.members[0]
		},
		"bad stake amount": func(src *fakePoolSource) { src.members[1].views[vectorProfile].MinStakeSnapshot = amount("01") },
		"bad profile stake amount": func(src *fakePoolSource) {
			src.members[1].views[vectorProfile].WeightInputs.Profiles[0].MinStakeSnapshot = amount("01")
		},
		"top-level support contradicts the profile entry": func(src *fakePoolSource) {
			src.members[1].views[vectorProfile].WeightInputs.Profiles[0].ProfileSupportFresh = false
		},
		"top-level min stake contradicts the profile entry": func(src *fakePoolSource) {
			src.members[1].views[vectorProfile].MinStakeSnapshot = amount("400")
		},
		"duplicate profile entries": func(src *fakePoolSource) {
			in := src.members[1].views[vectorProfile].WeightInputs
			in.Profiles = append(in.Profiles, in.Profiles[0])
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			src := vectorPoolSource()
			change(src)
			if _, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	src := vectorPoolSource()
	src.err = errors.New("chain unavailable")
	if _, err := BuildPool(context.Background(), vectorChainID, src, vectorEpoch, vectorProfile); !errors.Is(err, src.err) {
		t.Fatalf("chain error: %v", err)
	}
}

func TestPoolCacheReadsOncePerEpochAndProfile(t *testing.T) {
	src := vectorPoolSource()
	cache := NewPoolCache(vectorChainID, src)
	ctx := context.Background()
	first, err := cache.Pool(ctx, vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	again, err := cache.Pool(ctx, vectorEpoch, vectorProfile)
	if err != nil || again != first {
		t.Fatalf("cached pool differs: %v", err)
	}
	if src.listCalls != 1 || src.memberCalls != 3 {
		t.Fatalf("chain reads = %d lists, %d members; want 1, 3", src.listCalls, src.memberCalls)
	}
	if _, err := cache.Pool(ctx, vectorEpoch, Profile{ModelID: otherModel, Version: 1}); err != nil {
		t.Fatal(err)
	}
	next := vectorEpoch
	next.Number, next.ReferenceHeight, next.SnapshotID = 2, 200, fill32(0x67)
	if _, err := cache.Pool(ctx, next, vectorProfile); err != nil {
		t.Fatal(err)
	}
	if src.listCalls != 3 {
		t.Fatalf("another profile and another epoch must each read the chain: %d lists", src.listCalls)
	}

	cache.DropBefore(2)
	if _, err := cache.Pool(ctx, vectorEpoch, vectorProfile); err != nil {
		t.Fatal(err)
	}
	if src.listCalls != 4 {
		t.Fatalf("a dropped epoch must be read again: %d lists", src.listCalls)
	}
}

func TestEmptyPoolCannotBeDrawn(t *testing.T) {
	pool, err := BuildPool(context.Background(), vectorChainID, &fakePoolSource{}, vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.Members) != 0 {
		t.Fatalf("members = %v", pool.Members)
	}
	if _, err := pool.Draw(vectorChainID, fill32(1), 64); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("draw of an empty pool: %v", err)
	}
}
