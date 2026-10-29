package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Values of the wire dispatch_v1.json pool, roster and weighted order vectors.
const (
	vectorChainID = "trueopen-phase1-vector-1"
	vectorOp1     = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8" // slot 1, weight 1
	vectorOp3     = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3" // slot 3, weight 5
	vectorOp7     = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz" // slot 7, weight 2
	vectorRefH    = 100
)

var (
	vectorSnapshot = fill32(0x66)
	vectorModel    = fill32(0x77)
	vectorTaskID   = fill32(0x33)
	vectorProfile  = Profile{ModelID: vectorModel, Version: 1}
	vectorEpoch    = Epoch{Number: 1, ReferenceHeight: vectorRefH, Seed: fill32(0x5e), SnapshotID: vectorSnapshot}
	otherModel     = fill32(0x78)
)

func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("%s is not 32 bytes", s)
	}
	copy(out[:], b)
	return out
}

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

// writeKeyFile writes key as a VRF key file with the given mode and returns its path.
func writeKeyFile(t *testing.T, dir, name string, key ed25519.PrivateKey, pass string, mode os.FileMode) string {
	t.Helper()
	armored, err := signer.EncryptEd25519KeystoreArmor(key, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, name, armored, mode)
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeRegistry maps epochs to registered Builder VRF public keys.
type fakeRegistry struct {
	keys map[uint64][]byte
	err  error
}

func (r *fakeRegistry) BuilderVRFKey(_ context.Context, epoch uint64) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	key, ok := r.keys[epoch]
	if !ok {
		return nil, fmt.Errorf("epoch %d: %w", epoch, ErrNoVRFKey)
	}
	return key, nil
}

func registryFor(epochKeys map[uint64]ed25519.PrivateKey) *fakeRegistry {
	r := &fakeRegistry{keys: map[uint64][]byte{}}
	for epoch, key := range epochKeys {
		r.keys[epoch] = key.Public().(ed25519.PublicKey)
	}
	return r
}

// fakeEpochs answers EpochOf from a fixed table keyed by earliest_submit_height.
type fakeEpochs struct {
	byHeight map[uint64]Epoch
}

func (e *fakeEpochs) EpochOf(_ context.Context, height uint64) (Epoch, error) {
	ep, ok := e.byHeight[height]
	if !ok {
		return Epoch{}, fmt.Errorf("no epoch for height %d", height)
	}
	return ep, nil
}

// poolMember is one snapshot member of a fakePoolSource and its frozen view per profile.
type poolMember struct {
	slot     uint32
	version  uint64
	operator string
	views    map[Profile]*hubv1.CandidatePoolSnapshotMemberViewV1
}

type fakePoolSource struct {
	mu          sync.Mutex
	members     []poolMember
	memberCalls int
	listCalls   int
	err         error
}

func (s *fakePoolSource) SnapshotMembers(_ context.Context, snapshotID [32]byte) ([]*hubv1.CandidatePoolMemberViewV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	if s.err != nil {
		return nil, s.err
	}
	out := make([]*hubv1.CandidatePoolMemberViewV1, 0, len(s.members))
	for _, m := range s.members {
		out = append(out, &hubv1.CandidatePoolMemberViewV1{CandidateSlot: m.slot, SlotVersion: m.version, OperatorAddress: m.operator, BindingHash: bytes.Repeat([]byte{0xbb}, 32)})
	}
	return out, nil
}

func (s *fakePoolSource) SnapshotMember(_ context.Context, snapshotID [32]byte, operator string, profile Profile) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memberCalls++
	if s.err != nil {
		return nil, s.err
	}
	for _, m := range s.members {
		if m.operator != operator {
			continue
		}
		if v, ok := m.views[profile]; ok {
			return v, nil
		}
		return eligibleView(m.slot, m.version, 1, false), nil
	}
	return &hubv1.CandidatePoolSnapshotMemberViewV1{InPool: false}, nil
}

func amount(units string) *sharedv1.Amount { return &sharedv1.Amount{AtomicUnits: units} }

// eligibleView is a member view that passes every pool condition, with the given frozen weight.
// The weight inputs deliberately do not derive that weight: the pool must take candidate_weight.
func eligibleView(slot uint32, version, weight uint64, fresh bool) *hubv1.CandidatePoolSnapshotMemberViewV1 {
	return &hubv1.CandidatePoolSnapshotMemberViewV1{
		InPool:      true,
		Slot:        slot,
		SlotVersion: version,
		BindingHash: bytes.Repeat([]byte{0xbb}, 32),
		WeightInputs: &hubv1.CandidateWeightInputsV1{
			ActiveBond:               amount("1000"),
			AvailableBond:            amount("500"),
			PerformanceScorePpm:      1_000_000,
			PerformanceMethodVersion: 1,
			CandidateJailFactorPpm:   1_000_000,
			InferenceCapable:         true,
		},
		ProfileSupportFresh: &fresh,
		MinStakeSnapshot:    amount("500"),
		CandidateWeight:     &weight,
	}
}

// vectorPoolSource is the wire pool vector: slots {1:1, 3:5, 7:2} eligible for vectorProfile.
func vectorPoolSource() *fakePoolSource {
	member := func(slot uint32, op string, weight uint64) poolMember {
		return poolMember{slot: slot, version: 1, operator: op, views: map[Profile]*hubv1.CandidatePoolSnapshotMemberViewV1{
			vectorProfile: eligibleView(slot, 1, weight, true),
		}}
	}
	return &fakePoolSource{members: []poolMember{member(1, vectorOp1, 1), member(3, vectorOp3, 5), member(7, vectorOp7, 2)}}
}

func vectorPool(t *testing.T) *Pool {
	t.Helper()
	pool, err := BuildPool(context.Background(), vectorChainID, vectorPoolSource(), vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// leaf is a handraise root leaf of operator at slot serving profiles.
func leaf(operator string, slot uint32, admitted bool, free uint32, expiry uint64, profiles ...Profile) *taskv1.HandraiseRootLeafV1 {
	h := &taskv1.StandingHandraiseV1{
		SchemaVersion: 1,
		ChainId:       vectorChainID,
		Member:        &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: vectorSnapshot[:], Slot: slot, SlotVersion: 1, OperatorAddress: operator},
		FreeSlotCount: free,
		IssuedHeight:  90,
		ExpiryHeight:  expiry,
	}
	for _, p := range profiles {
		h.Profiles = append(h.Profiles, &taskv1.DispatchProfileV1{ModelId: append([]byte(nil), p.ModelID[:]...), ProfileVersion: p.Version})
	}
	out := &taskv1.HandraiseRootLeafV1{Handraise: h, Admitted: admitted}
	if !admitted {
		out.AdmitRejectReason = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE
	}
	return out
}

func issuedRoot(leaves ...*taskv1.HandraiseRootLeafV1) *handraise.IssuedRoot {
	return &handraise.IssuedRoot{
		Root:   &taskv1.SignedHandraiseRootV1{ChainId: vectorChainID, RootHeight: 99, LeafCount: uint32(len(leaves))},
		Leaves: leaves,
		Digest: fill32(0xd1),
	}
}

// vectorRoster admits all three vector members.
func vectorRoster(t *testing.T, pool *Pool) *Roster {
	t.Helper()
	root := issuedRoot(
		leaf(vectorOp7, 7, true, 1, 200, vectorProfile),
		leaf(vectorOp1, 1, true, 2, 200, vectorProfile),
		leaf(vectorOp3, 3, true, 1, 200, vectorProfile),
	)
	roster, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, 150, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return roster
}

func slots(members []dispatch.RosterMember) []uint32 {
	out := make([]uint32, len(members))
	for i, m := range members {
		out[i] = m.Slot
	}
	return out
}
