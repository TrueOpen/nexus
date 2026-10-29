package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

type epochChain struct {
	length    uint64
	beacons   map[uint64]string
	current   *hubv1.CandidatePoolSnapshotViewV1
	byEpoch   map[uint64][]byte
	headers   map[string]*hubv1.CandidatePoolSnapshotViewV1
	beaconAsk []uint64
}

func (c *epochChain) QueryEpochLengthBlocks(context.Context) (uint64, error) { return c.length, nil }

func (c *epochChain) QueryBeacon(_ context.Context, height uint64) (*hubv1.BeaconState, error) {
	c.beaconAsk = append(c.beaconAsk, height)
	r, ok := c.beacons[height]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return &hubv1.BeaconState{Height: height, RandomnessHex: r}, nil
}

func (c *epochChain) QueryCurrentCandidatePool(context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	if c.current == nil {
		return nil, chaincli.ErrNotFound
	}
	return c.current, nil
}

func (c *epochChain) CandidatePoolSnapshotOfEpoch(_ context.Context, epoch uint64) ([]byte, error) {
	s, ok := c.byEpoch[epoch]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return s, nil
}

func (c *epochChain) QueryCandidatePoolSnapshot(_ context.Context, id []byte) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	h, ok := c.headers[string(id)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return h, nil
}

func TestChainEpochsResolveTheEpochOfTheOrder(t *testing.T) {
	seed7, seed6 := fill32(0x07), fill32(0x06)
	snap7, snap6 := fill32(0xa7), fill32(0xa6)
	chain := &epochChain{
		length:  100,
		beacons: map[uint64]string{700: hex.EncodeToString(seed7[:]), 600: hex.EncodeToString(seed6[:])},
		current: &hubv1.CandidatePoolSnapshotViewV1{Epoch: 7, SnapshotId: snap7[:]},
		byEpoch: map[uint64][]byte{6: snap6[:]},
		headers: map[string]*hubv1.CandidatePoolSnapshotViewV1{string(snap6[:]): {Epoch: 6, SnapshotId: snap6[:]}},
	}
	epochs := NewChainEpochs(chain)
	for esh, want := range map[uint64]Epoch{
		700: {Number: 7, ReferenceHeight: 700, Seed: seed7, SnapshotID: snap7},
		799: {Number: 7, ReferenceHeight: 700, Seed: seed7, SnapshotID: snap7},
		650: {Number: 6, ReferenceHeight: 600, Seed: seed6, SnapshotID: snap6},
	} {
		got, err := epochs.EpochOf(context.Background(), esh)
		if err != nil || got != want {
			t.Fatalf("EpochOf(%d) = %+v, %v; want %+v", esh, got, err, want)
		}
	}
	if len(chain.beaconAsk) != 2 {
		t.Fatalf("beacon reads = %v, want one per epoch", chain.beaconAsk)
	}
	if current, err := epochs.CurrentEpoch(context.Background(), 899); err != nil || current != 8 {
		t.Fatalf("current epoch = %d, %v", current, err)
	}

	for name, esh := range map[string]uint64{"no snapshot known": 550, "no beacon": 820, "epoch zero": 5} {
		if _, err := epochs.EpochOf(context.Background(), esh); err == nil {
			t.Fatalf("%s: resolved", name)
		}
	}
	chain.beacons[500] = hex.EncodeToString(seed6[:])
	chain.byEpoch[5] = snap6[:] // the header says epoch 6
	if _, err := epochs.EpochOf(context.Background(), 550); err == nil {
		t.Fatal("a snapshot of another epoch was used")
	}
	chain.beacons[900] = "ABCD"
	chain.current = &hubv1.CandidatePoolSnapshotViewV1{Epoch: 9, SnapshotId: snap7[:]}
	if _, err := epochs.EpochOf(context.Background(), 900); err == nil {
		t.Fatal("a malformed beacon was used as the seed")
	}
}

type poolPager struct {
	members []*hubv1.CandidatePoolMemberViewV1
	asked   []chaincli.CandidatePoolMemberKey
	views   map[string]*hubv1.CandidatePoolSnapshotMemberViewV1
}

func (p *poolPager) QueryCandidatePoolMembers(_ context.Context, _, token []byte) ([]*hubv1.CandidatePoolMemberViewV1, []byte, error) {
	if len(token) == 0 {
		return p.members[:1], []byte("next"), nil
	}
	return p.members[1:], nil, nil
}

func (p *poolPager) QueryCandidatePoolSnapshotMember(_ context.Context, key chaincli.CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	p.asked = append(p.asked, key)
	return p.views[key.Operator], nil
}

// The pool is built from every page of the snapshot, with each member's frozen profile weight.
func TestChainPoolsBuildTheWholePool(t *testing.T) {
	fresh := true
	weight := func(w uint64) *uint64 { return &w }
	view := func(slot uint32, w uint64) *hubv1.CandidatePoolSnapshotMemberViewV1 {
		return &hubv1.CandidatePoolSnapshotMemberViewV1{
			InPool: true, Slot: slot, SlotVersion: 1, ProfileSupportFresh: &fresh, CandidateWeight: weight(w),
			MinStakeSnapshot: &sharedv1.Amount{AtomicUnits: "1"},
			WeightInputs: &hubv1.CandidateWeightInputsV1{InferenceCapable: true, CandidateJailFactorPpm: 1,
				AvailableBond: &sharedv1.Amount{AtomicUnits: "5"}},
		}
	}
	src := &poolPager{
		members: []*hubv1.CandidatePoolMemberViewV1{
			{CandidateSlot: 1, SlotVersion: 1, OperatorAddress: vectorOp1},
			{CandidateSlot: 3, SlotVersion: 1, OperatorAddress: vectorOp3},
		},
		views: map[string]*hubv1.CandidatePoolSnapshotMemberViewV1{vectorOp1: view(1, 1), vectorOp3: view(3, 5)},
	}
	pool, err := BuildPool(context.Background(), vectorChainID, ChainPools{Chain: src}, vectorEpoch, vectorProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.Members) != 2 || pool.Members[1].CandidateWeight != 5 {
		t.Fatalf("pool = %+v", pool.Members)
	}
	if k := src.asked[0]; !bytes.Equal(k.SnapshotID, vectorSnapshot[:]) || !bytes.Equal(k.ModelID, vectorModel[:]) || k.ProfileVersion != 1 {
		t.Fatalf("member query = %+v", k)
	}
}

type vrfChain struct {
	key chaincli.VrfKey
	err error
}

func (c *vrfChain) QueryVrfKey(_ context.Context, participantType, operator string) (chaincli.VrfKey, error) {
	if participantType != "BUILDER" || operator != "builder1" {
		return chaincli.VrfKey{}, errors.New("wrong domain or operator")
	}
	return c.key, c.err
}

// The key of each epoch is the active or pending key covering it; an older epoch keeps the key
// seen for it after the chain rotated.
func TestChainVRFKeysRememberTheKeyOfEachEpoch(t *testing.T) {
	a, b := []byte(testKey(1).Public().(ed25519.PublicKey)), []byte(testKey(2).Public().(ed25519.PublicKey))
	chain := &vrfChain{key: chaincli.VrfKey{ActivePubKey: a, ActiveFromEpoch: 3, PendingPubKey: b, PendingFromEpoch: 6}}
	keys := NewChainVRFKeys(chain, "builder1")
	for epoch, want := range map[uint64][]byte{3: a, 5: a, 6: b, 9: b} {
		got, err := keys.BuilderVRFKey(context.Background(), epoch)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("epoch %d = %x, %v", epoch, got, err)
		}
	}
	if _, err := keys.BuilderVRFKey(context.Background(), 2); !errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("epoch before any key: err = %v", err)
	}

	chain.key = chaincli.VrfKey{ActivePubKey: b, ActiveFromEpoch: 6}
	if got, err := keys.BuilderVRFKey(context.Background(), 5); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("epoch 5 after rotation = %x, %v; want the key seen for it", got, err)
	}
	if _, err := keys.BuilderVRFKey(context.Background(), 4); !errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("an epoch never looked up: err = %v", err)
	}
	chain.err = chaincli.ErrNotFound
	if got, err := keys.BuilderVRFKey(context.Background(), 6); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("remembered key without a chain row = %x, %v", got, err)
	}
	chain.err = errors.New("unreachable")
	if _, err := keys.BuilderVRFKey(context.Background(), 6); err == nil || errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("a failed read: err = %v", err)
	}
}
