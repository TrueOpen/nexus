package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

type epochChain struct {
	length    uint64
	beacons   map[uint64]string
	current   *hubv1.CandidatePoolSnapshotViewV1
	byEpoch   map[uint64][]byte
	headers   map[string]*hubv1.CandidatePoolSnapshotViewV1
	beaconAsk []uint64
	poolAsk   int
	// currentErr, when set, fails the current candidate pool read.
	currentErr error
	// beaconEdit, when set, alters each verified proposer VRF beacon returned.
	beaconEdit func(*hubv1.BeaconState)
}

func (c *epochChain) QueryEpochLengthBlocks(context.Context) (uint64, error) { return c.length, nil }

func (c *epochChain) QueryBeacon(_ context.Context, height uint64) (*hubv1.BeaconState, error) {
	c.beaconAsk = append(c.beaconAsk, height)
	r, ok := c.beacons[height]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	b := &hubv1.BeaconState{Height: height, RandomnessHex: r, SourceTag: "proposer_vrf_v1", Verified: true}
	if c.beaconEdit != nil {
		c.beaconEdit(b)
	}
	return b, nil
}

func (c *epochChain) QueryCurrentCandidatePool(context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	c.poolAsk++
	if c.currentErr != nil {
		return nil, c.currentErr
	}
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

// The epoch seed is the raw R_h of the committed, verified beacon at the epoch's start height. An
// unverified or placeholder beacon, or one recorded for another height, is no seed: the epoch stays
// unresolved and is asked again later.
func TestChainEpochsUseOnlyTheVerifiedEpochStartBeacon(t *testing.T) {
	seed, snap := fill32(0x07), fill32(0xa7)
	for name, edit := range map[string]func(*hubv1.BeaconState){
		"unverified":           func(b *hubv1.BeaconState) { b.Verified = false },
		"placeholder":          func(b *hubv1.BeaconState) { b.SourceTag = "placeholder_blockhash_v1" },
		"another height":       func(b *hubv1.BeaconState) { b.Height++ },
		"randomness not raw32": func(b *hubv1.BeaconState) { b.RandomnessHex = b.RandomnessHex[:62] },
	} {
		t.Run(name, func(t *testing.T) {
			chain := &epochChain{
				length:     100,
				beacons:    map[uint64]string{700: hex.EncodeToString(seed[:])},
				current:    &hubv1.CandidatePoolSnapshotViewV1{Epoch: 7, SnapshotId: snap[:]},
				beaconEdit: edit,
			}
			epochs := NewChainEpochs(chain)
			now := time.Unix(1_800_000_000, 0)
			epochs.now = func() time.Time { return now }
			if ep, err := epochs.EpochOf(context.Background(), 750); err == nil {
				t.Fatalf("resolved %+v", ep)
			}
			chain.beaconEdit = nil
			now = now.Add(epochMissTTL)
			if ep, err := epochs.EpochOf(context.Background(), 750); err != nil || ep.Seed != seed {
				t.Fatalf("after the beacon verified: %+v, %v", ep, err)
			}
		})
	}
}

// An epoch whose start beacon is not usable yet is not asked about again for every parked order:
// the miss is kept for epochMissTTL, then the beacon is read again.
func TestChainEpochsKeepAMissingSeedBriefly(t *testing.T) {
	seed, snap := fill32(0x07), fill32(0xa7)
	chain := &epochChain{
		length:     100,
		beacons:    map[uint64]string{700: hex.EncodeToString(seed[:])},
		current:    &hubv1.CandidatePoolSnapshotViewV1{Epoch: 7, SnapshotId: snap[:]},
		beaconEdit: func(b *hubv1.BeaconState) { b.Verified = false },
	}
	epochs := NewChainEpochs(chain)
	now := time.Unix(1_800_000_000, 0)
	epochs.now = func() time.Time { return now }
	for _, esh := range []uint64{701, 750, 799} {
		if _, err := epochs.EpochOf(context.Background(), esh); err == nil {
			t.Fatal("an unverified beacon resolved")
		}
	}
	if len(chain.beaconAsk) != 1 {
		t.Fatalf("beacon reads = %v, want one while the miss is kept", chain.beaconAsk)
	}
	chain.beaconEdit = nil
	now = now.Add(epochMissTTL)
	if ep, err := epochs.EpochOf(context.Background(), 750); err != nil || ep.Seed != seed {
		t.Fatalf("after the miss expired: %+v, %v", ep, err)
	}
	if len(chain.beaconAsk) != 2 {
		t.Fatalf("beacon reads = %v", chain.beaconAsk)
	}
}

// An epoch that cannot dispatch yet is NEXUS_INGRESS_DISPATCH_NOT_READY, naming the height from
// which it can when that is known: epoch 0 never dispatches (epoch 1 starts at epoch_length_blocks),
// a start beacon not committed yet commits with the epoch's first block, and a published snapshot
// not effective yet takes effect at its effective_height. A chain read that fails, or the snapshot
// of a past epoch that is not known, is not "not ready".
func TestChainEpochsAnswerNotReady(t *testing.T) {
	seed7, seed8 := fill32(0x07), fill32(0x08)
	snap7, snap8 := fill32(0xa7), fill32(0xa8)
	newChain := func() *epochChain {
		return &epochChain{
			length:  100,
			beacons: map[uint64]string{700: hex.EncodeToString(seed7[:]), 800: hex.EncodeToString(seed8[:]), 500: hex.EncodeToString(seed7[:])},
			current: &hubv1.CandidatePoolSnapshotViewV1{Epoch: 7, SnapshotId: snap7[:], Status: hubv1.CandidatePoolSnapshotStatus_CANDIDATE_POOL_SNAPSHOT_STATUS_ACTIVE},
			byEpoch: map[uint64][]byte{},
			headers: map[string]*hubv1.CandidatePoolSnapshotViewV1{},
		}
	}
	notReady := func(t *testing.T, err error, height uint64) {
		t.Helper()
		var nr *NotReadyError
		if !errors.Is(err, ErrDispatchNotReady) || !errors.As(err, &nr) || nr.DispatchableHeight != height {
			t.Fatalf("err = %v, want not ready with dispatchable height %d", err, height)
		}
		if !strings.HasPrefix(err.Error(), "NEXUS_INGRESS_DISPATCH_NOT_READY") {
			t.Fatalf("message %q does not start with the status code", err.Error())
		}
		mark := fmt.Sprintf("dispatchable_height=%d", height)
		if has := strings.Contains(err.Error(), "dispatchable_height="); has != (height != 0) || (height != 0 && !strings.HasSuffix(err.Error(), mark)) {
			t.Fatalf("message %q, want it to end with %q only when the height is known", err.Error(), mark)
		}
	}
	ctx := context.Background()

	t.Run("epoch zero", func(t *testing.T) {
		_, err := NewChainEpochs(newChain()).EpochOf(ctx, 5)
		notReady(t, err, 100)
	})
	t.Run("start beacon not committed", func(t *testing.T) {
		chain := newChain()
		delete(chain.beacons, 800)
		_, err := NewChainEpochs(chain).EpochOf(ctx, 801)
		notReady(t, err, 800)
	})
	t.Run("start beacon not verified", func(t *testing.T) {
		chain := newChain()
		chain.beaconEdit = func(b *hubv1.BeaconState) { b.Verified = false }
		_, err := NewChainEpochs(chain).EpochOf(ctx, 750)
		notReady(t, err, 0)
	})
	t.Run("snapshot published, not effective", func(t *testing.T) {
		chain := newChain()
		chain.byEpoch[8] = snap8[:]
		chain.headers[string(snap8[:])] = &hubv1.CandidatePoolSnapshotViewV1{
			Epoch: 8, SnapshotId: snap8[:], Status: hubv1.CandidatePoolSnapshotStatus_CANDIDATE_POOL_SNAPSHOT_STATUS_READY, EffectiveHeight: 803,
		}
		epochs := NewChainEpochs(chain)
		now := time.Unix(1_800_000_000, 0)
		epochs.now = func() time.Time { return now }
		_, err := epochs.EpochOf(ctx, 801)
		notReady(t, err, 803)
		// Once the snapshot is effective the same epoch resolves.
		chain.headers[string(snap8[:])].Status = hubv1.CandidatePoolSnapshotStatus_CANDIDATE_POOL_SNAPSHOT_STATUS_ACTIVE
		now = now.Add(epochMissTTL)
		if ep, err := epochs.EpochOf(ctx, 801); err != nil || ep.SnapshotID != snap8 || ep.Seed != seed8 {
			t.Fatalf("after the snapshot took effect: %+v, %v", ep, err)
		}
	})
	t.Run("snapshot not published", func(t *testing.T) {
		_, err := NewChainEpochs(newChain()).EpochOf(ctx, 801)
		notReady(t, err, 0)
	})
	t.Run("no current pool yet", func(t *testing.T) {
		chain := newChain()
		chain.current = nil
		_, err := NewChainEpochs(chain).EpochOf(ctx, 801)
		notReady(t, err, 0)
	})
	t.Run("snapshot of a past epoch unknown", func(t *testing.T) {
		_, err := NewChainEpochs(newChain()).EpochOf(ctx, 550)
		if err == nil || errors.Is(err, ErrDispatchNotReady) {
			t.Fatalf("err = %v, want a failure that is not \"not ready\"", err)
		}
	})
	t.Run("chain read failed", func(t *testing.T) {
		chain := newChain()
		chain.currentErr = errors.New("node unreachable")
		_, err := NewChainEpochs(chain).EpochOf(ctx, 750)
		if err == nil || errors.Is(err, ErrDispatchNotReady) {
			t.Fatalf("err = %v, want a failure that is not \"not ready\"", err)
		}
	})
}

// An epoch whose snapshot is not effective yet is not read again for every order: like a missing
// seed, the answer is kept for epochMissTTL.
func TestChainEpochsKeepANotReadySnapshotBriefly(t *testing.T) {
	seed8 := fill32(0x08)
	chain := &epochChain{
		length:  100,
		beacons: map[uint64]string{800: hex.EncodeToString(seed8[:])},
		current: &hubv1.CandidatePoolSnapshotViewV1{Epoch: 7, SnapshotId: bytes.Repeat([]byte{0xa7}, 32)},
	}
	epochs := NewChainEpochs(chain)
	now := time.Unix(1_800_000_000, 0)
	epochs.now = func() time.Time { return now }
	for _, esh := range []uint64{801, 850, 899} {
		if _, err := epochs.EpochOf(context.Background(), esh); !errors.Is(err, ErrDispatchNotReady) {
			t.Fatalf("EpochOf(%d) = %v", esh, err)
		}
	}
	if len(chain.beaconAsk) != 1 || chain.poolAsk != 1 {
		t.Fatalf("beacon reads %v, pool reads %d; want one each while the answer is kept", chain.beaconAsk, chain.poolAsk)
	}
	now = now.Add(epochMissTTL)
	if _, err := epochs.EpochOf(context.Background(), 850); !errors.Is(err, ErrDispatchNotReady) || chain.poolAsk != 2 {
		t.Fatalf("after the answer expired: %v, pool reads %d", err, chain.poolAsk)
	}
}

// The wire derivation vector: the order's epoch, its start height and the seed taken from the
// verified start beacon, and the VRF alpha and proof over that seed.
func TestChainEpochsMatchTheWireSeedDerivation(t *testing.T) {
	file := wirefixture.Load(t, dispatchVectors)
	var vec struct {
		Source struct {
			Length       uint64 `json:"epoch_length_blocks"`
			Height       uint64 `json:"earliest_submit_height"`
			Epoch        uint64 `json:"epoch"`
			Start        uint64 `json:"epoch_start_height"`
			BeaconHeight uint64 `json:"beacon_height"`
			Verified     bool   `json:"beacon_verified"`
			Beacon       string `json:"beacon_randomness_hex"`
			Seed         string `json:"epoch_seed_hex"`
			AlphaVector  string `json:"alpha_vector"`
			Alpha        string `json:"alpha_hex"`
			Proof        string `json:"vrf_proof_hex"`
		} `json:"epoch_seed_derivation"`
		VRF struct {
			PublicKey  string `json:"public_key_hex"`
			Randomness string `json:"randomness_hex"`
		} `json:"vrf"`
	}
	if err := json.Unmarshal(file.Raw, &vec); err != nil {
		t.Fatal(err)
	}
	src := vec.Source
	if !src.Verified || src.BeaconHeight != src.Start {
		t.Fatalf("vector source is not a verified start beacon: %+v", src)
	}
	snap := fill32(0xa1)
	chain := &epochChain{
		length:  src.Length,
		beacons: map[uint64]string{src.BeaconHeight: src.Beacon},
		current: &hubv1.CandidatePoolSnapshotViewV1{Epoch: src.Epoch, SnapshotId: snap[:]},
	}
	ep, err := NewChainEpochs(chain).EpochOf(context.Background(), src.Height)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Number != src.Epoch || ep.ReferenceHeight != src.Start || hex.EncodeToString(ep.Seed[:]) != src.Seed {
		t.Fatalf("epoch %+v, want epoch %d start %d seed %s", ep, src.Epoch, src.Start, src.Seed)
	}
	alphaVector := file.Vector(t, src.AlphaVector, 0)
	var session [32]byte
	copy(session[:], alphaVector.Field(t, "session_id").Bytes(t))
	alpha, err := VRFAlpha(alphaVector.Field(t, "chain_id").UTF8, ep.Number, ep.Seed, session, alphaVector.Field(t, "order_sequence").Uint64(t))
	if err != nil || hex.EncodeToString(alpha[:]) != src.Alpha {
		t.Fatalf("alpha = %x, %v; want %s", alpha, err, src.Alpha)
	}
	pub, _ := hex.DecodeString(vec.VRF.PublicKey)
	proof, _ := hex.DecodeString(src.Proof)
	randomness, _ := hex.DecodeString(vec.VRF.Randomness)
	if err := dispatch.VerifyDispatchVRF(pub, alpha[:], proof, randomness); err != nil {
		t.Fatalf("vector proof does not verify over the derived alpha: %v", err)
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
				AvailableBond: &sharedv1.Amount{AtomicUnits: "5"},
				Profiles: []*hubv1.CandidateProfileWeightInputV1{{
					ModelId: vectorProfile.ModelID[:], ProfileVersion: vectorProfile.Version,
					ProfileSupportFresh: true, MinStakeSnapshot: &sharedv1.Amount{AtomicUnits: "1"}, InferenceCapable: true,
				}}},
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
	key   chaincli.VrfKey
	err   error
	reads int
}

func (c *vrfChain) QueryVrfKey(_ context.Context, participantType, operator string) (chaincli.VrfKey, error) {
	c.reads++
	if participantType != "BUILDER" || operator != "builder1" {
		return chaincli.VrfKey{}, errors.New("wrong domain or operator")
	}
	return c.key, c.err
}

func vrfPub(seed byte) []byte { return []byte(testKey(seed).Public().(ed25519.PublicKey)) }

func newTestChainVRFKeys(t *testing.T, chain VRFKeyChain, store kv.Store) *ChainVRFKeys {
	t.Helper()
	return NewChainVRFKeys(chain, store, vectorChainID, "builder1")
}

// The key of an epoch is the chain's active key; an older epoch keeps the key seen for it after
// the chain rotated, also across a restart.
func TestChainVRFKeysRememberTheActiveKeyOfEachEpoch(t *testing.T) {
	a, b := vrfPub(1), vrfPub(2)
	store := kv.NewMemStore()
	chain := &vrfChain{key: chaincli.VrfKey{ActivePubKey: a, ActiveFromEpoch: 3}}
	keys := newTestChainVRFKeys(t, chain, store)
	for _, epoch := range []uint64{3, 5} {
		if got, err := keys.BuilderVRFKey(context.Background(), epoch); err != nil || !bytes.Equal(got, a) {
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
	if got, err := keys.BuilderVRFKey(context.Background(), 6); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("epoch 6 = %x, %v", got, err)
	}

	restarted := newTestChainVRFKeys(t, chain, store)
	if got, err := restarted.BuilderVRFKey(context.Background(), 5); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("epoch 5 after a restart = %x, %v; want the stored key", got, err)
	}
	chain.err = chaincli.ErrNotFound
	if got, err := restarted.BuilderVRFKey(context.Background(), 6); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("stored key without a chain row = %x, %v", got, err)
	}
	if _, err := restarted.BuilderVRFKey(context.Background(), 7); !errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("unseen epoch without a chain row: err = %v", err)
	}
	chain.err = errors.New("unreachable")
	if _, err := restarted.BuilderVRFKey(context.Background(), 7); err == nil || errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("a failed read: err = %v", err)
	}
}

// A pending key is never used: its activation may be postponed, and the chain verifies proofs of
// an epoch with the key active in it. While a pending key is due the answer is not remembered, so
// the cutover is seen once it happens.
func TestChainVRFKeysNeverUseThePendingKey(t *testing.T) {
	a, b := vrfPub(1), vrfPub(2)
	chain := &vrfChain{key: chaincli.VrfKey{ActivePubKey: a, ActiveFromEpoch: 3, PendingPubKey: b, PendingFromEpoch: 6}}
	keys := newTestChainVRFKeys(t, chain, kv.NewMemStore())
	for _, epoch := range []uint64{5, 6, 9} {
		if got, err := keys.BuilderVRFKey(context.Background(), epoch); err != nil || !bytes.Equal(got, a) {
			t.Fatalf("epoch %d = %x, %v; want the active key", epoch, got, err)
		}
	}
	chain.key = chaincli.VrfKey{ActivePubKey: b, ActiveFromEpoch: 6}
	if got, err := keys.BuilderVRFKey(context.Background(), 6); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("epoch 6 after the cutover = %x, %v", got, err)
	}
	if got, err := keys.BuilderVRFKey(context.Background(), 5); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("epoch 5 = %x, %v; want the key it was seen with", got, err)
	}
}

// A remembered epoch is answered without reading the chain: every draw asks for its epoch's key.
func TestChainVRFKeysReadTheChainOncePerEpoch(t *testing.T) {
	chain := &vrfChain{key: chaincli.VrfKey{ActivePubKey: vrfPub(1), ActiveFromEpoch: 3}}
	keys := newTestChainVRFKeys(t, chain, kv.NewMemStore())
	for range 3 {
		if _, err := keys.BuilderVRFKey(context.Background(), 4); err != nil {
			t.Fatal(err)
		}
	}
	if chain.reads != 1 {
		t.Fatalf("chain read %d times for one epoch, want 1", chain.reads)
	}
}

// Only the most recent epochs are kept, in memory and in the store.
func TestChainVRFKeysForgetOldEpochs(t *testing.T) {
	store := kv.NewMemStore()
	chain := &vrfChain{key: chaincli.VrfKey{ActivePubKey: vrfPub(1), ActiveFromEpoch: 1}}
	keys := newTestChainVRFKeys(t, chain, store)
	for epoch := uint64(1); epoch <= maxRememberedEpochs+1; epoch++ {
		if _, err := keys.BuilderVRFKey(context.Background(), epoch); err != nil {
			t.Fatal(err)
		}
	}
	chain.err = chaincli.ErrNotFound
	restarted := newTestChainVRFKeys(t, chain, store)
	if _, err := restarted.BuilderVRFKey(context.Background(), 1); !errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("epoch 1 beyond the kept window: err = %v", err)
	}
	if _, err := restarted.BuilderVRFKey(context.Background(), 2); err != nil {
		t.Fatalf("epoch 2 inside the kept window: err = %v", err)
	}
}
