package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// maxRememberedEpochs bounds the epochs the chain adapters remember: orders of older epochs are
// past every record deadline.
const maxRememberedEpochs = 64

// EpochChain is the chain reads ChainEpochs makes.
type EpochChain interface {
	QueryEpochLengthBlocks(ctx context.Context) (uint64, error)
	QueryBeacon(ctx context.Context, height uint64) (*hubv1.BeaconState, error)
	QueryCurrentCandidatePool(ctx context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error)
	CandidatePoolSnapshotOfEpoch(ctx context.Context, epoch uint64) ([]byte, error)
	QueryCandidatePoolSnapshot(ctx context.Context, snapshotID []byte) (*hubv1.CandidatePoolSnapshotViewV1, error)
}

// ChainEpochs implements EpochSource on the chain.
//
// Epochs are half-open runs of epoch_length_blocks heights: the epoch of a height is
// height / epoch_length_blocks, and it starts at epoch × epoch_length_blocks. The epoch of an order
// is the one containing its earliest_submit_height and its reference height is that start. The
// epoch seed is the beacon randomness recorded at the reference height, and the snapshot is the
// candidate pool snapshot the chain published for the epoch: the current pool when it serves that
// epoch, otherwise the one seen in a CANDIDATE_POOL_PUBLISHED or CANDIDATE_POOL_EXPIRED event.
// A resolved epoch never changes, so it is kept.
type ChainEpochs struct {
	chain EpochChain

	mu     sync.Mutex
	length uint64
	epochs map[uint64]Epoch
}

// NewChainEpochs resolves epochs through chain.
func NewChainEpochs(chain EpochChain) *ChainEpochs {
	return &ChainEpochs{chain: chain, epochs: map[uint64]Epoch{}}
}

// EpochOf implements EpochSource.
func (s *ChainEpochs) EpochOf(ctx context.Context, earliestSubmitHeight uint64) (Epoch, error) {
	length, err := s.epochLength(ctx)
	if err != nil {
		return Epoch{}, err
	}
	number := earliestSubmitHeight / length
	s.mu.Lock()
	ep, ok := s.epochs[number]
	s.mu.Unlock()
	if ok {
		return ep, nil
	}
	if number > math.MaxUint64/length {
		return Epoch{}, fmt.Errorf("epoch %d start height overflows", number)
	}
	ep = Epoch{Number: number, ReferenceHeight: number * length}
	if ep.ReferenceHeight == 0 {
		return Epoch{}, fmt.Errorf("epoch 0 has no beacon at its reference height")
	}
	beacon, err := s.chain.QueryBeacon(ctx, ep.ReferenceHeight)
	if err != nil {
		return Epoch{}, fmt.Errorf("read beacon at reference height %d: %w", ep.ReferenceHeight, err)
	}
	seed, err := hex.DecodeString(beacon.GetRandomnessHex())
	if err != nil || len(seed) != 32 || hex.EncodeToString(seed) != beacon.GetRandomnessHex() {
		return Epoch{}, fmt.Errorf("beacon at height %d has no canonical 32-byte randomness", ep.ReferenceHeight)
	}
	copy(ep.Seed[:], seed)
	snapshot, err := s.snapshotOf(ctx, number)
	if err != nil {
		return Epoch{}, err
	}
	copy(ep.SnapshotID[:], snapshot)
	s.remember(ep)
	return ep, nil
}

// CurrentEpoch returns the epoch containing height, for readiness checks.
func (s *ChainEpochs) CurrentEpoch(ctx context.Context, height uint64) (uint64, error) {
	length, err := s.epochLength(ctx)
	if err != nil {
		return 0, err
	}
	return height / length, nil
}

func (s *ChainEpochs) epochLength(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	length := s.length
	s.mu.Unlock()
	if length != 0 {
		return length, nil
	}
	length, err := s.chain.QueryEpochLengthBlocks(ctx)
	if err != nil {
		return 0, fmt.Errorf("read epoch length: %w", err)
	}
	if length == 0 {
		return 0, fmt.Errorf("epoch length is zero")
	}
	s.mu.Lock()
	s.length = length
	s.mu.Unlock()
	return length, nil
}

func (s *ChainEpochs) snapshotOf(ctx context.Context, epoch uint64) ([]byte, error) {
	current, err := s.chain.QueryCurrentCandidatePool(ctx)
	if err != nil && !errors.Is(err, chaincli.ErrNotFound) {
		return nil, fmt.Errorf("read current candidate pool: %w", err)
	}
	if err == nil && current.GetEpoch() == epoch {
		return current.GetSnapshotId(), nil
	}
	snapshot, err := s.chain.CandidatePoolSnapshotOfEpoch(ctx, epoch)
	if errors.Is(err, chaincli.ErrNotFound) {
		return nil, fmt.Errorf("no candidate pool snapshot is known for epoch %d (current pool serves epoch %d)", epoch, current.GetEpoch())
	}
	if err != nil {
		return nil, err
	}
	header, err := s.chain.QueryCandidatePoolSnapshot(ctx, snapshot)
	if err != nil {
		return nil, fmt.Errorf("read candidate pool snapshot %x: %w", snapshot, err)
	}
	if header.GetEpoch() != epoch {
		return nil, fmt.Errorf("candidate pool snapshot %x serves epoch %d, not %d", snapshot, header.GetEpoch(), epoch)
	}
	return snapshot, nil
}

func (s *ChainEpochs) remember(ep Epoch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epochs[ep.Number] = ep
	for number := range s.epochs {
		if number+maxRememberedEpochs <= ep.Number {
			delete(s.epochs, number)
		}
	}
}

// PoolChain is the chain reads ChainPools makes.
type PoolChain interface {
	chaincli.CandidatePoolMemberPager
	QueryCandidatePoolSnapshotMember(ctx context.Context, key chaincli.CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error)
}

// ChainPools implements PoolSource on the chain: the snapshot's members walked page by page, and
// each member's frozen view for the profile.
type ChainPools struct{ Chain PoolChain }

// SnapshotMembers implements PoolSource.
func (p ChainPools) SnapshotMembers(ctx context.Context, snapshotID [32]byte) ([]*hubv1.CandidatePoolMemberViewV1, error) {
	return chaincli.ListCandidatePoolMembers(ctx, p.Chain, snapshotID[:])
}

// SnapshotMember implements PoolSource.
func (p ChainPools) SnapshotMember(ctx context.Context, snapshotID [32]byte, operator string, profile Profile) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	return p.Chain.QueryCandidatePoolSnapshotMember(ctx, chaincli.CandidatePoolMemberKey{
		SnapshotID: snapshotID[:], Operator: operator, ModelID: profile.ModelID[:], ProfileVersion: profile.Version,
	})
}

// VRFKeyChain is the chain read ChainVRFKeys makes.
type VRFKeyChain interface {
	QueryVrfKey(ctx context.Context, participantType, operator string) (chaincli.VrfKey, error)
}

const vrfEpochKeyPrefix = "builder_vrf_epoch/"

// ChainVRFKeys implements VRFKeyRegistry with the Builder's registered VRF keys.
//
// The key of an epoch is the chain's active key: proofs of an epoch are verified with the key
// active in it, and a pending key is never used because its activation may be postponed. The chain
// keeps only the current active key, so the key found for each epoch is remembered (in the
// chain_state namespace, so a restart keeps it): after a rotation the older epoch's key stays
// available to its unexpired orders, and a draw does not read the chain for an epoch it already
// knows. Callers ask only for epochs that have begun, whose active key a later registration cannot
// change (a registration takes effect from the next epoch at the earliest).
type ChainVRFKeys struct {
	chain   VRFKeyChain
	store   kv.Store
	chainID string
	builder string

	mu     sync.Mutex
	loaded bool
	known  map[uint64][]byte
}

// NewChainVRFKeys reads builder's BUILDER VRF keys through chain and remembers the key of each
// epoch in store (nil keeps them in memory only).
func NewChainVRFKeys(chain VRFKeyChain, store kv.Store, chainID, builder string) *ChainVRFKeys {
	return &ChainVRFKeys{chain: chain, store: store, chainID: chainID, builder: builder}
}

// BuilderVRFKey implements VRFKeyRegistry.
func (k *ChainVRFKeys) BuilderVRFKey(ctx context.Context, epoch uint64) ([]byte, error) {
	key, ok, err := k.remembered(epoch)
	if err != nil || ok {
		return key, err
	}
	keys, err := k.chain.QueryVrfKey(ctx, "BUILDER", k.builder)
	if errors.Is(err, chaincli.ErrNotFound) {
		return nil, fmt.Errorf("builder %s: %w", k.builder, ErrNoVRFKey)
	}
	if err != nil {
		return nil, err
	}
	if epoch < keys.ActiveFromEpoch {
		return nil, fmt.Errorf("epoch %d precedes the active key (from epoch %d) and its key was not seen: %w",
			epoch, keys.ActiveFromEpoch, ErrNoVRFKey)
	}
	if len(keys.ActivePubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("builder VRF key is %d bytes", len(keys.ActivePubKey))
	}
	// While a pending key is due by epoch the cutover may not be visible yet: answer the active
	// key without remembering it, so the next read sees the cutover.
	if keys.PendingPubKey == nil || epoch < keys.PendingFromEpoch {
		if err := k.remember(epoch, keys.ActivePubKey); err != nil {
			return nil, err
		}
	}
	return bytes.Clone(keys.ActivePubKey), nil
}

func (k *ChainVRFKeys) vrfEpochKey(epoch uint64) string {
	return fmt.Sprintf("%s%s/%s/%020d", vrfEpochKeyPrefix, k.chainID, k.builder, epoch)
}

func (k *ChainVRFKeys) loadLocked() error {
	if k.loaded {
		return nil
	}
	k.known = map[uint64][]byte{}
	if k.store != nil {
		prefix := vrfEpochKeyPrefix + k.chainID + "/" + k.builder + "/"
		var bad error
		err := k.store.Scan(kv.NSChainState, func(key string, value []byte) bool {
			rest, ok := strings.CutPrefix(key, prefix)
			if !ok {
				return true
			}
			epoch, err := strconv.ParseUint(rest, 10, 64)
			if err != nil || len(value) != ed25519.PublicKeySize {
				bad = fmt.Errorf("malformed builder VRF epoch entry %q", key)
				return false
			}
			k.known[epoch] = bytes.Clone(value)
			return true
		})
		if err == nil {
			err = bad
		}
		if err != nil {
			return fmt.Errorf("load builder VRF epochs: %w", err)
		}
	}
	k.loaded = true
	return nil
}

func (k *ChainVRFKeys) remembered(epoch uint64) ([]byte, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return nil, false, err
	}
	key, ok := k.known[epoch]
	return bytes.Clone(key), ok, nil
}

// remember keeps key as the active key of epoch and forgets the oldest epochs beyond
// maxRememberedEpochs.
func (k *ChainVRFKeys) remember(epoch uint64, key []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.loadLocked(); err != nil {
		return err
	}
	if bytes.Equal(k.known[epoch], key) {
		return nil
	}
	ops := []kv.WriteOp{{NS: kv.NSChainState, Key: k.vrfEpochKey(epoch), Val: bytes.Clone(key)}}
	epochs := make([]uint64, 0, len(k.known)+1)
	for e := range k.known {
		if e != epoch {
			epochs = append(epochs, e)
		}
	}
	epochs = append(epochs, epoch)
	slices.Sort(epochs)
	var dropped []uint64
	for len(epochs) > maxRememberedEpochs {
		dropped = append(dropped, epochs[0])
		ops = append(ops, kv.WriteOp{NS: kv.NSChainState, Key: k.vrfEpochKey(epochs[0]), Delete: true})
		epochs = epochs[1:]
	}
	if k.store != nil {
		if err := k.store.WriteBatch(ops...); err != nil {
			return fmt.Errorf("store builder VRF epoch: %w", err)
		}
	}
	k.known[epoch] = bytes.Clone(key)
	for _, e := range dropped {
		delete(k.known, e)
	}
	return nil
}
