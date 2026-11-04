package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// maxRememberedEpochs bounds the epochs the chain adapters remember: orders of older epochs are
// past every record deadline.
const maxRememberedEpochs = 64

// epochMissTTL is how long an epoch that could not be resolved (no seed or no effective snapshot
// yet) is not read again: every order of the epoch parked on it asks on each block, and the
// OpenTask precheck asks for every new order; one read per block time is enough.
const epochMissTTL = time.Second

// placeholderBeaconSource tags a dev-only beacon derived from the block hash; it is never an epoch
// seed.
const placeholderBeaconSource = "placeholder_blockhash_v1"

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
// epoch seed is the raw R_h of the committed, verified beacon at the reference height
// (dispatch.ResolveEpochSeed): a missing, unverified or placeholder beacon leaves the epoch not
// ready, with no substitute, and epoch 0, which has no beacon at height 0, never resolves. The
// snapshot is the candidate pool snapshot the chain published for the epoch: the current pool when
// it serves that epoch, otherwise the one seen in a CANDIDATE_POOL_PUBLISHED or
// CANDIDATE_POOL_EXPIRED event; the epoch is not ready until it is effective. A resolved epoch
// never changes, so it is kept.
type ChainEpochs struct {
	chain EpochChain
	// head reads the chain head; nil keeps every unresolved answer for epochMissTTL.
	head func(context.Context) (uint64, error)
	now  func() time.Time

	mu     sync.Mutex
	length uint64
	epochs map[uint64]Epoch
	// misses keeps, per epoch, why it was not resolved and until when that answer stands.
	misses map[uint64]epochMiss
}

type epochMiss struct {
	err   error
	until time.Time
	// head is the chain head read when a "not ready" answer was kept (headKnown): once the head
	// has advanced past it the epoch is read again.
	head      uint64
	headKnown bool
}

// NewChainEpochs resolves epochs through chain. head, when set, reads the chain head: a kept "not
// ready" answer is read again once the head has advanced past the head seen when it was kept.
func NewChainEpochs(chain EpochChain, head func(context.Context) (uint64, error)) *ChainEpochs {
	return &ChainEpochs{chain: chain, head: head, now: time.Now, epochs: map[uint64]Epoch{}, misses: map[uint64]epochMiss{}}
}

// EpochOf implements EpochSource. An epoch that cannot dispatch yet fails with a *NotReadyError.
// A failure is kept for epochMissTTL, during which the epoch's other orders get the same answer
// without a chain read.
func (s *ChainEpochs) EpochOf(ctx context.Context, earliestSubmitHeight uint64) (Epoch, error) {
	length, err := s.epochLength(ctx)
	if err != nil {
		return Epoch{}, err
	}
	number := earliestSubmitHeight / length
	s.mu.Lock()
	ep, ok := s.epochs[number]
	miss, missed := s.misses[number]
	s.mu.Unlock()
	if ok {
		return ep, nil
	}
	if number == 0 {
		return Epoch{}, &NotReadyError{DispatchableHeight: length,
			Reason: "epoch 0 has no beacon at its reference height; dispatch starts in epoch 1"}
	}
	if missed && s.now().Before(miss.until) && !s.advanced(ctx, miss) {
		return Epoch{}, miss.err
	}
	ep, err = s.resolve(ctx, number, length, earliestSubmitHeight)
	var kept epochMiss
	if err != nil {
		kept = epochMiss{err: err, until: s.now().Add(epochMissTTL)}
		if s.head != nil && errors.Is(err, ErrDispatchNotReady) {
			if head, headErr := s.head(ctx); headErr == nil {
				kept.head, kept.headKnown = head, true
			}
		}
	}
	s.mu.Lock()
	if err != nil {
		s.misses[number] = kept
	} else {
		delete(s.misses, number)
	}
	s.mu.Unlock()
	if err != nil {
		return Epoch{}, err
	}
	s.remember(ep)
	return ep, nil
}

// advanced reports whether the head has advanced past the one read when a "not ready" answer was
// kept, so the epoch is read again at most once per block: with blocks shorter than epochMissTTL
// the answer could otherwise outlive the dispatchable height it names. The head is never compared
// with that height, which with a separate Hub is a height of another chain. An answer kept without
// a head, or a head that cannot be read, waits for the TTL.
func (s *ChainEpochs) advanced(ctx context.Context, miss epochMiss) bool {
	if !miss.headKnown {
		return false
	}
	head, err := s.head(ctx)
	return err == nil && head > miss.head
}

// resolve reads the seed and the candidate pool snapshot of epoch number.
func (s *ChainEpochs) resolve(ctx context.Context, number, length, earliestSubmitHeight uint64) (Epoch, error) {
	source, err := s.readSeed(ctx, number, length, earliestSubmitHeight)
	if err != nil {
		return Epoch{}, err
	}
	ep := Epoch{Number: source.Epoch, ReferenceHeight: source.ReferenceHeight, Seed: source.Randomness}
	snapshot, err := s.snapshotOf(ctx, number)
	if err != nil {
		return Epoch{}, err
	}
	copy(ep.SnapshotID[:], snapshot)
	return ep, nil
}

// readSeed reads the start beacon of epoch number and resolves its seed. A beacon not committed
// yet is not ready until the epoch's first block commits it; one that is committed but unusable
// (unverified, a placeholder, malformed) is not ready with no known height.
func (s *ChainEpochs) readSeed(ctx context.Context, number, length, earliestSubmitHeight uint64) (dispatch.EpochSeed, error) {
	reference := number * length // at most earliestSubmitHeight
	beacon, err := s.chain.QueryBeacon(ctx, reference)
	if errors.Is(err, chaincli.ErrNotFound) {
		return dispatch.EpochSeed{}, &NotReadyError{Epoch: number, DispatchableHeight: reference,
			Reason: fmt.Sprintf("the beacon at reference height %d is not committed", reference)}
	}
	if err != nil {
		return dispatch.EpochSeed{}, fmt.Errorf("read beacon at reference height %d: %w", reference, err)
	}
	seed, err := hex.DecodeString(beacon.GetRandomnessHex())
	if err != nil || hex.EncodeToString(seed) != beacon.GetRandomnessHex() {
		seed = nil
	}
	verified := beacon.GetVerified() && beacon.GetSourceTag() != placeholderBeaconSource
	source, err := dispatch.ResolveEpochSeed(earliestSubmitHeight, length, beacon.GetHeight(), seed, verified)
	if err != nil {
		return dispatch.EpochSeed{}, &NotReadyError{Epoch: number, Reason: fmt.Sprintf(
			"no seed from the beacon at height %d (source %q, verified %t): %v", reference, beacon.GetSourceTag(), beacon.GetVerified(), err)}
	}
	return source, nil
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

// snapshotOf returns the candidate pool snapshot of epoch. It is not ready while the chain has
// published none for the epoch and the current pool serves an earlier one, or while the published
// one has not reached its effective_height.
func (s *ChainEpochs) snapshotOf(ctx context.Context, epoch uint64) ([]byte, error) {
	current, err := s.chain.QueryCurrentCandidatePool(ctx)
	if err != nil && !errors.Is(err, chaincli.ErrNotFound) {
		return nil, fmt.Errorf("read current candidate pool: %w", err)
	}
	if err == nil && current.GetEpoch() == epoch {
		if err := effective(current, epoch); err != nil {
			return nil, err
		}
		return current.GetSnapshotId(), nil
	}
	snapshot, err := s.chain.CandidatePoolSnapshotOfEpoch(ctx, epoch)
	if errors.Is(err, chaincli.ErrNotFound) {
		if current.GetEpoch() < epoch {
			return nil, &NotReadyError{Epoch: epoch, Reason: fmt.Sprintf(
				"no candidate pool snapshot is published for epoch %d (current pool serves epoch %d)", epoch, current.GetEpoch())}
		}
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
	if err := effective(header, epoch); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// effective refuses a snapshot that is published but not effective yet (READY): its scoring
// coefficients are not frozen before its effective_height.
func effective(header *hubv1.CandidatePoolSnapshotViewV1, epoch uint64) error {
	if header.GetStatus() != hubv1.CandidatePoolSnapshotStatus_CANDIDATE_POOL_SNAPSHOT_STATUS_READY {
		return nil
	}
	return &NotReadyError{Epoch: epoch, DispatchableHeight: header.GetEffectiveHeight(), Reason: fmt.Sprintf(
		"candidate pool snapshot %x is not effective before height %d", header.GetSnapshotId(), header.GetEffectiveHeight())}
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
	for number := range s.misses {
		if number < ep.Number {
			delete(s.misses, number)
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
	if len(keys.ActivePubKey) == 0 {
		return nil, fmt.Errorf("builder %s has only a pending key (from epoch %d): %w", k.builder, keys.PendingFromEpoch, ErrNoVRFKey)
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
