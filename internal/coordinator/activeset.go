package coordinator

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"sync"

	"github.com/TrueOpen/nexus/internal/types"
)

// builderSetRef is the (builder_set_id, builder_set_hash) pair obtained in one on-chain read.
// The V2 envelope no longer carries it, but the seed path still stores it as a unit: the BuilderSet reference
// is an on-chain fact, and two separate queries at a term boundary can assemble a set that never existed.
type builderSetRef struct {
	ID   string
	Hash string
}

// activeSet holds the current active BuilderSet and this node's identity in a thread-safe way.
//
// Two feeding entry points: at startup seedBuilderSet queries the authoritative set via QueryBuilderSetAtHeight,
// afterwards BuilderSetUpdated events trigger the same seed path to reconcile again. epoch comes only from the
// term_id returned by the chain and is never derived locally (the current Node BuilderState has no active_term).
type activeSet struct {
	mu      sync.RWMutex
	self    string             // this builder's address (from config); empty = identity not configured
	epoch   uint64             // current roster epoch
	members []types.BuilderRef // current active roster
	// ref is the (builder_set_id, builder_set_hash) pair from one read. BusEnvelopeV1 fields 11/12 must come
	// from the same read; two separate queries can assemble a nonexistent set at a term boundary.
	ref builderSetRef
}

// newActiveSet constructs with this node's own builder address (self may be empty = no identity configured).
func newActiveSet(self string) *activeSet {
	return &activeSet{self: self}
}

// Update replaces the roster as a whole (called on BuilderSetUpdated events / when QueryBuilderSetAtHeight
// hits a real set at startup). ref and members come from the same on-chain read.
func (a *activeSet) Update(epoch uint64, members []types.BuilderRef, ref builderSetRef) {
	cp := make([]types.BuilderRef, len(members))
	copy(cp, members)
	a.mu.Lock()
	a.epoch = epoch
	a.members = cp
	a.ref = ref
	a.mu.Unlock()
}

// Ref returns the current BuilderSet reference. A false second return value means nothing has been read from the chain yet.
func (a *activeSet) Ref() (builderSetRef, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ref, a.ref.ID != "" && a.ref.Hash != ""
}

// Epoch returns the current roster's epoch.
func (a *activeSet) Epoch() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epoch
}

// Members returns a snapshot copy of the roster (callers cannot mutate internal state).
func (a *activeSet) Members() []types.BuilderRef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cp := make([]types.BuilderRef, len(a.members))
	copy(cp, a.members)
	return cp
}

// IsActive reports whether self is in the current roster (always false when self is empty).
func (a *activeSet) IsActive() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.self == "" {
		return false
	}
	for _, m := range a.members {
		if m.Address == a.self {
			return true
		}
	}
	return false
}

// Rank gives an address's deterministic rank for "this order".
//
// Algorithm: sort the current members ascending by sha256(seed || []byte(member.Address));
// the sorted position is the rank (1..N, 1-based); returns addr's rank and whether it was found.
//
// Important / forward-looking design: this is a deterministic placeholder that "simulates" a VRF permutation so
// Builders can agree on a soft coordination signal for "which 3 are selected and their ranks" without an on-chain selector.
// It MUST be replaced by an ordering identical to the on-chain VRF once the chain implements builder selection (VRF),
// otherwise it diverges from the chain's authoritative result. The chain is always authoritative; this is only a coordination/soft signal.
func (a *activeSet) Rank(seed []byte, addr string) (rank int, inSet bool) {
	a.mu.RLock()
	members := make([]types.BuilderRef, len(a.members))
	copy(members, a.members)
	a.mu.RUnlock()
	return rankAmong(seed, members, addr)
}

// rankAmong computes an address's deterministic rank (1..N) within the given member group.
// Group members compute the same order from the same seed, reaching agreement without communication (Detailed Design §4.2).
func rankAmong(seed []byte, members []types.BuilderRef, addr string) (rank int, inSet bool) {
	if len(members) == 0 {
		return 0, false
	}

	type scored struct {
		addr string
		key  [sha256.Size]byte
	}
	ss := make([]scored, len(members))
	for i, m := range members {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte(m.Address))
		var k [sha256.Size]byte
		copy(k[:], h.Sum(nil))
		ss[i] = scored{addr: m.Address, key: k}
	}
	sort.Slice(ss, func(i, j int) bool {
		if c := bytes.Compare(ss[i].key[:], ss[j].key[:]); c != 0 {
			return c < 0
		}
		// Equal hashes are extremely rare; fall back to the address to guarantee a deterministic total order.
		return ss[i].addr < ss[j].addr
	})
	for i, s := range ss {
		if s.addr == addr {
			return i + 1, true
		}
	}
	return 0, false
}

// MyRank is a convenience = Rank(seed, self). inSet=false when self is empty or not in the roster.
func (a *activeSet) MyRank(seed []byte) (rank int, inSet bool) {
	a.mu.RLock()
	self := a.self
	a.mu.RUnlock()
	if self == "" {
		return 0, false
	}
	return a.Rank(seed, self)
}
