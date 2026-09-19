// Package mmr implements the `MMR_ROOT_V1` framing frozen in Base Spec §9: a Merkle
// Mountain Range commitment over an append-only ordered list of variable-length byte
// leaves, able to recompute the root of any prefix in addition to the final root.
// Its only current user is the output_hash of streamed output (Verification
// Algorithm §8.1, domain `TRUEOPEN_OUTPUT_MMR_V1`).
//
//	MmrLeafV1(domain, index, leaf)  = SHA256("TRUEOPEN_MMR_LEAF_V1"  || u32_be(len(domain)) || domain || u64_be(index) || u64_be(len(leaf)) || leaf)
//	MmrNodeV1(domain, left, right)  = SHA256("TRUEOPEN_MMR_NODE_V1"  || u32_be(len(domain)) || domain || left || right)
//	MmrEmptyV1(domain)              = SHA256("TRUEOPEN_MMR_EMPTY_V1" || u32_be(len(domain)) || domain)
//
// Tree rules (§9 items 1-8): index is contiguous from 0; a new leaf is pushed as a
// height-0 peak and the last two peaks merge while they have equal height; the peak
// shape is uniquely determined by the binary form of the leaf count; folding runs right
// to left and with n == 1 the root is that single peak; the empty-list root is
// MmrEmptyV1; leaves are never duplicated, zero-padded or padded to a power of two.
package mmr

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"unicode/utf8"
)

const (
	leafPrefix  = "TRUEOPEN_MMR_LEAF_V1"
	nodePrefix  = "TRUEOPEN_MMR_NODE_V1"
	emptyPrefix = "TRUEOPEN_MMR_EMPTY_V1"
	// MaxDomainBytes matches the MERKLE_ROOT_V1 domain limit (Base Spec §9).
	MaxDomainBytes = 128
)

// ErrDomain means the domain violates Base Spec §4.2 (empty, too long or not UTF-8).
var ErrDomain = errors.New("mmr: invalid domain")

// Hash is a 32-byte SHA-256 digest.
type Hash = [sha256.Size]byte

func validateDomain(domain string) error {
	if domain == "" || len(domain) > MaxDomainBytes || !utf8.ValidString(domain) {
		return fmt.Errorf("%w: %q", ErrDomain, domain)
	}
	return nil
}

func writeDomain(h interface{ Write([]byte) (int, error) }, domain string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(domain)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(domain))
}

// LeafHash is MmrLeafV1(domain, index, leaf). The caller must have validated domain.
func LeafHash(domain string, index uint64, leaf []byte) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(leafPrefix))
	writeDomain(h, domain)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], index)
	_, _ = h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(len(leaf)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(leaf)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash is MmrNodeV1(domain, left, right).
func NodeHash(domain string, left, right Hash) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(nodePrefix))
	writeDomain(h, domain)
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRoot is MmrEmptyV1(domain): the root of the empty list, not 32 zero bytes.
func EmptyRoot(domain string) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(emptyPrefix))
	writeDomain(h, domain)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

type peak struct {
	hash   Hash
	height uint8
}

// Accumulator is an append-only MMR holding the current peaks (tallest on the left)
// and the leaf count. It is not safe for concurrent use; callers lock themselves.
type Accumulator struct {
	domain string
	peaks  []peak
	leaves uint64
}

// New creates an empty tree.
func New(domain string) (*Accumulator, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	return &Accumulator{domain: domain}, nil
}

// Restore rebuilds from a persisted leaf count and peak values: the number of peaks must
// equal the number of 1 bits in the leaf count, and peak heights follow from the bits
// high to low, so they need not be stored.
func Restore(domain string, leaves uint64, peaks []Hash) (*Accumulator, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if len(peaks) != bits.OnesCount64(leaves) {
		return nil, fmt.Errorf("mmr: %d peaks do not match %d leaves", len(peaks), leaves)
	}
	acc := &Accumulator{domain: domain, leaves: leaves, peaks: make([]peak, 0, len(peaks))}
	next := 0
	for bit := 63; bit >= 0; bit-- {
		if leaves&(1<<uint(bit)) == 0 {
			continue
		}
		acc.peaks = append(acc.peaks, peak{hash: peaks[next], height: uint8(bit)})
		next++
	}
	return acc, nil
}

// Clone returns a copy, used to compute and compare a root before adopting it.
func (a *Accumulator) Clone() *Accumulator {
	return &Accumulator{domain: a.domain, leaves: a.leaves, peaks: append([]peak(nil), a.peaks...)}
}

// Domain returns the commitment domain.
func (a *Accumulator) Domain() string { return a.domain }

// Leaves returns the number of appended leaves.
func (a *Accumulator) Leaves() uint64 { return a.leaves }

// Peaks returns the current peak values (left to right, decreasing height).
func (a *Accumulator) Peaks() []Hash {
	out := make([]Hash, len(a.peaks))
	for i, p := range a.peaks {
		out[i] = p.hash
	}
	return out
}

// Append adds one leaf (index = current leaf count) and returns the new root root_{n+1}.
func (a *Accumulator) Append(leaf []byte) Hash {
	node := peak{hash: LeafHash(a.domain, a.leaves, leaf)}
	for len(a.peaks) > 0 && a.peaks[len(a.peaks)-1].height == node.height {
		last := a.peaks[len(a.peaks)-1]
		a.peaks = a.peaks[:len(a.peaks)-1]
		node = peak{hash: NodeHash(a.domain, last.hash, node.hash), height: node.height + 1}
	}
	a.peaks = append(a.peaks, node)
	a.leaves++
	return a.Root()
}

// Root folds the peaks right to left: acc = rightmost peak; for the remaining peaks from
// right to left acc = Node(peak, acc). With a single peak the root is that peak; an
// empty tree returns EmptyRoot.
func (a *Accumulator) Root() Hash {
	if len(a.peaks) == 0 {
		return EmptyRoot(a.domain)
	}
	acc := a.peaks[len(a.peaks)-1].hash
	for i := len(a.peaks) - 2; i >= 0; i-- {
		acc = NodeHash(a.domain, a.peaks[i].hash, acc)
	}
	return acc
}

// Root computes the root of a whole leaf list in one pass.
func Root(domain string, leaves [][]byte) (Hash, error) {
	acc, err := New(domain)
	if err != nil {
		return Hash{}, err
	}
	for _, leaf := range leaves {
		acc.Append(leaf)
	}
	return acc.Root(), nil
}
