package mmr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

const testDomain = "TRUEOPEN_OUTPUT_MMR_V1"

// Recomputed by hand from the §9 formulas, without borrowing the code under test.
func manualLeaf(domain string, index uint64, leaf []byte) Hash {
	var buf bytes.Buffer
	buf.WriteString("TRUEOPEN_MMR_LEAF_V1")
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(domain)))
	buf.WriteString(domain)
	_ = binary.Write(&buf, binary.BigEndian, index)
	_ = binary.Write(&buf, binary.BigEndian, uint64(len(leaf)))
	buf.Write(leaf)
	return sha256.Sum256(buf.Bytes())
}

func manualNode(domain string, left, right Hash) Hash {
	var buf bytes.Buffer
	buf.WriteString("TRUEOPEN_MMR_NODE_V1")
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(domain)))
	buf.WriteString(domain)
	buf.Write(left[:])
	buf.Write(right[:])
	return sha256.Sum256(buf.Bytes())
}

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("chunk-%d", i))
	}
	return out
}

func TestEmptyRootIsDomainBoundNotZero(t *testing.T) {
	root, err := Root(testDomain, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.WriteString("TRUEOPEN_MMR_EMPTY_V1")
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(testDomain)))
	buf.WriteString(testDomain)
	if want := sha256.Sum256(buf.Bytes()); root != want || root == (Hash{}) {
		t.Fatalf("empty root = %x, want %x", root, want)
	}
	other, _ := Root("OTHER_DOMAIN_V1", nil)
	if other == root {
		t.Fatal("empty root must differ per domain")
	}
}

// Peak shape and fold direction: n=1 root is the leaf; n=2 one height-1 peak; n=3 folds
// Node(P(0,1), L2); n=4 single peak; n=5 Node(P4, L4); n=7 Node(P4, Node(P2, L6)).
func TestRootShapesFollowSpec(t *testing.T) {
	ls := leaves(7)
	L := make([]Hash, 7)
	for i := range ls {
		L[i] = manualLeaf(testDomain, uint64(i), ls[i])
	}
	p01 := manualNode(testDomain, L[0], L[1])
	p23 := manualNode(testDomain, L[2], L[3])
	p0123 := manualNode(testDomain, p01, p23)
	p45 := manualNode(testDomain, L[4], L[5])
	cases := []struct {
		n    int
		want Hash
	}{
		{1, L[0]},
		{2, p01},
		{3, manualNode(testDomain, p01, L[2])},
		{4, p0123},
		{5, manualNode(testDomain, p0123, L[4])},
		{6, manualNode(testDomain, p0123, p45)},
		{7, manualNode(testDomain, p0123, manualNode(testDomain, p45, L[6]))},
	}
	for _, c := range cases {
		got, err := Root(testDomain, ls[:c.n])
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("n=%d root = %x, want %x", c.n, got, c.want)
		}
	}
}

func TestAppendReturnsPrefixRootsAndPeaksRestore(t *testing.T) {
	acc, err := New(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	ls := leaves(37)
	for k, leaf := range ls {
		root := acc.Append(leaf)
		want, _ := Root(testDomain, ls[:k+1])
		if root != want {
			t.Fatalf("root after %d leaves = %x, want %x", k+1, root, want)
		}
		if acc.Leaves() != uint64(k+1) {
			t.Fatalf("leaves = %d", acc.Leaves())
		}
		// Restore from peaks midway, append the remaining leaves; result must equal the one-pass computation.
		restored, err := Restore(testDomain, acc.Leaves(), acc.Peaks())
		if err != nil {
			t.Fatalf("restore after %d leaves: %v", k+1, err)
		}
		if restored.Root() != root {
			t.Fatalf("restored root differs after %d leaves", k+1)
		}
		for _, rest := range ls[k+1:] {
			restored.Append(rest)
		}
		full, _ := Root(testDomain, ls)
		if restored.Root() != full {
			t.Fatalf("restored accumulator diverged after %d leaves", k+1)
		}
	}
}

func TestRestoreRejectsPeakCountMismatch(t *testing.T) {
	if _, err := Restore(testDomain, 3, []Hash{{}}); err == nil {
		t.Fatal("3 leaves need 2 peaks")
	}
	if _, err := Restore("", 0, nil); err == nil {
		t.Fatal("empty domain must be rejected")
	}
}

func TestLeafIndexAndLengthAreCommitted(t *testing.T) {
	a, _ := Root(testDomain, [][]byte{[]byte("ab"), []byte("c")})
	b, _ := Root(testDomain, [][]byte{[]byte("a"), []byte("bc")})
	c, _ := Root(testDomain, [][]byte{[]byte("c"), []byte("ab")})
	if a == b || a == c {
		t.Fatal("different chunking or order must change the root")
	}
	empty1, _ := Root(testDomain, [][]byte{{}})
	if empty1 == EmptyRoot(testDomain) {
		t.Fatal("one zero-length leaf is not the empty tree")
	}
}

func TestCloneDoesNotShareState(t *testing.T) {
	acc, _ := New(testDomain)
	acc.Append([]byte("x"))
	clone := acc.Clone()
	clone.Append([]byte("y"))
	if acc.Leaves() != 1 || clone.Leaves() != 2 || acc.Root() == clone.Root() {
		t.Fatal("clone must be independent")
	}
}
