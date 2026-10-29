package handraise

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

func TestRootIsSignedOverSortedLeaves(t *testing.T) {
	e := newEnv(t)
	var operators []cortex
	for i := byte(0); i < 5; i++ {
		c := e.addCortex(0x10+i, uint32(i))
		operators = append(operators, c)
		e.mustAccept(c, e.handraise(c, 100, 1))
	}
	issued := e.mustIssue()
	root := issued.Root
	if root.GetChainId() != testChainID || root.GetBuilderAddress() != e.builder.Address() ||
		root.GetRootHeight() != 100 || root.GetRootVersion() != 0 || root.GetLeafCount() != 5 {
		t.Fatalf("root = %v", root)
	}

	// Leaves ascend by standing handraise digest and the root is the wire Merkle root over them.
	var digests [][32]byte
	for i, leaf := range issued.Leaves {
		standing := standingDigest(t, leaf.GetHandraise())
		previous := standingDigest(t, issued.Leaves[max(i-1, 0)].GetHandraise())
		if i > 0 && bytes.Compare(previous[:], standing[:]) >= 0 {
			t.Fatal("leaves are not in ascending standing digest order")
		}
		digest, err := dispatch.HandraiseLeafDigest(standing, leaf.GetAdmitted(), uint32(leaf.GetAdmitRejectReason()), leaf.GetBuilderMeasuredRttMs())
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
	}
	want := dispatch.HandraiseRoot(digests)
	if !bytes.Equal(root.GetRoot(), want[:]) {
		t.Fatal("root is not the wire handraise root of the leaves")
	}

	// The signature is the Builder service key over the wire signing digest.
	digest := rootDigest(t, root)
	if digest != issued.Digest {
		t.Fatal("issued digest differs from the signing digest")
	}
	if err := dispatch.VerifyDigestSignature(e.builder.PubKeyCompressed(), digest[:], root.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("root signature: %v", err)
	}

	// Every member gets its own inclusion proof.
	for _, c := range operators {
		notice, ok := issued.Notice(c.operator())
		if !ok || !proto.Equal(notice.GetRoot(), root) {
			t.Fatalf("notice for %s missing", c.operator())
		}
		proof := notice.GetProof()
		if proof.GetLeaf().GetHandraise().GetMember().GetOperatorAddress() != c.operator() {
			t.Fatal("notice proves another member's leaf")
		}
		if !dispatch.VerifyHandraiseProof(want, digests[proof.GetLeafIndex()], proof.GetLeafIndex(), root.GetLeafCount(), toHashes(proof.GetSiblings())) {
			t.Fatalf("proof for %s does not verify", c.operator())
		}
		leafDigest, err := LeafDigest(proof.GetLeaf())
		if err != nil || leafDigest != digests[proof.GetLeafIndex()] {
			t.Fatalf("proof leaf digest mismatch: %v", err)
		}
	}
	if _, ok := issued.Notice(newSigner(t, 0x7f).Address()); ok {
		t.Fatal("notice for an operator without a leaf")
	}
}

func TestRootVersionIncrementsWithinHeightAndResets(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	b := e.addCortex(0x12, 2)
	e.mustAccept(a, e.handraise(a, 100, 1))
	first := e.mustIssue()

	// Nothing changed: no new root.
	if again := e.issue(); again != nil {
		t.Fatalf("unchanged leaves were re-signed as version %d", again.Root.GetRootVersion())
	}

	e.mustAccept(b, e.handraise(b, 100, 1))
	second := e.mustIssue()
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 100, 2))
	third := e.mustIssue()
	e.height.set(103)
	e.clock.advance(time.Second)
	e.mustAccept(b, e.handraise(b, 103, 1))
	fourth := e.mustIssue()

	for i, tc := range []struct {
		root            *IssuedRoot
		height, version uint64
	}{{first, 100, 0}, {second, 100, 1}, {third, 100, 2}, {fourth, 103, 0}} {
		if tc.root.Root.GetRootHeight() != tc.height || tc.root.Root.GetRootVersion() != tc.version {
			t.Fatalf("root %d = (%d, %d), want (%d, %d)", i, tc.root.Root.GetRootHeight(), tc.root.Root.GetRootVersion(), tc.height, tc.version)
		}
	}
	root, leaves, ok := e.reg.Latest()
	if !ok || !proto.Equal(root, fourth.Root) || len(leaves) != 2 {
		t.Fatalf("Latest = %v %d %v", root, len(leaves), ok)
	}
}

// A chain height that goes backwards (another node behind the last one) never lowers root order.
func TestRootHeightNeverGoesBackwards(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	b := e.addCortex(0x12, 2)
	e.mustAccept(a, e.handraise(a, 100, 1))
	e.mustIssue()
	e.height.set(99)
	e.mustAccept(b, e.handraise(b, 99, 1))
	next := e.mustIssue()
	if next.Root.GetRootHeight() != 100 || next.Root.GetRootVersion() != 1 {
		t.Fatalf("root after a lower height = (%d, %d), want (100, 1)", next.Root.GetRootHeight(), next.Root.GetRootVersion())
	}
}

// After a Builder key rotation the same leaves are signed again by the new key: the root binds no
// key generation, so the old signature would not verify under the new current key.
func TestRootReissuedOnBuilderKeyChange(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	e.mustAccept(a, e.handraise(a, 100, 1))
	first := e.mustIssue()

	rotated := newSigner(t, 0x09)
	reg, err := New(Options{
		ChainID: testChainID, BuilderAddress: e.builder.Address(), Config: e.cfg, Store: e.store,
		Keys: e.keys, Pool: e.pool, Height: e.height, Signer: rotated, Now: e.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.reg = reg
	second := e.mustIssue()
	if !bytes.Equal(second.Root.GetRoot(), first.Root.GetRoot()) || second.Root.GetRootVersion() != first.Root.GetRootVersion()+1 {
		t.Fatalf("root after rotation = %v", second.Root)
	}
	if err := dispatch.VerifyDigestSignature(rotated.PubKeyCompressed(), second.Digest[:], second.Root.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("root after rotation is not signed by the new key: %v", err)
	}
	if again := e.issue(); again != nil {
		t.Fatal("unchanged leaves re-signed under the same key")
	}
}

// No root is issued while the Builder's own current key cannot be confirmed.
func TestNoRootWithoutCurrentBuilderKey(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	e.mustAccept(a, e.handraise(a, 100, 1))
	e.keys.builderErr = errors.New("no current key")
	if root, err := e.reg.IssueRoot(context.Background()); err == nil || root != nil {
		t.Fatalf("IssueRoot = %v, %v; want an error", root, err)
	}
}

func TestNoRootBeforeAnyHandraise(t *testing.T) {
	e := newEnv(t)
	if root := e.issue(); root != nil {
		t.Fatal("a root was issued without any handraise")
	}
	if _, _, ok := e.reg.Latest(); ok {
		t.Fatal("Latest reported a root")
	}
}

func TestRootByDigest(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	b := e.addCortex(0x12, 2)
	e.mustAccept(a, e.handraise(a, 100, 1))
	first := e.mustIssue()
	e.mustAccept(b, e.handraise(b, 100, 1))
	e.mustIssue()

	got, found, err := e.reg.RootByDigest(first.Digest)
	if err != nil || !found {
		t.Fatalf("RootByDigest: %v %v", found, err)
	}
	if !proto.Equal(got.Root, first.Root) || len(got.Leaves) != 1 || !proto.Equal(got.Leaves[0], first.Leaves[0]) {
		t.Fatalf("RootByDigest = %v", got.Root)
	}
	if _, found, err := e.reg.RootByDigest([32]byte{1}); err != nil || found {
		t.Fatalf("unknown digest: %v %v", found, err)
	}
}

func TestPruneRootsBelowKeepsLatest(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	e.mustAccept(a, e.handraise(a, 100, 1))
	old := e.mustIssue()
	e.height.set(110)
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 110, 1))
	mid := e.mustIssue()
	e.height.set(120)
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 120, 1))
	latest := e.mustIssue()

	n, err := e.reg.PruneRootsBelow(200, func([32]byte) bool { return false })
	if err != nil || n != 2 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	for _, gone := range []*IssuedRoot{old, mid} {
		if _, found, _ := e.reg.RootByDigest(gone.Digest); found {
			t.Fatal("pruned root still found")
		}
	}
	if _, found, _ := e.reg.RootByDigest(latest.Digest); !found {
		t.Fatal("latest root was pruned")
	}
}

// A root the keep predicate holds (bound by retained dispatch evidence) is never pruned.
func TestPruneRootsBelowKeepsReferencedRoots(t *testing.T) {
	e := newEnv(t)
	a := e.addCortex(0x11, 1)
	e.mustAccept(a, e.handraise(a, 100, 1))
	bound := e.mustIssue()
	e.height.set(110)
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 110, 1))
	free := e.mustIssue()
	e.height.set(120)
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 120, 1))
	e.mustIssue()

	n, err := e.reg.PruneRootsBelow(200, func(d [32]byte) bool { return d == bound.Digest })
	if err != nil || n != 1 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	if _, found, _ := e.reg.RootByDigest(bound.Digest); !found {
		t.Fatal("referenced root was pruned")
	}
	if _, found, _ := e.reg.RootByDigest(free.Digest); found {
		t.Fatal("unreferenced root kept")
	}
}

func rootDigest(t *testing.T, root *taskv1.SignedHandraiseRootV1) [32]byte {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(rootName, raw)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func toHashes(in [][]byte) [][32]byte {
	out := make([][32]byte, len(in))
	for i := range in {
		copy(out[i][:], in[i])
	}
	return out
}
