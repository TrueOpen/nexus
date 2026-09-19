package mmr

import (
	"encoding/hex"
	"testing"
)

// MMR_ROOT_V1 primitive vectors from monorepo 10-Protocol Spec/00-Base Spec/Canonical
// Encoding and Domain Hashing.md §11.5, compared byte for byte. These are cross-language
// conformance vectors, not expectations computed by this implementation.
const goldenDomain = "TRUEOPEN_TEST_MMR_V1"

var goldenLeaves = [][]byte{
	[]byte("a"), []byte("bb"), []byte("ccc"), []byte("dddd"),
	[]byte("eeeee"), []byte("ffffff"), []byte("ggggggg"),
}

func mustHash(t *testing.T, encoded string) Hash {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad fixture hex %q", encoded)
	}
	var h Hash
	copy(h[:], raw)
	return h
}

func TestGoldenPrimitiveVectors(t *testing.T) {
	empty, err := Root(goldenDomain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(empty[:]); got != "3c16dfdfb27ee4ced6c1b13b9a50ed851bb5920197cbc4860e2cebfef120e1cb" {
		t.Fatalf("empty_root = %s", got)
	}
	for _, c := range []struct {
		n    int
		want string
	}{
		{1, "dbc7d3e5c3605543519d154eb0a305ee58b8139f73430235efea8aa599b6093d"},
		{2, "9862fe9d7ba78edad8ca4cb4b03a30a2be04c5d6ac8db82f4e4253f2286d302d"},
		{3, "1ae71241b47a2e87318b726529eacb9d18e3f44d6f4f1426acc3a3e010a4c199"},
		{7, "fa774b62e96d1dc3b5348e049842a9cadc2145baa9ac68d5a91eb9f36150b381"},
	} {
		root, err := Root(goldenDomain, goldenLeaves[:c.n])
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(root[:]); got != c.want {
			t.Fatalf("root_n%d = %s, want %s", c.n, got, c.want)
		}
	}
	// With n = 1 the root is the leaf itself, with no extra node layer.
	leaf := LeafHash(goldenDomain, 0, goldenLeaves[0])
	root1, _ := Root(goldenDomain, goldenLeaves[:1])
	if leaf != root1 {
		t.Fatal("root_n1 must equal MmrLeafV1(domain, 0, leaf)")
	}
}

// §11.5 pins the peak shape: n=3 is [height 1, height 0], n=7 is [height 2, height 1, height 0].
func TestGoldenPeakShapes(t *testing.T) {
	for _, c := range []struct {
		n     int
		peaks []string
	}{
		{3, []string{
			"9862fe9d7ba78edad8ca4cb4b03a30a2be04c5d6ac8db82f4e4253f2286d302d",
			"07886768c375a879d63ea64242caaf98d2b4d734be2a52b92e4c9e5c9fd20d12",
		}},
		{7, []string{
			"650b6e585f9b2d3357385cfb7e5943fb9f2c0284feb9b6c23c92a123d4f7cb95",
			"f4555b4f56afe1c8bea51912bda1f1cb20e18ad4309c62217dd09dc837c22c3b",
			"e84e98ddb1479f3a1c41dedc15f8e8f699290c5fe719317f18668434d7e9d8a0",
		}},
	} {
		acc, err := New(goldenDomain)
		if err != nil {
			t.Fatal(err)
		}
		for _, leaf := range goldenLeaves[:c.n] {
			acc.Append(leaf)
		}
		peaks := acc.Peaks()
		if len(peaks) != len(c.peaks) {
			t.Fatalf("n=%d peak count = %d, want %d", c.n, len(peaks), len(c.peaks))
		}
		for i, want := range c.peaks {
			if got := hex.EncodeToString(peaks[i][:]); got != want {
				t.Fatalf("n=%d peak %d = %s, want %s", c.n, i, got, want)
			}
		}
	}
	// Root for n=3 = MmrNodeV1(height-1 peak, height-0 peak); pins the left/right argument order.
	root3, _ := Root(goldenDomain, goldenLeaves[:3])
	if want := NodeHash(goldenDomain,
		mustHash(t, "9862fe9d7ba78edad8ca4cb4b03a30a2be04c5d6ac8db82f4e4253f2286d302d"),
		mustHash(t, "07886768c375a879d63ea64242caaf98d2b4d734be2a52b92e4c9e5c9fd20d12"),
	); root3 != want {
		t.Fatal("root_n3 must fold the height-1 peak as left and the height-0 peak as right")
	}
	// root_2 equals byte for byte the height-1 peak of the n=3 tree (smallest example of §9 item 6).
	root2, _ := Root(goldenDomain, goldenLeaves[:2])
	if hex.EncodeToString(root2[:]) != "9862fe9d7ba78edad8ca4cb4b03a30a2be04c5d6ac8db82f4e4253f2286d302d" {
		t.Fatal("root_2 must equal the height-1 peak of the n=3 tree")
	}
}

// Negative vector from §11.5: folding in the wrong direction (acc = Node(acc, peak)
// starting from the leftmost peak) yields a different root and must be rejected as
// non-conformant. n=7 is the smallest leaf count that distinguishes the two directions.
func TestGoldenFoldDirectionIsRightToLeft(t *testing.T) {
	acc, err := New(goldenDomain)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range goldenLeaves[:7] {
		acc.Append(leaf)
	}
	peaks := acc.Peaks()
	reversed := peaks[0]
	for _, peak := range peaks[1:] {
		reversed = NodeHash(goldenDomain, reversed, peak)
	}
	const wrong = "e295ae79a9d65352bb7f66ea5c55c7736c230d194206c1f334c0f8281a3ea88b"
	if got := hex.EncodeToString(reversed[:]); got != wrong {
		t.Fatalf("left-to-right fold = %s, want the spec's non-compliant value %s", got, wrong)
	}
	if acc.Root() == reversed {
		t.Fatal("right-to-left fold must differ from left-to-right at n=7")
	}
}
