package nodecontract

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/mmr"
)

// monorepo Verification Algorithm §8.1 "business conformance vectors",
// compared byte-for-byte: TRUEOPEN_OUTPUT_MMR_V1 prefix roots / final root / empty output, and
// TRUEOPEN_OUTPUT_CHUNK_V1 signing digest and full preimage.
const (
	goldenChainID  = "trueopen-localnet-1"
	goldenTaskHash = "1111111111111111111111111111111111111111111111111111111111111111"
)

var goldenChunks = [][]byte{[]byte("Hello"), []byte(", "), []byte("world"), []byte("!")}

func TestGoldenOutputMMRRoots(t *testing.T) {
	want := []string{
		"43563e7c76e0b5a63993b14b15d8d3db5be6a111e81e89532b426748997596ff",
		"6dfe72f925fdb0a408ad83b1339199d7a5cac40a0d79a0515cf167a858e5fa77",
		"6df2d843848de023d294eb25f4eb7b0b763bd28de0d6b363a5d79e3468d27c5d",
		"17da96c6c109eb9889d40d667f726a0fdbb8a0c85173d2274aef93e93ebb0d45", // output_hash, leaf_count = 4
	}
	acc, err := mmr.New(DomainOutputMMRV1)
	if err != nil {
		t.Fatal(err)
	}
	for i, chunk := range goldenChunks {
		root := acc.Append(chunk)
		if got := hex.EncodeToString(root[:]); got != want[i] {
			t.Fatalf("root_%d = %s, want %s", i+1, got, want[i])
		}
	}
	// Empty output is one zero-length leaf, not an empty tree.
	empty, err := mmr.Root(DomainOutputMMRV1, [][]byte{{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(empty[:]); got != "df63f8049ceef9870c9238e256a1af5bd0011692f442cc6141b3b3a69517a9a6" {
		t.Fatalf("empty output_hash = %s", got)
	}
	if empty == mmr.EmptyRoot(DomainOutputMMRV1) {
		t.Fatal("empty output must not be the empty-tree root")
	}
	// mutation: splitting/merging chunks and swapping order must all change the root.
	merged, _ := mmr.Root(DomainOutputMMRV1, [][]byte{[]byte("Hello, "), []byte("world"), []byte("!")})
	swapped, _ := mmr.Root(DomainOutputMMRV1, [][]byte{[]byte(", "), []byte("Hello"), []byte("world"), []byte("!")})
	final := acc.Root()
	if merged == final || swapped == final {
		t.Fatal("re-chunking or reordering must change output_hash")
	}
}

func TestGoldenOutputChunkSigningDigest(t *testing.T) {
	taskHash, err := hex.DecodeString(goldenTaskHash)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := mmr.New(DomainOutputMMRV1)
	if err != nil {
		t.Fatal(err)
	}
	roots := make([][]byte, 0, len(goldenChunks))
	for _, chunk := range goldenChunks {
		root := acc.Append(chunk)
		roots = append(roots, append([]byte(nil), root[:]...))
	}
	for _, c := range []struct {
		seq  uint64
		want string
	}{
		{0, "269082934bde72d562dc9d4850202be3240a2d8a14217d0ce95f6da852d26429"},
		{1, "f36f8dbbcbb6f0d1703ce01154ca4fc60ff6061434c4a56dbf7e72c14858fccf"},
	} {
		digest, err := OutputChunkSigningDigest(goldenChainID, taskHash, c.seq, roots[c.seq])
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(digest[:]); got != c.want {
			t.Fatalf("seq %d digest = %s, want %s", c.seq, got, c.want)
		}
	}
	// A mismatched seq and mmr_root pair must yield a different digest.
	mismatched, err := OutputChunkSigningDigest(goldenChainID, taskHash, 1, roots[0])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(mismatched[:]) == "f36f8dbbcbb6f0d1703ce01154ca4fc60ff6061434c4a56dbf7e72c14858fccf" {
		t.Fatal("seq and mmr_root must be committed together")
	}
	// Changing chain_id to another chain or flipping one bit of task_hash must likewise change the digest.
	otherChain, _ := OutputChunkSigningDigest("trueopen-localnet-2", taskHash, 1, roots[1])
	flipped := append([]byte(nil), taskHash...)
	flipped[0] ^= 0x01
	otherTask, _ := OutputChunkSigningDigest(goldenChainID, flipped, 1, roots[1])
	want := "f36f8dbbcbb6f0d1703ce01154ca4fc60ff6061434c4a56dbf7e72c14858fccf"
	if hex.EncodeToString(otherChain[:]) == want || hex.EncodeToString(otherTask[:]) == want {
		t.Fatal("chain_id and task_hash must be committed")
	}
}

// §8.1 gives the full H_FIELDS_V1 preimage for seq = 1, pinning field order and length prefixes byte-for-byte.
func TestGoldenOutputChunkPreimage(t *testing.T) {
	taskHash, _ := hex.DecodeString(goldenTaskHash)
	root, _ := hex.DecodeString("6dfe72f925fdb0a408ad83b1339199d7a5cac40a0d79a0515cf167a858e5fa77")
	chain, err := CanonicalUTF8Field("chain_id", goldenChainID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := CanonicalHash32Field("task_hash", taskHash)
	if err != nil {
		t.Fatal(err)
	}
	mmrRoot, err := CanonicalHash32Field("mmr_root", root)
	if err != nil {
		t.Fatal(err)
	}
	preimage := CanonicalFramePreimage(DomainOutputChunkV1, chain, task, Uint64BE(1), mmrRoot)
	want := strings.Join([]string{
		"0000000000000018545255454f50454e5f4f55545055545f4348554e4b5f5631",
		"0000000000000013747275656f70656e2d6c6f63616c6e65742d31",
		"00000000000000201111111111111111111111111111111111111111111111111111111111111111",
		"00000000000000080000000000000001",
		"00000000000000206dfe72f925fdb0a408ad83b1339199d7a5cac40a0d79a0515cf167a858e5fa77",
	}, "")
	if got := hex.EncodeToString(preimage); got != want {
		t.Fatalf("preimage = %s, want %s", got, want)
	}
}
