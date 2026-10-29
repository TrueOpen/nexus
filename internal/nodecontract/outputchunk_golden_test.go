package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// Streaming output conformance vectors,
// compared byte-for-byte: TRUEOPEN_OUTPUT_MMR_V1 prefix roots / final root / empty output, and
// TRUEOPEN_OUTPUT_CHUNK_V1 signing digests, preimage and signatures from wire output_mmr_v1.json.
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

type wireOutputChunkCase struct {
	Seq          uint64 `json:"seq"`
	MMRRootHex   string `json:"mmr_root_hex"`
	DigestHex    string `json:"digest_hex"`
	PreimageHex  string `json:"preimage_hex"`
	SignatureHex string `json:"signature_hex"`
}

type wireOutputMMR struct {
	Chunk struct {
		TicketHex     string                `json:"dispatch_ticket_hash_hex"`
		PrivateKeyHex string                `json:"test_private_key_hex"`
		Cases         []wireOutputChunkCase `json:"cases"`
	} `json:"chunk_signing"`
	Fin struct {
		ChainID     string `json:"chain_id"`
		TaskHashHex string `json:"task_hash_hex"`
		TicketHex   string `json:"dispatch_ticket_hash_hex"`
		FinalSeq    uint64 `json:"final_seq"`
		RootHex     string `json:"output_mmr_root_hex"`
		Accepted    []struct {
			Value     uint32 `json:"value"`
			DigestHex string `json:"digest_hex"`
		} `json:"accepted_finish_reasons"`
		Rejected []struct {
			Value int64 `json:"value"`
		} `json:"rejected_finish_reason_values"`
		Mutations []struct {
			Field     string          `json:"field"`
			Value     json.RawMessage `json:"value"`
			ValueHex  string          `json:"value_hex"`
			DigestHex string          `json:"digest_hex"`
		} `json:"mutation_digests"`
		PreimageHex  string `json:"eos_token_preimage_hex"`
		SignatureHex string `json:"eos_token_signature_hex"`
	} `json:"fin_signing"`
}

func loadWireOutputMMR(t *testing.T) wireOutputMMR {
	t.Helper()
	var v wireOutputMMR
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/output_mmr_v1.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return raw
}

// signRFC6979 signs a digest with the vector key: RFC6979 deterministic, raw64 R||S low-S.
func signRFC6979(t *testing.T, keyHex string, digest [32]byte) string {
	t.Helper()
	sig := ecdsa.Sign(secp256k1.PrivKeyFromBytes(mustHex(t, keyHex)), digest[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	return hex.EncodeToString(append(rb[:], sb[:]...))
}

// TestGoldenOutputChunkSigningDigest: every wire chunk_signing case, including the ticket binding.
func TestGoldenOutputChunkSigningDigest(t *testing.T) {
	v := loadWireOutputMMR(t)
	taskHash := mustHex(t, goldenTaskHash)
	ticket := mustHex(t, v.Chunk.TicketHex)
	if len(v.Chunk.Cases) == 0 {
		t.Fatal("wire chunk_signing has no cases")
	}
	for _, c := range v.Chunk.Cases {
		digest, err := OutputChunkSigningDigest(goldenChainID, taskHash, ticket, c.Seq, mustHex(t, c.MMRRootHex))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(digest[:]); got != c.DigestHex {
			t.Fatalf("seq %d digest = %s, want %s", c.Seq, got, c.DigestHex)
		}
		if c.PreimageHex != "" {
			if sha256.Sum256(mustHex(t, c.PreimageHex)) != digest {
				t.Fatalf("seq %d: published preimage does not hash to the digest", c.Seq)
			}
		}
		if got := signRFC6979(t, v.Chunk.PrivateKeyHex, digest); got != c.SignatureHex {
			t.Fatalf("seq %d signature = %s, want %s", c.Seq, got, c.SignatureHex)
		}
	}
	// Another ticket must change the digest: an attempt cannot reuse another attempt's frames.
	first := v.Chunk.Cases[0]
	other := bytes.Repeat([]byte{0x34}, 32)
	digest, err := OutputChunkSigningDigest(goldenChainID, taskHash, other, first.Seq, mustHex(t, first.MMRRootHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) == first.DigestHex {
		t.Fatal("dispatch_ticket_hash must be committed")
	}
}
