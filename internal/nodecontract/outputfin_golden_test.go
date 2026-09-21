package nodecontract

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// TrueOpen/wire v0.2.0 testdata/v1/task/output_mmr_v1.json "fin_signing", compared byte-for-byte:
// the TRUEOPEN_OUTPUT_FIN_V1 digest for each accepted finish reason, the full EOS_TOKEN preimage
// and the RFC6979 signature under the vector's test key.
const (
	goldenFinFinalSeq   = uint64(3)
	goldenFinOutputRoot = "17da96c6c109eb9889d40d667f726a0fdbb8a0c85173d2274aef93e93ebb0d45"
	goldenFinTestKey    = "0101010101010101010101010101010101010101010101010101010101010101"
)

var goldenFinDigests = []struct {
	reason uint32
	want   string
}{
	{1, "442343e71f2b2fa73e4c181941dc4e76f463b8dab9d0177b7d54c393ff5a2461"}, // EOS_TOKEN
	{2, "c65d52dff6a5b9b3eb83c15f706b440103cbb1cca878230dda004ac0511ea648"}, // STOP_SEQUENCE
	{3, "2556cd175ab1b82440ce6058abbca5560d8affc6a85be2e1c31f148d469bb3c3"}, // MAX_OUTPUT_TOKENS
	{4, "aea9a07c4693672496243e6ef85c547be0555b03d1caa55223ad8805f2bce5e0"}, // MAX_OUTPUT_DURATION
}

func TestGoldenOutputFinSigningDigest(t *testing.T) {
	taskHash, _ := hex.DecodeString(goldenTaskHash)
	root, _ := hex.DecodeString(goldenFinOutputRoot)
	for _, c := range goldenFinDigests {
		digest, err := OutputFinSigningDigest(goldenChainID, taskHash, goldenFinFinalSeq, root, c.reason)
		if err != nil {
			t.Fatalf("finish_reason %d: %v", c.reason, err)
		}
		if got := hex.EncodeToString(digest[:]); got != c.want {
			t.Fatalf("finish_reason %d digest = %s, want %s", c.reason, got, c.want)
		}
	}
	// rejected_finish_reason_values: UNSPECIFIED and unknown values fail closed before any digest.
	for _, reason := range []uint32{0, 5} {
		if _, err := OutputFinSigningDigest(goldenChainID, taskHash, goldenFinFinalSeq, root, reason); err == nil {
			t.Fatalf("finish_reason %d must be rejected", reason)
		}
	}
	// mutation_digests: each field mutated alone yields exactly the vector's digest.
	otherTask, _ := hex.DecodeString("1011111111111111111111111111111111111111111111111111111111111111")
	otherRoot, _ := hex.DecodeString("6df2d843848de023d294eb25f4eb7b0b763bd28de0d6b363a5d79e3468d27c5d")
	for _, m := range []struct {
		field    string
		chainID  string
		taskHash []byte
		finalSeq uint64
		root     []byte
		reason   uint32
		want     string
	}{
		{"chain_id", "trueopen-localnet-2", taskHash, goldenFinFinalSeq, root, 1, "36836105877d00df6612575b2b83bb6e2127703d5ec0d70a685b88361eace994"},
		{"task_hash", goldenChainID, otherTask, goldenFinFinalSeq, root, 1, "6adc6e19594c720e9bff13b3e2f5f0b1e464b6f23b265a4258cac653205c112a"},
		{"final_seq", goldenChainID, taskHash, 2, root, 1, "8e847f980e947467ea0de7b9bc88d4f466f5cda04e0ccba6f77e0838d9b781ed"},
		{"output_mmr_root", goldenChainID, taskHash, goldenFinFinalSeq, otherRoot, 1, "b01a94af3e8c41f258dd5938aa743a0e9189c976c24cb2b22ea73d5262924a11"},
		{"finish_reason", goldenChainID, taskHash, goldenFinFinalSeq, root, 2, "c65d52dff6a5b9b3eb83c15f706b440103cbb1cca878230dda004ac0511ea648"},
	} {
		digest, err := OutputFinSigningDigest(m.chainID, m.taskHash, m.finalSeq, m.root, m.reason)
		if err != nil {
			t.Fatalf("%s mutation: %v", m.field, err)
		}
		if got := hex.EncodeToString(digest[:]); got != m.want {
			t.Fatalf("%s mutation digest = %s, want %s", m.field, got, m.want)
		}
	}
}

// eos_token_preimage_hex pins field order and length prefixes byte-for-byte.
func TestGoldenOutputFinPreimage(t *testing.T) {
	taskHash, _ := hex.DecodeString(goldenTaskHash)
	root, _ := hex.DecodeString(goldenFinOutputRoot)
	chain, err := CanonicalUTF8Field("chain_id", goldenChainID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := CanonicalHash32Field("task_hash", taskHash)
	if err != nil {
		t.Fatal(err)
	}
	r, err := CanonicalHash32Field("output_mmr_root", root)
	if err != nil {
		t.Fatal(err)
	}
	preimage := CanonicalFramePreimage(DomainOutputFinV1, chain, task, Uint64BE(goldenFinFinalSeq), r, Uint32BE(1))
	want := strings.Join([]string{
		"0000000000000016", "545255454f50454e5f4f55545055545f46494e5f5631", // "TRUEOPEN_OUTPUT_FIN_V1"
		"0000000000000013", "747275656f70656e2d6c6f63616c6e65742d31", // "trueopen-localnet-1"
		"0000000000000020", goldenTaskHash,
		"0000000000000008", "0000000000000003", // final_seq = 3
		"0000000000000020", goldenFinOutputRoot,
		"0000000000000004", "00000001", // finish_reason = EOS_TOKEN
	}, "")
	if got := hex.EncodeToString(preimage); got != want {
		t.Fatalf("preimage = %s, want %s", got, want)
	}
}

// eos_token_signature_hex: secp256k1 direct over the digest, RFC6979 deterministic, raw64 R||S low-S.
func TestGoldenOutputFinSignature(t *testing.T) {
	taskHash, _ := hex.DecodeString(goldenTaskHash)
	root, _ := hex.DecodeString(goldenFinOutputRoot)
	digest, err := OutputFinSigningDigest(goldenChainID, taskHash, goldenFinFinalSeq, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(goldenFinTestKey)
	sig := ecdsa.Sign(secp256k1.PrivKeyFromBytes(key), digest[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	raw := append(rb[:], sb[:]...)
	const want = "40716cbc643760286c2b2d5cefb028abb708330925958d6885bf449407c54c66679a3c3f50a748927d3bed4a869f2ef6b517e379b2e167219a22dddbfd2e4afa"
	if got := hex.EncodeToString(raw); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
	pub := secp256k1.PrivKeyFromBytes(key).PubKey()
	if got := hex.EncodeToString(pub.SerializeCompressed()); got != "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f" {
		t.Fatalf("test public key = %s", got)
	}
}
