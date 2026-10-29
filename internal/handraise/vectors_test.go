package handraise

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const dispatchVectors = "task/dispatch_v1.json"

// singleLeafRoot is the handraise root over the one leaf of the wire handraise_root_leaf_admitted
// vector (leaf digest 9866bd91...).
const singleLeafRoot = "34e24171d240cab61ec9fcc4ff388d8737919fec23d86acd03c9dc7b3b7e8010"

// merkleCase is one independently computed handraise tree of the wire handraise_merkle vectors.
type merkleCase struct {
	Name            string   `json:"name"`
	StandingDigests []string `json:"standing_digests_hex"`
	LeafDigests     []string `json:"leaf_digests_hex"`
	Root            string   `json:"root_hex"`
	Proofs          []struct {
		LeafIndex uint32   `json:"leaf_index"`
		Siblings  []string `json:"siblings_hex"`
	} `json:"proofs"`
}

func loadMerkleCases(t *testing.T) (map[string]merkleCase, string) {
	t.Helper()
	var doc struct {
		Merkle struct {
			SignedRootVector string       `json:"signed_root_vector"`
			Cases            []merkleCase `json:"cases"`
		} `json:"handraise_merkle"`
	}
	if err := json.Unmarshal(wirefixture.Load(t, dispatchVectors).Raw, &doc); err != nil {
		t.Fatal(err)
	}
	cases := map[string]merkleCase{}
	for _, c := range doc.Merkle.Cases {
		cases[c.Name] = c
	}
	for _, name := range []string{"empty", "single", "odd_three"} {
		if _, ok := cases[name]; !ok {
			t.Fatalf("wire handraise_merkle case %q missing", name)
		}
	}
	return cases, doc.Merkle.SignedRootVector
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("%q is not 32 bytes", s)
	}
	return [32]byte(b)
}

type signedVector struct {
	ProtobufHex  string `json:"protobuf_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
}

func loadSigned(t *testing.T, v wirefixture.Vector) (raw, pub, sig []byte) {
	t.Helper()
	var sv signedVector
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	return mustHex(t, sv.ProtobufHex), mustHex(t, sv.PublicKeyHex), mustHex(t, sv.SignatureHex)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The wire StandingHandraiseV1 vector is accepted as signed, and the root built over it has the
// wire leaf digest and root.
func TestStandingHandraiseVectorAcceptedAndRooted(t *testing.T) {
	file := wirefixture.Load(t, dispatchVectors)
	vector := file.Vector(t, "task_v1_standinghandraisev1", 0)
	raw, pub, sig := loadSigned(t, vector)
	var h taskv1.StandingHandraiseV1
	if err := proto.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h.GetServiceSignature(), sig) {
		t.Fatal("vector signature field differs from signature_hex")
	}
	digest, err := StandingDigest(&h)
	if err != nil || digest != vector.Digest(t) {
		t.Fatalf("standing digest = %x, %v; want %s", digest, err, vector.DigestHex)
	}

	operator := h.GetMember().GetOperatorAddress()
	keys := &fakeKeys{cortex: map[string]*fakeKey{operator: {pub: pub, nonce: h.GetServiceAuthorizationNonce()}}}
	pool := &fakePool{
		members: map[string]bool{operator: true},
		support: map[string]map[string]bool{operator: {profileKey(h.GetProfiles()[0]): true}},
	}
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	reg, err := New(Options{
		ChainID: h.GetChainId(), BuilderAddress: h.GetBuilderAddress(), Config: testDispatchConfig(),
		Store: kv.NewMemStore(), Keys: keys, Pool: pool, Height: &fakeHeight{h: 1},
		Signer: newSigner(t, 0x01), Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Accept(context.Background(), operator, &h); err != nil {
		t.Fatalf("wire vector handraise refused: %v", err)
	}
	issued, err := reg.IssueRoot(context.Background())
	if err != nil || issued == nil {
		t.Fatalf("issue root: %v", err)
	}

	leafVector := file.Vector(t, "handraise_root_leaf_admitted", 0)
	leafVector.CheckPreimage(t)
	leafDigest, err := LeafDigest(issued.Leaves[0])
	if err != nil || leafDigest != leafVector.Digest(t) {
		t.Fatalf("leaf digest = %x, %v; want %s", leafDigest, err, leafVector.DigestHex)
	}

	// The root over that one leaf is the wire "single" tree and the root the signed root vector
	// carries.
	cases, signedRootName := loadMerkleCases(t)
	single := cases["single"]
	if got := hex.EncodeToString(issued.Root.GetRoot()); got != singleLeafRoot || got != single.Root {
		t.Fatalf("single-leaf root = %s, want %s", got, single.Root)
	}
	if len(single.StandingDigests) != 1 || single.StandingDigests[0] != vector.DigestHex ||
		len(single.LeafDigests) != 1 || single.LeafDigests[0] != leafVector.DigestHex {
		t.Fatalf("wire single tree is not over the standing and leaf vectors: %+v", single)
	}
	if got := file.Vector(t, signedRootName, 0).Field(t, "root").Hex; got != single.Root {
		t.Fatalf("signed root vector root = %s, want %s", got, single.Root)
	}
	notice, ok := issued.Notice(operator)
	if !ok || notice.GetProof().GetLeafIndex() != 0 || len(notice.GetProof().GetSiblings()) != 0 ||
		!dispatch.VerifyHandraiseProof([32]byte(issued.Root.GetRoot()), leafDigest, 0, 1, nil) {
		t.Fatalf("single-leaf notice = %v", notice)
	}
}

// Signing the wire SignedHandraiseRootV1 vector's fields with the fixture key reproduces its bytes,
// digest and signature exactly.
func TestSignedHandraiseRootVector(t *testing.T) {
	vector := wirefixture.Load(t, dispatchVectors).Vector(t, "task_v1_signedhandraiserootv1", 0)
	vector.CheckPreimage(t)
	raw, pub, sig := loadSigned(t, vector)
	key := newSigner(t, 0x01)
	if !bytes.Equal(key.PubKeyCompressed(), pub) {
		t.Fatal("fixture key is not the vector key")
	}
	root := &taskv1.SignedHandraiseRootV1{
		ChainId:        "trueopen-phase1-vector-1",
		BuilderAddress: vector.Field(t, "builder_address").Bech32,
		RootHeight:     vector.Field(t, "root_height").Uint64(t),
		RootVersion:    vector.Field(t, "root_version").Uint64(t),
		LeafCount:      uint32(vector.Field(t, "leaf_count").Uint64(t)),
		Root:           vector.Field(t, "root").Bytes(t),
	}
	gotRaw, digest, err := signRoot(key, root)
	if err != nil {
		t.Fatal(err)
	}
	if digest != vector.Digest(t) {
		t.Fatalf("root digest = %x, want %s", digest, vector.DigestHex)
	}
	if !bytes.Equal(root.GetBuilderServiceSignature(), sig) {
		t.Fatalf("signature = %x, want %x", root.GetBuilderServiceSignature(), sig)
	}
	if !bytes.Equal(gotRaw, raw) {
		t.Fatalf("root bytes = %x, want %x", gotRaw, raw)
	}
}

// The wire handraise_merkle trees: an issued root over their leaf digests has their root and hands
// out their inclusion paths, and leaves are in ascending standing digest order.
func TestHandraiseMerkleVectors(t *testing.T) {
	cases, _ := loadMerkleCases(t)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if len(c.StandingDigests) != len(c.LeafDigests) || len(c.Proofs) != len(c.LeafDigests) {
				t.Fatalf("malformed case: %+v", c)
			}
			issued := &IssuedRoot{Root: &taskv1.SignedHandraiseRootV1{LeafCount: uint32(len(c.LeafDigests))}}
			for i, digest := range c.LeafDigests {
				if i > 0 && c.StandingDigests[i-1] >= c.StandingDigests[i] {
					t.Fatal("wire leaves are not in ascending standing digest order")
				}
				issued.Leaves = append(issued.Leaves, &taskv1.HandraiseRootLeafV1{})
				issued.leafDigests = append(issued.leafDigests, hex32(t, digest))
			}
			root := dispatch.HandraiseRoot(issued.leafDigests)
			if hex.EncodeToString(root[:]) != c.Root {
				t.Fatalf("root = %x, want %s", root, c.Root)
			}
			for _, want := range c.Proofs {
				proof, err := issued.Proof(want.LeafIndex)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]string, len(proof.GetSiblings()))
				for i, s := range proof.GetSiblings() {
					got[i] = hex.EncodeToString(s)
				}
				if strings.Join(got, ",") != strings.Join(want.Siblings, ",") {
					t.Fatalf("leaf %d siblings = %v, want %v", want.LeafIndex, got, want.Siblings)
				}
				if !dispatch.VerifyHandraiseProof(root, issued.leafDigests[want.LeafIndex], want.LeafIndex, issued.Root.GetLeafCount(), toHashes(proof.GetSiblings())) {
					t.Fatalf("leaf %d proof does not verify", want.LeafIndex)
				}
			}
		})
	}
}

// A root issued after every handraise expired is the wire empty tree.
func TestEmptyRootMatchesWireVector(t *testing.T) {
	cases, _ := loadMerkleCases(t)
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.mustAccept(c, e.handraise(c, 100, 1))
	e.mustIssue()
	e.clock.advance(6*time.Second + time.Millisecond)
	empty := e.mustIssue()
	if empty.Root.GetLeafCount() != 0 || hex.EncodeToString(empty.Root.GetRoot()) != cases["empty"].Root {
		t.Fatalf("empty root = %d leaves, %x; want %s", empty.Root.GetLeafCount(), empty.Root.GetRoot(), cases["empty"].Root)
	}
}
