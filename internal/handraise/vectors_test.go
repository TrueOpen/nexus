package handraise

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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
	keys := &fakeKeys{cortex: map[string]*fakeKey{operator: {pub: pub, nonce: h.GetServiceAuthorizationNonce()}}, builderNonce: 1}
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

	// The root field of the wire SignedHandraiseRootV1 vector is a filler value, not the root of
	// the leaf vector, so the single-leaf root is checked against the wire tree function and
	// pinned until wire publishes a root vector.
	if want := dispatch.HandraiseRoot([][32]byte{leafDigest}); !bytes.Equal(issued.Root.GetRoot(), want[:]) {
		t.Fatalf("root = %x, want %x", issued.Root.GetRoot(), want)
	}
	if got := hex.EncodeToString(issued.Root.GetRoot()); got != singleLeafRoot {
		t.Fatalf("single-leaf root = %s, want %s", got, singleLeafRoot)
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
		ChainId:                   "trueopen-phase1-vector-1",
		BuilderAddress:            vector.Field(t, "builder_address").Bech32,
		RootHeight:                vector.Field(t, "root_height").Uint64(t),
		RootVersion:               vector.Field(t, "root_version").Uint64(t),
		LeafCount:                 uint32(vector.Field(t, "leaf_count").Uint64(t)),
		Root:                      vector.Field(t, "root").Bytes(t),
		ServiceAuthorizationNonce: vector.Field(t, "service_authorization_nonce").Uint64(t),
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
