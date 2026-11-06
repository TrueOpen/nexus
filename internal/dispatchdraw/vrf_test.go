package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const dispatchVectors = "task/dispatch_v1.json"

// The VRF input digest is the wire DispatchVrfInputV1 signing digest and the protobuf bytes it is
// computed from are the wire vector's.
func TestVRFAlphaMatchesWireVector(t *testing.T) {
	v := wirefixture.Load(t, dispatchVectors).Vector(t, "task_v1_dispatchvrfinputv1", 0)
	v.CheckPreimage(t)
	var seed, session [32]byte
	copy(seed[:], v.Field(t, "epoch_seed").Bytes(t))
	copy(session[:], v.Field(t, "session_id").Bytes(t))
	in := vrfInput(v.Field(t, "chain_id").UTF8, v.Field(t, "epoch").Uint64(t), seed, session, v.Field(t, "order_sequence").Uint64(t))

	var want struct {
		ProtobufHex string `json:"protobuf_hex"`
	}
	if err := json.Unmarshal(v.Raw, &want); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(in)
	if err != nil || hex.EncodeToString(raw) != want.ProtobufHex {
		t.Fatalf("protobuf = %x, %v; want %s", raw, err, want.ProtobufHex)
	}
	alpha, err := VRFAlpha(in.GetChainId(), in.GetEpoch(), seed, session, in.GetOrderSequence())
	if err != nil || alpha != v.Digest(t) {
		t.Fatalf("alpha = %x, %v; want %s", alpha, err, v.DigestHex)
	}
}

// Proving the wire VRF vector's alpha with its key gives the vector's proof and randomness.
func TestProveMatchesWireVRFVector(t *testing.T) {
	file := wirefixture.Load(t, dispatchVectors)
	var vec struct {
		VRF struct {
			Alpha      string `json:"alpha_hex"`
			Seed       string `json:"private_seed_hex"`
			Proof      string `json:"proof_hex"`
			PublicKey  string `json:"public_key_hex"`
			Randomness string `json:"randomness_hex"`
		} `json:"vrf"`
	}
	if err := json.Unmarshal(file.Raw, &vec); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(mustHex(t, vec.VRF.Seed))
	if !bytes.Equal(key.Public().(ed25519.PublicKey), mustHex(t, vec.VRF.PublicKey)) {
		t.Fatal("vector public key does not derive from its seed")
	}
	// The vector alpha is the DispatchVrfInputV1 vector digest, so prove through the real input.
	in := file.Vector(t, "task_v1_dispatchvrfinputv1", 0)
	if in.DigestHex != vec.VRF.Alpha {
		t.Fatalf("vrf alpha %s is not the DispatchVrfInputV1 digest %s", vec.VRF.Alpha, in.DigestHex)
	}
	var seed, session [32]byte
	copy(seed[:], in.Field(t, "epoch_seed").Bytes(t))
	copy(session[:], in.Field(t, "session_id").Bytes(t))
	epoch := in.Field(t, "epoch").Uint64(t)

	keys, err := NewVRFKeys([]ed25519.PrivateKey{key}, registryFor(map[uint64]ed25519.PrivateKey{epoch: key}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := keys.Prove(context.Background(), in.Field(t, "chain_id").UTF8, Epoch{Number: epoch, Seed: seed}, session, in.Field(t, "order_sequence").Uint64(t))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.Proof) != vec.VRF.Proof || hex.EncodeToString(got.Output[:]) != vec.VRF.Randomness {
		t.Fatalf("proof = %x output = %x; want %s / %s", got.Proof, got.Output, vec.VRF.Proof, vec.VRF.Randomness)
	}
	if got.Epoch != epoch || hex.EncodeToString(got.Alpha[:]) != vec.VRF.Alpha {
		t.Fatalf("proof epoch %d alpha %x", got.Epoch, got.Alpha)
	}
}

// r depends only on (chain, epoch, epoch seed, session, sequence): the same order proven again,
// re-signed with other content, or re-dispatched in a later round gets the same r.
func TestProveIsDeterministicPerSessionSequenceEpoch(t *testing.T) {
	key := testKey(7)
	keys, err := NewVRFKeys([]ed25519.PrivateKey{key}, registryFor(map[uint64]ed25519.PrivateKey{3: key, 4: key}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ep3 := Epoch{Number: 3, ReferenceHeight: 300, Seed: fill32(0x03), SnapshotID: fill32(0x13)}
	ep4 := Epoch{Number: 4, ReferenceHeight: 400, Seed: fill32(0x04), SnapshotID: fill32(0x14)}
	session := fill32(0xab)

	base, err := keys.Prove(ctx, "chain-1", ep3, session, 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.VerifyDispatchVRF(key.Public().(ed25519.PublicKey), base.Alpha[:], base.Proof, base.Output[:]); err != nil {
		t.Fatalf("proof does not verify: %v", err)
	}
	again, _ := keys.Prove(ctx, "chain-1", ep3, session, 9)
	if again.Output != base.Output || !bytes.Equal(again.Proof, base.Proof) {
		t.Fatal("same (session, sequence, epoch) must give the same r and proof")
	}
	variants := map[string]VRFProof{}
	variants["sequence"], _ = keys.Prove(ctx, "chain-1", ep3, session, 10)
	variants["session"], _ = keys.Prove(ctx, "chain-1", ep3, fill32(0xac), 9)
	variants["epoch"], _ = keys.Prove(ctx, "chain-1", ep4, session, 9)
	variants["chain"], _ = keys.Prove(ctx, "chain-2", ep3, session, 9)
	for name, v := range variants {
		if v.Output == base.Output {
			t.Fatalf("changing the %s must change r", name)
		}
	}
	// The reference height and snapshot are not VRF inputs.
	shifted := ep3
	shifted.ReferenceHeight, shifted.SnapshotID = 301, fill32(0x99)
	if same, _ := keys.Prove(ctx, "chain-1", shifted, session, 9); same.Output != base.Output {
		t.Fatal("reference height and snapshot must not change r")
	}
}

func TestProveRefusesWithoutTheRegisteredKey(t *testing.T) {
	keys, _ := NewVRFKeys([]ed25519.PrivateKey{testKey(1)}, registryFor(map[uint64]ed25519.PrivateKey{3: testKey(2)}))
	_, err := keys.Prove(context.Background(), "chain-1", Epoch{Number: 3}, fill32(1), 1)
	if !errors.Is(err, ErrVRFKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}
