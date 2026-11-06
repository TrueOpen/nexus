package dispatchdraw

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	voied25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/ecvrf"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func vrfKeyPoPVector(t *testing.T) wirefixture.Vector {
	t.Helper()
	v := wirefixture.Load(t, "hub/bridge_vrf_v1.json").Vector(t, "vrf_key_pop_v1", 0)
	v.CheckPreimage(t)
	return v
}

// The possession digest is pinned by wire's vrf_key_pop_v1 vector, including one mutation per
// field: chain_id, raw 20-byte operator address, raw 32-byte VRF public key and the big-endian
// authorization nonce. The participant type is not part of it.
func TestVRFKeyPoPDigestMatchesWireVector(t *testing.T) {
	v := vrfKeyPoPVector(t)
	chainID := v.Field(t, "chain_id").UTF8
	operator := v.Field(t, "operator_address").Bech32
	operatorRaw := v.Field(t, "operator_address").Bytes(t)
	pub := v.Field(t, "vrf_pubkey").Bytes(t)
	nonce := v.Field(t, "vrf_authorization_nonce").Uint64(t)

	got, err := VRFKeyPoPDigest(chainID, operator, pub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got != v.Digest(t) {
		t.Fatalf("digest = %x, want %s", got, v.DigestHex)
	}

	flip := func(b []byte) []byte {
		out := bytes.Clone(b)
		out[len(out)-1] ^= 1
		return out
	}
	mutations := map[string][32]byte{
		"field.chain_id":                vrfKeyPoPDigest("trueopen-golden-0", operatorRaw, pub, nonce),
		"field.operator_address":        vrfKeyPoPDigest(chainID, flip(operatorRaw), pub, nonce),
		"field.vrf_pubkey":              vrfKeyPoPDigest(chainID, operatorRaw, flip(pub), nonce),
		"field.vrf_authorization_nonce": vrfKeyPoPDigest(chainID, operatorRaw, pub, 2),
	}
	var listed struct {
		Mutations []struct {
			Name      string `json:"name"`
			DigestHex string `json:"digest_hex"`
		} `json:"mutations"`
	}
	if err := json.Unmarshal(v.Raw, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Mutations) != len(mutations) {
		t.Fatalf("vector lists %d mutations, test covers %d", len(listed.Mutations), len(mutations))
	}
	for _, m := range listed.Mutations {
		want, ok := mutations[m.Name]
		if !ok {
			t.Fatalf("mutation %s not covered", m.Name)
		}
		if got := hex.EncodeToString(want[:]); got != m.DigestHex {
			t.Fatalf("%s: digest = %s, want %s", m.Name, got, m.DigestHex)
		}
	}
}

func TestVRFKeyPoPDigestRejectsBadInput(t *testing.T) {
	v := vrfKeyPoPVector(t)
	operator := v.Field(t, "operator_address").Bech32
	pub := v.Field(t, "vrf_pubkey").Bytes(t)
	cases := map[string]func() error{
		"empty chain id": func() error { _, err := VRFKeyPoPDigest("", operator, pub, 1); return err },
		"bad operator":   func() error { _, err := VRFKeyPoPDigest("c", "trueopen1bad", pub, 1); return err },
		"upper operator": func() error { _, err := VRFKeyPoPDigest("c", strings.ToUpper(operator), pub, 1); return err },
		"short pubkey":   func() error { _, err := VRFKeyPoPDigest("c", operator, pub[:31], 1); return err },
		"zero nonce":     func() error { _, err := VRFKeyPoPDigest("c", operator, pub, 0); return err },
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if run() == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The possession proof is one ECVRF prove over the digest, in the RFC 9381 suite the chain's
// possession verifier runs (ecvrf.Verify over the submitted public key and the recomputed digest).
func TestProveVRFKeyPossessionVerifiesOnlyForItsKeyAndNonce(t *testing.T) {
	v := vrfKeyPoPVector(t)
	chainID := v.Field(t, "chain_id").UTF8
	operator := v.Field(t, "operator_address").Bech32
	key, other := testKey(7), testKey(8)
	pub := key.Public().(ed25519.PublicKey)

	proof, err := ProveVRFKeyPossession(key, chainID, operator, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 80 {
		t.Fatalf("proof is %d bytes, want 80", len(proof))
	}
	digest, err := VRFKeyPoPDigest(chainID, operator, pub, 3)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(pub []byte, alpha [32]byte) bool {
		ok, _ := ecvrf.Verify(voied25519.PublicKey(pub), proof, alpha[:])
		return ok
	}
	if !verify(pub, digest) {
		t.Fatal("proof does not verify under its key")
	}
	if verify(other.Public().(ed25519.PublicKey), digest) {
		t.Fatal("proof verifies under another key")
	}
	otherNonce, err := VRFKeyPoPDigest(chainID, operator, pub, 4)
	if err != nil {
		t.Fatal(err)
	}
	if verify(pub, otherNonce) {
		t.Fatal("proof verifies for another nonce")
	}
	if _, err := ProveVRFKeyPossession(key[:10], chainID, operator, 3); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}
