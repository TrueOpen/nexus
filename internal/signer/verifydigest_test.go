package signer

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// A frozen signing digest must be verified directly and must not be hashed again.
//
// The node's VerifyStrictSecp256k1Digest runs ECDSA verification straight on the 32-byte digest
// (x/shared/types/signature.go), and the Cortex signer likewise signs the digest directly.
// VerifySig applies another sha256 to its input and only fits the case where the input is a preimage;
// a consensus digest must go through VerifyDigestSig, otherwise nexus and the chain reach opposite conclusions for the same signature.
func TestVerifyDigestSigMatchesChainConvention(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.PubKey().SerializeCompressed()

	digest := sha256.Sum256([]byte("frozen receipt preimage"))
	sig := ecdsa.Sign(priv, digest[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	compact := make([]byte, 64)
	copy(compact[:32], rb[:])
	copy(compact[32:], sb[:])

	if !VerifyDigestSig(pub, digest[:], compact) {
		t.Fatal("VerifyDigestSig rejected a digest signature the chain would accept")
	}
	if VerifySig(pub, digest[:], compact) {
		t.Fatal("VerifySig must not accept a digest signature -- it adds another hashing layer, which is exactly why the two are distinguished")
	}
	if !VerifySig(pub, []byte("frozen receipt preimage"), compact) {
		t.Fatal("VerifySig should accept the preimage")
	}
	if VerifyDigestSig(pub, bytes.Repeat([]byte{0x01}, 31), compact) {
		t.Fatal("a digest that is not 32 bytes must be rejected")
	}
}
