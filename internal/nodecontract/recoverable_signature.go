// Canonical form of the 65-byte recoverable signature (base spec §10.1a,
// TaskOrder Hashing and Signing §7.3/§7.5).
//
// The user signature of SignedOrderV2 is a recoverable ECDSA over the order-domain EIP-712
// digest: R || S || V, V ∈ {27,28}, low-S. Nexus **does not verify the signature**: the user
// signature must be checked against the on-chain account public key, which is the Keeper's
// job (nexus creates no consensus facts). Only a shape check happens here, so that envelopes
// bound to be rejected by the Keeper are stopped at the entry point and ingress and
// coordinator share one rule instead of each writing its own.
package nodecontract

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SignedOrderSchemeV2 is the only accepted value of SignedOrderV2.signature_scheme
// (TaskOrder Hashing and Signing §7.3): byte-for-byte lowercase ASCII; no alias, case variant or the historical "secp256k1".
const SignedOrderSchemeV2 = "eip712"

// RecoverableSignatureLen is the raw length of R||S||V.
const RecoverableSignatureLen = 65

// secp256k1HalfOrder is the low-S criterion: an S greater than it is high-S and must be
// rejected, otherwise the same authorization has two signatures that both pass.
var secp256k1HalfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)

// ValidateRecoverableSignature checks the canonical form of a 65-byte recoverable signature:
// length, V ∈ {27,28} (the personal_sign / eth_sign prefixed paths cannot produce a valid
// signature with any other value, and §7.4 explicitly forbids those paths), R ∈ [1, N-1],
// S non-zero and low-S. No recovery on the curve is performed.
func ValidateRecoverableSignature(signature []byte) error {
	if len(signature) != RecoverableSignatureLen {
		return fmt.Errorf("recoverable signature must be exactly %d raw bytes R||S||V, got %d",
			RecoverableSignatureLen, len(signature))
	}
	if v := signature[64]; v != 27 && v != 28 {
		return fmt.Errorf("recoverable signature V must be 27 or 28, got %d", v)
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Sign() == 0 || r.Cmp(secp256k1.S256().N) >= 0 {
		return fmt.Errorf("recoverable signature R must be in [1, N-1]")
	}
	s := new(big.Int).SetBytes(signature[32:64])
	if s.Sign() == 0 {
		return fmt.Errorf("recoverable signature S must be non-zero")
	}
	if s.Cmp(secp256k1HalfOrder) > 0 {
		return fmt.Errorf("recoverable signature must be low-S")
	}
	return nil
}

// ValidateSignedOrderEnvelopeV2 is the shape check of the SignedOrderV2 transport envelope
// (TaskOrder Hashing and Signing §7.3, §7.5): the scheme literal plus the signature canonical form.
func ValidateSignedOrderEnvelopeV2(signatureScheme string, userSignature []byte) error {
	if signatureScheme != SignedOrderSchemeV2 {
		return fmt.Errorf("signed_order signature_scheme must be exactly %q, got %q",
			SignedOrderSchemeV2, signatureScheme)
	}
	if err := ValidateRecoverableSignature(userSignature); err != nil {
		return fmt.Errorf("signed_order user_signature: %w", err)
	}
	return nil
}
