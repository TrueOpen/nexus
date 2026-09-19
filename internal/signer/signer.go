// Package signer is the minimal account-key implementation: deterministic secp256k1 signing (64-byte r||s)
// plus eth_secp256k1 account address derivation.
//
// The whole chain has exactly one account type (Account & Signing Protocol §2.1):
//
//	account_type = eth_secp256k1
//	address      = bech32(prefix, keccak256(pub_uncompressed_xy)[12:32])   (§3.1)
//
// Builder keys, Cortex service keys and user accounts are all derived by this rule; there is no second address space.
// The ripemd160(sha256(compressed)) form customary in Cosmos yields a different address for the same key,
// and that account does not exist on chain -- it must **not** be kept here as a fallback.
//
// On-chain transactions take §5.1 path A: SIGN_MODE_DIRECT, keccak256(SignDoc), raw64 R||S, with the digest
// derived by chaincli and signed directly through SignDigest; the SHA-256 semantics of Sign(msg) serve only
// the off-chain protocols (bus envelopes, SDK request envelopes, credentials).
//
// In production, startup loads the account only from an encrypted keystore file:
// NEXUS_KEYSTORE_FILE + NEXUS_KEYSTORE_PASSWORD or NEXUS_KEYSTORE_PASSWORD_FILE.
package signer

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/cosmos/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Signer signs SignDoc bytes (used by chaincli when assembling a transaction).
type Signer interface {
	// PubKeyCompressed is the 33-byte compressed public key (goes into SignerInfo.public_key).
	PubKeyCompressed() []byte
	// Address is this signer's bech32 account address.
	Address() string
	// Sign takes SHA-256 of msg, signs it deterministically with secp256k1 and returns 64-byte r||s.
	Sign(msg []byte) ([]byte, error)
	// SignDigest signs an **already derived signing digest** directly, without another hashing layer, and returns 64-byte r||s.
	// What H_FIELDS_V1 / H_V1 produce is already SHA-256; hashing it once more no longer matches the chain's strict verifier
	// (nor VerifyDigestSig).
	SignDigest(digest [32]byte) ([]byte, error)
}

type secpSigner struct {
	priv   *secp256k1.PrivateKey
	pub    []byte // compressed public key
	addr   string // bech32
	prefix string
}

// NewFromBytes builds a signer from a 32-byte secp256k1 secret.
func NewFromBytes(raw []byte, prefix string) (Signer, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("signer: key must be 32 bytes, got %d", len(raw))
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	pub := priv.PubKey().SerializeCompressed()
	addr, err := deriveAddress(pub, prefix)
	if err != nil {
		return nil, err
	}
	return &secpSigner{priv: priv, pub: pub, addr: addr, prefix: prefix}, nil
}

// NewFromHex builds a signer from a hex private key (32 bytes). prefix is the bech32 account prefix (e.g. "trueopen").
// It is only for tests and the offline keystore generation tool; the startup path never reads a bare private key.
func NewFromHex(hexKey, prefix string) (Signer, error) {
	raw, err := ParsePrivateKeyHex(hexKey)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(raw, prefix)
}

// LoadKeystoreFromEnv loads the account from an encrypted keystore file. When NEXUS_KEYSTORE_FILE is not
// configured it returns (nil, nil) and the caller decides whether a dev fallback is allowed.
func LoadKeystoreFromEnv(prefix string) (Signer, error) {
	path := strings.TrimSpace(os.Getenv("NEXUS_KEYSTORE_FILE"))
	if path == "" {
		return nil, nil
	}
	passphrase, err := keystorePassphraseFromEnv()
	if err != nil {
		return nil, err
	}
	return LoadKeystoreFile(path, passphrase, prefix)
}

func keystorePassphraseFromEnv() ([]byte, error) {
	if f := strings.TrimSpace(os.Getenv("NEXUS_KEYSTORE_PASSWORD_FILE")); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("signer: read keystore password file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	if p := os.Getenv("NEXUS_KEYSTORE_PASSWORD"); p != "" {
		return []byte(p), nil
	}
	return nil, fmt.Errorf("signer: NEXUS_KEYSTORE_PASSWORD_FILE or NEXUS_KEYSTORE_PASSWORD required")
}

// LoadKeystoreFile decrypts an armor keystore file produced by the Cosmos SDK `keys export`.
func LoadKeystoreFile(path string, passphrase []byte, prefix string) (Signer, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("signer: empty keystore passphrase")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer: read keystore file: %w", err)
	}
	return LoadKeystoreArmor(b, passphrase, prefix)
}

// LoadKeystoreArmor decrypts an armor keystore produced by the Cosmos SDK `keys export`.
// It supports both the SDK's original bcrypt/xsalsa20 format and the newer argon2/chacha20poly1305 format;
// it accepts plain Cosmos secp256k1 only and explicitly rejects eth_secp256k1/EVM keys.
func LoadKeystoreArmor(data, passphrase []byte, prefix string) (Signer, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("signer: empty keystore passphrase")
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("signer: empty keystore armor")
	}
	if strings.TrimSpace(prefix) == "" {
		return nil, fmt.Errorf("signer: bech32 prefix required")
	}

	raw, err := decryptCosmosSecp256k1Armor(data, passphrase)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(raw, prefix)
}

// LoadPrivateKeyMaterial detects the form of Cosmos private key input automatically:
// - the TENDERMINT PRIVATE KEY armor that keys export writes by default: a passphrase is required;
// - the 32-byte secp256k1 hex written by --unsafe --unarmored-hex: no passphrase needed.
func LoadPrivateKeyMaterial(data, passphrase []byte, prefix string) (Signer, error) {
	material := strings.TrimSpace(string(data))
	if material == "" {
		return nil, fmt.Errorf("signer: empty private key material")
	}
	if strings.HasPrefix(material, "-----BEGIN TENDERMINT PRIVATE KEY-----") {
		return LoadKeystoreArmor([]byte(material), passphrase, prefix)
	}
	return NewFromHex(material, prefix)
}

func (s *secpSigner) PubKeyCompressed() []byte { return s.pub }
func (s *secpSigner) Address() string          { return s.addr }

func (s *secpSigner) Sign(msg []byte) ([]byte, error) {
	return s.SignDigest(sha256.Sum256(msg))
}

func (s *secpSigner) SignDigest(digest [32]byte) ([]byte, error) {
	sig := ecdsa.Sign(s.priv, digest[:]) // RFC6979 deterministic, low-S normalized
	r := sig.R()
	sv := sig.S()
	rb := r.Bytes()
	sb := sv.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rb[:])
	copy(out[32:], sb[:])
	return out, nil
}

// VerifySig verifies a 64-byte r||s signature: sig covers sha256(msg) and pub is the 33-byte compressed public key.
// It is the inverse of Signer.Sign's convention and is reused for inbound verification (SDK envelopes / credentials / hand-raises).
func VerifySig(pubCompressed, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	pub, err := secp256k1.ParsePubKey(pubCompressed)
	if err != nil {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
		return false // overflows the modulus
	}
	if s.IsOverHalfOrder() {
		return false
	}
	digest := sha256.Sum256(msg)
	return ecdsa.NewSignature(&r, &s).Verify(digest[:], pub)
}

// VerifyDigestSig verifies a 64-byte r||s signature that covers an **already derived signing digest**.
//
// The only difference from VerifySig is that nothing is hashed: digest is the ECDSA message itself. The chain's
// VerifyStrictSecp256k1Digest (node x/shared/types/signature.go) and the Cortex signer both follow this
// convention for frozen digests; handing a digest to VerifySig adds another hashing layer and makes nexus reach
// the opposite conclusion from the chain for the same signature.
//
// Use VerifySig when the input is a preimage, and this function when it is a frozen digest.
func VerifyDigestSig(pubCompressed, digest, sig []byte) bool {
	if len(sig) != 64 || len(digest) != sha256.Size {
		return false
	}
	pub, err := secp256k1.ParsePubKey(pubCompressed)
	if err != nil {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
		return false // overflows the modulus
	}
	if s.IsOverHalfOrder() {
		return false
	}
	return ecdsa.NewSignature(&r, &s).Verify(digest, pub)
}

// AddressFromPubKey derives the bech32 account address from a compressed public key (used to check signer_address after verification).
func AddressFromPubKey(prefix string, pubCompressed []byte) (string, error) {
	if _, err := secp256k1.ParsePubKey(pubCompressed); err != nil {
		return "", fmt.Errorf("signer: parse pubkey: %w", err)
	}
	return deriveAddress(pubCompressed, prefix)
}

// AddressBytesFromPubKey is the 20-byte address_bytes of §3.1: keccak256 over the **64-byte X||Y without the 0x04
// prefix**, keeping the last 20 bytes. It is byte-for-byte identical to the EVM address of the same private key.
func AddressBytesFromPubKey(pubCompressed []byte) ([20]byte, error) {
	pub, err := secp256k1.ParsePubKey(pubCompressed)
	if err != nil {
		return [20]byte{}, fmt.Errorf("signer: parse pubkey: %w", err)
	}
	xy := pub.SerializeUncompressed()[1:]
	hash := sha3.NewLegacyKeccak256()
	hash.Write(xy)
	var out [20]byte
	copy(out[:], hash.Sum(nil)[12:])
	return out, nil
}

// deriveAddress bech32(prefix, keccak256(pub_uncompressed_xy)[12:32]) (§3.1).
func deriveAddress(compressedPub []byte, prefix string) (string, error) {
	raw, err := AddressBytesFromPubKey(compressedPub)
	if err != nil {
		return "", err
	}
	five, err := bech32.ConvertBits(raw[:], 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("signer: convert bits: %w", err)
	}
	addr, err := bech32.Encode(prefix, five)
	if err != nil {
		return "", fmt.Errorf("signer: bech32 encode: %w", err)
	}
	return addr, nil
}
