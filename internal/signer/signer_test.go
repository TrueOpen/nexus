package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/cosmos/btcutil/bech32"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck // Cosmos SDK keys export still uses OpenPGP armor.
)

// Fixed test private key (for tests only, never use it in any real environment).
const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

const cosmosArmorPassphrase = "passphrase"

// TestAddressDerivationMatchesContractVector pins the account vector of wire v0.4.1
// testdata/v1/shared/account_signing_v1.json: private key 01x32 ->
// keccak256(XY)[12:] = 1a642f0e…14f1 → trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz
// (Account & Signing Protocol §3.1). The whole chain has only the eth_secp256k1 account type (§2.1); the Cosmos
// ripemd160(sha256(compressed)) form yields a different address for the same key, one that does not exist on chain.
func TestAddressDerivationMatchesContractVector(t *testing.T) {
	const (
		vectorKeyHex   = "0101010101010101010101010101010101010101010101010101010101010101"
		wantAddr       = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
		wantAddrBytes  = "1a642f0e3c3af545e7acbd38b07251b3990914f1"
		wantCompressed = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
		cosmosAddr     = "trueopen10xcqpzrky6eff2g52qdye53xkk9jxkvrrdt9h3"
	)
	got, err := NewFromHex(vectorKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	if hex.EncodeToString(got.PubKeyCompressed()) != wantCompressed {
		t.Fatalf("pubkey = %x, want %s", got.PubKeyCompressed(), wantCompressed)
	}
	if got.Address() != wantAddr {
		t.Fatalf("address = %s, want contract %s", got.Address(), wantAddr)
	}
	if got.Address() == cosmosAddr {
		t.Fatal("address still uses the Cosmos ripemd160 derivation")
	}
	derived, err := AddressFromPubKey("trueopen", got.PubKeyCompressed())
	if err != nil || derived != wantAddr {
		t.Fatalf("AddressFromPubKey = %s, %v; want %s", derived, err, wantAddr)
	}
	// The address bytes are the EVM address: the 20 bytes decoded from bech32 must equal the keccak result byte for byte.
	_, five, err := bech32.Decode(wantAddr, 1023)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bech32.ConvertBits(five, 5, 8, false)
	if err != nil || hex.EncodeToString(raw) != wantAddrBytes {
		t.Fatalf("address bytes = %x, %v; want %s", raw, err, wantAddrBytes)
	}
}

func TestAddressDerivationStableAndPrefixed(t *testing.T) {
	s, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	addr := s.Address()
	if !strings.HasPrefix(addr, "trueopen1") {
		t.Fatalf("address prefix: %s", addr)
	}
	// Deriving again from the same key must be exactly identical (deterministic).
	s2, _ := NewFromHex("0x"+testKeyHex, "trueopen")
	if s2.Address() != addr {
		t.Fatalf("address not deterministic: %s vs %s", s2.Address(), addr)
	}
	if len(s.PubKeyCompressed()) != 33 {
		t.Fatalf("compressed pubkey len = %d", len(s.PubKeyCompressed()))
	}
}

func TestSignDeterministicAndVerifiable(t *testing.T) {
	s, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	msg := []byte("sign-doc-bytes")

	sig1, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig2, _ := s.Sign(msg)
	if string(sig1) != string(sig2) {
		t.Fatal("signature not deterministic (RFC6979)")
	}
	if len(sig1) != 64 {
		t.Fatalf("sig len = %d, want 64 (r||s)", len(sig1))
	}

	// Verify r||s independently with the public key.
	pub, err := secp256k1.ParsePubKey(s.PubKeyCompressed())
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	var r, sv secp256k1.ModNScalar
	if r.SetByteSlice(sig1[:32]) || sv.SetByteSlice(sig1[32:]) {
		t.Fatal("r/s overflow")
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.NewSignature(&r, &sv).Verify(digest[:], pub) {
		t.Fatal("signature does not verify")
	}
}

func TestVerifySigRejectsHighS(t *testing.T) {
	s, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("reject malleable signature")
	signature, err := s.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	var scalar secp256k1.ModNScalar
	if scalar.SetByteSlice(signature[32:]) {
		t.Fatal("signature S overflows group order")
	}
	scalar.Negate()
	highS := scalar.Bytes()
	malleable := append([]byte(nil), signature...)
	copy(malleable[32:], highS[:])
	if VerifySig(s.PubKeyCompressed(), message, malleable) {
		t.Fatal("high-S signature was accepted")
	}
}

func TestNewFromHexRejectsBadKey(t *testing.T) {
	if _, err := NewFromHex("zz", "trueopen"); err == nil {
		t.Fatal("want error for non-hex")
	}
	if _, err := NewFromHex("abcd", "trueopen"); err == nil {
		t.Fatal("want error for short key")
	}
}

func TestLoadCosmosArgon2ArmorKeystore(t *testing.T) {
	want, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	armored := makeCosmosArgon2Armor(t, testKeyHex, cosmosArmorPassphrase, cosmosSecp256k1Algo)

	got, err := LoadKeystoreArmor([]byte(armored), []byte(cosmosArmorPassphrase), "trueopen")
	if err != nil {
		t.Fatalf("LoadKeystoreArmor: %v", err)
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
	sig, err := got.Sign([]byte("sign-doc"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !VerifySig(got.PubKeyCompressed(), []byte("sign-doc"), sig) {
		t.Fatal("keystore signer signature does not verify")
	}

	if _, err := LoadKeystoreArmor([]byte(armored), []byte("wrong"), "trueopen"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

func TestLoadLegacyCosmosBcryptArmorKeystore(t *testing.T) {
	want, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	armored := makeCosmosBcryptArmor(t, testKeyHex, cosmosArmorPassphrase, cosmosSecp256k1Algo)

	got, err := LoadKeystoreArmor([]byte(armored), []byte(cosmosArmorPassphrase), "trueopen")
	if err != nil {
		t.Fatalf("LoadKeystoreArmor: %v", err)
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func TestLoadCosmosArmorRejectsEVMSecp256k1(t *testing.T) {
	armored := makeCosmosArgon2Armor(t, testKeyHex, cosmosArmorPassphrase, "eth_secp256k1")
	_, err := LoadKeystoreArmor([]byte(armored), []byte(cosmosArmorPassphrase), "trueopen")
	if err == nil {
		t.Fatal("eth_secp256k1 armor must be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported cosmos key type") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadPrivateKeyMaterialDetectsCosmosArmor(t *testing.T) {
	want, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	armored := makeCosmosArgon2Armor(t, testKeyHex, cosmosArmorPassphrase, cosmosSecp256k1Algo)

	got, err := LoadPrivateKeyMaterial([]byte(armored), []byte(cosmosArmorPassphrase), "trueopen")
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial: %v", err)
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func TestLoadPrivateKeyMaterialDetectsUnsafeHex(t *testing.T) {
	want, err := NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	got, err := LoadPrivateKeyMaterial([]byte("0x"+testKeyHex+"\n"), nil, "trueopen")
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial: %v", err)
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func makeCosmosArgon2Armor(t *testing.T, keyHex, passphrase, keyType string) string {
	t.Helper()
	plain := cosmosAminoSecp256k1Plaintext(t, keyHex)
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(passphrase), salt, cosmosArgon2Time, cosmosArgon2Memory, cosmosArgon2Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	return encodeCosmosArmor(t, map[string]string{
		"kdf":  cosmosArgon2KDF,
		"salt": hex.EncodeToString(salt),
		"type": keyType,
	}, aead.Seal(nil, nonce, plain, nil))
}

func makeCosmosBcryptArmor(t *testing.T, keyHex, passphrase, keyType string) string {
	t.Helper()
	if passphrase != "passphrase" {
		t.Fatalf("test vector only precomputes bcrypt secret for passphrase=%q", "passphrase")
	}
	plain := cosmosAminoSecp256k1Plaintext(t, keyHex)
	salt := []byte("0123456789abcdef")
	secretHex := "c91a43581b8775f19f9d809d74eb955140818ac7385cf9b137a9fd288dbbdfd7"
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("decode bcrypt secret: %v", err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secret)
	var nonce [24]byte
	copy(nonce[:], []byte("fixed-cosmos-test-nonce!"))
	ciphertext := make([]byte, 24)
	copy(ciphertext, nonce[:])
	ciphertext = secretbox.Seal(ciphertext, plain, &nonce, &secretKey)
	return encodeCosmosArmor(t, map[string]string{
		"kdf":  cosmosBcryptKDF,
		"salt": hex.EncodeToString(salt),
		"type": keyType,
	}, ciphertext)
}

func cosmosAminoSecp256k1Plaintext(t *testing.T, keyHex string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	plain := make([]byte, 0, 5+len(raw))
	plain = append(plain, 0xe1, 0xb0, 0xf7, 0x9b) // amino prefix for tendermint/PrivKeySecp256k1
	plain = append(plain, byte(len(raw)))
	plain = append(plain, raw...)
	return plain
}

func encodeCosmosArmor(t *testing.T, headers map[string]string, body []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, cosmosArmorPrivKeyBlock, headers)
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("armor write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.String()
}
