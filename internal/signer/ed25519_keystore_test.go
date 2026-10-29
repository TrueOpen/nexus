package signer

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck
)

// Fixed test-only seed; never use it for a real key.
var ed25519TestSeed = bytes.Repeat([]byte{0x2a}, ed25519.SeedSize)

func TestEd25519KeystoreArmorRoundTrip(t *testing.T) {
	key := ed25519.NewKeyFromSeed(ed25519TestSeed)
	got, err := encryptEd25519KeystoreArmor(key, []byte("password"), bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	block, err := armor.Decode(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	if block.Type != cosmosArmorPrivKeyBlock || armorHeader(block.Header, "kdf") != cosmosArgon2KDF || armorHeader(block.Header, "type") != cosmosEd25519Algo {
		t.Fatalf("armor = %s %#v", block.Type, block.Header)
	}
	loaded, err := LoadEd25519KeystoreArmor(got, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, key) {
		t.Fatal("loaded key differs from the encrypted key")
	}
	if _, err := LoadEd25519KeystoreArmor(got, []byte("wrong")); err == nil {
		t.Fatal("wrong password must fail")
	}
	if _, err := LoadEd25519KeystoreArmor(got, nil); err == nil {
		t.Fatal("empty password must fail")
	}
}

func TestEd25519AndSecp256k1KeystoresDoNotCross(t *testing.T) {
	edArmor, err := EncryptEd25519KeystoreArmor(ed25519.NewKeyFromSeed(ed25519TestSeed), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeystoreArmor(edArmor, []byte("password"), "trueopen"); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("secp256k1 loader on an ed25519 keystore: err = %v", err)
	}
	raw, err := ParsePrivateKeyHex(encryptTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	secpArmor, err := EncryptKeystoreArmor(raw, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519KeystoreArmor(secpArmor, []byte("password")); err == nil || !strings.Contains(err.Error(), "secp256k1") {
		t.Fatalf("ed25519 loader on a secp256k1 keystore: err = %v", err)
	}
}

func TestEncryptEd25519KeystoreRejectsMalformedKey(t *testing.T) {
	if _, err := EncryptEd25519KeystoreArmor(ed25519.PrivateKey(make([]byte, 10)), []byte("password")); err == nil {
		t.Fatal("short key must be rejected")
	}
	if _, err := EncryptEd25519KeystoreArmor(ed25519.NewKeyFromSeed(ed25519TestSeed), nil); err == nil {
		t.Fatal("empty password must be rejected")
	}
	// A 64-byte key whose public half does not match its seed is corrupt.
	bad := append(ed25519.PrivateKey(nil), ed25519.NewKeyFromSeed(ed25519TestSeed)...)
	bad[63] ^= 1
	if _, err := EncryptEd25519KeystoreArmor(bad, []byte("password")); err == nil {
		t.Fatal("inconsistent key must be rejected")
	}
}
