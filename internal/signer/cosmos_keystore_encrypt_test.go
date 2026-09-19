package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck
)

// Fixed test-only key; never use it for a real account.
const encryptTestKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func TestEncryptKeystoreArmorRoundTrip(t *testing.T) {
	raw, err := ParsePrivateKeyHex(encryptTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := encryptKeystoreArmor(raw, []byte("password"), bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	block, err := armor.Decode(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	if armorHeader(block.Header, "kdf") != cosmosArgon2KDF || armorHeader(block.Header, "type") != cosmosSecp256k1Algo {
		t.Fatalf("headers = %#v", block.Header)
	}
	salt, err := hex.DecodeString(armorHeader(block.Header, "salt"))
	if err != nil || len(salt) != cosmosArgon2SaltSize {
		t.Fatalf("salt = %x, err = %v", salt, err)
	}

	want, err := NewFromBytes(raw, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeystoreArmor(got, []byte("password"), "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", loaded.Address(), want.Address())
	}
	msg := []byte("round-trip")
	sig, err := loaded.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySig(loaded.PubKeyCompressed(), msg, sig) {
		t.Fatal("round-trip signature is invalid")
	}
	if _, err := LoadKeystoreArmor(got, []byte("wrong"), "trueopen"); err == nil {
		t.Fatal("wrong password must fail")
	}
}

func TestEncryptKeystoreArmorUsesFreshSalt(t *testing.T) {
	raw, err := ParsePrivateKeyHex(encryptTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	one, err := encryptKeystoreArmor(raw, []byte("password"), bytes.NewReader(bytes.Repeat([]byte{0x11}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	two, err := encryptKeystoreArmor(raw, []byte("password"), bytes.NewReader(bytes.Repeat([]byte{0x22}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one, two) {
		t.Fatal("different salts produced identical armor")
	}
	oneBlock, err := armor.Decode(bytes.NewReader(one))
	if err != nil {
		t.Fatal(err)
	}
	twoBlock, err := armor.Decode(bytes.NewReader(two))
	if err != nil {
		t.Fatal(err)
	}
	oneBody, err := io.ReadAll(oneBlock.Body)
	if err != nil {
		t.Fatal(err)
	}
	twoBody, err := io.ReadAll(twoBlock.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oneBody, twoBody) {
		t.Fatal("different salts produced identical ciphertext bodies")
	}
}

func TestEncryptKeystoreArmorRejectsInvalidInput(t *testing.T) {
	valid, err := ParsePrivateKeyHex(encryptTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptKeystoreArmor(make([]byte, 32), []byte("password"), strings.NewReader(strings.Repeat("x", 16))); err == nil {
		t.Fatal("zero key must fail")
	}
	if _, err := encryptKeystoreArmor([]byte{1}, []byte("password"), strings.NewReader(strings.Repeat("x", 16))); err == nil {
		t.Fatal("short key must fail")
	}
	order, err := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptKeystoreArmor(order, []byte("password"), strings.NewReader(strings.Repeat("x", 16))); err == nil {
		t.Fatal("out-of-range key must fail")
	}
	if _, err := encryptKeystoreArmor(valid, nil, strings.NewReader(strings.Repeat("x", 16))); err == nil {
		t.Fatal("empty password must fail")
	}
	wantErr := errors.New("random failed")
	if _, err := encryptKeystoreArmor(valid, []byte("password"), errorReader{wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
