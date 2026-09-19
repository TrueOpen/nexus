package identity

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck // Cosmos SDK keys export still uses OpenPGP armor.
)

const testPrivateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func TestLoadSignerFromPrivateKeyHex(t *testing.T) {
	want, err := signer.NewFromHex(testPrivateKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	got, err := LoadSigner(config.IdentityConfig{
		Bech32Prefix:  "trueopen",
		PrivateKeyHex: testPrivateKeyHex,
	})
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if got == nil {
		t.Fatal("LoadSigner returned nil signer")
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func TestLoadServiceSignerFallsBackToAccountSigner(t *testing.T) {
	account, err := signer.NewFromHex(testPrivateKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	got, shared, err := LoadServiceSigner(config.IdentityConfig{Bech32Prefix: "trueopen"}, account)
	if err != nil {
		t.Fatal(err)
	}
	if !shared || got != account {
		t.Fatalf("service signer = %T shared=%v", got, shared)
	}
}

func TestLoadServiceSignerRequiresPassword(t *testing.T) {
	_, _, err := LoadServiceSigner(config.IdentityConfig{
		Bech32Prefix:        "trueopen",
		ServiceKeystoreFile: filepath.Join(t.TempDir(), "service.key"),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "service keystore password") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadSignerFromPrivateKeyFile(t *testing.T) {
	want, err := signer.NewFromHex(testPrivateKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	path := filepath.Join(t.TempDir(), "builder.key")
	if err := os.WriteFile(path, []byte("0x"+testPrivateKeyHex+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := LoadSigner(config.IdentityConfig{
		Bech32Prefix:   "trueopen",
		PrivateKeyFile: path,
	})
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if got == nil {
		t.Fatal("LoadSigner returned nil signer")
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func TestLoadSignerFromCosmosPrivateKeyFile(t *testing.T) {
	want, err := signer.NewFromHex(testPrivateKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("NewFromHex: %v", err)
	}
	path := filepath.Join(t.TempDir(), "builder.armor")
	if err := os.WriteFile(path, []byte(makeCosmosArmor(t, testPrivateKeyHex, "passphrase")), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := LoadSigner(config.IdentityConfig{
		Bech32Prefix:     "trueopen",
		PrivateKeyFile:   path,
		KeystorePassword: "passphrase",
	})
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if got == nil {
		t.Fatal("LoadSigner returned nil signer")
	}
	if got.Address() != want.Address() {
		t.Fatalf("address = %s, want %s", got.Address(), want.Address())
	}
}

func makeCosmosArmor(t *testing.T, keyHex, passphrase string) string {
	t.Helper()
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	plain := make([]byte, 0, 5+len(raw))
	plain = append(plain, 0xe1, 0xb0, 0xf7, 0x9b)
	plain = append(plain, byte(len(raw)))
	plain = append(plain, raw...)

	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "TENDERMINT PRIVATE KEY", map[string]string{
		"kdf":  "argon2",
		"salt": hex.EncodeToString(salt),
		"type": "secp256k1",
	})
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if _, err := w.Write(aead.Seal(nil, nonce, plain, nil)); err != nil {
		t.Fatalf("armor write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.String()
}
