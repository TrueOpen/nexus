package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// cosmosEd25519Algo is the armor key type of an Ed25519 key, as the Cosmos SDK writes it.
const cosmosEd25519Algo = "ed25519"

var cosmosPrivKeyEd25519Prefix = aminoPrefix("tendermint/PrivKeyEd25519")

// LoadEd25519KeystoreArmor decrypts a Cosmos private key armor holding an Ed25519 key (armor type
// "ed25519", amino tendermint/PrivKeyEd25519: the 32-byte seed followed by the 32-byte public key),
// in the bcrypt or argon2 format LoadKeystoreArmor accepts. It is the Builder VRF key format.
func LoadEd25519KeystoreArmor(data, passphrase []byte) (ed25519.PrivateKey, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("signer: empty keystore passphrase")
	}
	plain, err := decryptCosmosArmor(data, passphrase, cosmosEd25519Algo)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(plain, cosmosPrivKeyEd25519Prefix[:]) {
		return nil, fmt.Errorf("signer: unsupported cosmos privkey amino prefix %X", firstBytes(plain, 4))
	}
	rest := plain[len(cosmosPrivKeyEd25519Prefix):]
	keyLen, n := binary.Uvarint(rest)
	if n <= 0 || keyLen != ed25519.PrivateKeySize || len(rest) != n+ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: malformed cosmos ed25519 key bytes")
	}
	key := ed25519.PrivateKey(append([]byte(nil), rest[n:]...))
	if err := validateEd25519Key(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptEd25519KeystoreArmor encrypts an Ed25519 private key into the armor
// LoadEd25519KeystoreArmor reads (argon2 / chacha20poly1305).
func EncryptEd25519KeystoreArmor(key ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	return encryptEd25519KeystoreArmor(key, passphrase, rand.Reader)
}

func encryptEd25519KeystoreArmor(key ed25519.PrivateKey, passphrase []byte, random io.Reader) ([]byte, error) {
	if err := validateEd25519Key(key); err != nil {
		return nil, err
	}
	return encryptCosmosArmor(aminoKey(cosmosPrivKeyEd25519Prefix, key), passphrase, cosmosEd25519Algo, random)
}

// validateEd25519Key checks the key length and that its public half derives from its seed.
func validateEd25519Key(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("signer: ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return fmt.Errorf("signer: ed25519 public key does not match its seed")
	}
	return nil
}
