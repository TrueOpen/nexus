package signer

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck
)

const cosmosArgon2SaltSize = 16

// EncryptKeystoreArmor encrypts a raw Cosmos secp256k1 private key.
func EncryptKeystoreArmor(raw, passphrase []byte) ([]byte, error) {
	return encryptKeystoreArmor(raw, passphrase, rand.Reader)
}

func encryptKeystoreArmor(raw, passphrase []byte, random io.Reader) ([]byte, error) {
	if err := validatePrivateKey(raw); err != nil {
		return nil, err
	}
	return encryptCosmosArmor(aminoKey(cosmosPrivKeySecp256k1Prefix, raw), passphrase, cosmosSecp256k1Algo, random)
}

// aminoKey is the amino encoding of a private key: the type prefix and the length-prefixed key.
func aminoKey(prefix [4]byte, raw []byte) []byte {
	plain := make([]byte, 0, len(prefix)+binary.MaxVarintLen64+len(raw))
	plain = append(plain, prefix[:]...)
	plain = binary.AppendUvarint(plain, uint64(len(raw)))
	return append(plain, raw...)
}

// encryptCosmosArmor writes the argon2/chacha20poly1305 Cosmos armor of an amino encoded key.
func encryptCosmosArmor(plain, passphrase []byte, algo string, random io.Reader) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("signer: empty keystore passphrase")
	}
	salt := make([]byte, cosmosArgon2SaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("signer: generate cosmos keystore salt: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, cosmosArgon2Time, cosmosArgon2Memory, cosmosArgon2Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("signer: init cosmos argon2 cipher: %w", err)
	}
	ciphertext := aead.Seal(nil, make([]byte, aead.NonceSize()), plain, nil)

	var out bytes.Buffer
	w, err := armor.Encode(&out, cosmosArmorPrivKeyBlock, map[string]string{
		"kdf":  cosmosArgon2KDF,
		"salt": hex.EncodeToString(salt),
		"type": algo,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: encode cosmos keystore armor: %w", err)
	}
	if _, err := w.Write(ciphertext); err != nil {
		return nil, fmt.Errorf("signer: write cosmos keystore armor: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("signer: close cosmos keystore armor: %w", err)
	}
	return out.Bytes(), nil
}
