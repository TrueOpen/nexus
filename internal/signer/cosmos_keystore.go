package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/openpgp/armor" //nolint:staticcheck // Cosmos SDK keys export still uses OpenPGP armor.
)

const (
	cosmosArmorPrivKeyBlock = "TENDERMINT PRIVATE KEY"
	cosmosSecp256k1Algo     = "secp256k1"
	cosmosBcryptKDF         = "bcrypt"
	cosmosArgon2KDF         = "argon2"

	cosmosArgon2Time    = 1
	cosmosArgon2Memory  = 64 * 1024
	cosmosArgon2Threads = 4
	cosmosBcryptCost    = 12
)

var cosmosPrivKeySecp256k1Prefix = aminoPrefix("tendermint/PrivKeySecp256k1")

func decryptCosmosSecp256k1Armor(data, passphrase []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("signer: decode cosmos keystore armor: %w", err)
	}
	if block.Type != cosmosArmorPrivKeyBlock {
		return nil, fmt.Errorf("signer: unsupported cosmos armor type %q", block.Type)
	}

	algo := armorHeader(block.Header, "type")
	if algo == "" {
		algo = cosmosSecp256k1Algo
	}
	if algo != cosmosSecp256k1Algo {
		return nil, fmt.Errorf("signer: unsupported cosmos key type %q", algo)
	}

	encBytes, err := io.ReadAll(block.Body)
	if err != nil {
		return nil, fmt.Errorf("signer: read cosmos keystore body: %w", err)
	}
	plain, err := decryptCosmosPrivKeyBytes(block.Header, encBytes, passphrase)
	if err != nil {
		return nil, err
	}
	return secp256k1SecretFromAmino(plain)
}

func decryptCosmosPrivKeyBytes(header map[string]string, encBytes, passphrase []byte) ([]byte, error) {
	kdf := strings.ToLower(armorHeader(header, "kdf"))
	if kdf != cosmosBcryptKDF && kdf != cosmosArgon2KDF {
		return nil, fmt.Errorf("signer: unsupported cosmos keystore kdf %q", kdf)
	}
	saltHex := armorHeader(header, "salt")
	if saltHex == "" {
		return nil, fmt.Errorf("signer: missing cosmos keystore salt")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("signer: decode cosmos keystore salt: %w", err)
	}

	switch kdf {
	case cosmosArgon2KDF:
		return decryptCosmosArgon2(encBytes, passphrase, salt)
	case cosmosBcryptKDF:
		return decryptCosmosBcrypt(encBytes, passphrase, salt)
	default:
		panic("unreachable")
	}
}

func decryptCosmosArgon2(encBytes, passphrase, salt []byte) ([]byte, error) {
	key := argon2.IDKey(passphrase, salt, cosmosArgon2Time, cosmosArgon2Memory, cosmosArgon2Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("signer: init cosmos argon2 cipher: %w", err)
	}
	if len(encBytes) < aead.NonceSize() {
		return nil, fmt.Errorf("signer: encrypted cosmos key is too short")
	}
	nonce := make([]byte, aead.NonceSize())
	plain, err := aead.Open(nil, nonce, encBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("signer: decrypt cosmos keystore: wrong passphrase or corrupted file")
	}
	return plain, nil
}

func decryptCosmosBcrypt(encBytes, passphrase, salt []byte) ([]byte, error) {
	key, err := cosmosBcryptGenerateFromPassword(salt, passphrase, cosmosBcryptCost)
	if err != nil {
		return nil, fmt.Errorf("signer: derive cosmos bcrypt key: %w", err)
	}
	secret := sha256.Sum256(key)
	if len(encBytes) <= secretbox.Overhead+24 {
		return nil, fmt.Errorf("signer: encrypted cosmos key is too short")
	}
	var nonce [24]byte
	copy(nonce[:], encBytes[:24])
	var secretKey [32]byte
	copy(secretKey[:], secret[:])

	plain, ok := secretbox.Open(nil, encBytes[24:], &nonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("signer: decrypt cosmos keystore: wrong passphrase or corrupted file")
	}
	return plain, nil
}

func secp256k1SecretFromAmino(plain []byte) ([]byte, error) {
	if !bytes.HasPrefix(plain, cosmosPrivKeySecp256k1Prefix[:]) {
		return nil, fmt.Errorf("signer: unsupported cosmos privkey amino prefix %X", firstBytes(plain, 4))
	}
	rest := plain[len(cosmosPrivKeySecp256k1Prefix):]
	keyLen, n := binary.Uvarint(rest)
	if n <= 0 {
		return nil, fmt.Errorf("signer: decode cosmos privkey amino length")
	}
	if keyLen != 32 {
		return nil, fmt.Errorf("signer: unsupported cosmos secp256k1 key length %d", keyLen)
	}
	if len(rest) != n+int(keyLen) {
		return nil, fmt.Errorf("signer: malformed cosmos secp256k1 key bytes")
	}
	raw := make([]byte, 32)
	copy(raw, rest[n:])
	return raw, nil
}

func aminoPrefix(name string) [4]byte {
	sum := sha256.Sum256([]byte(name))
	bz := sum[:]
	for bz[0] == 0x00 {
		bz = bz[1:]
	}
	bz = bz[3:]
	for bz[0] == 0x00 {
		bz = bz[1:]
	}
	var out [4]byte
	copy(out[:], bz[:4])
	return out
}

func armorHeader(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
