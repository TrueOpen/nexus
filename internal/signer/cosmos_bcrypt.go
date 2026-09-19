package signer

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/blowfish"
)

const (
	cosmosBcryptMinCost            uint32 = 4
	cosmosBcryptMaxCost            uint32 = 31
	cosmosBcryptDefaultCost        uint32 = 10
	cosmosBcryptSaltSize                  = 16
	cosmosBcryptEncodedSaltSize           = 22
	cosmosBcryptEncodedHashSize           = 31
	cosmosBcryptMaxCryptedHashSize        = 23
	cosmosBcryptMajorVersion              = '2'
	cosmosBcryptMinorVersion              = 'a'
)

var (
	cosmosBcryptAlphabet   = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	cosmosBcryptCipherData = []byte{
		0x4f, 0x72, 0x70, 0x68,
		0x65, 0x61, 0x6e, 0x42,
		0x65, 0x68, 0x6f, 0x6c,
		0x64, 0x65, 0x72, 0x53,
		0x63, 0x72, 0x79, 0x44,
		0x6f, 0x75, 0x62, 0x74,
	}
)

// cosmosBcryptGenerateFromPassword mirrors Cosmos SDK's modified bcrypt helper:
// it accepts an explicit 16-byte salt from the armor header, then returns the
// canonical bcrypt hash bytes that Cosmos hashes again for xsalsa20/secretbox.
func cosmosBcryptGenerateFromPassword(salt, password []byte, cost uint32) ([]byte, error) {
	if len(salt) != cosmosBcryptSaltSize {
		return nil, fmt.Errorf("salt len must be %d", cosmosBcryptSaltSize)
	}
	if cost < cosmosBcryptMinCost {
		cost = cosmosBcryptDefaultCost
	}
	if cost > cosmosBcryptMaxCost {
		return nil, fmt.Errorf("bcrypt cost %d is outside allowed range", cost)
	}

	encodedSalt := cosmosBcryptBase64Encode(salt)
	hash, err := cosmosBcrypt(password, cost, encodedSalt)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 60)
	out[0] = '$'
	out[1] = cosmosBcryptMajorVersion
	out[2] = cosmosBcryptMinorVersion
	out[3] = '$'
	out[4] = byte('0' + cost/10)
	out[5] = byte('0' + cost%10)
	out[6] = '$'
	copy(out[7:], encodedSalt)
	copy(out[7+cosmosBcryptEncodedSaltSize:], hash)
	return out[:7+cosmosBcryptEncodedSaltSize+cosmosBcryptEncodedHashSize], nil
}

func cosmosBcrypt(password []byte, cost uint32, encodedSalt []byte) ([]byte, error) {
	cipherData := make([]byte, len(cosmosBcryptCipherData))
	copy(cipherData, cosmosBcryptCipherData)

	c, err := cosmosBcryptSetup(password, cost, encodedSalt)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 24; i += 8 {
		for range 64 {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}
	return cosmosBcryptBase64Encode(cipherData[:cosmosBcryptMaxCryptedHashSize]), nil
}

func cosmosBcryptSetup(key []byte, cost uint32, encodedSalt []byte) (*blowfish.Cipher, error) {
	salt, err := cosmosBcryptBase64Decode(encodedSalt)
	if err != nil {
		return nil, err
	}
	compatKey := append(key[:len(key):len(key)], 0)
	c, err := blowfish.NewSaltedCipher(compatKey, salt)
	if err != nil {
		return nil, err
	}
	rounds := uint64(1) << cost
	for range rounds {
		blowfish.ExpandKey(compatKey, c)
		blowfish.ExpandKey(salt, c)
	}
	return c, nil
}

func cosmosBcryptBase64Encode(src []byte) []byte {
	n := cosmosBcryptAlphabet.EncodedLen(len(src))
	dst := make([]byte, n)
	cosmosBcryptAlphabet.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func cosmosBcryptBase64Decode(src []byte) ([]byte, error) {
	numEquals := 4 - (len(src) % 4)
	padded := append([]byte(nil), src...)
	for range numEquals {
		padded = append(padded, '=')
	}
	dst := make([]byte, cosmosBcryptAlphabet.DecodedLen(len(padded)))
	n, err := cosmosBcryptAlphabet.Decode(dst, padded)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
