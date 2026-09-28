// Package eip712 holds the EIP-712 building blocks every User-signed request shares: the domain
// separator, typed-data encoding of the field kinds TrueOpen uses, the signing digest, and the one
// strict recovery of a 65-byte R||S||V signature.
//
// Every User request path (SDK request envelope, session grant, USER Task data request) verifies
// through Recover, so the signature rules live in one place: exactly 65 bytes, V in {27, 28}, low S,
// non-zero R and S, and the digest is used as signed, never hashed again.
package eip712

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// DomainType is the encodeType of the EIP712Domain every TrueOpen domain uses.
const DomainType = "EIP712Domain(string name,string version,uint256 chainId)"

// ErrSignature marks a signature that is not a well-formed recoverable signature or does not recover.
var ErrSignature = errors.New("eip712: invalid signature")

// Keccak256 hashes the concatenation of parts.
func Keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Uint encodes an unsigned integer as a 32-byte big-endian word, the EIP-712 encoding of uintN.
func Uint(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

// String encodes a string member: keccak256 of its UTF-8 bytes.
func String(value string) []byte {
	sum := Keccak256([]byte(value))
	return sum[:]
}

// Address encodes an address member: the 20 bytes left-padded to a 32-byte word.
func Address(value [20]byte) []byte {
	word := make([]byte, 32)
	copy(word[12:], value[:])
	return word
}

// TypeHash is keccak256 of an encodeType.
func TypeHash(encodeType string) [32]byte {
	return Keccak256([]byte(encodeType))
}

// HashStruct is keccak256(typeHash || encoded members), members already encoded as 32-byte words.
func HashStruct(encodeType string, members ...[]byte) [32]byte {
	typeHash := TypeHash(encodeType)
	return Keccak256(append([][]byte{typeHash[:]}, members...)...)
}

// DomainSeparator is hashStruct(EIP712Domain{name, version, chainId}).
func DomainSeparator(name, version string, chainID uint64) [32]byte {
	return HashStruct(DomainType, String(name), String(version), Uint(chainID))
}

// Digest is the signed value: keccak256(0x19 0x01 || domainSeparator || hashStruct).
func Digest(domainSeparator, hashStruct [32]byte) [32]byte {
	return Keccak256([]byte{0x19, 0x01}, domainSeparator[:], hashStruct[:])
}

// halfOrder is the low-S bound: a signature with a higher S is the malleated twin of a valid one
// and is rejected, so one authorization never has two accepted encodings.
var halfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)

// Recovered is the signer a digest and signature recover to.
type Recovered struct {
	Address    [20]byte // keccak256(uncompressed X||Y)[12:32]
	Compressed []byte   // 33-byte compressed public key
}

// Recover recovers the signer of digest from a 65-byte R||S||V signature. Only V in {27, 28} is
// accepted: personal_sign and eth_sign sign a different, prefixed message, and their signatures
// must not pass. The digest is used exactly as given.
func Recover(digest [32]byte, signature []byte) (Recovered, error) {
	if len(signature) != 65 {
		return Recovered{}, fmt.Errorf("%w: must be exactly 65 bytes R||S||V", ErrSignature)
	}
	v := signature[64]
	if v != 27 && v != 28 {
		return Recovered{}, fmt.Errorf("%w: V must be 27 or 28", ErrSignature)
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if r.Sign() == 0 || s.Sign() == 0 {
		return Recovered{}, fmt.Errorf("%w: R and S must be non-zero", ErrSignature)
	}
	if s.Cmp(halfOrder) > 0 {
		return Recovered{}, fmt.Errorf("%w: S must be low", ErrSignature)
	}
	// dcrec's compact layout is [V R S] with V based at 27; the compressed flag (+4) is not set, so
	// the key recovers uncompressed, which the address derivation needs.
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], signature[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return Recovered{}, fmt.Errorf("%w: does not recover", ErrSignature)
	}
	uncompressed := pub.SerializeUncompressed()
	sum := Keccak256(uncompressed[1:])
	var out Recovered
	copy(out.Address[:], sum[12:])
	out.Compressed = pub.SerializeCompressed()
	return out, nil
}
