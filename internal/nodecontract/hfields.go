package nodecontract

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cosmos/cosmos-sdk/types/bech32"
)

// H_FIELDS_V1 is the single framing primitive for the frozen V1 consensus preimage
// (Keeper Interface Contract §1.2; x/shared/types/canonical.go at node d1dbf81).
//
//	preimage = u64_be(len(domain)) || domain
//	           || for each field: u64_be(len(field)) || field
//	digest   = SHA256(preimage)
//
// Field encoding (§1.2, item by item identical to the node reference implementation):
//
//	string  bytes after strict UTF-8 validation; no trim, no case folding, no NFC normalization
//	bytes   raw bytes; a Hash32 is exactly 32 bytes, never hex text
//	uint32  4-byte big-endian
//	uint64  8-byte big-endian
//	bool    0x00 / 0x01
//	enum    uint32 big-endian
//	address address codec bytes (the 20 bytes decoded from bech32), never bech32 text (ruling 24)
//	frame   nested FieldFrameV1: no domain prefix, encoded recursively in ascending schema field-number order
//
// The old domainHash(domain, fields ...string) wrote uint64 as decimal text and Hash32 as
// hex text and is incompatible with this framing: it only serves the pre-freeze helpers not
// registered in §1.4, and the two must never be mixed.

// canonicalLengthBytes is the length-prefix width of every field (u64 big-endian).
const canonicalLengthBytes = 8

// maxAddressCodecBytes matches the cosmos-sdk address length limit. §1.2 frames the address
// codec bytes, so the only structural upper bound the derivation can impose is the codec's own.
const maxAddressCodecBytes = 255

// Uint32BE is the §1.2 uint32 encoding.
func Uint32BE(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, value)
	return encoded
}

// Uint64BE is the §1.2 uint64 encoding.
func Uint64BE(value uint64) []byte {
	encoded := make([]byte, canonicalLengthBytes)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

// Int32BE is the §1.2 int32 encoding: reinterpret as uint32 via two's complement, then write
// big-endian, byte-for-byte identical to Int32BE in node x/shared/types/canonical.go.
// Negative values (e.g. presence_penalty_milli = -500) must go through here and never be
// converted to decimal text first.
func Int32BE(value int32) []byte {
	return Uint32BE(uint32(value))
}

// BoolByte is the §1.2 bool encoding.
func BoolByte(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

// EnumBE is the §1.2 enum encoding: the enum value is written as uint32 big-endian, not as name text.
func EnumBE(value uint32) []byte {
	return Uint32BE(value)
}

// CanonicalFrameBytes encodes ordered fields into a u64 big-endian length-prefixed frame. It is
// both the framing of the top-level preimage and of a nested FieldFrameV1; the latter merely
// lacks the domain field.
func CanonicalFrameBytes(fields ...[]byte) []byte {
	size := 0
	for _, field := range fields {
		size += canonicalLengthBytes + len(field)
	}
	framed := make([]byte, 0, size)
	var length [canonicalLengthBytes]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}

// CanonicalFramePreimage returns the full preimage bytes of H_FIELDS_V1(domain, fields...).
// Use it to align byte-for-byte with a golden vector's preimage_hex so debugging does not
// have to guess at the digest first.
func CanonicalFramePreimage(domain string, fields ...[]byte) []byte {
	all := make([][]byte, 0, len(fields)+1)
	all = append(all, []byte(domain))
	all = append(all, fields...)
	return CanonicalFrameBytes(all...)
}

// CanonicalHashBytes is H_FIELDS_V1: SHA256(CanonicalFramePreimage(domain, fields...)).
func CanonicalHashBytes(domain string, fields ...[]byte) [32]byte {
	return sha256.Sum256(CanonicalFramePreimage(domain, fields...))
}

// CanonicalUTF8Field applies the §1.2 string rule: validate strict UTF-8 first, then take the
// bytes. No sanitizing happens here: the bytes the caller signed are the bytes that get framed.
func CanonicalUTF8Field(field, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, fmt.Errorf("%s must be strict UTF-8", field)
	}
	return []byte(value), nil
}

// CanonicalHash32Field applies §1.1/§1.4 rule 3: a Hash32 in a consensus preimage is the raw
// 32 bytes, neither hex text nor a shorter placeholder value.
func CanonicalHash32Field(field string, value []byte) ([]byte, error) {
	if len(value) != sha256.Size {
		return nil, fmt.Errorf("%s must be exactly %d raw bytes, got %d", field, sha256.Size, len(value))
	}
	return value, nil
}

// CanonicalOperatorAddressBytes converts a bech32 operator address into the address codec
// bytes that every §1.2 preimage actually frames (ruling 24 / node#95). The bech32 text
// **never enters the preimage**: the human-readable prefix belongs to the presentation layer,
// and cross-chain isolation is the job of the chain_id field.
//
// It is a pure function: it depends neither on the global SDK prefix nor on the keeper's
// address.Codec, so it is reproducible byte-for-byte against the node's
// CanonicalOperatorAddressBytes. It does DecodeAndConvert plus a re-encode equality check,
// rejecting the empty string, leading/trailing whitespace, non-canonical input (including
// uppercase) and out-of-range lengths.
func CanonicalOperatorAddressBytes(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s must be a non-empty canonical Bech32 address", field)
	}
	if strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("%s must not carry leading or trailing whitespace", field)
	}
	hrp, raw, err := bech32.DecodeAndConvert(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not a decodable Bech32 address: %w", field, err)
	}
	if len(raw) == 0 || len(raw) > maxAddressCodecBytes {
		return nil, fmt.Errorf("%s decodes to %d address bytes, outside 1..%d", field, len(raw), maxAddressCodecBytes)
	}
	reencoded, err := bech32.ConvertAndEncode(hrp, raw)
	if err != nil {
		return nil, fmt.Errorf("%s could not be re-encoded: %w", field, err)
	}
	if reencoded != value {
		return nil, fmt.Errorf("%s must be the canonical Bech32 encoding of its address bytes", field)
	}
	return raw, nil
}
