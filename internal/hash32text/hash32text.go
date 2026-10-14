// Package hash32text converts a Hash32 between the spelling clients use on the IngressAPI and the
// one nexus uses internally.
//
// On the IngressAPI a Hash32 carried as a string is "0x" followed by exactly 64 lowercase hex
// characters, 66 characters in all; a bare 64-character string, uppercase hex and "0X" are
// rejected. Inside nexus (task keys, stores, NATS subjects, chain queries) the same value stays 64
// lowercase hex characters without the prefix, so conversion happens only where a request is read
// or a response is written.
package hash32text

import "encoding/hex"

// Prefix starts every IngressAPI Hash32 string.
const Prefix = "0x"

// Len is the length of an IngressAPI Hash32 string.
const Len = len(Prefix) + 64

// Decode returns the 32 raw bytes of an IngressAPI Hash32 string, or false if value is not
// exactly "0x" followed by 64 lowercase hex characters.
func Decode(value string) ([32]byte, bool) {
	var out [32]byte
	if len(value) != Len || value[:len(Prefix)] != Prefix {
		return out, false
	}
	for _, c := range value[len(Prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return out, false
		}
	}
	_, _ = hex.Decode(out[:], []byte(value[len(Prefix):]))
	return out, true
}

// ToInternal returns the internal spelling (64 lowercase hex, no prefix) of an IngressAPI Hash32
// string, or false if value is not in the IngressAPI spelling.
func ToInternal(value string) (string, bool) {
	if _, ok := Decode(value); !ok {
		return "", false
	}
	return value[len(Prefix):], true
}

// FromInternal returns the IngressAPI spelling of an internal Hash32 string. An empty value stays
// empty, so an unset field remains unset.
func FromInternal(value string) string {
	if value == "" {
		return ""
	}
	return Prefix + value
}

// Encode returns the IngressAPI spelling of 32 raw bytes.
func Encode(raw []byte) string {
	return Prefix + hex.EncodeToString(raw)
}
