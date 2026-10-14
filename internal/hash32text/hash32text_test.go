package hash32text

import (
	"strings"
	"testing"
)

func TestDecodeAcceptsOnlyPrefixedLowercase(t *testing.T) {
	bare := strings.Repeat("ab", 32)
	raw, ok := Decode("0x" + bare)
	if !ok || raw[0] != 0xab || raw[31] != 0xab {
		t.Fatalf("Decode(0x+hex) = %x, %v", raw, ok)
	}
	for name, value := range map[string]string{
		"bare":            bare,
		"uppercase hex":   "0x" + strings.ToUpper(bare),
		"uppercase 0X":    "0X" + bare,
		"short":           "0x" + bare[:62],
		"65 characters":   "0x" + bare[:63],
		"67 characters":   "0x" + bare + "a",
		"long":            "0x" + bare + "ab",
		"non-hex":         "0x" + bare[:63] + "g",
		"empty":           "",
		"prefix only":     "0x",
		"leading space":   " 0x" + bare[:63],
		"double prefix":   "0x0x" + bare[:62],
		"internal spaces": "0x" + bare[:31] + " " + bare[32:],
	} {
		if _, ok := Decode(value); ok {
			t.Errorf("%s: Decode(%q) accepted", name, value)
		}
		if _, ok := ToInternal(value); ok {
			t.Errorf("%s: ToInternal(%q) accepted", name, value)
		}
	}
}

func TestInternalRoundTrip(t *testing.T) {
	bare := strings.Repeat("0f", 32)
	wire := FromInternal(bare)
	if wire != "0x"+bare || len(wire) != Len {
		t.Fatalf("FromInternal = %q", wire)
	}
	back, ok := ToInternal(wire)
	if !ok || back != bare {
		t.Fatalf("ToInternal(%q) = %q, %v", wire, back, ok)
	}
	if FromInternal("") != "" {
		t.Fatal("FromInternal(\"\") must stay empty")
	}
	raw, _ := Decode(wire)
	if Encode(raw[:]) != wire {
		t.Fatalf("Encode = %q, want %q", Encode(raw[:]), wire)
	}
}
