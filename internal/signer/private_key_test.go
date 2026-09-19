package signer

import (
	"bytes"
	"strings"
	"testing"
)

func TestParsePrivateKeyHex(t *testing.T) {
	want := bytes.Repeat([]byte{0x01}, 32)
	for _, input := range []string{
		strings.Repeat("01", 32),
		"0x" + strings.Repeat("01", 32),
		"  0X" + strings.Repeat("01", 32) + "\n",
	} {
		got, err := ParsePrivateKeyHex(input)
		if err != nil {
			t.Fatalf("ParsePrivateKeyHex(%q): %v", input, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("key = %x, want %x", got, want)
		}
	}
}

func TestParsePrivateKeyHexRejectsInvalidInput(t *testing.T) {
	tests := map[string]string{
		"invalid hex": "zz",
		"short":       "abcd",
		"zero":        strings.Repeat("00", 32),
		"curve order": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePrivateKeyHex(input); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
