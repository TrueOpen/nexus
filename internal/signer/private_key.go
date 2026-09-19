package signer

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ParsePrivateKeyHex decodes an optional-0x, 32-byte secp256k1 private key.
func ParsePrivateKeyHex(input string) ([]byte, error) {
	normalized := strings.TrimSpace(input)
	if strings.HasPrefix(normalized, "0x") || strings.HasPrefix(normalized, "0X") {
		normalized = normalized[2:]
	}
	if len(normalized) != 64 {
		return nil, fmt.Errorf("signer: private key must contain 64 hex characters")
	}
	raw, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("signer: decode private key hex: %w", err)
	}
	if err := validatePrivateKey(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func validatePrivateKey(raw []byte) error {
	if len(raw) != 32 {
		return fmt.Errorf("signer: private key must be 32 bytes")
	}
	var scalar secp256k1.ModNScalar
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return fmt.Errorf("signer: invalid secp256k1 private key")
	}
	return nil
}
