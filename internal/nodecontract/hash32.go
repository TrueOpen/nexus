package nodecontract

import (
	"encoding/hex"
	"fmt"
)

// Hash32Bytes decodes a Hash32 in nexus's internal spelling into the 32 raw
// consensus bytes that the Keeper wire uses. The internal spelling is 64
// lowercase hex characters; uppercase, a "0x" prefix, whitespace and any
// length other than 32 bytes are rejected. IngressAPI strings carry a "0x"
// prefix and are converted by package hash32text first.
func Hash32Bytes(field, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical lowercase 64-hex Hash32", field)
	}
	return raw, nil
}

// Signature64Bytes decodes a canonical compact secp256k1 signature into its 64
// raw bytes (R || S). DER, 65-byte and uppercase encodings are rejected here;
// low-S and range checks stay with the Keeper.
func Signature64Bytes(field, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical lowercase 128-hex compact secp256k1 signature", field)
	}
	return raw, nil
}
