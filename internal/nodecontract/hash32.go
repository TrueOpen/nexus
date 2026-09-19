package nodecontract

import (
	"encoding/hex"
	"fmt"
)

// Hash32Bytes decodes a canonical Hash32 into the 32 raw consensus bytes that
// the Keeper wire uses (Keeper Interface Contract §1.1). The JSON/REST representation is
// 64 lowercase hex characters; uppercase, a "0x" prefix, whitespace and any
// length other than 32 bytes are rejected.
func Hash32Bytes(field, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical lowercase 64-hex Hash32", field)
	}
	return raw, nil
}

// Signature64Bytes decodes a canonical compact secp256k1 signature into its 64
// raw bytes (R || S). DER, 65-byte and uppercase encodings are rejected here;
// low-S and range checks stay with the Keeper (Keeper Interface Contract §1.1/§1.3).
func Signature64Bytes(field, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical lowercase 128-hex compact secp256k1 signature", field)
	}
	return raw, nil
}
