package nodecontract

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// testRecoverableSignature builds a well-formed 65-byte R||S||V: R and S are both
// 32 × 0x55 (S < N/2, so low-S holds), V = 27. It is only a fixture and matches no real signature.
func testRecoverableSignature() []byte {
	return append(bytes.Repeat([]byte{0x55}, 64), 27)
}

func TestValidateRecoverableSignatureAccepts(t *testing.T) {
	for _, v := range []byte{27, 28} {
		sig := testRecoverableSignature()
		sig[64] = v
		if err := ValidateRecoverableSignature(sig); err != nil {
			t.Fatalf("V=%d must be accepted: %v", v, err)
		}
	}

	// S == N/2 is exactly the upper bound of low-S and must be accepted.
	half := new(big.Int).Rsh(secp256k1.S256().N, 1)
	sig := append(append(bytes.Repeat([]byte{0x55}, 32), half.FillBytes(make([]byte, 32))...), 27)
	if err := ValidateRecoverableSignature(sig); err != nil {
		t.Fatalf("S = N/2 must be accepted: %v", err)
	}
}

// 08 §7.5 / base spec §10.1a: 65 bytes, V ∈ {27,28}, R ∈ [1, N-1], S non-zero and low-S;
// failing any one of them is a rejection.
func TestValidateRecoverableSignatureRejects(t *testing.T) {
	n := secp256k1.S256().N
	half := new(big.Int).Rsh(n, 1)
	halfPlusOne := new(big.Int).Add(half, big.NewInt(1))
	nPlusOne := new(big.Int).Add(n, big.NewInt(1))

	highS := append(append(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0xff}, 32)...), 27)
	zeroS := append(append(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0x00}, 32)...), 27)
	zeroR := append(append(bytes.Repeat([]byte{0x00}, 32), bytes.Repeat([]byte{0x55}, 32)...), 27)
	sHalfPlusOne := append(append(bytes.Repeat([]byte{0x55}, 32), halfPlusOne.FillBytes(make([]byte, 32))...), 27)
	rEqualsN := append(append(n.FillBytes(make([]byte, 32)), bytes.Repeat([]byte{0x55}, 32)...), 27)
	rEqualsNPlusOne := append(append(nPlusOne.FillBytes(make([]byte, 32)), bytes.Repeat([]byte{0x55}, 32)...), 27)

	cases := map[string][]byte{
		"nil":           nil,
		"64 bytes (V1)": bytes.Repeat([]byte{0x55}, 64),
		"66 bytes":      append(testRecoverableSignature(), 0),
		"V=0":           append(bytes.Repeat([]byte{0x55}, 64), 0),
		"V=1":           append(bytes.Repeat([]byte{0x55}, 64), 1),
		"V=29":          append(bytes.Repeat([]byte{0x55}, 64), 29),
		"high-S":        highS,
		"zero S":        zeroS,
		"zero R":        zeroR,
		"S = N/2 + 1":   sHalfPlusOne,
		"R = N":         rEqualsN,
		"R = N + 1":     rEqualsNPlusOne,
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRecoverableSignature(sig); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
}

// SignedOrderV2 envelope: the scheme must equal lowercase "eip712" byte for byte, and the
// signature follows the rules above.
func TestValidateSignedOrderEnvelopeV2(t *testing.T) {
	if err := ValidateSignedOrderEnvelopeV2("eip712", testRecoverableSignature()); err != nil {
		t.Fatalf("canonical envelope rejected: %v", err)
	}
	cases := map[string]struct {
		scheme string
		sig    []byte
	}{
		"legacy secp256k1":    {"secp256k1", bytes.Repeat([]byte{0x55}, 64)},
		"uppercase":           {"EIP712", testRecoverableSignature()},
		"empty scheme":        {"", testRecoverableSignature()},
		"64-byte with eip712": {"eip712", bytes.Repeat([]byte{0x55}, 64)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSignedOrderEnvelopeV2(c.scheme, c.sig); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
}
