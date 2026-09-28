package eip712

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func TestKeccak256(t *testing.T) {
	got := Keccak256()
	if hex.EncodeToString(got[:]) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("keccak256(\"\") = %x", got)
	}
}

// wireRequest is the wallet-signed sdk_request of wire account_signing_v1.json.
func wireRequest(t *testing.T) (digest [32]byte, signature []byte, recovered, pubCompressed string) {
	t.Helper()
	var file struct {
		Account struct {
			PubCompressed string `json:"pub_compressed"`
		} `json:"account"`
		SDKRequest struct {
			Digest    string `json:"signing_digest"`
			Signature string `json:"signature_65"`
			Recovered string `json:"recovered_address"`
		} `json:"sdk_request"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, filepath.Join("testdata", "v1", "shared", "account_signing_v1.json")), &file); err != nil {
		t.Fatal(err)
	}
	d, err := hex.DecodeString(file.SDKRequest.Digest)
	if err != nil || len(d) != 32 {
		t.Fatalf("digest: %v", err)
	}
	copy(digest[:], d)
	signature, err = hex.DecodeString(file.SDKRequest.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return digest, signature, file.SDKRequest.Recovered, file.Account.PubCompressed
}

func TestRecoverWireVector(t *testing.T) {
	digest, signature, recovered, pub := wireRequest(t)
	got, err := Recover(digest, signature)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.Address[:]) != recovered || hex.EncodeToString(got.Compressed) != pub {
		t.Fatalf("recovered %x / %x, want %s / %s", got.Address, got.Compressed, recovered, pub)
	}
}

// Every malformed or non-canonical signature is refused, not recovered to some other address.
func TestRecoverRejects(t *testing.T) {
	digest, signature, _, _ := wireRequest(t)
	n := secp256k1.S256().N
	word := func(v *big.Int) []byte {
		out := make([]byte, 32)
		v.FillBytes(out)
		return out
	}
	with := func(r, s []byte, v byte) []byte {
		out := append(append(append([]byte{}, r...), s...), v)
		return out
	}
	r, s, v := signature[:32], signature[32:64], signature[64]
	highS := word(new(big.Int).Sub(n, new(big.Int).SetBytes(s)))
	flipped := byte(27 + 28 - int(v))
	zero := make([]byte, 32)
	cases := map[string][]byte{
		"64 bytes (no V)":     signature[:64],
		"66 bytes":            append(append([]byte{}, signature...), 0),
		"V = 0":               with(r, s, v-27),
		"V = 1":               with(r, s, 1),
		"V = 29":              with(r, s, 29),
		"high S":              with(r, highS, flipped),
		"R = 0":               with(zero, s, v),
		"S = 0":               with(r, zero, v),
		"R = n":               with(word(n), s, v),
		"R above n":           with(word(new(big.Int).Add(n, big.NewInt(1))), s, v),
		"S = n":               with(r, word(n), v),
		"V||R||S (dcrd form)": append([]byte{v}, signature[:64]...),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := Recover(digest, sig); !errors.Is(err, ErrSignature) {
				t.Fatalf("Recover = %x, %v; want ErrSignature", got.Address, err)
			}
		})
	}
}
