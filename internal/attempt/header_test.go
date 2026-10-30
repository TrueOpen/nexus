package attempt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const dispatchVectors = "task/dispatch_v1.json"

type signedVector struct {
	ProtobufHex  string `json:"protobuf_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
}

func newTestSigner(t testing.TB, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{seed}, 32), "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// vectorHeader is the wire DispatchResultHeaderV1 vector with its signed bytes and signature.
func vectorHeader(t *testing.T) (wirefixture.Vector, *nexusv1.DispatchResultHeaderV1, []byte, []byte) {
	t.Helper()
	v := wirefixture.Load(t, dispatchVectors).Vector(t, "nexus_v1_dispatchresultheaderv1", 0)
	v.CheckPreimage(t)
	var sv signedVector
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(sv.ProtobufHex)
	sig, _ := hex.DecodeString(sv.SignatureHex)
	pub, _ := hex.DecodeString(sv.PublicKeyHex)
	if !bytes.Equal(newTestSigner(t, 0x01).PubKeyCompressed(), pub) {
		t.Fatal("fixture key is not the vector key")
	}
	var h nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return v, &h, raw, sig
}

// The result header is signed over the wire DispatchResultHeaderV1 projection: digest, signature
// and bytes equal the wire vector.
func TestSignResultHeaderMatchesWire(t *testing.T) {
	v, want, wantRaw, wantSig := vectorHeader(t)
	if want.GetServiceAuthorizationNonce() == 0 {
		t.Fatal("the header vector signs no Builder nonce")
	}
	h := proto.Clone(want).(*nexusv1.DispatchResultHeaderV1)
	h.ServiceAuthorizationNonce = 0
	raw, err := SignResultHeader(servicekey.Key{Signer: newTestSigner(t, 0x01), Nonce: want.GetServiceAuthorizationNonce()}, h)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := digestOf(resultHeaderName, h)
	if err != nil || digest != v.Digest(t) {
		t.Fatalf("digest = %x, %v; want %s", digest, err, v.DigestHex)
	}
	if !bytes.Equal(h.GetBuilderServiceSignature(), wantSig) || !bytes.Equal(raw, wantRaw) {
		t.Fatalf("signed header = %x sig %x, want %x sig %x", raw, h.GetBuilderServiceSignature(), wantRaw, wantSig)
	}
}

// A header is signed under the nonce of the key that signs it, never one older than its winner
// ticket's: a key without a nonce, or of an older generation than the ticket, signs nothing.
func TestSignResultHeaderRefusesAnOlderGenerationThanItsTicket(t *testing.T) {
	_, want, _, _ := vectorHeader(t)
	headerOf := func() *nexusv1.DispatchResultHeaderV1 {
		h := proto.Clone(want).(*nexusv1.DispatchResultHeaderV1)
		h.WinnerTicket.ServiceAuthorizationNonce = 5
		return h
	}
	for _, nonce := range []uint64{0, 4} {
		if _, err := SignResultHeader(servicekey.Key{Signer: newTestSigner(t, 0x01), Nonce: nonce}, headerOf()); err == nil {
			t.Fatalf("header signed under nonce %d for a ticket of nonce 5", nonce)
		}
	}
	for _, nonce := range []uint64{5, 6} {
		h := headerOf()
		if _, err := SignResultHeader(servicekey.Key{Signer: newTestSigner(t, 0x01), Nonce: nonce}, h); err != nil || h.GetServiceAuthorizationNonce() != nonce {
			t.Fatalf("header under nonce %d: signed nonce %d, %v", nonce, h.GetServiceAuthorizationNonce(), err)
		}
	}
}
