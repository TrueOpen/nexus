package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func wireOutputStreamHeader(t *testing.T) (OutputStreamHeader, wirefixture.Vector) {
	t.Helper()
	v := wirefixture.Load(t, "task/output_stream_header_v1.json").Vector(t, "output_stream_header_v2_plaintext", 0)
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	return OutputStreamHeader{
		ChainID:             f("chain_id").UTF8,
		TaskHash:            f("task_hash").Bytes(t),
		DispatchTicketHash:  f("dispatch_ticket_hash").Bytes(t),
		StreamInstance:      uint32(f("stream_instance").Uint64(t)),
		UserRecipientPubkey: f("user_recipient_pubkey").Bytes(t),
		OutputKeyCommitment: f("output_key_commitment").Bytes(t),
		KeyPackageHash:      f("key_package_hash").Bytes(t),
	}, v
}

// TestOutputStreamHeaderMatchesWireVector: digest and signature of the wire plaintext header.
func TestOutputStreamHeaderMatchesWireVector(t *testing.T) {
	header, v := wireOutputStreamHeader(t)
	v.CheckPreimage(t)
	digest, err := header.SigningDigest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("digest = %x, want %s", digest, v.DigestHex)
	}
	var sig struct {
		Hex    string `json:"signature_raw64_hex"`
		Pubkey string `json:"service_pubkey_compressed_hex"`
	}
	if err := json.Unmarshal(v.Raw, &sig); err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString(sig.Hex)
	pub, _ := hex.DecodeString(sig.Pubkey)
	if err := header.ValidatePlaintext(); err != nil {
		t.Fatalf("the wire plaintext header must pass admission: %v", err)
	}
	if len(pub) != 33 {
		t.Fatalf("service pubkey length = %d", len(pub))
	}
	if !signer.VerifyDigestSig(pub, digest[:], signature) {
		t.Fatal("wire vector signature does not verify under the ticket-bound digest")
	}
	// The signature binds the ticket: the same header naming another ticket does not verify.
	other := header
	other.DispatchTicketHash = repeatByte(0x77, 32)
	otherDigest, err := other.SigningDigest()
	if err != nil {
		t.Fatal(err)
	}
	if signer.VerifyDigestSig(pub, otherDigest[:], signature) {
		t.Fatal("wire vector signature verifies for another dispatch_ticket_hash")
	}
}

// TestOutputStreamHeaderRejectedCases covers the wire rejected_cases.
func TestOutputStreamHeaderRejectedCases(t *testing.T) {
	cases := map[string]func(*OutputStreamHeader){
		"missing dispatch_ticket_hash":   func(h *OutputStreamHeader) { h.DispatchTicketHash = nil },
		"stream_instance != 1":           func(h *OutputStreamHeader) { h.StreamInstance = 2 },
		"nonempty user_recipient_pubkey": func(h *OutputStreamHeader) { h.UserRecipientPubkey = repeatByte(4, 65) },
		"nonzero output_key_commitment":  func(h *OutputStreamHeader) { h.OutputKeyCommitment = repeatByte(1, 32) },
		"nonzero key_package_hash":       func(h *OutputStreamHeader) { h.KeyPackageHash = repeatByte(1, 32) },
		"empty output_key_commitment":    func(h *OutputStreamHeader) { h.OutputKeyCommitment = nil },
		"empty key_package_hash":         func(h *OutputStreamHeader) { h.KeyPackageHash = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			header, _ := wireOutputStreamHeader(t)
			edit(&header)
			if err := header.ValidatePlaintext(); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
}
