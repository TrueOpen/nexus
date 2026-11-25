package recorder

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

func attestation(t *testing.T, digest byte, count uint64) []byte {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&taskv1.OrderInputTokensAttestationV1{
		SchemaVersion: 1, ChainId: "trueopen-test-1", OrderDigest: bytes.Repeat([]byte{digest}, 32), InputTokenCount: count,
		SignatureScheme: "eip712", UserSignature: bytes.Repeat([]byte{0x05}, 65), SignatureChainId: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The user's signed input token count travels in the same record message as its entry, in entry
// order; an entry without one adds nothing, and the gas covers the larger message.
func TestRecordCarriesInputTokenAttestations(t *testing.T) {
	e := newEnv(t)
	a, b, c := bundle(0xaa, 0, 1, 50), bundle(0xbb, 0, 2, 50), bundle(0xcc, 0, 3, 50)
	a.InputTokens, c.InputTokens = attestation(t, 0xa1, 17), attestation(t, 0xc1, 4000)
	e.record(a, b, c)
	e.block(10)
	msg, _ := e.lastSent()
	if len(msg.GetEntries()) != 3 {
		t.Fatalf("entries = %d, want 3", len(msg.GetEntries()))
	}
	got := msg.GetInputTokensAttestations()
	if len(got) != 2 {
		t.Fatalf("attestations = %d, want the two that were supplied", len(got))
	}
	counts := map[byte]uint64{}
	for _, att := range got {
		counts[att.GetOrderDigest()[0]] = att.GetInputTokenCount()
	}
	if counts[0xa1] != 17 || counts[0xc1] != 4000 {
		t.Fatalf("attestations = %v", counts)
	}
	if gas := e.tx.gas[len(e.tx.gas)-1]; gas != recordGas(msg) {
		t.Fatalf("gas = %d, want %d for the message with its attestations", gas, recordGas(msg))
	}
}

// Without any attestation the record message is byte for byte what it was before.
func TestRecordWithoutAttestationsIsUnchanged(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(10)
	msg, _ := e.lastSent()
	if len(msg.GetInputTokensAttestations()) != 0 {
		t.Fatalf("attestations = %d, want none", len(msg.GetInputTokensAttestations()))
	}
}

// An attestation that does not decode is left out; its entry is still recorded.
func TestUndecodableAttestationDoesNotBlockItsEntry(t *testing.T) {
	e := newEnv(t)
	a := bundle(0xaa, 0, 1, 50)
	a.InputTokens = []byte{0xff, 0xff, 0xff}
	e.record(a)
	e.block(10)
	msg, _ := e.lastSent()
	if len(msg.GetEntries()) != 1 || len(msg.GetInputTokensAttestations()) != 0 {
		t.Fatalf("entries %d attestations %d, want the entry alone", len(msg.GetEntries()), len(msg.GetInputTokensAttestations()))
	}
}
