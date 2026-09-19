package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// Build the preimage by hand per H_FIELDS_V1: u64_be(len(domain)) || domain || per field u64_be(len) || field.
func TestOutputChunkSigningDigestMatchesHFieldsV1(t *testing.T) {
	taskHash := bytes.Repeat([]byte{0xab}, 32)
	root := bytes.Repeat([]byte{0xcd}, 32)
	got, err := OutputChunkSigningDigest("trueopen-localnet-1", taskHash, 7, root)
	if err != nil {
		t.Fatal(err)
	}
	var pre bytes.Buffer
	field := func(b []byte) {
		_ = binary.Write(&pre, binary.BigEndian, uint64(len(b)))
		pre.Write(b)
	}
	field([]byte(DomainOutputChunkV1))
	field([]byte("trueopen-localnet-1"))
	field(taskHash)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], 7)
	field(seq[:])
	field(root)
	if want := sha256.Sum256(pre.Bytes()); got != want {
		t.Fatalf("digest = %x, want %x", got, want)
	}

	if _, err := OutputChunkSigningDigest("", taskHash, 0, root); err == nil {
		t.Fatal("empty chain_id must be rejected")
	}
	if _, err := OutputChunkSigningDigest("trueopen-localnet-1", taskHash[:31], 0, root); err == nil {
		t.Fatal("task_hash must be 32 bytes")
	}
	other, _ := OutputChunkSigningDigest("trueopen-localnet-1", taskHash, 8, root)
	if other == got {
		t.Fatal("seq must be committed")
	}
}
