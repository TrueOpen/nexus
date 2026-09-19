package ingress

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/TrueOpen/nexus/internal/types"
)

// The sign bytes of a role signature must be the preimage, not the digest.
//
// signer.VerifySig sha256-hashes the given message itself (byte-for-byte identical to Cosmos
// PubKey.VerifySignature). Cortex signs the digest value "sha256 over the length-prefixed concatenation"
// itself. So only by handing the preimage to VerifySig do both sides compute the same ECDSA message;
// passing the digest adds an extra hash layer and the signature never verifies.
//
// taskdata.RequestSignBytes follows the preimage convention; this test pins ingress role signatures
// to the same convention.
func TestInferReceiptSignBytesIsPreimage(t *testing.T) {
	receipt := types.InferReceiptSubmission{
		SessionID:                 "session",
		SchemaVersion:             1,
		ChainID:                   "trueopen-localnet-1",
		TaskID:                    "task",
		TaskHash:                  "hash",
		WorkerAddress:             "trueopen1worker",
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    bytes.Repeat([]byte{0x11}, 32),
		OutputHash:                bytes.Repeat([]byte{0x22}, 32),
		OutputSizeBytes:           88,
		ExpiryHeight:              1000,
		InferReceiptHash:          bytes.Repeat([]byte{0x33}, 32),
		WorkerServiceSignature:    bytes.Repeat([]byte{0x44}, 64),
		EvidenceCommitments: []types.EvidenceCommitment{
			{Kind: 1, HashOrRoot: bytes.Repeat([]byte{0x55}, 32), EncodedSizeBytes: 9},
		},
	}

	// Cortex-side digest: same fields, sha256 over the length-prefixed concatenation.
	want := sha256.Sum256(framedForTest(
		[]byte("TRUEOPEN_SUBMIT_INFER_RECEIPT_V1"),
		[]byte(receipt.SessionID), be32ForTest(receipt.SchemaVersion), []byte(receipt.ChainID),
		[]byte(receipt.TaskID), []byte(receipt.TaskHash), []byte(receipt.WorkerAddress),
		be64ForTest(receipt.ServiceAuthorizationNonce), receipt.GenerationParamsDigest,
		receipt.OutputHash, be64ForTest(receipt.OutputSizeBytes), be64ForTest(receipt.ExpiryHeight),
		receipt.InferReceiptHash, receipt.WorkerServiceSignature,
		be32ForTest(receipt.EvidenceCommitments[0].Kind), receipt.EvidenceCommitments[0].HashOrRoot,
		be64ForTest(receipt.EvidenceCommitments[0].EncodedSizeBytes),
	))

	signBytes := inferReceiptSignBytes(receipt)
	got := sha256.Sum256(signBytes)
	if got != want {
		t.Fatalf("VerifySig computes ECDSA message %x from sign bytes %x, but Cortex signed %x", got, signBytes, want)
	}
}

func framedForTest(fields ...[]byte) []byte {
	var buf bytes.Buffer
	var l [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		buf.Write(l[:])
		buf.Write(f)
	}
	return buf.Bytes()
}

func be32ForTest(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func be64ForTest(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
