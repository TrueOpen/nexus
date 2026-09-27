package nodecontract

import "fmt"

// DomainOutputStreamHeaderV1 is the Worker's signature domain over the declaration that opens an
// OUTPUT stream (OutputStreamHeaderV2), registered in TrueOpen/wire registry/v1/domains.json.
const DomainOutputStreamHeaderV1 = "TRUEOPEN_OUTPUT_STREAM_HEADER_V1"

// Plaintext stream identity: the first attempt of the only stream of a task.
const (
	PlaintextOutputStreamAttempt  uint32 = 0
	PlaintextOutputStreamInstance uint32 = 1
)

// OutputStreamHeader is the signed part of OutputStreamHeaderV2.
type OutputStreamHeader struct {
	ChainID             string
	TaskHash            []byte
	Attempt             uint32
	StreamInstance      uint32
	UserRecipientPubkey []byte
	OutputKeyCommitment []byte
	KeyPackageHash      []byte
}

// SigningDigest is H_FIELDS_V1("TRUEOPEN_OUTPUT_STREAM_HEADER_V1", chain_id, task_hash, attempt,
// stream_instance, user_recipient_pubkey, output_key_commitment, key_package_hash), signed by the
// selected Worker's service key direct-digest, raw64 R||S, low-S. It binds the stream to the Worker
// independently of the upload request authorization, which only says who is calling. Conformance
// vector: wire testdata/v1/task/output_stream_header_v1.json.
func (h OutputStreamHeader) SigningDigest() ([32]byte, error) {
	chain, err := CanonicalUTF8Field("chain_id", h.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	task, err := CanonicalHash32Field("task_hash", h.TaskHash)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainOutputStreamHeaderV1,
		chain, task, Uint32BE(h.Attempt), Uint32BE(h.StreamInstance),
		h.UserRecipientPubkey, h.OutputKeyCommitment, h.KeyPackageHash,
	), nil
}

// ValidatePlaintext is the admission rule while encryption is inactive: attempt 0, stream_instance 1,
// no recipient key and two 32-zero-byte commitments. Empty commitments are rejected, not padded.
func (h OutputStreamHeader) ValidatePlaintext() error {
	switch {
	case h.Attempt != PlaintextOutputStreamAttempt:
		return fmt.Errorf("attempt must be %d, got %d", PlaintextOutputStreamAttempt, h.Attempt)
	case h.StreamInstance != PlaintextOutputStreamInstance:
		return fmt.Errorf("stream_instance must be %d, got %d", PlaintextOutputStreamInstance, h.StreamInstance)
	case len(h.UserRecipientPubkey) != 0:
		return fmt.Errorf("user_recipient_pubkey must be empty for a plaintext stream")
	case !IsZeroHash32(h.OutputKeyCommitment):
		return fmt.Errorf("output_key_commitment must be 32 zero bytes for a plaintext stream")
	case !IsZeroHash32(h.KeyPackageHash):
		return fmt.Errorf("key_package_hash must be 32 zero bytes for a plaintext stream")
	}
	return nil
}
