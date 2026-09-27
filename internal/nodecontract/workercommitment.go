package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Domains of the two Worker evidence commitments, registered in TrueOpen/wire registry/v1/domains.json.
// A Worker commits to its evidence in two bundles: the token opening (the input and generated token ids
// and the finish reason) and the value opening (the Merkle root of its per-position values).
const (
	DomainWorkerTokenCommitmentV1 = "TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1"
	DomainWorkerValueCommitmentV3 = "TRUEOPEN_WORKER_VALUE_COMMITMENT_V3"
	DomainWorkerValueLeafV1       = "TRUEOPEN_PREFILL_WORKER_VALUE_LEAF_V1"
	DomainWorkerValueRootV1       = "TRUEOPEN_PREFILL_WORKER_VALUE_ROOT_V1"
	DomainInputTokenIDsV1         = "TRUEOPEN_INPUT_TOKEN_IDS_V1"
	DomainGeneratedTokenIDsV1     = "TRUEOPEN_GENERATED_TOKEN_IDS_V1"
)

// Schema versions of the two Worker commitments and of a Worker value leaf.
const (
	WorkerTokenCommitmentSchemaV1 = 1
	WorkerValueCommitmentSchemaV3 = 3
	WorkerValueLeafVersionV1      = 1
)

// MaxTokenIDCountV1 is the absolute token-id count bound: floor((33,554,432 - 4) / 4), the 32 MiB
// single-field limit minus the count prefix.
// wire testdata/v1/task/token_ids_v1.json lists a larger count as a rejected encoding.
const MaxTokenIDCountV1 = 8_388_607

// TokenIDsHash is H_FIELDS_V1(domain, token_ids_raw), where token_ids_raw
// is uint32_be(count) || repeated uint32_be(token_id) and is framed as one raw field. Only the
// framing is checked (the count prefix matches the length and is within bound); the ids themselves
// are not interpreted. Conformance vectors: wire testdata/v1/task/token_ids_v1.json.
func TokenIDsHash(domain string, raw []byte) ([32]byte, error) {
	return TokenIDsHashReader(domain, bytes.NewReader(raw), uint64(len(raw)))
}

// TokenIDsHashReader is TokenIDsHash over exactly size bytes read from r, without holding the
// vector in memory.
func TokenIDsHashReader(domain string, r io.Reader, size uint64) ([32]byte, error) {
	if domain != DomainInputTokenIDsV1 && domain != DomainGeneratedTokenIDsV1 {
		return [32]byte{}, fmt.Errorf("unknown token ids domain %q", domain)
	}
	if size < 4 {
		return [32]byte{}, fmt.Errorf("token_ids_raw is %d bytes, shorter than its count prefix", size)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return [32]byte{}, fmt.Errorf("read token_ids_raw count: %w", err)
	}
	count := uint64(binary.BigEndian.Uint32(prefix[:]))
	if count > MaxTokenIDCountV1 {
		return [32]byte{}, fmt.Errorf("token_ids_raw count %d exceeds %d", count, MaxTokenIDCountV1)
	}
	if size != 4+4*count {
		return [32]byte{}, fmt.Errorf("token_ids_raw is %d bytes, count %d needs %d", size, count, 4+4*count)
	}
	// H_FIELDS_V1 with a single field: u64_be(len(domain)) || domain || u64_be(len(raw)) || raw.
	digest := sha256.New()
	digest.Write(CanonicalFrameBytes([]byte(domain)))
	digest.Write(Uint64BE(size))
	digest.Write(prefix[:])
	if written, err := io.CopyN(digest, r, int64(size-4)); err != nil {
		return [32]byte{}, fmt.Errorf("read token_ids_raw: %d of %d bytes: %w", written+4, size, err)
	}
	var out [32]byte
	copy(out[:], digest.Sum(nil))
	return out, nil
}

// WorkerTokenCommitmentV1 is the input of the WORKER_TOKEN_OPENING commitment
// (task.v1.WorkerTokenCommitmentV1). Hash32 fields are raw 32 bytes; WorkerOperatorAddress is bech32.
type WorkerTokenCommitmentV1 struct {
	ChainID                    string
	TaskID                     []byte
	AcceptedTaskHash           []byte
	WorkerOperatorAddress      string
	GenerationParamsDigest     []byte
	EvidenceSchemaHash         []byte
	OutputHash                 []byte
	OutputSizeBytes            uint64
	OutputLeafCount            uint64
	FinishReason               uint32
	GeneratedTokenCount        uint64
	InputTokenIDsHash          []byte
	GeneratedTokenIDsHash      []byte
	InputTokenIDsSizeBytes     uint64
	GeneratedTokenIDsSizeBytes uint64
}

// Digest is H_FIELDS_V1(TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1, ...) over the 16 fields in schema order,
// i.e. the receipt's WORKER_TOKEN_OPENING evidence_hash_or_root. Conformance vector:
// wire testdata/v1/task/worker_token_commitment_v1.json.
func (c WorkerTokenCommitmentV1) Digest() ([32]byte, error) {
	if c.FinishReason < 1 || c.FinishReason > MaxFinishReasonV1 {
		return [32]byte{}, fmt.Errorf("finish_reason %d is not in 1..%d", c.FinishReason, MaxFinishReasonV1)
	}
	chain, err := CanonicalUTF8Field("chain_id", c.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", c.WorkerOperatorAddress)
	if err != nil {
		return [32]byte{}, err
	}
	hashes, err := canonicalHash32Fields([]hash32Field{
		{"task_id", c.TaskID},
		{"accepted_task_hash", c.AcceptedTaskHash},
		{"generation_params_digest", c.GenerationParamsDigest},
		{"evidence_schema_hash", c.EvidenceSchemaHash},
		{"output_hash", c.OutputHash},
		{"input_token_ids_hash", c.InputTokenIDsHash},
		{"generated_token_ids_hash", c.GeneratedTokenIDsHash},
	})
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainWorkerTokenCommitmentV1,
		Uint32BE(WorkerTokenCommitmentSchemaV1),
		chain,
		hashes[0], // task_id
		hashes[1], // accepted_task_hash
		worker,
		hashes[2], // generation_params_digest
		hashes[3], // evidence_schema_hash
		hashes[4], // output_hash
		Uint64BE(c.OutputSizeBytes),
		Uint64BE(c.OutputLeafCount),
		EnumBE(c.FinishReason),
		Uint64BE(c.GeneratedTokenCount),
		hashes[5], // input_token_ids_hash
		hashes[6], // generated_token_ids_hash
		Uint64BE(c.InputTokenIDsSizeBytes),
		Uint64BE(c.GeneratedTokenIDsSizeBytes),
	), nil
}

// WorkerValueCommitmentV3 is the input of the WORKER_VALUE_OPENING commitment
// (task.v1.WorkerValueCommitmentV3).
type WorkerValueCommitmentV3 struct {
	ChainID                      string
	TaskID                       []byte
	AcceptedTaskHash             []byte
	WorkerOperatorAddress        string
	EvidenceSchemaHash           []byte
	WorkerValueRoot              []byte
	WorkerValuesEncodedSizeBytes uint64
}

// Digest is H_FIELDS_V1(TRUEOPEN_WORKER_VALUE_COMMITMENT_V3, ...) over the 8 fields in schema order,
// i.e. the receipt's WORKER_VALUE_OPENING evidence_hash_or_root. Conformance vector:
// wire testdata/v1/task/worker_value_commitment_v3.json.
func (c WorkerValueCommitmentV3) Digest() ([32]byte, error) {
	chain, err := CanonicalUTF8Field("chain_id", c.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", c.WorkerOperatorAddress)
	if err != nil {
		return [32]byte{}, err
	}
	hashes, err := canonicalHash32Fields([]hash32Field{
		{"task_id", c.TaskID},
		{"accepted_task_hash", c.AcceptedTaskHash},
		{"evidence_schema_hash", c.EvidenceSchemaHash},
		{"worker_value_root", c.WorkerValueRoot},
	})
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainWorkerValueCommitmentV3,
		Uint32BE(WorkerValueCommitmentSchemaV3),
		chain,
		hashes[0], // task_id
		hashes[1], // accepted_task_hash
		worker,
		hashes[2], // evidence_schema_hash
		hashes[3], // worker_value_root
		Uint64BE(c.WorkerValuesEncodedSizeBytes),
	), nil
}

// hash32Field is one named Hash32 preimage field.
type hash32Field struct {
	name  string
	value []byte
}

// canonicalHash32Fields checks each field as a Hash32 and returns them in order.
func canonicalHash32Fields(fields []hash32Field) ([][]byte, error) {
	out := make([][]byte, 0, len(fields))
	for _, f := range fields {
		field, err := CanonicalHash32Field(f.name, f.value)
		if err != nil {
			return nil, err
		}
		out = append(out, field)
	}
	return out, nil
}
