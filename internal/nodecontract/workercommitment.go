package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Domains of the Worker evidence commitment (validation algorithm §7 and §7.0b), registered in
// TrueOpen/wire registry/v1/domains.json.
const (
	DomainWorkerValueCommitmentV2 = "TRUEOPEN_WORKER_VALUE_COMMITMENT_V2"
	DomainInputTokenIDsV1         = "TRUEOPEN_INPUT_TOKEN_IDS_V1"
	DomainGeneratedTokenIDsV1     = "TRUEOPEN_GENERATED_TOKEN_IDS_V1"
)

// WorkerValueCommitmentSchemaV2 is WorkerValueCommitmentV2.schema_version, always 2 in the Phase 0
// contract.
const WorkerValueCommitmentSchemaV2 = 2

// MaxTokenIDCountV1 is the absolute token-id count bound of validation algorithm §7:
// floor((33,554,432 - 4) / 4), the Canonical §6 32 MiB single-field limit minus the count prefix.
// wire testdata/v1/task/token_ids_v1.json lists a larger count as a rejected encoding.
const MaxTokenIDCountV1 = 8_388_607

// TokenIDsHash is H_FIELDS_V1(domain, token_ids_raw) of validation algorithm §7, where token_ids_raw
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

// WorkerValueCommitmentV2 is the input of the single WORKER_VALUE_OPENING commitment
// (task.v1.WorkerValueCommitmentV2). Hash32 fields are raw 32 bytes; WorkerOperatorAddress is bech32.
type WorkerValueCommitmentV2 struct {
	ChainID                    string
	TaskID                     []byte
	AcceptedTaskHash           []byte
	WorkerOperatorAddress      string
	GenerationParamsDigest     []byte
	EvidenceSchemaHash         []byte
	OutputHash                 []byte
	OutputSizeBytes            uint64
	FinishReason               uint32
	TraceRoot                  []byte
	TraceEncodedSizeBytes      uint64
	CheckpointRoot             []byte
	CheckpointEncodedSizeBytes uint64
	GeneratedTokenCount        uint64
	OutputLeafCount            uint64
	InputTokenIDsHash          []byte
	GeneratedTokenIDsHash      []byte
	InputTokenIDsSizeBytes     uint64
	GeneratedTokenIDsSizeBytes uint64
}

// Digest is H_FIELDS_V1(TRUEOPEN_WORKER_VALUE_COMMITMENT_V2, ...) over the 20 fields in schema order,
// i.e. the receipt's WORKER_VALUE_OPENING evidence_hash_or_root. Conformance vector:
// wire testdata/v1/task/worker_value_commitment_v2.json.
func (c WorkerValueCommitmentV2) Digest() ([32]byte, error) {
	chain, err := CanonicalUTF8Field("chain_id", c.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", c.WorkerOperatorAddress)
	if err != nil {
		return [32]byte{}, err
	}
	hashes := []struct {
		name  string
		value []byte
	}{
		{"task_id", c.TaskID},
		{"accepted_task_hash", c.AcceptedTaskHash},
		{"generation_params_digest", c.GenerationParamsDigest},
		{"evidence_schema_hash", c.EvidenceSchemaHash},
		{"output_hash", c.OutputHash},
		{"trace_root", c.TraceRoot},
		{"checkpoint_root", c.CheckpointRoot},
		{"input_token_ids_hash", c.InputTokenIDsHash},
		{"generated_token_ids_hash", c.GeneratedTokenIDsHash},
	}
	framed := make(map[string][]byte, len(hashes))
	for _, h := range hashes {
		field, err := CanonicalHash32Field(h.name, h.value)
		if err != nil {
			return [32]byte{}, err
		}
		framed[h.name] = field
	}
	return CanonicalHashBytes(DomainWorkerValueCommitmentV2,
		Uint32BE(WorkerValueCommitmentSchemaV2),
		chain,
		framed["task_id"],
		framed["accepted_task_hash"],
		worker,
		framed["generation_params_digest"],
		framed["evidence_schema_hash"],
		framed["output_hash"],
		Uint64BE(c.OutputSizeBytes),
		EnumBE(c.FinishReason),
		framed["trace_root"],
		Uint64BE(c.TraceEncodedSizeBytes),
		framed["checkpoint_root"],
		Uint64BE(c.CheckpointEncodedSizeBytes),
		Uint64BE(c.GeneratedTokenCount),
		Uint64BE(c.OutputLeafCount),
		framed["input_token_ids_hash"],
		framed["generated_token_ids_hash"],
		Uint64BE(c.InputTokenIDsSizeBytes),
		Uint64BE(c.GeneratedTokenIDsSizeBytes),
	), nil
}
