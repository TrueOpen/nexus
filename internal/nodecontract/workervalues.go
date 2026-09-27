package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Merkle primitive tags of MERKLE_ROOT_V1.
const (
	merkleLeafTagV1  = "TRUEOPEN_MERKLE_LEAF_V1"
	merkleNodeTagV1  = "TRUEOPEN_MERKLE_NODE_V1"
	merkleEmptyTagV1 = "TRUEOPEN_MERKLE_EMPTY_V1"
)

// worker value leaf field sizes, fixed by the leaf schema.
const (
	workerValueLeafFieldCount = 11
	maxWorkerValueFieldBytes  = 32 << 20
	// minWorkerValueLeafBytes is the smallest encoded leaf: eleven 8-byte length prefixes.
	minWorkerValueLeafBytes = workerValueLeafFieldCount * 8
)

// MerkleRootV1 is MERKLE_ROOT_V1 over raw Hash32 leaves in the given order:
//
//	domain_frame = u32_be(len(domain)) || domain
//	leaf  = SHA256("TRUEOPEN_MERKLE_LEAF_V1"  || domain_frame || raw_hash32_leaf)
//	node  = SHA256("TRUEOPEN_MERKLE_NODE_V1"  || domain_frame || left || right)
//	empty = SHA256("TRUEOPEN_MERKLE_EMPTY_V1" || domain_frame)
//
// Levels pair left to right and an odd final node is promoted unchanged. Leaves are never sorted,
// deduplicated or padded; the caller owns their order.
func MerkleRootV1(domain string, leaves [][32]byte) [32]byte {
	frame := append(Uint32BE(uint32(len(domain))), domain...)
	if len(leaves) == 0 {
		return sha256.Sum256(append([]byte(merkleEmptyTagV1), frame...))
	}
	level := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		h := sha256.New()
		h.Write([]byte(merkleLeafTagV1))
		h.Write(frame)
		h.Write(leaf[:])
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			h := sha256.New()
			h.Write([]byte(merkleNodeTagV1))
			h.Write(frame)
			h.Write(level[i][:])
			h.Write(level[i+1][:])
			var node [32]byte
			copy(node[:], h.Sum(nil))
			next = append(next, node)
		}
		level = next
	}
	return level[0]
}

// WorkerValueScope is what every leaf of a Worker's worker_values artifact must repeat: the task
// and Worker the values belong to. Hash32 fields are raw 32 bytes; WorkerOperatorAddress is bech32.
type WorkerValueScope struct {
	ChainID               string
	TaskID                []byte
	AcceptedTaskHash      []byte
	WorkerOperatorAddress string
}

// WorkerValuesRootReader strictly decodes a worker_values artifact of exactly size bytes from r and
// returns its worker_value_root.
//
// The artifact is u32_be(leaf_count) followed by each leaf's worker_value_leaf_bytes in position
// order, with no extra length in front of a leaf: a leaf is a fixed sequence of eleven length-prefixed
// fields (chain_id, task_id, accepted_task_hash, worker_operator_address, position, token_id,
// worker_logprob_fp_1e6, worker_rank, topk_entries, missing_flag, finite_flag). Every leaf must repeat
// scope, positions must run 0..leaf_count-1, and leaf_count must equal wantLeaves (the receipt's
// generated_token_count). Each leaf hashes as
// H_FIELDS_V1("TRUEOPEN_PREFILL_WORKER_VALUE_LEAF_V1", u32_be(1), worker_value_leaf_bytes), and the
// root is MERKLE_ROOT_V1 over those hashes under TRUEOPEN_PREFILL_WORKER_VALUE_ROOT_V1.
//
// Only the encoding and the scope are checked. Whether the values themselves are right is the
// Verifier's comparison, not the Builder's.
func WorkerValuesRootReader(r io.Reader, size uint64, scope WorkerValueScope, wantLeaves uint64) ([32]byte, error) {
	chainID, err := CanonicalUTF8Field("chain_id", scope.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	scopeHashes, err := canonicalHash32Fields([]hash32Field{
		{"task_id", scope.TaskID},
		{"accepted_task_hash", scope.AcceptedTaskHash},
	})
	if err != nil {
		return [32]byte{}, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", scope.WorkerOperatorAddress)
	if err != nil {
		return [32]byte{}, err
	}
	d := &valueDecoder{r: r, left: size}
	countBytes, err := d.take(4)
	if err != nil {
		return [32]byte{}, fmt.Errorf("worker_values leaf count: %w", err)
	}
	count := uint64(binary.BigEndian.Uint32(countBytes))
	if count != wantLeaves {
		return [32]byte{}, fmt.Errorf("worker_values has %d leaves, the receipt's generated_token_count is %d", count, wantLeaves)
	}
	// The leaf count is the Worker's claim: bound it by the token limit and by the bytes actually
	// present before allocating anything for it, so a short artifact cannot ask for a huge slice.
	if count > MaxTokenIDCountV1 {
		return [32]byte{}, fmt.Errorf("worker_values leaf count %d exceeds %d", count, MaxTokenIDCountV1)
	}
	if d.left < count*minWorkerValueLeafBytes {
		return [32]byte{}, fmt.Errorf("worker_values has %d bytes after its count, %d leaves need at least %d",
			d.left, count, count*minWorkerValueLeafBytes)
	}
	leaves := make([][32]byte, 0, count)
	for position := uint64(0); position < count; position++ {
		var leaf bytes.Buffer
		fields := make([][]byte, 0, workerValueLeafFieldCount)
		for i := 0; i < workerValueLeafFieldCount; i++ {
			field, raw, err := d.frame()
			if err != nil {
				return [32]byte{}, fmt.Errorf("worker_values leaf %d field %d: %w", position, i+1, err)
			}
			leaf.Write(raw)
			fields = append(fields, field)
		}
		if err := checkWorkerValueLeaf(fields, position, chainID, scopeHashes[0], scopeHashes[1], worker); err != nil {
			return [32]byte{}, fmt.Errorf("worker_values leaf %d: %w", position, err)
		}
		leaves = append(leaves, CanonicalHashBytes(DomainWorkerValueLeafV1, Uint32BE(WorkerValueLeafVersionV1), leaf.Bytes()))
	}
	if d.left != 0 {
		return [32]byte{}, fmt.Errorf("worker_values has %d trailing bytes after %d leaves", d.left, count)
	}
	return MerkleRootV1(DomainWorkerValueRootV1, leaves), nil
}

// checkWorkerValueLeaf checks the typed shape of one decoded leaf and that it repeats the scope.
func checkWorkerValueLeaf(fields [][]byte, position uint64, chainID, taskID, taskHash, worker []byte) error {
	switch {
	case !bytes.Equal(fields[0], chainID):
		return fmt.Errorf("chain_id does not match the task")
	case !bytes.Equal(fields[1], taskID):
		return fmt.Errorf("task_id does not match the task")
	case !bytes.Equal(fields[2], taskHash):
		return fmt.Errorf("accepted_task_hash does not match the task")
	case !bytes.Equal(fields[3], worker):
		return fmt.Errorf("worker_operator_address does not match the Worker")
	case len(fields[4]) != 4 || uint64(binary.BigEndian.Uint32(fields[4])) != position:
		return fmt.Errorf("position is not %d", position)
	case len(fields[5]) != 4:
		return fmt.Errorf("token_id must be 4 bytes")
	case len(fields[6]) != 8:
		return fmt.Errorf("worker_logprob_fp_1e6 must be 8 bytes")
	case len(fields[7]) != 4:
		return fmt.Errorf("worker_rank must be 4 bytes")
	}
	if err := checkTopKEntries(fields[8]); err != nil {
		return fmt.Errorf("topk_entries: %w", err)
	}
	for _, flag := range []struct {
		name  string
		value []byte
	}{{"missing_flag", fields[9]}, {"finite_flag", fields[10]}} {
		if len(flag.value) != 1 || flag.value[0] > 1 {
			return fmt.Errorf("%s must be one byte 00 or 01", flag.name)
		}
	}
	return nil
}

// checkTopKEntries checks the nested frame u32_be(count) followed by count entries, each a nested
// frame of token_id (uint32) and logprob_fp_1e6 (int64).
func checkTopKEntries(frame []byte) error {
	d := &valueDecoder{r: bytes.NewReader(frame), left: uint64(len(frame))}
	countField, _, err := d.frame()
	if err != nil {
		return err
	}
	if len(countField) != 4 {
		return fmt.Errorf("count must be 4 bytes")
	}
	count := binary.BigEndian.Uint32(countField)
	for i := uint32(0); i < count; i++ {
		entry, _, err := d.frame()
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		e := &valueDecoder{r: bytes.NewReader(entry), left: uint64(len(entry))}
		tokenID, _, err := e.frame()
		if err != nil || len(tokenID) != 4 {
			return fmt.Errorf("entry %d token_id must be a 4-byte field", i)
		}
		logprob, _, err := e.frame()
		if err != nil || len(logprob) != 8 {
			return fmt.Errorf("entry %d logprob_fp_1e6 must be an 8-byte field", i)
		}
		if e.left != 0 {
			return fmt.Errorf("entry %d has trailing bytes", i)
		}
	}
	if d.left != 0 {
		return fmt.Errorf("%d trailing bytes after %d entries", d.left, count)
	}
	return nil
}

// valueDecoder reads length-prefixed fields from exactly left bytes of r.
type valueDecoder struct {
	r    io.Reader
	left uint64
}

func (d *valueDecoder) take(n uint64) ([]byte, error) {
	if n > d.left {
		return nil, fmt.Errorf("needs %d bytes, %d left", n, d.left)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, err
	}
	d.left -= n
	return buf, nil
}

// frame reads u64_be(len) || value and returns the value and the raw bytes including the prefix.
func (d *valueDecoder) frame() (value, raw []byte, err error) {
	prefix, err := d.take(8)
	if err != nil {
		return nil, nil, err
	}
	n := binary.BigEndian.Uint64(prefix)
	if n > maxWorkerValueFieldBytes {
		return nil, nil, fmt.Errorf("field of %d bytes exceeds %d", n, maxWorkerValueFieldBytes)
	}
	value, err = d.take(n)
	if err != nil {
		return nil, nil, err
	}
	return value, append(prefix, value...), nil
}
