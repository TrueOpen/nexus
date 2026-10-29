package nodecontract

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
)

// The two domains of streaming output.
//
//	output_hash          = MmrRoot(DomainOutputMMRV1, [chunk_0 .. chunk_{n-1}])   -- internal/mmr
//	chunk_signing_digest = H_FIELDS_V1(DomainOutputChunkV1, chain_id, task_hash, dispatch_ticket_hash, seq, mmr_root)
//
// The chunk and fin digests are computed by the wire dispatch package; conformance vectors are wire
// testdata/v1/task/output_mmr_v1.json (outputchunk_golden_test.go) and internal/mmr/golden_test.go.
const (
	DomainOutputMMRV1   = "TRUEOPEN_OUTPUT_MMR_V1"
	DomainOutputChunkV1 = "TRUEOPEN_OUTPUT_CHUNK_V1"
)

// OutputChunkSigningDigest is the Worker's signing digest over one output frame: exactly 5 top-level
// fields, in order chain_id(string) / task_hash(Hash32) / dispatch_ticket_hash(Hash32) / seq(uint64) /
// mmr_root(Hash32). The ticket binds the frame to one dispatch attempt, so frames of two attempts of
// the same order cannot be mixed. mmr_root is the prefix root root_{seq+1} after appending leaf seq;
// what is signed is the cumulative commitment, not the single frame's content.
// Signing is direct-digest: secp256k1 signs this digest directly, raw64 R||S, low-S.
func OutputChunkSigningDigest(chainID string, taskHash, ticketHash []byte, seq uint64, mmrRoot []byte) ([32]byte, error) {
	chain, task, ticket, root, err := outputDigestInputs(chainID, taskHash, ticketHash, "mmr_root", mmrRoot)
	if err != nil {
		return [32]byte{}, err
	}
	return dispatch.OutputChunkDigest(chain, task, ticket, seq, root), nil
}

// outputDigestInputs validates the fields shared by the chunk and fin digests.
func outputDigestInputs(chainID string, taskHash, ticketHash []byte, rootName string, rootBytes []byte) (string, [32]byte, [32]byte, [32]byte, error) {
	var task, ticket, root [32]byte
	if chainID == "" {
		return "", task, ticket, root, fmt.Errorf("chain_id must not be empty")
	}
	if _, err := CanonicalUTF8Field("chain_id", chainID); err != nil {
		return "", task, ticket, root, err
	}
	for _, field := range []struct {
		name  string
		value []byte
		out   *[32]byte
	}{
		{"task_hash", taskHash, &task},
		{"dispatch_ticket_hash", ticketHash, &ticket},
		{rootName, rootBytes, &root},
	} {
		raw, err := CanonicalHash32Field(field.name, field.value)
		if err != nil {
			return "", task, ticket, root, err
		}
		copy(field.out[:], raw)
	}
	return chainID, task, ticket, root, nil
}
