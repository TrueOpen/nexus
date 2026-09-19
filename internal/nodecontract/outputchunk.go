package nodecontract

import "fmt"

// The two domains of ADR-0017 streaming output (04-task/05-verification-algorithm §8.1).
//
//	output_hash          = MmrRoot(DomainOutputMMRV1, [chunk_0 .. chunk_{n-1}])   -- internal/mmr
//	chunk_signing_digest = H_FIELDS_V1(DomainOutputChunkV1, chain_id, task_hash, seq, mmr_root)
//
// Both activate together with TRUEOPEN_INFER_RECEIPT_V2; the wire v0.4.0 registry does not yet list them (wire#25),
// so this follows the protocol text. Conformance vectors come from monorepo 04-task/05-verification-algorithm §8.1
// and the base spec §11.5; see outputchunk_golden_test.go and internal/mmr/golden_test.go.
// Once wire publishes vectors of the same name, switch to consuming wire's testdata directly.
const (
	DomainOutputMMRV1   = "TRUEOPEN_OUTPUT_MMR_V1"
	DomainOutputChunkV1 = "TRUEOPEN_OUTPUT_CHUNK_V1"
)

// OutputChunkSigningDigest is the Worker's signing digest over one output frame: exactly 4 top-level fields,
// in order chain_id(string) / task_hash(Hash32) / seq(uint64) / mmr_root(Hash32).
// mmr_root is the prefix root root_{seq+1} after appending leaf seq; what is signed is the cumulative commitment, not the single frame's content.
// Signing is direct-digest (base spec §10): secp256k1 signs this digest directly, raw64 R||S, low-S.
func OutputChunkSigningDigest(chainID string, taskHash []byte, seq uint64, mmrRoot []byte) ([32]byte, error) {
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("chain_id must not be empty")
	}
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return [32]byte{}, err
	}
	task, err := CanonicalHash32Field("task_hash", taskHash)
	if err != nil {
		return [32]byte{}, err
	}
	root, err := CanonicalHash32Field("mmr_root", mmrRoot)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainOutputChunkV1, chain, task, Uint64BE(seq), root), nil
}
