package nodecontract

import "fmt"

// DomainOutputFinV1 is the Worker-authenticated OUTPUT terminal frame domain registered in
// TrueOpen/wire registry/v1/domains.json (wire#35): H_FIELDS_V1 over chain_id, task_hash,
// uint64_be(final_seq), output_mmr_root, uint32_be(finish_reason).
const DomainOutputFinV1 = "TRUEOPEN_OUTPUT_FIN_V1"

// OutputFinSigningDigest is the Worker's signing digest over the Fin frame: exactly 5 top-level
// fields in order chain_id(string) / task_hash(Hash32) / final_seq(uint64) / output_mmr_root(Hash32)
// / finish_reason(uint32 enum number). Like the chunk digest it is signed direct-digest, raw64
// R||S, low-S.
//
// Only the FinishReasonV1 values 1..4 are successful terminations; the registry requires
// UNSPECIFIED, unknown values, failures and cancellations to be rejected before any digest
// is verified, so this returns an error for them rather than a digest a caller could accept.
// Conformance vectors: wire testdata/v1/task/output_mmr_v1.json fin_signing, see
// outputfin_golden_test.go.
func OutputFinSigningDigest(chainID string, taskHash []byte, finalSeq uint64, outputMMRRoot []byte, finishReason uint32) ([32]byte, error) {
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("chain_id must not be empty")
	}
	if finishReason < 1 || finishReason > 4 {
		return [32]byte{}, fmt.Errorf("finish_reason %d is not an accepted successful termination", finishReason)
	}
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return [32]byte{}, err
	}
	task, err := CanonicalHash32Field("task_hash", taskHash)
	if err != nil {
		return [32]byte{}, err
	}
	root, err := CanonicalHash32Field("output_mmr_root", outputMMRRoot)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainOutputFinV1, chain, task, Uint64BE(finalSeq), root, Uint32BE(finishReason)), nil
}
