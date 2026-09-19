package nodecontract

import (
	"crypto/sha256"
	"fmt"
	"math"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/types"
)

// Frozen V1 stage-wire signing digests (Keeper Interface Contract §5.14 / §1.2 / §1.4).
// Reference implementation and golden vectors: node x/task/types/signature.go,
// x/task/types/evidence_commitments.go and testdata/task_domains_v1.json.

// DomainInferEvidenceCommitmentsV1 is the domain of evidence_commitments_hash.
// Note the domain name is TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1 (35 ASCII bytes), not
// TRUEOPEN_EVIDENCE_COMMITMENTS_V1; §1.4 registers the former.
const DomainInferEvidenceCommitmentsV1 = "TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1"

// InferReceiptSchemaVersionV2 is the schema_version value of InferReceiptV2. In the Phase 0
// fresh contract it is the only stage wire with value 2 (wire v0.4.1): the other
// three §5.14 stage wires and the two §4.1 handraise wires stay at 1, and InferReceiptV1 has
// neither an alias nor a dual decoder.
//
// The derivation functions do NOT assert schema_version == 2: the frozen-wire guarantee is that
// "a signer who guesses the wrong value gets a digest the Keeper never accepts", which only holds if the
// derivation stays total. The equality check is an admission check left to callers (see workerverifier / submitter).
const InferReceiptSchemaVersionV2 uint32 = 2

// ResultReceiptSchemaVersionV2 is the schema_version value of ResultReceiptV2. Like
// InferReceiptV2 it is 2 in the fresh contract: the V1 receipt's single result_reveal_hash was
// replaced by three fields verifier_evidence_bundle_hash + manifest size + salt, and the domain
// moved to TRUEOPEN_RESULT_V2, with no alias and no dual decoder (since wire v0.4.0).
const ResultReceiptSchemaVersionV2 uint32 = 2

// evidenceCommitmentFrameBytesV1 is the exact length of one EvidenceCommitmentV1 frame:
// u64_be(4)||uint32_be(evidence_kind) + u64_be(32)||evidence_hash_or_root +
// u64_be(8)||uint64_be(encoded_size_bytes). It is a derived constant used only for assertions,
// never as an encoding input, so adding a field later fails loudly instead of silently changing the digest.
const evidenceCommitmentFrameBytesV1 = (8 + 4) + (8 + sha256.Size) + (8 + 8)

// CanonicalEvidenceCommitmentFrameV1 encodes one EvidenceCommitmentV1 as the nested
// FieldFrameV1 that TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1 wraps as a single length-prefixed element.
//
// §1.2: "a required nested message recursively encodes its field frames in ascending schema
// field-number order", so the element frame has NO domain prefix and is written by field number 1/2/3:
//
//	u64_be(4)  || uint32_be(evidence_kind)   // enum → uint32_be
//	u64_be(32) || evidence_hash_or_root      // raw Hash32, not hex
//	u64_be(8)  || uint64_be(encoded_size_bytes)
//
// The result is always 68 bytes. Elements are NOT flattened into top-level fields.
func CanonicalEvidenceCommitmentFrameV1(item *taskv1.EvidenceCommitmentV1) ([]byte, error) {
	if item == nil {
		return nil, fmt.Errorf("evidence commitment is required")
	}
	kind, err := canonicalEvidenceKind(item.GetEvidenceKind())
	if err != nil {
		return nil, err
	}
	hashOrRoot, err := CanonicalHash32Field("evidence_hash_or_root", item.GetEvidenceHashOrRoot())
	if err != nil {
		return nil, err
	}
	frame := CanonicalFrameBytes(
		EnumBE(kind),
		hashOrRoot,
		Uint64BE(item.GetEncodedSizeBytes()),
	)
	if len(frame) != evidenceCommitmentFrameBytesV1 {
		return nil, fmt.Errorf("evidence commitment frame must be exactly %d bytes, got %d",
			evidenceCommitmentFrameBytesV1, len(frame))
	}
	return frame, nil
}

// EvidenceCommitmentsHash derives the 10th field of the InferReceiptV2 preimage,
// evidence_commitments_hash. It is a Keeper-derived value, NEVER a wire field submitted by the caller
// (§5.14):
//
//	evidence_commitments_hash =
//	  H_FIELDS_V1("TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1",
//	    uint32_be(count), commitment[0], ... commitment[count-1])
//
// This preimage carries NEITHER chain_id NOR task_id: it is a pure content commitment whose scope
// is bound by the outer TRUEOPEN_INFER_RECEIPT_V1 digest. The sibling domains TRUEOPEN_RESULT_RECEIPT_REFS_V1 /
// TRUEOPEN_CONSENSUS_CLUSTER_V1 both bind those two, so an implementation is tempted to "helpfully" add
// them here; doing so double-binds and the digest can never match.
//
// Order is not the caller's choice: the list must be strictly ascending by evidence_kind with unique
// kinds; a non-ascending or duplicate list is rejected before hashing and is NEVER silently reordered.
//
// count == 0 stays fully defined: write uint32_be(0) with no element frames, giving
// 393ca3fb29b409f454b6f870f972c4a8fdffbf9934eadd628ecfdf0f03789764,
// which is NEVER 32 zero bytes, nor an empty byte string, and the count field must not be omitted; nil and [] share the digest.
// Whether count == 0 is *acceptable* is an admission question the contract does not register
// (a known contract gap), so no lower bound is enforced here.
func EvidenceCommitmentsHash(items []*taskv1.EvidenceCommitmentV1) ([32]byte, error) {
	if uint64(len(items)) > uint64(math.MaxUint32) {
		return [32]byte{}, fmt.Errorf("evidence commitment count %d overflows uint32", len(items))
	}
	frames := make([][]byte, 0, len(items))
	for index, item := range items {
		if index > 0 && items[index-1].GetEvidenceKind() >= item.GetEvidenceKind() {
			return [32]byte{}, fmt.Errorf(
				"required_evidence_commitments must be strictly ascending by evidence_kind with unique kinds: "+
					"element %d has kind %d after kind %d",
				index, item.GetEvidenceKind(), items[index-1].GetEvidenceKind())
		}
		frame, err := CanonicalEvidenceCommitmentFrameV1(item)
		if err != nil {
			return [32]byte{}, fmt.Errorf("required_evidence_commitments[%d]: %w", index, err)
		}
		frames = append(frames, frame)
	}
	// The repeated value is ONE nested field, not N top-level fields: the nested frame first writes the
	// element count, then each element (each with its own length prefix), and the whole thing is wrapped
	// into the top level as one field (§1.2 repeated nested message rule; on-chain CanonicalRepeatedFramesV1 encodes it this way).
	// The top-level count is a separate field required by §5.14 and is not the same position as the one inside the nested frame.
	nested := make([][]byte, 0, len(frames)+1)
	nested = append(nested, Uint32BE(uint32(len(items))))
	nested = append(nested, frames...)
	return CanonicalHashBytes(DomainInferEvidenceCommitmentsV1,
		Uint32BE(uint32(len(items))),
		CanonicalFrameBytes(nested...),
	), nil
}

// InferReceiptSigningDigest is the single ordered preimage of infer_receipt_signing_digest and
// infer_receipt_hash; §5.14 writes both as the same equation, so there is no second "application-level hash":
//
//	infer_receipt_hash = infer_receipt_signing_digest =
//	  H_FIELDS_V1("TRUEOPEN_INFER_RECEIPT_V1",
//	    schema_version, chain_id, task_id, task_hash,
//	    worker_operator_address, service_authorization_nonce,
//	    generation_params_digest, output_hash, output_size_bytes,
//	    evidence_commitments_hash, expiry_height, generated_token_count,
//	    output_leaf_count)
//
// 13 fields; service_signature (wire field 12) is not among them. The 10th field is not a wire field:
// required_evidence_commitments (wire field 10) enters the preimage only through EvidenceCommitmentsHash,
// so the signature still covers the whole typed list. worker_operator_address is framed as address codec
// bytes, not bech32 text (ruling 24).
//
// The returned 32 bytes are the message handed to the strict secp256k1 verifier; consistent with the other
// nexus domains, signer.VerifySig applies SHA256 once more internally, byte-for-byte identical to Cosmos
// secp256k1 PubKey.VerifySignature.
func InferReceiptSigningDigest(receipt *taskv1.InferReceiptV2) ([32]byte, error) {
	if receipt == nil {
		return [32]byte{}, fmt.Errorf("receipt is required")
	}
	chainID, err := CanonicalUTF8Field("chain_id", receipt.GetChainId())
	if err != nil {
		return [32]byte{}, err
	}
	taskID, err := CanonicalHash32Field("task_id", receipt.GetTaskId())
	if err != nil {
		return [32]byte{}, err
	}
	taskHash, err := CanonicalHash32Field("task_hash", receipt.GetTaskHash())
	if err != nil {
		return [32]byte{}, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", receipt.GetWorkerOperatorAddress())
	if err != nil {
		return [32]byte{}, err
	}
	generationParamsDigest, err := CanonicalHash32Field("generation_params_digest", receipt.GetGenerationParamsDigest())
	if err != nil {
		return [32]byte{}, err
	}
	outputHash, err := CanonicalHash32Field("output_hash", receipt.GetOutputHash())
	if err != nil {
		return [32]byte{}, err
	}
	evidenceCommitmentsHash, err := EvidenceCommitmentsHash(receipt.GetRequiredEvidenceCommitments())
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(
		DomainInferReceiptV2,
		Uint32BE(receipt.GetSchemaVersion()),
		chainID,
		taskID,
		taskHash,
		worker,
		Uint64BE(receipt.GetServiceAuthorizationNonce()),
		generationParamsDigest,
		outputHash,
		Uint64BE(receipt.GetOutputSizeBytes()),
		evidenceCommitmentsHash[:],
		Uint64BE(receipt.GetExpiryHeight()),
		Uint64BE(receipt.GetGeneratedTokenCount()),
		Uint64BE(receipt.GetOutputLeafCount()),
	), nil
}

// InferReceiptV2FromSubmission converts the Nexus-internal submission object into the frozen-wire
// task.v1.InferReceiptV2, for the coordinator to build MsgSubmitInferReceipt and for ingress and
// taskdata to recompute the signing digest. The conversion is a pure mapping: Hash32 is decoded from
// canonical lowercase 64-hex into raw 32 bytes, evidence kinds become the closed enum, no defaults are filled in and the list is not reordered.
func InferReceiptV2FromSubmission(receipt types.InferReceiptSubmission) (*taskv1.InferReceiptV2, error) {
	taskID, err := Hash32Bytes("task_id", receipt.TaskID)
	if err != nil {
		return nil, err
	}
	taskHash, err := Hash32Bytes("task_hash", receipt.TaskHash)
	if err != nil {
		return nil, err
	}
	return &taskv1.InferReceiptV2{
		SchemaVersion:               receipt.SchemaVersion,
		ChainId:                     receipt.ChainID,
		TaskId:                      taskID,
		TaskHash:                    taskHash,
		WorkerOperatorAddress:       receipt.WorkerAddress,
		ServiceAuthorizationNonce:   receipt.ServiceAuthorizationNonce,
		GenerationParamsDigest:      receipt.GenerationParamsDigest,
		OutputHash:                  receipt.OutputHash,
		OutputSizeBytes:             receipt.OutputSizeBytes,
		RequiredEvidenceCommitments: evidenceCommitmentsFromSubmission(receipt),
		ExpiryHeight:                receipt.ExpiryHeight,
		ServiceSignature:            receipt.WorkerServiceSignature,
		GeneratedTokenCount:         receipt.GeneratedTokenCount,
		OutputLeafCount:             receipt.OutputLeafCount,
	}, nil
}

// EvidenceCommitmentsHashFromSubmission derives the submission object's evidence_commitments_hash.
// It deliberately looks only at EvidenceCommitments: this preimage carries neither chain_id nor task_id
// (it is scoped by the outer receipt digest), so deriving it does not require any receipt scope field to be valid.
func EvidenceCommitmentsHashFromSubmission(receipt types.InferReceiptSubmission) ([32]byte, error) {
	return EvidenceCommitmentsHash(evidenceCommitmentsFromSubmission(receipt))
}

func evidenceCommitmentsFromSubmission(receipt types.InferReceiptSubmission) []*taskv1.EvidenceCommitmentV1 {
	commitments := make([]*taskv1.EvidenceCommitmentV1, 0, len(receipt.EvidenceCommitments))
	for _, commitment := range receipt.EvidenceCommitments {
		commitments = append(commitments, &taskv1.EvidenceCommitmentV1{
			EvidenceKind:       sharedv1.EvidenceKind(commitment.Kind),
			EvidenceHashOrRoot: commitment.HashOrRoot,
			EncodedSizeBytes:   commitment.EncodedSizeBytes,
		})
	}
	return commitments
}

// InferReceiptSigningDigestFromSubmission is InferReceiptV2FromSubmission +
// InferReceiptSigningDigest combined, so each recomputation site need not repeat the conversion.
func InferReceiptSigningDigestFromSubmission(receipt types.InferReceiptSubmission) ([32]byte, error) {
	wire, err := InferReceiptV2FromSubmission(receipt)
	if err != nil {
		return [32]byte{}, err
	}
	return InferReceiptSigningDigest(wire)
}

// canonicalEvidenceKind rejects the unspecified and unregistered enum values §1.2 requires to be
// rejected ("unknown oneof/enum ... reject outright").
func canonicalEvidenceKind(kind sharedv1.EvidenceKind) (uint32, error) {
	switch kind {
	case sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING,
		sharedv1.EvidenceKind_EVIDENCE_KIND_VERIFIER_VALUE_OPENING,
		sharedv1.EvidenceKind_EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING:
		return uint32(kind), nil
	case sharedv1.EvidenceKind_EVIDENCE_KIND_UNSPECIFIED:
		return 0, fmt.Errorf("evidence_kind must not be EVIDENCE_KIND_UNSPECIFIED")
	default:
		return 0, fmt.Errorf("evidence_kind %d is not a registered EvidenceKind value", int32(kind))
	}
}
