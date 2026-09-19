package nodecontract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	DomainOrderV1             = "TRUEOPEN_ORDER_V1"
	DomainAssignBuilderV1     = "TRUEOPEN_ASSIGN_BUILDER_V1"
	DomainOpenVerifyBuilderV1 = "TRUEOPEN_OPEN_VERIFY_BUILDER_V1"
	DomainInferReceiptV2      = "TRUEOPEN_INFER_RECEIPT_V2"
	DomainWorkerHandraiseV1   = "TRUEOPEN_WORKER_HANDRAISE_V1"
	DomainVerifierHandraiseV1 = "TRUEOPEN_VERIFIER_HANDRAISE_V1"
	DomainSettlementV1        = "TRUEOPEN_SETTLEMENT_V1"
)

func OrderSigningBytes(chainID, ownerAddress, sessionID string, orderSequence uint64, orderEnvelope string) []byte {
	return domainHash(DomainOrderV1, chainID, ownerAddress, sessionID, strconv.FormatUint(orderSequence, 10), orderEnvelope)
}

// CurrentOrderSigningBytes mirrors the current task order contract.
// OrderSigningBytes remains for the deprecated SubmitOrder compatibility path.
func CurrentOrderSigningBytes(chainID, ownerAddress, sessionID string, orderSequence uint64, orderEnvelope string) []byte {
	return domainHash(DomainOrderV1, chainID, ownerAddress, sessionID, strconv.FormatUint(orderSequence, 10), orderEnvelope)
}

// The two pre-freeze Builder identity helpers (ServiceKeyAuthorizationBytes / domain
// TRUEOPEN_CURRENT_SERVICE_KEY_V2, ServiceDescriptorAuthorizationBytes / domain
// TRUEOPEN_SERVICE_DESCRIPTOR_V2) have been removed entirely, **with no aliases kept**:
//
//   - The authoritative domain for the service key PoP is TRUEOPEN_SERVICE_REGISTRATION_V1 in
//     §10.0c, with H_FIELDS_V1 framing (enum as uint32_be, operator as address codec bytes,
//     pubkey as the raw 33 bytes); the old helper wrote them all as decimal/hex text, which
//     the Keeper must reject. The new form is ServiceRegistrationBytes in servicedescriptor.go.
//   - MsgUpdateServiceDescriptor has no controller_signature field at all in the frozen
//     contract: authorization is carried by the Cosmos account signature
//     (signer=operator_address), so there is no second-layer detached signature to build.
func AssignBuilderSigningBytes(chainID, taskID, orderDigest, candidateSetHash, workerHandraiseSet, builderAddress string, builderRank uint64) []byte {
	return domainHash(
		DomainAssignBuilderV1,
		chainID,
		taskID,
		orderDigest,
		candidateSetHash,
		workerHandraiseSet,
		builderAddress,
		strconv.FormatUint(builderRank, 10),
	)
}

func WorkerHandraiseSigningBytes(chainID, taskID, orderDigest, candidateSnapshotID, candidateSetHash, workerAddress string, expiryHeight uint64, membershipProof string) []byte {
	return domainHash(
		DomainWorkerHandraiseV1,
		chainID,
		taskID,
		orderDigest,
		candidateSnapshotID,
		candidateSetHash,
		workerAddress,
		strconv.FormatUint(expiryHeight, 10),
		membershipProof,
	)
}

func OpenVerifyBuilderSigningBytes(chainID, taskID, winnerWorker, inferReceiptCommitHash, inferReceiptHash, builderAddress string, builderRank uint64) []byte {
	return domainHash(
		DomainOpenVerifyBuilderV1,
		chainID,
		taskID,
		winnerWorker,
		inferReceiptCommitHash,
		inferReceiptHash,
		builderAddress,
		strconv.FormatUint(builderRank, 10),
	)
}

// The pre-freeze infer-receipt signing-bytes helper and its hex receipt-hash wrappers
// (the old InferReceiptSigningBytes / InferReceiptHashV1FromSigningBytes /
// InferReceiptHashV1 / InferReceiptHash in this file) have been removed entirely,
// **with no aliases kept**: it wrote uint64 as
// decimal text and covered infer_receipt_commit_hash / trace_commit_root /
// checkpoint_commit_root / batch_log_root / token_count / work_unit, six fields that §5.14
// removed from the wire. Keeping an alias would let callers keep producing digests the
// frozen wire never accepts.
//
// New form: InferReceiptSigningDigest (inferreceipt.go), H_FIELDS_V1 typed framing.

func VerifierHandraiseSigningBytes(chainID, taskID, inferReceiptHash, outputHash, candidateSnapshotID, membershipProof, verifierAddress string, expiryHeight uint64) []byte {
	return domainHash(
		DomainVerifierHandraiseV1,
		chainID,
		taskID,
		inferReceiptHash,
		outputHash,
		candidateSnapshotID,
		membershipProof,
		verifierAddress,
		strconv.FormatUint(expiryHeight, 10),
	)
}

func SettlementSigningBytes(chainID, settlementID, taskID, taskVerdict, settlementStatus, payoutHash, faultSummaryHash, taskEvidenceRoot string, challengeCloseHeight uint64) []byte {
	return domainHash(
		DomainSettlementV1,
		chainID,
		settlementID,
		taskID,
		taskVerdict,
		settlementStatus,
		payoutHash,
		faultSummaryHash,
		taskEvidenceRoot,
		strconv.FormatUint(challengeCloseHeight, 10),
	)
}

func SignHex(s signer.Signer, canonical []byte) (string, error) {
	sig, err := s.Sign(canonical)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func domainHash(domain string, fields ...string) []byte {
	parts := make([]string, 0, len(fields)+1)
	parts = append(parts, domain)
	parts = append(parts, fields...)
	hasher := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(part))
	}
	return hasher.Sum(nil)
}
