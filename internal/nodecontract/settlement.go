package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	BuilderSelectionProofVersion = "trueopen-builder-selection-v2"
	SupportedVerifyRoundV1       = uint64(1)

	builderStageAssignDomain     = "TRUEOPEN_BUILDER_STAGE1_V1"
	builderStageOpenVerifyDomain = "TRUEOPEN_BUILDER_STAGE2_V1"
	builderStageSettleDomain     = "TRUEOPEN_BUILDER_STAGE3_V1"
	builderSetDomain             = "TRUEOPEN_BUILDER_SET_V1"

	settlementBillDomain         = "TRUEOPEN_SETTLEMENT_BILL_V1"
	settlementFaultSummaryDomain = "TRUEOPEN_FAULT_SUMMARY_V1"
	settlementResultRefsDomain   = "TRUEOPEN_RESULT_RECEIPT_REFS_V1"
	settlementFullRefsDomain     = "TRUEOPEN_REGISTERED_FULL_RESULT_REFS_V1"
	settlementManifestDomain     = "TRUEOPEN_EVIDENCE_MANIFEST_V1"
	settlementEvidenceLeafDomain = "TRUEOPEN_EVIDENCE_LEAF_V1"
	settlementEvidenceNodeDomain = "TRUEOPEN_EVIDENCE_MERKLE_NODE_V1"
	settlementEvidenceRootDomain = "TRUEOPEN_TASK_EVIDENCE_ROOT_V1"
	settlementEvidenceSchemaV1   = "TRUEOPEN_EVIDENCE_SCHEMA_V1"
)

// BuilderSetHash mirrors the Hub's ordered BuilderSet commitment.
func BuilderSetHash(termID, startHeight, endHeight uint64, builders []string) string {
	return canonicalHashHex(
		builderSetDomain,
		strconv.FormatUint(termID, 10),
		strconv.FormatUint(startHeight, 10),
		strconv.FormatUint(endHeight, 10),
		strings.Join(builders, ","),
	)
}

type BuilderSelection struct {
	TermID             uint64
	ChainID            string
	SessionID          string
	TaskID             string
	Stage              string
	StageRef           string
	SelectedBuilders   []string
	SeedHash           string
	SelectionProofHash string
}

func ComputeBuilderSelection(termID uint64, chainID, sessionID, taskID, stage, stageRef, setHash string, builders []string) (BuilderSelection, error) {
	stage = strings.ToUpper(strings.TrimSpace(stage))
	if termID == 0 {
		return BuilderSelection{}, fmt.Errorf("builder selection: term, chain, task, and set hash are required")
	}
	for _, field := range []struct {
		name     string
		value    string
		required bool
	}{
		{name: "chain", value: chainID, required: true},
		{name: "session", value: sessionID},
		{name: "task", value: taskID, required: true},
		{name: "stage ref", value: stageRef},
		{name: "set hash", value: setHash, required: true},
	} {
		if field.required && field.value == "" {
			return BuilderSelection{}, fmt.Errorf("builder selection: %s is required", field.name)
		}
		if strings.TrimSpace(field.value) != field.value || strings.ContainsRune(field.value, '\x00') {
			return BuilderSelection{}, fmt.Errorf("builder selection: %s must be canonical", field.name)
		}
	}
	stageDomain := ""
	switch stage {
	case "ASSIGN":
		stageDomain = builderStageAssignDomain
	case "OPEN_VERIFY":
		stageDomain = builderStageOpenVerifyDomain
	case "SETTLE":
		stageDomain = builderStageSettleDomain
	default:
		return BuilderSelection{}, fmt.Errorf("builder selection: invalid stage %q", stage)
	}
	if len(builders) < 3 {
		return BuilderSelection{}, fmt.Errorf("builder selection: need at least three builders")
	}

	seedFields := []string{chainID, strconv.FormatUint(termID, 10), sessionID, taskID, stageRef, setHash}
	type rankedBuilder struct {
		address string
		hash    []byte
	}
	ranked := make([]rankedBuilder, 0, len(builders))
	seen := make(map[string]struct{}, len(builders))
	for _, address := range builders {
		if address == "" || strings.TrimSpace(address) != address || strings.ContainsRune(address, '\x00') {
			return BuilderSelection{}, fmt.Errorf("builder selection: builder address must be canonical")
		}
		if _, exists := seen[address]; exists {
			return BuilderSelection{}, fmt.Errorf("builder selection: duplicate builder %q", address)
		}
		seen[address] = struct{}{}
		ranked = append(ranked, rankedBuilder{address: address, hash: canonicalHash(stageDomain, append(seedFields, address)...)})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if cmp := bytes.Compare(ranked[i].hash, ranked[j].hash); cmp != 0 {
			return cmp < 0
		}
		return ranked[i].address < ranked[j].address
	})
	selected := []string{ranked[0].address, ranked[1].address, ranked[2].address}
	seedHash := canonicalHashHex(stageDomain, seedFields...)
	proofHash := canonicalHashHex(
		BuilderSelectionProofVersion,
		strconv.FormatUint(termID, 10), chainID, sessionID, taskID, stage, stageRef,
		strings.Join(selected, ","), setHash, seedHash,
	)
	return BuilderSelection{
		TermID: termID, ChainID: chainID, SessionID: sessionID, TaskID: taskID,
		Stage: stage, StageRef: stageRef, SelectedBuilders: selected,
		SeedHash: seedHash, SelectionProofHash: proofHash,
	}, nil
}

func (s BuilderSelection) ProofFor(builder string) (uint64, string, error) {
	builder = strings.TrimSpace(builder)
	rank := uint64(0)
	for i, selected := range s.SelectedBuilders {
		if selected == builder {
			rank = uint64(i + 1)
			break
		}
	}
	if rank == 0 {
		return 0, "", fmt.Errorf("builder selection: builder %q is not selected", builder)
	}
	frame := canonicalFrame(
		strconv.FormatUint(s.TermID, 10), s.ChainID, s.SessionID, s.TaskID, s.Stage, s.StageRef,
		strings.Join(s.SelectedBuilders, ","), s.SeedHash, s.SelectionProofHash,
		strconv.FormatUint(rank, 10), builder,
	)
	return rank, BuilderSelectionProofVersion + ":" + hex.EncodeToString(frame), nil
}

type SettlementBill struct {
	SessionID                 string
	TaskID                    string
	SettlementID              string
	TaskVerdict               string
	SettlementStatus          string
	InferActualFee            uint64
	VerifyActualFee           uint64
	WorkerPayout              uint64
	VerifierPayouts           string
	GasReimbursements         string
	MaintenanceFee            uint64
	RefundAmount              uint64
	FaultEvents               string
	OutlierVerifier           string
	MissingOrTimeoutVerifiers string
}

func SettlementPayoutHash(input SettlementBill) string {
	return canonicalHashHex(
		settlementBillDomain,
		input.SessionID, input.TaskID, input.SettlementID, input.TaskVerdict, input.SettlementStatus,
		strconv.FormatUint(input.InferActualFee, 10), strconv.FormatUint(input.VerifyActualFee, 10),
		strconv.FormatUint(input.WorkerPayout, 10), canonicalPayoutString(input.VerifierPayouts),
		canonicalPayoutString(input.GasReimbursements), strconv.FormatUint(input.MaintenanceFee, 10),
		strconv.FormatUint(input.RefundAmount, 10), canonicalCSV(input.FaultEvents),
	)
}

func SettlementFaultSummaryHash(input SettlementBill, failureClass string) string {
	return canonicalHashHex(
		settlementFaultSummaryDomain,
		input.SessionID, input.TaskID, input.SettlementID, input.TaskVerdict, input.SettlementStatus,
		failureClass, canonicalCSV(input.OutlierVerifier), canonicalCSV(input.MissingOrTimeoutVerifiers),
		canonicalCSV(input.FaultEvents),
	)
}

func SettlementEvidenceSchemaHash(modelID string, profileVersion uint32, componentSchemaVersion, judgmentFunctionVersion string) string {
	return canonicalHashHex(
		settlementEvidenceSchemaV1, modelID, strconv.FormatUint(uint64(profileVersion), 10),
		componentSchemaVersion, judgmentFunctionVersion,
	)
}

type SettlementResultReceipt struct {
	Verifier         string
	CommitHash       string
	ResultRevealHash string
	CommitHeight     uint64
	ResultHeight     uint64
}

type SettlementEvidenceInput struct {
	SessionID              string
	TaskID                 string
	WinnerWorker           string
	SettlementID           string
	ModelID                string
	ProfileVersion         uint32
	VerificationSampleSeed string
	// EvidenceCommitmentsHash replaces the pre-freeze TraceCommitRoot / CheckpointCommitRoot:
	// §5.14 collapses the Worker's set of commitments into typed required_evidence_commitments
	// and enters the receipt preimage as a single TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1 derived value.
	// This helper as a whole is still the pre-freeze shape (settlement leaf encoding not frozen,
	// K-BLOCK-16 unresolved, no SETTLEMENT_BILL leaf written on chain), so this is only an
	// equivalent substitution and makes no claim to be the frozen form.
	EvidenceCommitmentsHash string
	EvidenceSchemaHash      string
	JudgmentFunctionVersion string
	TaskVerdict             string
	SettlementStatus        string
	PayoutHash              string
	FaultSummaryHash        string
	GasReimbursements       string
	RefundAmount            uint64
	MaintenanceFee          uint64
	FormalVerifiers         []string
	AcceptedResults         []SettlementResultReceipt
	FullResultRevealRefs    []string
}

type SettlementEvidence struct {
	CommitHeightRefs             string
	FullResultRevealRefs         []string
	WorkerRevealReceiptRef       string
	ResultReceiptRefsHash        string
	RegisteredFullResultRefsHash string
	LeafCountByType              string
	RootManifestHash             string
	TaskEvidenceRoot             string
}

func BuildSettlementEvidence(input SettlementEvidenceInput) (SettlementEvidence, error) {
	if input.SessionID == "" || input.TaskID == "" || input.WinnerWorker == "" || input.SettlementID == "" ||
		input.ModelID == "" || input.ProfileVersion == 0 || input.VerificationSampleSeed == "" ||
		input.EvidenceCommitmentsHash == "" || input.EvidenceSchemaHash == "" ||
		input.JudgmentFunctionVersion == "" || input.TaskVerdict == "" || input.SettlementStatus == "" ||
		input.PayoutHash == "" || input.FaultSummaryHash == "" {
		return SettlementEvidence{}, fmt.Errorf("settlement evidence: required facts are incomplete")
	}
	if len(input.FormalVerifiers) != 3 {
		return SettlementEvidence{}, fmt.Errorf("settlement evidence: exactly three formal verifiers are required")
	}
	results := make(map[string]SettlementResultReceipt, len(input.AcceptedResults))
	for _, result := range input.AcceptedResults {
		if result.Verifier == "" || result.CommitHash == "" || result.ResultRevealHash == "" || result.CommitHeight == 0 || result.ResultHeight == 0 {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: accepted result is incomplete")
		}
		if _, duplicate := results[result.Verifier]; duplicate {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: duplicate result for %q", result.Verifier)
		}
		results[result.Verifier] = result
	}
	if len(results) < 2 {
		return SettlementEvidence{}, fmt.Errorf("settlement evidence: at least two accepted results are required")
	}

	formal := make(map[string]struct{}, len(input.FormalVerifiers))
	refs := make([]string, 0, len(results))
	resultLeaves := make([]string, 0, len(results))
	for index, verifier := range input.FormalVerifiers {
		if verifier == "" {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: verifier is empty")
		}
		if _, duplicate := formal[verifier]; duplicate {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: duplicate formal verifier %q", verifier)
		}
		formal[verifier] = struct{}{}
		result, ok := results[verifier]
		if !ok {
			continue
		}
		ref := FormatCommitKey(input.SessionID, input.TaskID, SupportedVerifyRoundV1, verifier)
		refs = append(refs, ref)
		resultLeaves = append(resultLeaves, canonicalHashHex(
			settlementResultRefsDomain, strconv.Itoa(index), ref, result.CommitHash, result.ResultRevealHash,
			strconv.FormatUint(result.CommitHeight, 10), strconv.FormatUint(result.ResultHeight, 10),
		))
		delete(results, verifier)
	}
	if len(results) != 0 {
		return SettlementEvidence{}, fmt.Errorf("settlement evidence: result is not from the formal verifier set")
	}

	fullSet := make(map[string]struct{}, len(input.FullResultRevealRefs))
	for _, ref := range input.FullResultRevealRefs {
		if ref == "" || strings.TrimSpace(ref) != ref {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: full result ref must be canonical")
		}
		if _, duplicate := fullSet[ref]; duplicate {
			return SettlementEvidence{}, fmt.Errorf("settlement evidence: duplicate full result ref")
		}
		fullSet[ref] = struct{}{}
	}
	fullRefs := make([]string, 0, len(fullSet))
	for _, verifier := range input.FormalVerifiers {
		ref := FormatCommitKey(input.SessionID, input.TaskID, SupportedVerifyRoundV1, verifier)
		if _, ok := fullSet[ref]; ok {
			fullRefs = append(fullRefs, ref)
			delete(fullSet, ref)
		}
	}
	if len(fullSet) != 0 {
		return SettlementEvidence{}, fmt.Errorf("settlement evidence: unexpected full result ref")
	}

	resultRefsHash := canonicalHashHex(settlementResultRefsDomain, resultLeaves...)
	fullRefsHash := canonicalHashHex(settlementFullRefsDomain, fullRefs...)
	workerRef := FormatCommitKey(input.SessionID, input.TaskID, SupportedVerifyRoundV1, input.WinnerWorker)
	leafCount := strings.Join([]string{
		"TASK_META=1", "WORKER_REVEAL_RECEIPT=1",
		fmt.Sprintf("VERIFIER_RESULT_RECEIPT=%d", len(resultLeaves)),
		fmt.Sprintf("REGISTERED_FULL_RESULT_REVEAL=%d", len(fullRefs)),
		"SETTLEMENT_BILL=1",
	}, ",")
	refsHash := canonicalHashHex(settlementManifestDomain, workerRef, resultRefsHash, fullRefsHash, input.PayoutHash, input.FaultSummaryHash)
	manifest := canonicalHashHex(
		settlementManifestDomain, input.TaskID, input.SettlementID, "1", input.EvidenceSchemaHash, leafCount, refsHash,
	)
	leaves := []string{
		settlementLeaf(
			"TASK_META", input.TaskID, "1", input.ModelID, strconv.FormatUint(uint64(input.ProfileVersion), 10),
			input.JudgmentFunctionVersion, input.VerificationSampleSeed,
		),
		settlementLeaf("WORKER_REVEAL_RECEIPT", input.WinnerWorker, workerRef, input.EvidenceCommitmentsHash, input.EvidenceSchemaHash),
	}
	leaves = append(leaves, resultLeaves...)
	for _, ref := range fullRefs {
		leaves = append(leaves, settlementLeaf("REGISTERED_FULL_RESULT_REVEAL", ref))
	}
	leaves = append(leaves, settlementLeaf(
		"SETTLEMENT_BILL", input.TaskVerdict, input.SettlementStatus, input.PayoutHash, input.FaultSummaryHash,
		input.GasReimbursements, strconv.FormatUint(input.RefundAmount, 10), strconv.FormatUint(input.MaintenanceFee, 10),
	))
	return SettlementEvidence{
		CommitHeightRefs: strings.Join(refs, ","), FullResultRevealRefs: fullRefs,
		WorkerRevealReceiptRef: workerRef, ResultReceiptRefsHash: resultRefsHash,
		RegisteredFullResultRefsHash: fullRefsHash, LeafCountByType: leafCount,
		RootManifestHash: manifest, TaskEvidenceRoot: settlementMerkleRoot(leaves),
	}, nil
}

func FormatCommitKey(sessionID, taskID string, verifyRound uint64, address string) string {
	return strings.Join([]string{sessionID, taskID, strconv.FormatUint(verifyRound, 10), address}, "/")
}

func settlementLeaf(kind string, fields ...string) string {
	return canonicalHashHex(settlementEvidenceLeafDomain, append([]string{kind}, fields...)...)
}

func settlementMerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return canonicalHashHex(settlementEvidenceRootDomain)
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, canonicalHashHex(settlementEvidenceNodeDomain, level[i], level[i+1]))
		}
		level = next
	}
	return canonicalHashHex(settlementEvidenceRootDomain, level[0])
}

func canonicalPayoutString(value string) string { return canonicalAssignmentString(value, true) }
func canonicalCSV(value string) string          { return canonicalAssignmentString(value, false) }

func canonicalAssignmentString(value string, assignment bool) string {
	items := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if assignment && !strings.Contains(item, "=") {
			return value
		}
		items = append(items, item)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func canonicalHashHex(domain string, fields ...string) string {
	return hex.EncodeToString(canonicalHash(domain, fields...))
}

func canonicalHash(domain string, fields ...string) []byte {
	values := append([]string{domain}, fields...)
	sum := sha256.Sum256(canonicalFrame(values...))
	return sum[:]
}

func canonicalFrame(fields ...string) []byte {
	var length [8]byte
	size := 0
	for _, field := range fields {
		size += 8 + len(field)
	}
	framed := make([]byte, 0, size)
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}
