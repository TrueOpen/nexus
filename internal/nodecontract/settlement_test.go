package nodecontract

import (
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestComputeBuilderSelectionMatchesSDKGoldenVector(t *testing.T) {
	builders := []string{
		"trueopen1870sqtdru7dj3xgwpzcexry0dwvyz2ku7xv9mg",
		"trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
		"trueopen1yfse4c367uc2rja5g3905ynmnuv2hjk8gcgvfl",
	}
	selection, err := ComputeBuilderSelection(
		1,
		"trueopen-localnet-1",
		"",
		"4f5fc5f611e7fe40cecd95c945bdb8a3383ddbd7d55545758ae8c860546ce193",
		"ASSIGN",
		"",
		"68f4c02de973deecab42a56635ac34c47b311371b5c326cf50688065970f7322",
		builders,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"trueopen1870sqtdru7dj3xgwpzcexry0dwvyz2ku7xv9mg",
		"trueopen1yfse4c367uc2rja5g3905ynmnuv2hjk8gcgvfl",
		"trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
	}
	if !reflect.DeepEqual(selection.SelectedBuilders, want) {
		t.Fatalf("selected builders=%v want=%v", selection.SelectedBuilders, want)
	}
	reversed, err := ComputeBuilderSelection(
		1,
		"trueopen-localnet-1",
		"",
		"4f5fc5f611e7fe40cecd95c945bdb8a3383ddbd7d55545758ae8c860546ce193",
		"ASSIGN",
		"",
		"68f4c02de973deecab42a56635ac34c47b311371b5c326cf50688065970f7322",
		[]string{builders[2], builders[1], builders[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reversed.SelectedBuilders, want) {
		t.Fatalf("reversed selected builders=%v want=%v", reversed.SelectedBuilders, want)
	}
}

func TestBuilderSetHashMatchesSDKGoldenSnapshot(t *testing.T) {
	builders := []string{
		"trueopen1870sqtdru7dj3xgwpzcexry0dwvyz2ku7xv9mg",
		"trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
		"trueopen1yfse4c367uc2rja5g3905ynmnuv2hjk8gcgvfl",
	}
	want := "68f4c02de973deecab42a56635ac34c47b311371b5c326cf50688065970f7322"
	if got := BuilderSetHash(1, 1, 60479999, builders); got != want {
		t.Fatalf("builder set hash=%q want=%q", got, want)
	}
}

func TestComputeBuilderSelectionRejectsNonCanonicalInputs(t *testing.T) {
	tests := []struct {
		name      string
		termID    uint64
		chainID   string
		sessionID string
		taskID    string
		stageRef  string
		setHash   string
		builders  []string
	}{
		{name: "zero term", termID: 0, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "blank chain", termID: 1, chainID: "", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "chain padding", termID: 1, chainID: " chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "session padding", termID: 1, chainID: "chain-1", sessionID: "session-1 ", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "task padding", termID: 1, chainID: "chain-1", taskID: "task-1\n", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "stage ref padding", termID: 1, chainID: "chain-1", taskID: "task-1", stageRef: " ref-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "set hash padding", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash ", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "task NUL", termID: 1, chainID: "chain-1", taskID: "task\x00-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2", "builder-3"}},
		{name: "blank builder", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"", "builder-2", "builder-3"}},
		{name: "builder padding", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{" builder-1", "builder-2", "builder-3"}},
		{name: "builder NUL", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"builder\x00-1", "builder-2", "builder-3"}},
		{name: "duplicate builder", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-1", "builder-3"}},
		{name: "too few builders", termID: 1, chainID: "chain-1", taskID: "task-1", setHash: "set-hash", builders: []string{"builder-1", "builder-2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ComputeBuilderSelection(tt.termID, tt.chainID, tt.sessionID, tt.taskID, "ASSIGN", tt.stageRef, tt.setHash, tt.builders)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestComputeBuilderSelectionEncodesNodeProofFrame(t *testing.T) {
	selection, err := ComputeBuilderSelection(7, "chain-1", "session-1", "task-1", "ASSIGN", "", "set-hash", []string{
		"builder-4", "builder-2", "builder-1", "builder-3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.SelectedBuilders) != 3 || selection.SeedHash == "" || selection.SelectionProofHash == "" {
		t.Fatalf("selection=%+v", selection)
	}
	rank, proof, err := selection.ProofFor(selection.SelectedBuilders[1])
	if err != nil {
		t.Fatal(err)
	}
	if rank != 2 || !strings.HasPrefix(proof, BuilderSelectionProofVersion+":") {
		t.Fatalf("rank=%d proof=%q", rank, proof)
	}
	wantFrame := canonicalFrame(
		"7", "chain-1", "session-1", "task-1", "ASSIGN", "",
		strings.Join(selection.SelectedBuilders, ","), selection.SeedHash, selection.SelectionProofHash,
		"2", selection.SelectedBuilders[1],
	)
	if proof != BuilderSelectionProofVersion+":"+hex.EncodeToString(wantFrame) {
		t.Fatalf("proof=%q", proof)
	}
}

func TestBuildSettlementEvidenceMatchesNodeReferenceShape(t *testing.T) {
	input := SettlementEvidenceInput{
		SessionID: "session-1", TaskID: "task-1", WinnerWorker: "worker-1", SettlementID: "settlement-1",
		ModelID: "model-1", ProfileVersion: math.MaxUint32, VerificationSampleSeed: "sample-seed",
		EvidenceCommitmentsHash: "evidence-commitments-hash",
		EvidenceSchemaHash:      "schema-hash", JudgmentFunctionVersion: "JUDGMENT_V1",
		TaskVerdict: "PASS", SettlementStatus: "SETTLED_PASS", PayoutHash: "payout-hash",
		FaultSummaryHash: "fault-hash", RefundAmount: 100,
		FormalVerifiers: []string{"verifier-1", "verifier-2", "verifier-3"},
		AcceptedResults: []SettlementResultReceipt{
			{Verifier: "verifier-1", CommitHash: "commit-1", ResultRevealHash: "result-1", CommitHeight: 80, ResultHeight: 90},
			{Verifier: "verifier-2", CommitHash: "commit-2", ResultRevealHash: "result-2", CommitHeight: 81, ResultHeight: 91},
		},
		FullResultRevealRefs: []string{"session-1/task-1/1/verifier-3"},
	}
	got, err := BuildSettlementEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitHeightRefs != "session-1/task-1/1/verifier-1,session-1/task-1/1/verifier-2" {
		t.Fatalf("commit refs=%q", got.CommitHeightRefs)
	}
	if got.WorkerRevealReceiptRef != "session-1/task-1/1/worker-1" {
		t.Fatalf("worker ref=%q", got.WorkerRevealReceiptRef)
	}
	if got.LeafCountByType != "TASK_META=1,WORKER_REVEAL_RECEIPT=1,VERIFIER_RESULT_RECEIPT=2,REGISTERED_FULL_RESULT_REVEAL=1,SETTLEMENT_BILL=1" {
		t.Fatalf("leaf count=%q", got.LeafCountByType)
	}
	for name, value := range map[string]string{
		"result refs": got.ResultReceiptRefsHash, "full refs": got.RegisteredFullResultRefsHash,
		"manifest": got.RootManifestHash, "root": got.TaskEvidenceRoot,
	} {
		if len(value) != 64 {
			t.Fatalf("%s=%q", name, value)
		}
	}
}

func TestSettlementEvidenceSchemaHashSupportsUint32ProfileVersion(t *testing.T) {
	got := SettlementEvidenceSchemaHash("model-1", math.MaxUint32, "component-v1", "judgment-v1")
	want := canonicalHashHex(settlementEvidenceSchemaV1, "model-1", "4294967295", "component-v1", "judgment-v1")
	if got != want {
		t.Fatalf("schema hash=%q want=%q", got, want)
	}
}

func TestSettlementBillHashesUseCurrentDomains(t *testing.T) {
	bill := SettlementBill{
		SessionID: "session-1", TaskID: "task-1", SettlementID: "settlement-1",
		TaskVerdict: "PASS", SettlementStatus: "SETTLED_PASS", RefundAmount: 100,
	}
	if got := SettlementPayoutHash(bill); len(got) != 64 {
		t.Fatalf("payout hash=%q", got)
	}
	if got := SettlementFaultSummaryHash(bill, "NONE"); len(got) != 64 {
		t.Fatalf("fault hash=%q", got)
	}
	if got := SettlementEvidenceSchemaHash("model-1", 2, "trueopen-worker-reveal-v1", "JUDGMENT_V1"); len(got) != 64 {
		t.Fatalf("schema hash=%q", got)
	}
}
