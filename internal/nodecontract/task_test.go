package nodecontract

import (
	"math"
	"sort"
	"strings"
	"testing"
)

func TestParseAssignmentOrderEnvelopePreservesCanonicalInputs(t *testing.T) {
	raw := canonicalOrderFixture()
	envelope, err := ParseAssignmentOrderEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != OrderEnvelopeSchemaV1 || envelope.ModelID != "model-1" || envelope.MaxFee != 1000 || envelope.InferTimeoutBlocks != 20 {
		t.Fatalf("envelope=%+v", envelope)
	}
	canonical, err := CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != raw {
		t.Fatalf("canonical=%s want=%s", canonical, raw)
	}
}

func TestParseAssignmentOrderEnvelopeSupportsUint32ProfileVersion(t *testing.T) {
	raw := strings.Replace(canonicalOrderFixture(), `"profile_version":1`, `"profile_version":4294967295`, 1)
	envelope, err := ParseAssignmentOrderEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.ProfileVersion != math.MaxUint32 {
		t.Fatalf("profile_version=%d want=%d", envelope.ProfileVersion, uint32(math.MaxUint32))
	}
	canonical, err := CanonicalAssignmentOrderEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != raw {
		t.Fatalf("canonical=%s want=%s", canonical, raw)
	}
}

func TestParseAssignmentOrderEnvelopeRejectsLegacyAndNonCanonicalJSON(t *testing.T) {
	for _, raw := range []string{
		`{"session_id":"session-1","order_sequence":1,"model_id":"model-1"}`,
		` {"schema_version":"trueopen-order-envelope-v1"}`,
		strings.Replace(canonicalOrderFixture(), `"model_id":"model-1","profile_version":1`, `"profile_version":1,"model_id":"model-1"`, 1),
		strings.Replace(canonicalOrderFixture(), `"profile_version":1`, `"profile_version":"1"`, 1),
		strings.Replace(canonicalOrderFixture(), `"profile_version":1`, `"profile_version":0`, 1),
		strings.Replace(canonicalOrderFixture(), `"profile_version":1`, `"profile_version":-1`, 1),
		strings.Replace(canonicalOrderFixture(), `"payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"payload_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, 1),
		strings.Replace(canonicalOrderFixture(), `"payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"payload_hash":"short"`, 1),
		strings.Replace(canonicalOrderFixture(), `"payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","payload_keyring_hash":"legacy"`, 1),
	} {
		if _, err := ParseAssignmentOrderEnvelope(raw); err == nil {
			t.Fatalf("accepted non-canonical envelope %q", raw)
		}
	}
}

func TestCanonicalHandraiseSetsSortAndRejectDuplicates(t *testing.T) {
	workers := []WorkerHandraiseV1{
		validWorkerHandraise("worker-2"),
		validWorkerHandraise("worker-1"),
	}
	raw, err := CanonicalWorkerHandraiseSet(workers)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, `[{"schema_version":"trueopen-worker-handraise-v1","worker_operator_address":"worker-1"`) {
		t.Fatalf("worker set=%s", raw)
	}
	workers[1].WorkerOperatorAddress = "worker-2"
	if _, err := CanonicalWorkerHandraiseSet(workers); err == nil {
		t.Fatal("duplicate worker must fail")
	}

	verifiers := []VerifierHandraiseV1{validVerifierHandraise("verifier-2"), validVerifierHandraise("verifier-1")}
	raw, err = CanonicalVerifierHandraiseList(verifiers)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Fatalf("verifier set=%s", raw)
	}
}

func TestSelectedVerifierCSVUsesNodeHandraiseRanking(t *testing.T) {
	input := []VerifierHandraiseV1{
		validVerifierHandraise("verifier-c"), validVerifierHandraise("verifier-a"), validVerifierHandraise("verifier-b"),
	}
	got, err := SelectedVerifierCSV(input, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]VerifierHandraiseV1(nil), input...)
	sort.SliceStable(want, func(i, j int) bool {
		left := canonicalHash("TRUEOPEN_VERIFIER_HANDRAISE_SORT_V1", want[i].TaskID, want[i].InferReceiptHash, want[i].OutputHash, want[i].VerifierOperatorAddress)
		right := canonicalHash("TRUEOPEN_VERIFIER_HANDRAISE_SORT_V1", want[j].TaskID, want[j].InferReceiptHash, want[j].OutputHash, want[j].VerifierOperatorAddress)
		return string(left) < string(right)
	})
	wantCSV := want[0].VerifierOperatorAddress + "," + want[1].VerifierOperatorAddress + "," + want[2].VerifierOperatorAddress
	if got != wantCSV {
		t.Fatalf("selected=%q want=%q", got, wantCSV)
	}
}

func TestVerifierCandidateWindowProofUsesNodeDomain(t *testing.T) {
	got := VerifierCandidateWindowProof("snapshot-1", "window-hash")
	want := canonicalHashHex("TRUEOPEN_VERIFIER_CANDIDATE_WINDOW_PROOF_V1", "snapshot-1", "window-hash")
	if got != want {
		t.Fatalf("proof=%q want=%q", got, want)
	}
}

func canonicalOrderFixture() string {
	return `{"schema_version":"trueopen-order-envelope-v1","model_id":"model-1","profile_version":1,"task_type":"inference","reward_bucket":1,"profile_resource_tier":2,"infer_input_unit_price_bid":2,"infer_output_unit_price_bid":3,"verify_unit_price_bid":4,"max_fee":1000,"tx_fee_reserve":100,"infer_fee_cap":600,"verify_fee_cap":300,"order_value":900,"valid_after_height":10,"deadline_height":100,"payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","infer_timeout_blocks":20,"reference_bucket_key":"reference-v1","timeout_bucket_key":"timeout-v1"}`
}

func validWorkerHandraise(address string) WorkerHandraiseV1 {
	return WorkerHandraiseV1{
		SchemaVersion: WorkerHandraiseSchemaV1, WorkerOperatorAddress: address, TaskID: "task-1", TaskHash: "task-hash",
		CandidateSnapshotID: "snapshot",
		ExpiryHeight:        100, ServiceSignature: "signature-" + address,
	}
}

func validVerifierHandraise(address string) VerifierHandraiseV1 {
	return VerifierHandraiseV1{
		SchemaVersion: VerifierHandraiseSchemaV1, VerifierOperatorAddress: address, TaskID: "task-1",
		InferReceiptHash: "receipt", OutputHash: "output",
		CandidateSnapshotID: "snapshot", MembershipProof: "proof-" + address,
		ExpiryHeight: 100, ServiceSignature: "signature-" + address,
	}
}
