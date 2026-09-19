package msgbus

import (
	"strings"
	"testing"

	"github.com/TrueOpen/wire/bus"
)

// The 8 subjects of contract §5.1, checked one by one against their wire kind and tier.
// The frozen kind -> payload message type mapping is owned and tested by wire bus.
func TestSubjectListV1MatchesContract(t *testing.T) {
	taskID := strings.Repeat("a", 64)
	cases := []struct {
		subject string
		kind    int32
		tier    SubjectTier
		want    string
	}{
		{SubjectTaskOpen("llama-3-8b"), bus.KindOrderBroadcast, TierCore, "trueopen.task.open.llama-3-8b"},
		{SubjectWorkerHandraiseV1(taskID), bus.KindWorkerHandraise, TierCore, "trueopen.handraise.worker." + taskID},
		{SubjectVerifyOpen(taskID), bus.KindOpenVerify, TierCore, "trueopen.verify.open." + taskID},
		{SubjectVerifierHandraiseV1(taskID), bus.KindVerifierHandraise, TierCore, "trueopen.handraise.verifier." + taskID},
		{SubjectWorkerAssignment(taskID), bus.KindWorkerAssignmentNotify, TierJetStream, "trueopen.worker-assignment." + taskID},
		{SubjectOutputAvailableV1(taskID), bus.KindOutputAvailable, TierJetStream, "trueopen.output-avail." + taskID},
		{SubjectVerifierAssignment(taskID), bus.KindVerifierAssignmentNotify, TierJetStream, "trueopen.verifier-assignment." + taskID},
		{SubjectVerifyResultV1(taskID), bus.KindVerifyResult, TierJetStream, "trueopen.verify-result." + taskID},
	}
	if len(SubjectSpecsV1()) != len(cases) {
		t.Fatalf("subject count = %d, want %d", len(SubjectSpecsV1()), len(cases))
	}
	for _, testCase := range cases {
		if testCase.subject != testCase.want {
			t.Errorf("subject = %q, want %q", testCase.subject, testCase.want)
		}
		spec, placeholder, ok := LookupSubjectV1(testCase.subject)
		if !ok {
			t.Fatalf("%s must resolve", testCase.subject)
		}
		if spec.WireKind != testCase.kind || spec.Tier != testCase.tier {
			t.Errorf("%s resolved to kind=%d tier=%s, want kind=%d tier=%s",
				testCase.subject, spec.WireKind, spec.Tier, testCase.kind, testCase.tier)
		}
		if placeholder == "" {
			t.Errorf("%s placeholder must be non-empty", testCase.subject)
		}
	}
}

// Contract §5.1: there is no trueopen.orders.* and no trueopen.assign.<task_id>.
func TestSubjectListV1RejectsRetiredSubjects(t *testing.T) {
	taskID := strings.Repeat("a", 64)
	for _, subject := range []string{
		"trueopen.orders.llama-3-8b",
		"trueopen.assign." + taskID,
		"trueopen.verify-select." + taskID,
		"trueopen.sample-ready." + taskID,
		"trueopen.prepare." + taskID,
		"trueopen.task.open." + taskID + ".extra",
		"trueopen.output-avail.*",
		"trueopen.verify-result.>",
		"trueopen.task.open.",
	} {
		if _, _, ok := LookupSubjectV1(subject); ok {
			t.Errorf("%s must not resolve to a contract subject", subject)
		}
	}
}

func TestJetStreamNameV1(t *testing.T) {
	if JetStreamName != "TRUEOPEN_TASK" {
		t.Fatalf("JetStream stream = %q, want TRUEOPEN_TASK", JetStreamName)
	}
}

// Contract §5.12: the stream only covers the subjects marked JetStream in §5.1.
// The wildcards used to create the stream must derive from that same table, otherwise the stream
// configuration silently falls behind whenever the subjects change.
func TestJetStreamSubjectWildcardsV1(t *testing.T) {
	got := JetStreamSubjectWildcardsV1()
	want := []string{
		"trueopen.worker-assignment.*",
		"trueopen.output-avail.*",
		"trueopen.verifier-assignment.*",
		"trueopen.verify-result.*",
	}
	if len(got) != len(want) {
		t.Fatalf("wildcards = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wildcards = %v, want %v", got, want)
		}
	}
}

// The internal Builder-to-Builder subject deliberately stays out of the trueopen.* namespace: the table of
// contract §5.1 is a closed set, and adding a row to it would mean an implementation extending the protocol on its own. It
// must also not appear in the SubjectSpecsV1() contract surface, and it carries no BusEnvelopeV1
// (WireKind = 0; for the signature format see coordinator/prepare.go).
func TestInternalPrepareSubjectStaysOutOfTheContractNamespace(t *testing.T) {
	taskID := strings.Repeat("a", 64)
	subject := SubjectBuilderPrepare(taskID)
	if strings.HasPrefix(subject, "trueopen.") {
		t.Fatalf("internal subject %q occupies the contract namespace", subject)
	}
	spec, placeholder, ok := LookupSubjectV1(subject)
	if !ok || spec.WireKind != 0 || placeholder != taskID {
		t.Fatalf("internal subject did not resolve: spec=%+v placeholder=%q ok=%v", spec, placeholder, ok)
	}
	if spec.Tier != TierCore {
		t.Fatalf("internal prepare spec = %+v, want CORE", spec)
	}
	for _, contractSpec := range SubjectSpecsV1() {
		if contractSpec.Prefix == "nexus.builder-prepare." {
			t.Fatal("the internal subject leaked into the contract subject list")
		}
	}
}
