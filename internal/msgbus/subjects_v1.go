// The NATS subject catalogue and tiers (Nexus-Cortex Interface Contract §5.1).
//
// This file is the **only** subject catalogue: the contract states explicitly that "trueopen.orders.* and
// trueopen.assign.<task_id> do not exist". Besides the 8 contract subjects of §5.1 there is a second,
// internal Builder-to-Builder catalogue (internalSubjectSpecsV1) which deliberately stays out of the
// trueopen.* namespace: the contract's subject table is a closed set, and adding a row to it would mean an implementation
// extending the protocol on its own.
//
// The envelope layer has moved to the proto BusEnvelopeV1 + TRUEOPEN_BUS_ENVELOPE_V2 (internal/busadapter,
// with the canonical implementation in github.com/TrueOpen/wire/bus). The Kind/SenderRole/Stage
// vocabularies of the old JSON envelope were removed with it: the kind of a V2 envelope is a
// bus.v1.BusMessageKind value, and the sender permission matrix collapses into "the participant type
// per kind", which the receiver checks on the FSM side.
package msgbus

import (
	"github.com/TrueOpen/wire/bus"
)

// SubjectTier is the tier: Core = best effort / lowest latency; JetStream = at-least-once + dedup + durable.
type SubjectTier string

const (
	TierCore      SubjectTier = "CORE"
	TierJetStream SubjectTier = "JETSTREAM"
)

// JetStreamName is the JetStream stream name mandated by contract §5.12.
const JetStreamName = "TRUEOPEN_TASK"

// Subject prefixes (contract §5.1). Model-level subjects append <model_id>, the rest append <task_id>.
const (
	subjectV1TaskOpenPrefix           = "trueopen.task.open."
	subjectV1HandraiseWorkerPrefix    = "trueopen.handraise.worker."
	subjectV1VerifyOpenPrefix         = "trueopen.verify.open."
	subjectV1HandraiseVerifierPrefix  = "trueopen.handraise.verifier."
	subjectV1WorkerAssignmentPrefix   = "trueopen.worker-assignment."
	subjectV1OutputAvailPrefix        = "trueopen.output-avail."
	subjectV1VerifierAssignmentPrefix = "trueopen.verifier-assignment."
	subjectV1VerifyResultPrefix       = "trueopen.verify-result."

	// subjectV1BuilderPreparePrefix is not under trueopen.*: prepare is an internal Builder-to-Builder
	// de-duplication announcement, it is not part of the nexus-cortex contract and it is not wrapped in a
	// BusEnvelopeV1 (see internal/coordinator/prepare.go).
	subjectV1BuilderPreparePrefix = "nexus.builder-prepare."
)

// SubjectTaskOpen Builder → Worker candidate (Core).
// Contract §5.4: a candidate decides whether to hand-raise from the broadcast metadata alone and may not download the input.
func SubjectTaskOpen(modelID string) string { return subjectV1TaskOpenPrefix + modelID }

// SubjectWorkerHandraiseV1 Worker candidate → Builder (Core).
func SubjectWorkerHandraiseV1(taskID string) string { return subjectV1HandraiseWorkerPrefix + taskID }

// SubjectVerifyOpen Builder → Verifier candidate (Core).
func SubjectVerifyOpen(taskID string) string { return subjectV1VerifyOpenPrefix + taskID }

// SubjectVerifierHandraiseV1 Verifier candidate → Builder (Core).
func SubjectVerifierHandraiseV1(taskID string) string {
	return subjectV1HandraiseVerifierPrefix + taskID
}

// SubjectWorkerAssignment Builder → selected Worker (JetStream).
// Contract §5.7: may only be sent after the on-chain EventWorkerAssignmentFinalized;
// Cortex must take the on-chain assignment as authoritative, and this message does not decide the selected Worker.
func SubjectWorkerAssignment(taskID string) string { return subjectV1WorkerAssignmentPrefix + taskID }

// SubjectOutputAvailableV1 Worker/Builder -> participants (JetStream, optional hint).
func SubjectOutputAvailableV1(taskID string) string { return subjectV1OutputAvailPrefix + taskID }

// SubjectVerifierAssignment Builder → selected Worker/selected Verifier (JetStream).
// Contract §5.9: may only be sent after the on-chain EventVerifierAssignmentFinalized.
func SubjectVerifierAssignment(taskID string) string {
	return subjectV1VerifierAssignmentPrefix + taskID
}

// SubjectVerifyResultV1 selected Verifier → Builder (JetStream, durable transport).
func SubjectVerifyResultV1(taskID string) string { return subjectV1VerifyResultPrefix + taskID }

// SubjectBuilderPrepare announces the rank1 submission intent to avoid duplicate submissions (Core, Builder-to-Builder, not a contract subject).
func SubjectBuilderPrepare(taskID string) string { return subjectV1BuilderPreparePrefix + taskID }

// SubjectSpecV1 describes the target state of one subject: its placeholder, wire kind and tier.
// WireKind is a bus.v1.BusMessageKind value (bus.Kind*); 0 means the subject carries no
// BusEnvelopeV1 (currently only the internal Builder-to-Builder prepare).
type SubjectSpecV1 struct {
	Prefix      string
	Placeholder string // "model_id" or "task_id"
	WireKind    int32
	Tier        SubjectTier
}

// subjectSpecsV1 holds the 8 subjects of contract §5.1. kind maps one-to-one onto subject;
// the frozen kind -> payload message type mapping lives in gen/bus/v1 (the BusPayloadType comments).
var subjectSpecsV1 = []SubjectSpecV1{
	{subjectV1TaskOpenPrefix, "model_id", bus.KindOrderBroadcast, TierCore},
	{subjectV1HandraiseWorkerPrefix, "task_id", bus.KindWorkerHandraise, TierCore},
	{subjectV1VerifyOpenPrefix, "task_id", bus.KindOpenVerify, TierCore},
	{subjectV1HandraiseVerifierPrefix, "task_id", bus.KindVerifierHandraise, TierCore},
	{subjectV1WorkerAssignmentPrefix, "task_id", bus.KindWorkerAssignmentNotify, TierJetStream},
	{subjectV1OutputAvailPrefix, "task_id", bus.KindOutputAvailable, TierJetStream},
	{subjectV1VerifierAssignmentPrefix, "task_id", bus.KindVerifierAssignmentNotify, TierJetStream},
	{subjectV1VerifyResultPrefix, "task_id", bus.KindVerifyResult, TierJetStream},
}

// internalSubjectSpecsV1 is the internal Builder-to-Builder catalogue. It is kept separate from
// subjectSpecsV1 so SubjectSpecsV1() still returns only the 8 contract subjects and nobody mistakes an
// internal subject for the contract surface.
var internalSubjectSpecsV1 = []SubjectSpecV1{
	{subjectV1BuilderPreparePrefix, "task_id", 0, TierCore},
}

// SubjectSpecsV1 returns the subject catalogue of contract §5.1 (a copy).
func SubjectSpecsV1() []SubjectSpecV1 {
	out := make([]SubjectSpecV1, len(subjectSpecsV1))
	copy(out, subjectSpecsV1)
	return out
}

// LookupSubjectV1 resolves an actual subject to its spec and placeholder value.
// An unknown subject must be rejected.
func LookupSubjectV1(subject string) (SubjectSpecV1, string, bool) {
	for _, spec := range allSubjectSpecsV1() {
		if len(subject) <= len(spec.Prefix) || subject[:len(spec.Prefix)] != spec.Prefix {
			continue
		}
		token := subject[len(spec.Prefix):]
		// The placeholder is a single token: further nesting is disallowed, which rules out over-reaching subjects such as trueopen.output-avail.a.b.
		for i := 0; i < len(token); i++ {
			if token[i] == '.' || token[i] == '*' || token[i] == '>' {
				return SubjectSpecV1{}, "", false
			}
		}
		return spec, token, true
	}
	return SubjectSpecV1{}, "", false
}

func allSubjectSpecsV1() []SubjectSpecV1 {
	out := make([]SubjectSpecV1, 0, len(subjectSpecsV1)+len(internalSubjectSpecsV1))
	out = append(out, subjectSpecsV1...)
	return append(out, internalSubjectSpecsV1...)
}

// JetStreamSubjectWildcardsV1 returns the subject wildcards that JetStream must cover (contract §5.12).
func JetStreamSubjectWildcardsV1() []string {
	out := make([]string, 0, len(subjectSpecsV1))
	for _, spec := range subjectSpecsV1 {
		if spec.Tier == TierJetStream {
			out = append(out, spec.Prefix+"*")
		}
	}
	return out
}

// DurableConsumer builds the name of a JetStream durable consumer (contract §5.12):
// it carries the node ID and the purpose, which helps when troubleshooting.
func DurableConsumer(nodeID, purpose string) string {
	return "nexus-" + nodeID + "-" + purpose
}
