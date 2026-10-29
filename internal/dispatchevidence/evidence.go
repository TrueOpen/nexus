// Package dispatchevidence keeps the evidence of the orders a Builder dispatched after they left
// the dispatcher, for as long as the chain can ask for it.
//
// A Worker may claim compensation on any ticket it accepted that was not recorded as winner, from
// the order's record deadline on, and dispatch challenges can be opened against a recorded order
// for a while after it was recorded. The Builder answers them with what it signed and received:
// every round's roster and bound handraise root, every ticket as signed with whether it reached
// its target, every reject and late accept as received, the winner's accept, the signed record
// and the signed order. The dispatcher writes an order's evidence when it is accepted, when it
// fails and when it is recorded; it is kept until every claim and challenge window on it closed
// (Params.RetainUntil), and while a claim or challenge on it is open at least until that claim's
// rebuttal deadline or that challenge's proof deadline (Extend, called by package
// dispatchresponse).
package dispatchevidence

import (
	"fmt"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Rebuttable reports whether a compensation claim on an attempt may be rebutted: only a ticket
// that reached its Worker and ended REJECTED, TIMEOUT or REVOKED. A ticket that timed out unsent,
// a VOIDED one (the Builder gave up an accepted ticket) and the winner are owed the compensation.
// Every rebuttal goes through this check.
func Rebuttable(sent bool, outcome taskv1.DispatchAttemptOutcomeV1) bool {
	if !sent {
		return false
	}
	switch outcome {
	case taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED,
		taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_TIMEOUT,
		taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REVOKED:
		return true
	}
	return false
}

// Attempt is one ticket of an order and what came of it.
type Attempt struct {
	// Ticket is the signed DispatchTicketV1, Hash its dispatch_ticket_hash.
	Ticket []byte `json:"ticket"`
	Hash   []byte `json:"hash"`
	Rank   uint32 `json:"rank"`
	// Operator is the target's operator address.
	Operator string `json:"operator"`
	// Sent is false for a ticket that never reached its target.
	Sent    bool                            `json:"sent"`
	Outcome taskv1.DispatchAttemptOutcomeV1 `json:"outcome"`
	// Reject is the signed DispatchRejectV1 of a REJECTED attempt as received.
	Reject []byte `json:"reject,omitempty"`
	// LateAccept is the signed DispatchAcceptV1 of an attempt VOIDED because its accept came too
	// late to record the order.
	LateAccept []byte `json:"late_accept,omitempty"`
}

// Rebuttable applies Rebuttable to the attempt.
func (a *Attempt) Rebuttable() bool { return Rebuttable(a.Sent, a.Outcome) }

// Round is one dispatch round: its roster as sent (DispatchRosterV1), the roster_hash its tickets
// commit, the handraise root they bind and its attempts in rank order.
type Round struct {
	Number     uint32 `json:"number"`
	RootDigest []byte `json:"root_digest"`
	// SignedRoot is the SignedHandraiseRootV1 of RootDigest as synced, in a group member's copy;
	// the dispatching Builder finds its own roots in its handraise registry instead.
	SignedRoot []byte    `json:"signed_root,omitempty"`
	Roster     []byte    `json:"roster"`
	RosterHash []byte    `json:"roster_hash"`
	Attempts   []Attempt `json:"attempts"`
}

// Order is the evidence of one version of an order in one epoch: the tickets of one task_id under
// one VRF output.
type Order struct {
	// Builder is the order's dispatching Builder when this Builder holds the evidence as another
	// member of the order's Task Builders group, synced from it; empty for this Builder's own orders.
	Builder   string `json:"builder,omitempty"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id"`
	TaskHash  string `json:"task_hash"`
	Epoch     uint64 `json:"epoch"`
	// SignedOrder is the SignedOrderV2 offered with the tickets.
	SignedOrder []byte `json:"signed_order"`
	// DeadlineBase is the largest max(earliest_submit_height, bound_change_height) a ticket of the
	// order commits: claims on a ticket open record_deadline_blocks after its own base.
	DeadlineBase uint64  `json:"deadline_base"`
	Rounds       []Round `json:"rounds"`
	// Accept is the winner's signed DispatchAcceptV1, when there is a winner.
	Accept []byte `json:"accept,omitempty"`
	// Record is a signed DispatchRecordV1 listing every attempt: the record of the dispatch entry
	// when there is a winner, otherwise one with no winner.
	Record []byte `json:"record"`
	// Recorded is set once the chain admitted the record at RecordedHeight.
	Recorded       bool   `json:"recorded,omitempty"`
	RecordedHeight uint64 `json:"recorded_height,omitempty"`
	// RetainUntil is the last height the evidence is kept at; the store sets it.
	RetainUntil uint64 `json:"retain_until"`
}

// Key identifies the evidence: one per (session, sequence, task_id, epoch), and per dispatching
// Builder for a member's copy, which stays apart from this Builder's own evidence of the order.
func (o *Order) Key() string {
	key := fmt.Sprintf("%s/%020d/%s/%020d", o.SessionID, o.Sequence, o.TaskID, o.Epoch)
	if o.Builder != "" {
		key += "@" + o.Builder
	}
	return key
}

// Attempt finds the attempt of a ticket hash.
func (o *Order) Attempt(hash []byte) (*Attempt, bool) {
	for i := range o.Rounds {
		for j := range o.Rounds[i].Attempts {
			if string(o.Rounds[i].Attempts[j].Hash) == string(hash) {
				return &o.Rounds[i].Attempts[j], true
			}
		}
	}
	return nil, false
}

// Round finds a round by number.
func (o *Order) Round(number uint32) (*Round, bool) {
	for i := range o.Rounds {
		if o.Rounds[i].Number == number {
			return &o.Rounds[i], true
		}
	}
	return nil, false
}

// Params are the task params dispatch windows the retention follows.
type Params struct {
	RecordDeadlineBlocks    uint64
	ClaimWindowBlocks       uint64
	RebuttalBlocks          uint64
	ChallengeWindowBlocks   uint64
	ChallengeResponseBlocks uint64
	// RetentionBlocks is dispatch_evidence_retention_blocks.
	RetentionBlocks uint64
}

// ParamsFromChain takes the windows from task params dispatch.
func ParamsFromChain(d *taskv1.DispatchParamsV1) Params {
	return Params{
		RecordDeadlineBlocks:    d.GetRecordDeadlineBlocks(),
		ClaimWindowBlocks:       d.GetDispatchCompensationClaimWindowBlocks(),
		RebuttalBlocks:          d.GetDispatchCompensationRebuttalBlocks(),
		ChallengeWindowBlocks:   d.GetDispatchChallengeWindowBlocks(),
		ChallengeResponseBlocks: d.GetDispatchChallengeResponseBlocks(),
		RetentionBlocks:         d.GetDispatchEvidenceRetentionBlocks(),
	}
}

// RetainUntil is the last height o must be kept at. Every order is kept until a claim filed on
// the last block of its claim window was rebutted: deadline base + record_deadline_blocks + claim
// window + rebuttal blocks. A recorded order is also kept until a challenge opened on the last
// block of its challenge window was answered. dispatch_evidence_retention_blocks is added to
// both, a margin for parameter changes and late reads.
func (p Params) RetainUntil(o *Order) uint64 {
	until := o.DeadlineBase + p.RecordDeadlineBlocks + p.ClaimWindowBlocks + p.RebuttalBlocks
	if o.Recorded {
		until = max(until, o.RecordedHeight+p.ChallengeWindowBlocks+p.ChallengeResponseBlocks)
	}
	return until + p.RetentionBlocks
}
