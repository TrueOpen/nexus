package dispatchresponse

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

const claimPending = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL

// handleClaim rebuts an open claim when it is still pending, inside its window, and the evidence
// shows its ticket's compensation is not owed. A claim whose evidence is not there yet stays open
// and is looked at again next block.
func (r *Responder) handleClaim(ctx context.Context, head uint64, it item) {
	ticket := hex.EncodeToString(it.ID)
	if it.Deadline != 0 && head+1 > it.Deadline {
		r.log.Info("compensation claim window closed", "ticket", ticket, "rebuttal_deadline", it.Deadline)
		r.close(claimPrefix, r.claims, it.ID)
		return
	}
	if !it.ready(head) {
		return
	}
	if r.settleLastSend(ctx, head, &it) {
		r.update(claimPrefix, r.claims, &it)
		return
	}
	if it.spent() {
		r.update(claimPrefix, r.claims, &it)
		return
	}
	claim, err := r.cfg.Chain.QueryDispatchCompensationClaim(ctx, it.ID)
	switch {
	case isNotFound(err) && it.Deadline != 0:
		return // the claim may not be readable yet
	case isNotFound(err):
		r.close(claimPrefix, r.claims, it.ID)
		return
	case err != nil:
		r.log.Warn("compensation claim not read", "ticket", ticket, "err", err)
		return
	}
	switch {
	case claim.GetStatus() != claimPending:
		r.log.Info("compensation claim settled", "ticket", ticket, "status", claim.GetStatus())
		r.close(claimPrefix, r.claims, it.ID)
		return
	case head+1 > claim.GetRebuttalDeadlineHeight():
		r.log.Info("compensation claim window closed", "ticket", ticket, "rebuttal_deadline", claim.GetRebuttalDeadlineHeight())
		r.close(claimPrefix, r.claims, it.ID)
		return
	case claim.GetBuilderAddress() != r.cfg.Builder && !r.holdsCopyOf(it.ID, claim.GetBuilderAddress()):
		r.close(claimPrefix, r.claims, it.ID)
		return
	}
	it.Deadline = claim.GetRebuttalDeadlineHeight()
	ev, attempt, found, err := r.cfg.Evidence.ByTicket(it.ID)
	if err != nil {
		r.log.Warn("dispatch evidence not read", "ticket", ticket, "err", err)
		return
	}
	if !found {
		if !it.Missing {
			r.log.Warn("compensation claimed on a ticket without evidence here; it is paid unless evidence arrives in time", "ticket", ticket,
				"worker", claim.GetWorkerOperatorAddress(), "rebuttal_deadline", it.Deadline)
			it.Missing = true
			r.update(claimPrefix, r.claims, &it)
		}
		return
	}
	if dispatcherOf(ev, r.cfg.Builder) != claim.GetBuilderAddress() {
		r.log.Info("compensation claim names another Builder than the evidence of its ticket", "ticket", ticket, "builder", claim.GetBuilderAddress())
		r.close(claimPrefix, r.claims, it.ID)
		return
	}
	if err := r.cfg.Evidence.Extend(ev.Key(), it.Deadline); err != nil {
		r.log.Warn("evidence of an open claim not extended", "ticket", ticket, "err", err)
	}
	if ev.Builder != "" && !memberTurn(head, it.Deadline, r.cfg.Evidence.Params().RebuttalBlocks) {
		r.update(claimPrefix, r.claims, &it)
		return
	}
	if ev.Builder != "" && len(ev.Record) == 0 {
		// The dispatching Builder's record has not been synced to this member yet.
		if !it.RecordMissing {
			r.log.Warn("compensation claim on a synced copy without its record yet; looked at again next block", "ticket", ticket,
				"builder", ev.Builder, "rebuttal_deadline", it.Deadline)
			it.RecordMissing = true
		}
		r.update(claimPrefix, r.claims, &it)
		return
	}
	msg, err := rebuttal(r.cfg.Responder(), ev, attempt, claim)
	if err != nil {
		r.claimsOwed.Add(1)
		r.log.Info("compensation claim not rebutted: it is owed", "ticket", ticket, "worker", claim.GetWorkerOperatorAddress(), "reason", err)
		r.close(claimPrefix, r.claims, it.ID)
		return
	}
	if ev.Builder != "" && !r.currentMember(&it, ticket) {
		r.update(claimPrefix, r.claims, &it)
		return
	}
	res, err := r.cfg.Tx.SubmitRebutDispatchCompensation(ctx, msg, r.gas(msg, &it))
	if r.held(&it, err) {
		r.update(claimPrefix, r.claims, &it)
		return
	}
	if err != nil {
		r.log.Warn("compensation rebuttal not sent; tried again next block", "ticket", ticket, "err", err)
		return
	}
	r.signed()
	r.claimsRebutted.Add(1)
	r.log.Info("compensation claim rebutted", "ticket", ticket, "worker", claim.GetWorkerOperatorAddress(), "outcome", attempt.Outcome)
	it.sent(head, res)
	r.update(claimPrefix, r.claims, &it)
}

// rebuttal builds the MsgRebutDispatchCompensation of a claim, or says why the compensation is
// owed. It is the only place a rebuttal is decided. The attempt must be rebuttable
// (dispatchevidence.Rebuttable: the ticket reached the Worker and it rejected, timed out or was
// revoked), the claim must name the attempt's Worker and the evidence's order, the stored record
// must show the attempt with the same outcome, and a REJECTED attempt goes with the Worker's own
// reject of that ticket. Anything else is never sent: a rebuttal states a fact against a Worker.
// No key is picked here: the chain verifies the record and the reject each under the generation
// its own nonce selects, a previous (or explicitly revoked) one only when the larger of the claim's
// frozen earliest_submit_height and bound_change_height (its original order's and ticket's) is
// below that key's cutoff.
func rebuttal(responder string, ev *dispatchevidence.Order, a *dispatchevidence.Attempt, claim *taskv1.DispatchCompensationClaimState) (*taskv1.MsgRebutDispatchCompensation, error) {
	if !a.Rebuttable() {
		return nil, fmt.Errorf("attempt is %s, sent %v", a.Outcome, a.Sent)
	}
	if claim.GetWorkerOperatorAddress() != a.Operator {
		return nil, fmt.Errorf("claim names worker %s, the ticket's target is %s", claim.GetWorkerOperatorAddress(), a.Operator)
	}
	if hex.EncodeToString(claim.GetTaskId()) != ev.TaskID || hex.EncodeToString(claim.GetSessionId()) != ev.SessionID || claim.GetOrderSequence() != ev.Sequence {
		return nil, fmt.Errorf("claim names another order than the evidence")
	}
	var record taskv1.DispatchRecordV1
	if err := proto.Unmarshal(ev.Record, &record); err != nil {
		return nil, fmt.Errorf("stored record: %w", err)
	}
	if !bytes.Equal(record.GetTaskId(), claim.GetTaskId()) || !bytes.Equal(record.GetSessionId(), claim.GetSessionId()) || record.GetOrderSequence() != claim.GetOrderSequence() {
		return nil, fmt.Errorf("stored record names another order than the claim")
	}
	shown := recordOutcome(&record, a.Hash)
	if shown != a.Outcome {
		return nil, fmt.Errorf("stored record shows the attempt %s, the evidence %s", shown, a.Outcome)
	}
	msg := &taskv1.MsgRebutDispatchCompensation{DispatchTicketHash: append([]byte(nil), a.Hash...), ResponderAddress: responder, Record: &record}
	if a.Outcome == taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED {
		reject, err := storedReject(a)
		if err != nil {
			return nil, err
		}
		msg.Reject = reject
	}
	return msg, nil
}

// storedReject decodes the Worker's reject kept for a REJECTED attempt and checks it rejects that
// ticket as its target.
func storedReject(a *dispatchevidence.Attempt) (*taskv1.DispatchRejectV1, error) {
	if len(a.Reject) == 0 {
		return nil, fmt.Errorf("no reject is stored for the REJECTED attempt")
	}
	var reject taskv1.DispatchRejectV1
	if err := proto.Unmarshal(a.Reject, &reject); err != nil {
		return nil, fmt.Errorf("stored reject: %w", err)
	}
	if !bytes.Equal(reject.GetDispatchTicketHash(), a.Hash) || reject.GetMember().GetOperatorAddress() != a.Operator {
		return nil, fmt.Errorf("stored reject is not the target's reject of the ticket")
	}
	return &reject, nil
}

// recordOutcome is the outcome a record shows for a ticket; UNSPECIFIED when it does not list it.
func recordOutcome(record *taskv1.DispatchRecordV1, hash []byte) taskv1.DispatchAttemptOutcomeV1 {
	for _, round := range record.GetRounds() {
		for _, a := range round.GetAttempts() {
			if bytes.Equal(a.GetDispatchTicketHash(), hash) {
				return a.GetOutcome()
			}
		}
	}
	return taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED
}

// dispatcherOf is the Builder that dispatched the order of ev: the one named in a member's copy,
// otherwise this Builder.
func dispatcherOf(ev *dispatchevidence.Order, self string) string {
	if ev.Builder != "" {
		return ev.Builder
	}
	return self
}

// currentMember reports whether this Builder is in the current BuilderSet, which a member's
// rebuttal needs: the chain refuses one from a Builder outside it, whatever group froze the
// order. Outside it, or without a known set, nothing is sent and the claim is looked at again
// next block (the set may change within the window); leaving the set is logged once per claim.
func (r *Responder) currentMember(it *item, ticket string) bool {
	set, ok := r.cfg.BuilderSet.CurrentBuilderSet()
	switch {
	case !ok:
		return false
	case !slices.Contains(set.Members, r.cfg.Builder):
		if !it.NotMember {
			r.log.Warn("compensation claim on a synced copy not rebutted: this Builder is not in the current BuilderSet", "ticket", ticket,
				"builder_set", set.ID, "rebuttal_deadline", it.Deadline)
			it.NotMember = true
		}
		return false
	}
	it.NotMember = false
	return true
}

// memberTurn reports whether a group member answers at head a claim or challenge whose answer is
// due by deadline after a window of the given length: in the second half of the window. The first
// half is the dispatching Builder's, so the group does not pay for the same answer twice.
func memberTurn(head, deadline, window uint64) bool {
	return head+window/2 >= deadline
}

// holdsCopyOf reports whether this Builder holds builder's evidence of a ticket as a member of
// the ticket's Task Builders group.
func (r *Responder) holdsCopyOf(ticketHash []byte, builder string) bool {
	ev, _, found, err := r.cfg.Evidence.ByTicket(ticketHash)
	return err == nil && found && ev.Builder != "" && ev.Builder == builder
}
