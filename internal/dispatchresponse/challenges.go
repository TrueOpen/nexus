package dispatchresponse

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// answerable reports whether a challenge kind takes an answer: SKIP (the Worker's reject) and
// ROSTER_UNAVAILABLE (the round's roster). OMISSION, DRAW and DOUBLE_DISPATCH have none.
func answerable(kind sharedv1.DispatchChallengeKindV1) bool {
	return kind == sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP ||
		kind == sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE
}

// handleChallenge answers an open challenge while it awaits an answer and its deadline is ahead.
// A challenge whose answer is not held here is left to the deadline.
func (r *Responder) handleChallenge(ctx context.Context, head uint64, it item) {
	id := hex.EncodeToString(it.ID)
	if it.Deadline != 0 && head+1 > it.Deadline {
		r.log.Info("dispatch challenge deadline passed", "challenge_id", id, "proof_deadline", it.Deadline)
		r.close(challengePrefix, r.challenges, it.ID)
		return
	}
	if head < it.RetryAt || !it.ready(head) {
		return
	}
	if len(it.TaskID) != 0 && !r.holdsTask(it.TaskID) {
		if it.Kind == sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP {
			r.close(challengePrefix, r.challenges, it.ID)
		}
		return // a ROSTER_UNAVAILABLE waits for evidence (a group member's copy) until its deadline
	}
	if r.settleLastSend(ctx, head, &it) {
		r.update(challengePrefix, r.challenges, &it)
		return
	}
	if it.spent() {
		r.update(challengePrefix, r.challenges, &it)
		return
	}
	ch, err := r.cfg.Chain.QueryDispatchChallenge(ctx, it.ID)
	switch {
	case isNotFound(err) && it.Deadline != 0:
		return
	case isNotFound(err):
		r.close(challengePrefix, r.challenges, it.ID)
		return
	case err != nil:
		r.log.Warn("dispatch challenge not read", "challenge_id", id, "err", err)
		return
	}
	awaiting := ch.GetStatus() == taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF ||
		ch.GetStatus() == taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_ROSTER
	if !awaiting || head+1 > ch.GetProofDeadlineHeight() || !answerable(ch.GetKind()) {
		r.close(challengePrefix, r.challenges, it.ID)
		return
	}
	it.Deadline = ch.GetProofDeadlineHeight()
	r.extendTask(ch.GetTaskId(), it.Deadline)
	if !r.holdsOwnTask(ch.GetTaskId()) && !memberTurn(head, it.Deadline, r.cfg.Evidence.Params().ChallengeResponseBlocks) {
		r.update(challengePrefix, r.challenges, &it)
		return
	}
	msg := &taskv1.MsgRespondDispatchChallenge{ChallengeId: append([]byte(nil), it.ID...), ResponderAddress: r.cfg.Responder()}
	var answerErr error
	switch ch.GetKind() {
	case sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP:
		var reject *taskv1.DispatchRejectV1
		if reject, answerErr = r.skipAnswer(ch); answerErr == nil {
			msg.Response = &taskv1.MsgRespondDispatchChallenge_Reject{Reject: reject}
		}
	default:
		var roster *taskv1.DispatchRosterV1
		if roster, answerErr = r.rosterAnswer(ctx, ch); answerErr == nil {
			msg.Response = &taskv1.MsgRespondDispatchChallenge_Roster{Roster: roster}
		}
	}
	if answerErr != nil {
		if !it.Missing {
			r.log.Warn("dispatch challenge not answered", "challenge_id", id, "kind", ch.GetKind(), "proof_deadline", it.Deadline, "reason", answerErr)
			it.Missing = true
		}
		it.RetryAt = head + resubmitBlocks
		r.update(challengePrefix, r.challenges, &it)
		return
	}
	res, err := r.cfg.Tx.SubmitRespondDispatchChallenge(ctx, msg, r.gas(msg, &it))
	if r.held(&it, err) {
		r.update(challengePrefix, r.challenges, &it)
		return
	}
	if err != nil {
		r.log.Warn("dispatch challenge response not sent; tried again next block", "challenge_id", id, "err", err)
		return
	}
	r.signed()
	r.answered.Add(1)
	r.log.Info("dispatch challenge answered", "challenge_id", id, "kind", ch.GetKind())
	it.sent(head, res)
	r.update(challengePrefix, r.challenges, &it)
}

// holdsTask reports whether this Builder holds evidence of a task; a failed read counts as held.
func (r *Responder) holdsTask(taskID []byte) bool {
	orders, err := r.cfg.Evidence.ByTask(hex.EncodeToString(taskID))
	return err != nil || len(orders) > 0
}

// holdsOwnTask reports whether this Builder dispatched the task: it holds evidence of it that is
// not a member's copy. A failed read counts as held.
func (r *Responder) holdsOwnTask(taskID []byte) bool {
	orders, err := r.cfg.Evidence.ByTask(hex.EncodeToString(taskID))
	if err != nil {
		return true
	}
	for _, ev := range orders {
		if ev.Builder == "" {
			return true
		}
	}
	return false
}

// extendTask keeps every evidence of a task until height: a challenge on it is open.
func (r *Responder) extendTask(taskID []byte, height uint64) {
	orders, err := r.cfg.Evidence.ByTask(hex.EncodeToString(taskID))
	if err != nil {
		r.log.Warn("evidence of a challenged task not read", "task_id", hex.EncodeToString(taskID), "err", err)
		return
	}
	for _, ev := range orders {
		if err := r.cfg.Evidence.Extend(ev.Key(), height); err != nil {
			r.log.Warn("evidence of an open challenge not extended", "task_id", ev.TaskID, "err", err)
		}
	}
}

// skipAnswer is the Worker's reject stored for the challenged ticket. Only the dispatching Builder
// answers a SKIP.
func (r *Responder) skipAnswer(ch *taskv1.DispatchChallengeState) (*taskv1.DispatchRejectV1, error) {
	if ch.GetBuilderAddress() != r.cfg.Builder {
		return nil, fmt.Errorf("challenged record is %s's", ch.GetBuilderAddress())
	}
	ev, a, found, err := r.cfg.Evidence.ByTicket(ch.GetChallengedTicketHash())
	if err != nil || !found {
		return nil, fmt.Errorf("no evidence of the challenged ticket (%v)", err)
	}
	if hex.EncodeToString(ch.GetTaskId()) != ev.TaskID {
		return nil, fmt.Errorf("evidence of the challenged ticket names another task")
	}
	if a.Outcome != taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED {
		return nil, fmt.Errorf("challenged attempt is %s here", a.Outcome)
	}
	return storedReject(a)
}

// rosterAnswer is the stored roster of the challenged round of a recorded task: the one whose
// roster_hash the chain's record holds for that round. Whether the evidence was marked recorded
// does not matter: the chain's record decides.
func (r *Responder) rosterAnswer(ctx context.Context, ch *taskv1.DispatchChallengeState) (*taskv1.DispatchRosterV1, error) {
	if ch.DispatchRound == nil {
		return nil, fmt.Errorf("challenge names no dispatch round")
	}
	round := ch.GetDispatchRound()
	orders, err := r.cfg.Evidence.ByTask(hex.EncodeToString(ch.GetTaskId()))
	if err != nil {
		return nil, err
	}
	records := map[string]*taskv1.DispatchRecordState{}
	for _, ev := range orders {
		key := fmt.Sprintf("%s/%d", ev.SessionID, ev.Sequence)
		record, ok := records[key]
		if !ok {
			record, err = r.cfg.Chain.QueryDispatchRecordByOrder(ctx, ev.SessionID, ev.Sequence)
			if isNotFound(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("chain record of the task: %w", err)
			}
			records[key] = record
		}
		if !bytes.Equal(record.GetTaskId(), ch.GetTaskId()) {
			continue
		}
		want := chainRosterHash(record, round)
		if want == nil {
			return nil, fmt.Errorf("chain record has no round %d", round)
		}
		if roster, ok := ev.RosterFor(r.cfg.ChainID, round, want); ok {
			return roster, nil
		}
	}
	return nil, fmt.Errorf("no stored roster of round %d matches the chain's record", round)
}

func chainRosterHash(record *taskv1.DispatchRecordState, round uint32) []byte {
	for _, r := range record.GetRounds() {
		if r.GetDispatchRound() == round {
			return r.GetRosterHash()
		}
	}
	return nil
}
