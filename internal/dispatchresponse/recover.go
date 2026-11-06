package dispatchresponse

import (
	"context"
	"sort"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

// recoverOpen reads, after a role stream gap, every claim pending rebuttal and every challenge
// awaiting an answer against this Builder, and against each Builder whose evidence it holds as a
// group member, from the chain's open indexes (each walk pinned to one height by its page token),
// and opens those it would have followed from their events. Already open items keep their state;
// the event stream goes on from where it reconnected, so nothing between is lost. It reports false
// when a walk failed: the recovery is then made again, from a fresh height, at the next spacing.
func (r *Responder) recoverOpen(ctx context.Context) bool {
	builders := append([]string{r.cfg.Builder}, r.copyBuilders()...)
	complete := true
	claims, challenges := 0, 0
	for _, builder := range builders {
		rows, err := chaincli.ListOpenDispatchCompensationClaims(ctx, r.cfg.Chain, builder)
		if err != nil {
			r.log.Warn("open compensation claims not read after a role stream gap", "builder", builder, "err", err)
			complete = false
		}
		for _, claim := range rows {
			if builder != r.cfg.Builder && !r.holdsCopyOf(claim.GetDispatchTicketHash(), builder) {
				continue
			}
			if r.open(claimPrefix, r.claims, &item{ID: claim.GetDispatchTicketHash(), Deadline: claim.GetRebuttalDeadlineHeight()}) {
				claims++
			}
		}
		open, err := chaincli.ListOpenDispatchChallenges(ctx, r.cfg.Chain, builder)
		if err != nil {
			r.log.Warn("open dispatch challenges not read after a role stream gap", "builder", builder, "err", err)
			complete = false
		}
		for _, ch := range open {
			kind, taskID := ch.GetKind(), ch.GetTaskId()
			// As from an event: only a kind with an answer, and a SKIP only on a task with evidence
			// here; another Builder's challenge only on a task this member holds a copy of.
			if !answerable(kind) ||
				(kind == sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP || builder != r.cfg.Builder) && !r.holdsTask(taskID) {
				continue
			}
			if r.open(challengePrefix, r.challenges, &item{ID: ch.GetChallengeId(), Deadline: ch.GetProofDeadlineHeight(), Kind: kind, TaskID: taskID}) {
				challenges++
			}
		}
	}
	r.log.Info("open claims and challenges read after a role stream gap", "builders", len(builders),
		"claims_opened", claims, "challenges_opened", challenges, "complete", complete)
	return complete
}

// copyBuilders lists, sorted, the other Builders whose evidence this Builder holds as a group
// member. A failed scan lists those seen before it failed.
func (r *Responder) copyBuilders() []string {
	seen := map[string]bool{}
	err := r.cfg.Evidence.Scan(func(ev *dispatchevidence.Order) bool {
		if ev.Builder != "" && ev.Builder != r.cfg.Builder {
			seen[ev.Builder] = true
		}
		return true
	})
	if err != nil {
		r.log.Warn("dispatch evidence not fully scanned for group members' copies", "err", err)
	}
	out := make([]string, 0, len(seen))
	for builder := range seen {
		out = append(out, builder)
	}
	sort.Strings(out)
	return out
}
