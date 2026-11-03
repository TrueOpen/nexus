package dispatchresponse

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

// memberCopy marks o as this Builder's copy of an order dispatched by other.
func memberCopy(o *dispatchevidence.Order) *dispatchevidence.Order {
	o.Builder = other
	return o
}

// memberClaim files a pending claim on a ticket of other's and delivers its event.
func (e *env) memberClaim(hash []byte, worker string, deadline uint64) {
	e.t.Helper()
	e.chain.mu.Lock()
	e.chain.claims[string(hash)] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: hash, TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: other,
		WorkerOperatorAddress: worker, Status: statusPending, ClaimedHeight: deadline - testParams.RebuttalBlocks, RebuttalDeadlineHeight: deadline,
	}
	e.chain.mu.Unlock()
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Height: int64(deadline - testParams.RebuttalBlocks), Typed: chaincli.DispatchCompensationClaimed{
		TicketHash: hash, TaskID: hex.EncodeToString(testTask), Builder: other, Worker: worker, RebuttalDeadlineHeight: deadline,
	}})
}

// A group member rebuts a claim on the dispatching Builder's ticket from its synced copy, from its
// own service account. It leaves the first half of the window to the dispatching Builder.
func TestMemberRebutsAClaimFromItsSyncedCopy(t *testing.T) {
	e := newEnv(t)
	o := memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeRejected}, {op: op1, sent: true, outcome: outcomeTimeout}}))
	e.put(o)
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.block(151)
	if got := e.rebuts(); len(got) != 0 {
		t.Fatalf("member rebutted in the dispatching Builder's half of the window: %v", got)
	}
	e.block(155)
	got := e.rebuts()
	if len(got) != 1 || got[0].GetResponderAddress() != responder || got[0].GetReject() == nil {
		t.Fatalf("rebuttals = %v", got)
	}
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(o.Record, &rec); err != nil || !proto.Equal(got[0].GetRecord(), &rec) {
		t.Fatal("member rebuttal does not carry the dispatching Builder's record")
	}
}

// The halves of a window are those of the claim's or challenge's own window as the chain opened it
// (claimed_height to rebuttal_deadline_height, opened_height to proof_deadline_height): the
// session's frozen windows, whatever the current params say.
func TestMemberTurnIsHalfTheWindowTheChainOpened(t *testing.T) {
	e := newEnv(t)
	e.put(memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeRejected}, {op: op1, sent: true, outcome: outcomeTimeout}})))
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.setClaim(ticketHash(0, 0), func(c *taskv1.DispatchCompensationClaimState) { c.ClaimedHeight = 120 }) // a 40-block window
	e.block(139)
	if got := e.rebuts(); len(got) != 0 {
		t.Fatalf("member rebutted in the dispatching Builder's half of the window: %v", got)
	}
	e.block(140)
	if got := e.rebuts(); len(got) != 1 {
		t.Fatalf("rebuttals in the member's half of the 40-block window = %v", got)
	}

	e = newEnv(t)
	o := memberCopy(recordedOrder(t))
	e.put(o)
	e.chainRecord(o)
	e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: other, DispatchRound: u32(1), OpenedHeight: 105, ProofDeadlineHeight: u64(125), Status: awaitingRoster,
	})
	e.block(114)
	if got := e.responds(); len(got) != 0 {
		t.Fatalf("member answered in the dispatching Builder's half of the window: %v", got)
	}
	e.block(115)
	if got := e.responds(); len(got) != 1 {
		t.Fatalf("responses in the member's half of the 20-block window = %v", got)
	}
}

// Only the dispatching Builder or a member of the current BuilderSet may rebut: a member that left
// the current set, or that does not know it, sends nothing, and rebuts once it is in the set again
// within the window. The dispatching Builder rebuts its own claims whatever the set.
func TestMemberRebutsOnlyInTheCurrentBuilderSet(t *testing.T) {
	e := newEnv(t)
	e.put(memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}})))
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.set.set(true, other, op1)
	e.block(155)
	e.block(156)
	if got := e.rebuts(); len(got) != 0 {
		t.Fatalf("a member outside the current BuilderSet rebutted: %v", got)
	}
	if e.logs.count("compensation claim on a synced copy not rebutted: this Builder is not in the current BuilderSet") != 1 {
		t.Fatal("leaving the set is not logged once")
	}
	e.set.set(false)
	e.block(157)
	if got := e.rebuts(); len(got) != 0 {
		t.Fatalf("a member without a known BuilderSet rebutted: %v", got)
	}
	if len(e.r.openClaims()) != 1 {
		t.Fatal("the claim was dropped while the set is not known")
	}
	e.set.set(true, other, self)
	e.block(158)
	if got := e.rebuts(); len(got) != 1 {
		t.Fatalf("rebuttals back in the set = %v", got)
	}

	own := newEnv(t)
	own.set.set(true, other)
	own.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	own.claim(ticketHash(0, 0), op7, 160)
	own.block(151)
	if got := own.rebuts(); len(got) != 1 {
		t.Fatalf("the dispatching Builder outside the set did not rebut: %v", got)
	}
}

// A claim the dispatching Builder already rebutted is settled on chain: the member closes it.
func TestMemberLeavesASettledClaim(t *testing.T) {
	e := newEnv(t)
	e.put(memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}})))
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.setClaim(ticketHash(0, 0), func(c *taskv1.DispatchCompensationClaimState) { c.Status = statusDismissed })
	e.block(156)
	if len(e.rebuts()) != 0 || len(e.r.openClaims()) != 0 {
		t.Fatalf("settled claim: rebuts %v, open %v", e.rebuts(), e.r.openClaims())
	}
}

// Claims on another Builder's tickets are only followed when this Builder holds that Builder's
// copy of the ticket.
func TestClaimsOfOtherBuildersNeedTheirCopy(t *testing.T) {
	e := newEnv(t)
	e.memberClaim(ticketHash(0, 0), op7, 160)
	if len(e.r.openClaims()) != 0 {
		t.Fatal("claim on a ticket without a copy here was opened")
	}
	// Own evidence of the same ticket does not answer a claim naming another Builder.
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.block(156)
	if len(e.rebuts()) != 0 {
		t.Fatal("own evidence rebutted a claim on another Builder's ticket")
	}
}

// After a role stream gap the open claims and challenges of every Builder whose copies this member
// holds are read too, and those on its copies are followed.
func TestResyncRecoversMemberClaimsAndChallenges(t *testing.T) {
	e := newEnv(t)
	o := memberCopy(recordedOrder(t))
	e.put(o)
	e.chainRecord(o)
	e.chain.claims[string(ticketHash(0, 0))] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: ticketHash(0, 0), TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: other,
		WorkerOperatorAddress: op7, Status: statusPending, RebuttalDeadlineHeight: 160,
	}
	// A claim on another ticket of that Builder that this member holds no copy of.
	e.chain.claims[string(fill(0x77))] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: fill(0x77), TaskId: fill(0x78), BuilderAddress: other, Status: statusPending, RebuttalDeadlineHeight: 160,
	}
	e.chain.challenges[string(fill(0xc2))] = &taskv1.DispatchChallengeState{
		ChallengeId: fill(0xc2), TaskId: testTask, Kind: kindRoster, BuilderAddress: other, DispatchRound: u32(1),
		ProofDeadlineHeight: u64(158), Status: awaitingRoster,
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(151)
	if got := e.r.openClaims(); len(got) != 1 || !bytes.Equal(got[0].ID, ticketHash(0, 0)) {
		t.Fatalf("open claims = %v", got)
	}
	if got := e.r.openChallenges(); len(got) != 1 {
		t.Fatalf("open challenges = %v", got)
	}
	e.block(156)
	if len(e.rebuts()) != 1 || len(e.responds()) != 1 {
		t.Fatalf("member answers of the gap: rebuts %d, responds %d", len(e.rebuts()), len(e.responds()))
	}
}

// A member answers ROSTER_UNAVAILABLE from its synced copy, in the second half of the proof
// window: any member's answer lifts the challenge.
func TestMemberAnswersRosterUnavailable(t *testing.T) {
	e := newEnv(t)
	o := memberCopy(recordedOrder(t))
	e.put(o)
	e.chainRecord(o)
	e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: other, DispatchRound: u32(1), ProofDeadlineHeight: u64(125), Status: awaitingRoster,
	})
	e.block(121)
	if got := e.responds(); len(got) != 0 {
		t.Fatalf("member answered in the dispatching Builder's half of the window: %v", got)
	}
	e.block(123)
	got := e.responds()
	if len(got) != 1 {
		t.Fatalf("%d responses", len(got))
	}
	var roster taskv1.DispatchRosterV1
	if err := proto.Unmarshal(o.Rounds[1].Roster, &roster); err != nil || !proto.Equal(got[0].GetRoster(), &roster) {
		t.Fatalf("response = %v", got[0])
	}
}

// A SKIP is answered only by the dispatching Builder: a member's copy holds the reject too, but
// the challenged record is not its own.
func TestMemberDoesNotAnswerSkip(t *testing.T) {
	e := newEnv(t)
	e.put(memberCopy(recordedOrder(t)))
	e.challenge(0xc1, &taskv1.DispatchChallengeState{
		Kind: kindSkip, BuilderAddress: other, ChallengedTicketHash: ticketHash(0, 0), AttemptRank: u32(0),
		ProofDeadlineHeight: u64(125), Status: awaitingProof,
	})
	e.block(124)
	if got := e.responds(); len(got) != 0 {
		t.Fatalf("member answered a SKIP: %v", got)
	}
}

// A member's copy whose record has not been synced yet is not a reason to give the claim up: it
// is looked at again on the next blocks, and rebutted once the record arrives.
func TestMemberWaitsForTheSyncedRecord(t *testing.T) {
	e := newEnv(t)
	o := memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	record := o.Record
	o.Record = nil
	e.put(o)
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.block(155)
	if len(e.rebuts()) != 0 || len(e.r.openClaims()) != 1 {
		t.Fatalf("claim without the synced record: rebuts %v, open %v", e.rebuts(), e.r.openClaims())
	}
	o.Record = record
	e.put(o)
	e.block(156)
	if len(e.rebuts()) != 1 {
		t.Fatal("claim not rebutted once the record arrived")
	}
}

// The wait for a synced copy's record is logged once on its own: a claim item already marked as
// having missed its evidence still logs it.
func TestMemberLogsTheMissingRecordOnItsOwn(t *testing.T) {
	e := newEnv(t)
	var logs bytes.Buffer
	e.r.log = slog.New(slog.NewTextHandler(&logs, nil))
	o := memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	o.Record = nil
	e.put(o)
	e.memberClaim(ticketHash(0, 0), op7, 160)
	e.r.mu.Lock()
	for _, it := range e.r.claims {
		it.Missing = true // the evidence was looked for earlier and not found
	}
	e.r.mu.Unlock()
	e.block(155)
	e.block(156)
	if n := strings.Count(logs.String(), "without its record yet"); n != 1 {
		t.Fatalf("missing record logged %d times: %s", n, logs.String())
	}
}
