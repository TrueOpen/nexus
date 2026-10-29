package dispatchresponse

import (
	"encoding/hex"
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
		WorkerOperatorAddress: worker, Status: statusPending, RebuttalDeadlineHeight: deadline,
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

// After a role stream gap the member's copies are looked up too.
func TestResyncRechecksMemberClaims(t *testing.T) {
	e := newEnv(t)
	e.put(memberCopy(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}})))
	e.chain.claims[string(ticketHash(0, 0))] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: ticketHash(0, 0), TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: other,
		WorkerOperatorAddress: op7, Status: statusPending, RebuttalDeadlineHeight: 160,
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(151)
	e.block(156)
	if len(e.rebuts()) != 1 {
		t.Fatal("member claim of the gap not rebutted")
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
