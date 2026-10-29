package dispatchresponse

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

// recordedOrder is a recorded order: round 0 op7 REJECTED, op1 TIMEOUT; round 1 op3 ACCEPTED.
func recordedOrder(t *testing.T) *dispatchevidence.Order {
	return evidenceOrder(t, true,
		[]attemptSpec{{op: op7, sent: true, outcome: outcomeRejected}, {op: op1, sent: true, outcome: outcomeTimeout}},
		[]attemptSpec{{op: op3, sent: true, outcome: outcomeAccepted}})
}

// chainRecord is the DispatchRecordState the chain holds for o.
func (e *env) chainRecord(o *dispatchevidence.Order) {
	e.t.Helper()
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(o.Record, &rec); err != nil {
		e.t.Fatal(err)
	}
	e.chain.records[o.SessionID] = &taskv1.DispatchRecordState{
		TaskId: rec.GetTaskId(), DispatchRecordHash: fill(0x77), DispatchTicketHash: rec.GetDispatchTicketHash(), BuilderAddress: self,
		Rounds: rec.GetRounds(), RecordedHeight: o.RecordedHeight,
	}
}

// A SKIP challenge on this Builder's record is answered with the Worker's reject stored for the
// challenged ticket.
func TestSkipIsAnsweredWithTheStoredReject(t *testing.T) {
	e := newEnv(t)
	o := recordedOrder(t)
	e.put(o)
	cid := e.challenge(0xc1, &taskv1.DispatchChallengeState{
		Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 0), AttemptRank: u32(0),
		ProofDeadlineHeight: u64(125), Status: awaitingProof,
	})
	e.block(121)
	got := e.responds()
	if len(got) != 1 {
		t.Fatalf("%d responses", len(got))
	}
	var reject taskv1.DispatchRejectV1
	if err := proto.Unmarshal(o.Rounds[0].Attempts[0].Reject, &reject); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[0].GetChallengeId(), cid) || got[0].GetResponderAddress() != responder || !proto.Equal(got[0].GetReject(), &reject) {
		t.Fatalf("response = %v", got[0])
	}
}

// Only the dispatching Builder answers a SKIP, only with a reject it holds for that ticket, only
// while the challenge awaits it and before its deadline.
func TestSkipIsNotAnsweredOtherwise(t *testing.T) {
	for name, tc := range map[string]struct {
		state *taskv1.DispatchChallengeState
		head  uint64
	}{
		"another Builder": {&taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: other, ChallengedTicketHash: ticketHash(0, 0), ProofDeadlineHeight: u64(125), Status: awaitingProof}, 121},
		"no reject held":  {&taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 1), ProofDeadlineHeight: u64(125), Status: awaitingProof}, 121},
		"unknown ticket":  {&taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: fill(0x99), ProofDeadlineHeight: u64(125), Status: awaitingProof}, 121},
		"resolved":        {&taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 0), ProofDeadlineHeight: u64(125), Status: upheld}, 121},
		"past deadline":   {&taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 0), ProofDeadlineHeight: u64(125), Status: awaitingProof}, 125},
	} {
		e := newEnv(t)
		e.put(recordedOrder(t))
		e.challenge(0xc1, tc.state)
		e.block(tc.head)
		if got := e.responds(); len(got) != 0 {
			t.Fatalf("%s: answered %v", name, got)
		}
	}
}

// A ROSTER_UNAVAILABLE challenge is answered with the stored roster of the challenged round, the
// one whose roster_hash the chain's record holds.
func TestRosterUnavailableIsAnsweredWithTheRoundsRoster(t *testing.T) {
	e := newEnv(t)
	o := recordedOrder(t)
	e.put(o)
	e.chainRecord(o)
	cid := e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: self, DispatchRound: u32(1), ProofDeadlineHeight: u64(125), Status: awaitingRoster,
	})
	e.block(121)
	got := e.responds()
	if len(got) != 1 {
		t.Fatalf("%d responses", len(got))
	}
	var roster taskv1.DispatchRosterV1
	if err := proto.Unmarshal(o.Rounds[1].Roster, &roster); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[0].GetChallengeId(), cid) || !proto.Equal(got[0].GetRoster(), &roster) {
		t.Fatalf("response = %v", got[0])
	}
}

// The evidence of an order the chain recorded may not be marked recorded (its write was lost on a
// restart): the roster is matched against the chain's record all the same.
func TestRosterUnavailableIsAnsweredFromUnmarkedEvidence(t *testing.T) {
	e := newEnv(t)
	o := recordedOrder(t)
	o.Recorded, o.RecordedHeight = false, 0
	e.put(o)
	o.RecordedHeight = 115
	e.chainRecord(o)
	e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: self, DispatchRound: u32(0), ProofDeadlineHeight: u64(125), Status: awaitingRoster,
	})
	e.block(121)
	if got := e.responds(); len(got) != 1 || got[0].GetRoster() == nil {
		t.Fatalf("responses = %v", got)
	}
}

// A roster whose hash is not the one the chain's record holds for the round is never sent.
func TestRosterOfAnotherHashIsNotSent(t *testing.T) {
	e := newEnv(t)
	o := recordedOrder(t)
	e.put(o)
	e.chainRecord(o)
	e.chain.records[o.SessionID].Rounds[1].RosterHash = fill(0x55)
	e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: self, DispatchRound: u32(1), ProofDeadlineHeight: u64(125), Status: awaitingRoster,
	})
	e.block(121)
	if got := e.responds(); len(got) != 0 {
		t.Fatalf("answered with a roster the record does not commit: %v", got)
	}
}

// OMISSION, DRAW and DOUBLE_DISPATCH challenges have no answer: they are counted, not followed.
func TestChallengesWithoutAnAnswerAreOnlyCounted(t *testing.T) {
	e := newEnv(t)
	e.put(recordedOrder(t))
	for i, kind := range []sharedv1.DispatchChallengeKindV1{kindOmission, kindDraw, kindDouble} {
		e.challenge(0xc3+byte(i), &taskv1.DispatchChallengeState{Kind: kind, BuilderAddress: self, Status: awaitingProof, ProofDeadlineHeight: u64(125)})
	}
	e.block(121)
	if len(e.responds()) != 0 || len(e.r.openChallenges()) != 0 || e.chain.chalReads != 0 {
		t.Fatal("a challenge without an answer was followed")
	}
	if c := e.r.Counts(); c.UnanswerableChallenges != 3 {
		t.Fatalf("counts = %+v", c)
	}
}

// The resolved event closes an open challenge.
func TestResolvedChallengeIsClosed(t *testing.T) {
	e := newEnv(t)
	cid := e.challenge(0xc1, &taskv1.DispatchChallengeState{Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 0), ProofDeadlineHeight: u64(125), Status: awaitingProof})
	if len(e.r.openChallenges()) != 1 {
		t.Fatal("challenge not open")
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Typed: chaincli.DispatchChallengeResolved{ChallengeID: cid, Kind: kindSkip, Outcome: upheld}})
	if len(e.r.openChallenges()) != 0 {
		t.Fatal("resolved challenge still open")
	}
}

// Expired evidence is pruned on a block, and handraise roots are pruned below the record deadline
// margin except those retained evidence binds.
func TestPruneKeepsReferencedRoots(t *testing.T) {
	e := newEnv(t)
	e.put(recordedOrder(t)) // binds roots 0xd1 and 0xd2
	e.block(200)
	if e.roots.height != 200-testParams.RecordDeadlineBlocks-rootKeepMarginBlocks {
		t.Fatalf("roots pruned below %d", e.roots.height)
	}
	if !e.roots.kept[[32]byte(fill(0xd1))] || !e.roots.kept[[32]byte(fill(0xd2))] || e.roots.kept[[32]byte(fill(0xd9))] {
		t.Fatalf("kept = %v", e.roots.kept)
	}
	// A root an order still dispatching binds is kept too.
	e.live[[32]byte(fill(0xd9))] = true
	e.block(200 + pruneEveryBlocks)
	if !e.roots.kept[[32]byte(fill(0xd9))] {
		t.Fatal("root bound by a dispatching order not kept")
	}
	delete(e.live, [32]byte(fill(0xd9)))
	// Recorded at 115: kept until max(100+60, 115+55) + 100 = 270.
	e.block(270 + pruneEveryBlocks)
	if _, _, found, _ := e.evidence.ByTicket(ticketHash(0, 0)); found {
		t.Fatal("expired evidence kept")
	}
	if e.roots.kept[[32]byte(fill(0xd1))] {
		t.Fatal("root of pruned evidence still kept")
	}
}

// An open challenge keeps the task's evidence until its deadline.
func TestOpenChallengeKeepsItsEvidence(t *testing.T) {
	e := newEnv(t)
	o := recordedOrder(t)
	e.put(o)
	e.chainRecord(o)
	e.challenge(0xc2, &taskv1.DispatchChallengeState{
		Kind: kindRoster, BuilderAddress: self, DispatchRound: u32(1), ProofDeadlineHeight: u64(900), Status: awaitingRoster,
	})
	e.block(121)
	if got, _, _, _ := e.evidence.ByTicket(ticketHash(0, 0)); got.RetainUntil < 900 {
		t.Fatalf("evidence of an open challenge kept until %d", got.RetainUntil)
	}
}
