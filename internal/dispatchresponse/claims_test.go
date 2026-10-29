package dispatchresponse

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

// A claim on a sent ticket the Worker rejected is rebutted with the record and the Worker's own
// reject, from the service account, within the rebuttal window.
func TestRebutsARejectedTicketWithItsReject(t *testing.T) {
	e := newEnv(t)
	o := evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeRejected}, {op: op1, sent: true, outcome: outcomeTimeout}})
	e.put(o)
	hash := ticketHash(0, 0)
	e.claim(hash, op7, 160)
	e.block(151)
	got := e.rebuts()
	if len(got) != 1 {
		t.Fatalf("%d rebuttals", len(got))
	}
	m := got[0]
	if !bytes.Equal(m.GetDispatchTicketHash(), hash) || m.GetResponderAddress() != responder {
		t.Fatalf("rebuttal = %v", m)
	}
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(o.Record, &rec); err != nil || !proto.Equal(m.GetRecord(), &rec) {
		t.Fatal("rebuttal does not carry the stored record")
	}
	var reject taskv1.DispatchRejectV1
	if err := proto.Unmarshal(o.Rounds[0].Attempts[0].Reject, &reject); err != nil || !proto.Equal(m.GetReject(), &reject) {
		t.Fatal("rebuttal does not carry the Worker's reject as received")
	}
}

// Sent tickets that timed out or were revoked are rebutted with the record alone.
func TestRebutsTimeoutAndRevoked(t *testing.T) {
	for _, outcome := range []taskv1.DispatchAttemptOutcomeV1{outcomeTimeout, outcomeRevoked} {
		e := newEnv(t)
		e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcome}, {op: op1, sent: true, outcome: outcomeTimeout}}))
		e.claim(ticketHash(0, 0), op7, 160)
		e.block(151)
		got := e.rebuts()
		if len(got) != 1 || got[0].Reject != nil || got[0].GetRecord() == nil {
			t.Fatalf("%s: rebuttals %v", outcome, got)
		}
	}
}

// The compensation of an unsent ticket, a VOIDED attempt and the winner is owed: such a claim is
// never rebutted, whatever the claim looks like.
func TestNeverRebutsAnOwedClaim(t *testing.T) {
	for _, spec := range []attemptSpec{
		{op: op7, sent: true, outcome: outcomeVoided},
		{op: op7, sent: true, outcome: outcomeAccepted},
		{op: op7, sent: false, outcome: outcomeTimeout},
		{op: op7, sent: false, outcome: outcomeRejected},
		{op: op7, sent: true, outcome: taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED},
	} {
		e := newEnv(t)
		e.put(evidenceOrder(t, false, []attemptSpec{spec}))
		e.claim(ticketHash(0, 0), op7, 160)
		e.block(151)
		e.block(152)
		if got := e.rebuts(); len(got) != 0 {
			t.Fatalf("sent=%v %s rebutted: %v", spec.sent, spec.outcome, got)
		}
		if n := len(e.r.openClaims()); n != 0 {
			t.Fatalf("sent=%v %s: claim still open", spec.sent, spec.outcome)
		}
	}
}

// A REJECTED attempt is only rebutted with the Worker's reject: without it nothing is sent.
func TestRejectedWithoutItsRejectIsNotRebutted(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeRejected, noReject: true}}))
	e.claim(ticketHash(0, 0), op7, 160)
	e.block(151)
	if got := e.rebuts(); len(got) != 0 {
		t.Fatalf("rebutted without the reject: %v", got)
	}
}

// The stored record must show the same rebuttable outcome as the attempt: a record that shows the
// attempt VOIDED or ACCEPTED is never sent.
func TestRecordShowingAnOwedOutcomeIsNotSent(t *testing.T) {
	for _, shown := range []taskv1.DispatchAttemptOutcomeV1{outcomeVoided, outcomeAccepted} {
		e := newEnv(t)
		e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout, recordOutcome: shown}}))
		e.claim(ticketHash(0, 0), op7, 160)
		e.block(151)
		if got := e.rebuts(); len(got) != 0 {
			t.Fatalf("record showing %s sent: %v", shown, got)
		}
	}
}

// A claim must name the attempt's Worker, this Builder and the order of the evidence.
func TestClaimMustMatchTheEvidence(t *testing.T) {
	for name, change := range map[string]func(*taskv1.DispatchCompensationClaimState){
		"worker":   func(c *taskv1.DispatchCompensationClaimState) { c.WorkerOperatorAddress = op1 },
		"builder":  func(c *taskv1.DispatchCompensationClaimState) { c.BuilderAddress = other },
		"task":     func(c *taskv1.DispatchCompensationClaimState) { c.TaskId = bytes.Repeat([]byte{0xab}, 32) },
		"sequence": func(c *taskv1.DispatchCompensationClaimState) { c.OrderSequence = 4 },
		"session":  func(c *taskv1.DispatchCompensationClaimState) { c.SessionId = bytes.Repeat([]byte{0x02}, 32) },
	} {
		e := newEnv(t)
		e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
		e.claim(ticketHash(0, 0), op7, 160)
		e.setClaim(ticketHash(0, 0), change)
		e.block(151)
		if got := e.rebuts(); len(got) != 0 {
			t.Fatalf("claim with another %s rebutted", name)
		}
	}
}

// Only a claim still PENDING_REBUTTAL and inside its window is rebutted; one of another Builder is
// not followed.
func TestClaimStatusAndWindow(t *testing.T) {
	spec := []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}
	for _, status := range []taskv1.DispatchCompensationClaimStatusV1{statusPaid, statusDismissed} {
		e := newEnv(t)
		e.put(evidenceOrder(t, false, spec))
		e.claim(ticketHash(0, 0), op7, 160)
		e.setClaim(ticketHash(0, 0), func(c *taskv1.DispatchCompensationClaimState) { c.Status = status })
		e.block(151)
		if len(e.rebuts()) != 0 || len(e.r.openClaims()) != 0 {
			t.Fatalf("%s claim rebutted or kept open", status)
		}
	}
	// The rebuttal lands in the next block at the earliest: at the deadline it is too late.
	e := newEnv(t)
	e.put(evidenceOrder(t, false, spec))
	e.claim(ticketHash(0, 0), op7, 160)
	e.block(160)
	if len(e.rebuts()) != 0 || len(e.r.openClaims()) != 0 {
		t.Fatal("claim rebutted after its window")
	}
	// A claim against another Builder is not this Builder's to rebut (no group evidence yet).
	e = newEnv(t)
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Typed: chaincli.DispatchCompensationClaimed{
		TicketHash: ticketHash(0, 0), Builder: other, Worker: op7, RebuttalDeadlineHeight: 160,
	}})
	if len(e.r.openClaims()) != 0 {
		t.Fatal("claim of another Builder followed")
	}
}

// Evidence that is not there yet (being written, or later synced) is looked for again on every
// block until the window closes; an open claim keeps its evidence past its normal retention.
func TestClaimWaitsForItsEvidence(t *testing.T) {
	e := newEnv(t)
	o := evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}})
	e.claim(ticketHash(0, 0), op7, 400)
	e.block(390)
	if len(e.rebuts()) != 0 || len(e.r.openClaims()) != 1 {
		t.Fatal("claim without evidence rebutted or dropped")
	}
	e.put(o)
	e.block(391)
	if len(e.rebuts()) != 1 {
		t.Fatal("claim not rebutted once its evidence arrived")
	}
	if got, _, _, _ := e.evidence.ByTicket(ticketHash(0, 0)); got.RetainUntil < 400 {
		t.Fatalf("evidence of an open claim kept until %d", got.RetainUntil)
	}
}

// A rebuttal sent is not sent again while it may still land; a claim still pending after it
// landed (refused when executed) is rebutted again, and the rebutted event closes it.
func TestRebuttalIsResentOnlyAfterItCouldHaveLanded(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 200)
	e.block(151)
	e.block(152)
	if n := len(e.rebuts()); n != 1 {
		t.Fatalf("%d rebuttals in two blocks", n)
	}
	hash := e.tx.hashes[0]
	e.chain.txResults[string(hash)] = chaincli.TxResult{TxHash: hash, Code: 7, Codespace: "task"}
	e.block(151 + resubmitBlocks)
	if n := len(e.rebuts()); n != 2 {
		t.Fatalf("%d rebuttals after %d blocks", n, resubmitBlocks)
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Typed: chaincli.DispatchCompensationRebutted{
		TicketHash: ticketHash(0, 0), Builder: self, Worker: op7, AttemptOutcome: outcomeTimeout,
	}})
	if len(e.r.openClaims()) != 0 {
		t.Fatal("rebutted claim still open")
	}
}

// A rebuttal that lands without settling the claim (refused when executed) is sent at most
// maxSends times.
func TestRebuttalIsSentAtMostMaxSends(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 400)
	for h := uint64(151); h < 151+10*resubmitBlocks; h++ {
		e.block(h)
	}
	if n := len(e.rebuts()); n != maxSends {
		t.Fatalf("%d rebuttals, want %d", n, maxSends)
	}
}

// A rebuttal's gas grows with its encoded size.
func TestRebuttalGasFollowsItsSize(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeRejected}}))
	e.claim(ticketHash(0, 0), op7, 400)
	e.block(151)
	got := e.rebuts()
	if len(got) != 1 {
		t.Fatalf("%d rebuttals", len(got))
	}
	if want := uint64(testGasBase + testGasPerByte*proto.Size(got[0])); e.tx.gas[0] != want {
		t.Fatalf("gas %d, want %d", e.tx.gas[0], want)
	}
}

// A rebuttal that ran out of gas goes again with twice the gas, up to eight times the first, and
// such a send does not count against maxSends; out of gas at the cap counts.
func TestOutOfGasRebuttalGoesAgainWithMoreGas(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 400)
	for h := uint64(151); h < 151+20*resubmitBlocks; h++ {
		e.block(h)
		e.tx.mu.Lock()
		for _, hash := range e.tx.hashes {
			e.chain.txResults[string(hash)] = chaincli.TxResult{TxHash: hash, Code: 11, Codespace: "sdk"}
		}
		e.tx.mu.Unlock()
	}
	g := e.tx.gas[0]
	if want := []uint64{g, 2 * g, 4 * g, 8 * g, 8 * g, 8 * g}; !reflect.DeepEqual(e.tx.gas, want) {
		t.Fatalf("gas = %v, want %v", e.tx.gas, want)
	}
}

// A rebuttal whose transaction is not found yet (not in a block) is looked up again after another
// resubmitBlocks before anything is sent; an out-of-gas result found then still doubles the gas.
func TestRebuttalNotFoundYetIsLookedUpAgain(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 400)
	e.block(151)
	e.block(151 + resubmitBlocks)
	if n := len(e.rebuts()); n != 1 {
		t.Fatalf("%d rebuttals while the first was not found yet", n)
	}
	hash := e.tx.hashes[0]
	e.chain.txResults[string(hash)] = chaincli.TxResult{TxHash: hash, Code: 11, Codespace: "sdk"}
	e.block(151 + 2*resubmitBlocks)
	if len(e.tx.gas) != 2 || e.tx.gas[1] != 2*e.tx.gas[0] {
		t.Fatalf("gas = %v", e.tx.gas)
	}
}

// A failed submission is tried again at the next block.
func TestFailedRebuttalIsRetried(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 200)
	e.tx.err = errors.New("node unreachable")
	e.block(151)
	e.tx.err = nil
	e.block(152)
	if n := len(e.rebuts()); n != 1 {
		t.Fatalf("%d rebuttals after a failed one", n)
	}
}

// Open claims survive a restart.
func TestOpenClaimsSurviveARestart(t *testing.T) {
	e := newEnv(t)
	e.claim(ticketHash(0, 0), op7, 200)
	e.open()
	if len(e.r.openClaims()) != 1 {
		t.Fatal("open claim lost across a restart")
	}
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.block(151)
	if len(e.rebuts()) != 1 {
		t.Fatal("restored claim not rebutted")
	}
}

// After a gap in the role stream every claimable ticket the evidence could rebut is looked up on
// chain; tickets whose compensation is owed are not even asked about.
func TestResyncRechecksClaims(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{
		{op: op7, sent: true, outcome: outcomeTimeout},
		{op: op1, sent: false, outcome: outcomeTimeout},
		{op: op3, sent: true, outcome: outcomeVoided},
	}))
	// A claim filed during the gap: its event never arrived.
	e.chain.claims[string(ticketHash(0, 0))] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: ticketHash(0, 0), TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: self,
		WorkerOperatorAddress: op7, Status: statusPending, RebuttalDeadlineHeight: 170,
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(151)
	if got := e.chain.claimReads; len(got) == 0 || got[0] != hexOf(ticketHash(0, 0)) {
		t.Fatalf("claim reads %v", got)
	}
	for _, read := range e.chain.claimReads {
		if read == hexOf(ticketHash(0, 1)) || read == hexOf(ticketHash(0, 2)) {
			t.Fatalf("owed ticket %s asked about", read[:8])
		}
	}
	if len(e.rebuts()) != 1 {
		t.Fatal("claim of the gap not rebutted")
	}
}

// Evidence past every claim window is not asked about on a resync.
func TestResyncSkipsClosedClaimWindows(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(100 + 20 + 30 + 10 + 1)
	if len(e.chain.claimReads) != 0 {
		t.Fatalf("closed claim windows asked about: %v", e.chain.claimReads)
	}
}

// A claim cannot be filed before its ticket's record deadline passed: such tickets are not asked
// about on a resync.
func TestResyncSkipsClaimWindowsNotOpenYet(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(100 + 20)
	if len(e.chain.claimReads) != 0 {
		t.Fatalf("claims asked about before their window: %v", e.chain.claimReads)
	}
	// Once the record deadline passed, the next resync asks.
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(100 + 20 + e.r.recheckSpacing())
	if len(e.chain.claimReads) != 1 {
		t.Fatalf("claim reads %v", e.chain.claimReads)
	}
}

// Resyncs closer together than recheckSpacing are folded into one.
func TestResyncIsRateLimited(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(130)
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(131)
	if len(e.chain.claimReads) != 1 {
		t.Fatalf("claim reads %v after two close resyncs", e.chain.claimReads)
	}
	e.block(130 + e.r.recheckSpacing())
	if len(e.chain.claimReads) != 2 {
		t.Fatalf("deferred resync not done: %v", e.chain.claimReads)
	}
}

// A resync held back by the rate limit still comes in time to rebut a claim filed during the gap:
// resyncs are spaced at most half the rebuttal window apart.
func TestDeferredResyncDoesNotMissAClaim(t *testing.T) {
	e := newEnv(t) // rebuttal window 10 blocks
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	e.block(130)
	// A claim filed at 131 while the stream was down; its event is lost.
	e.chain.claims[string(ticketHash(0, 0))] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: ticketHash(0, 0), TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: self,
		WorkerOperatorAddress: op7, Status: statusPending, ClaimedHeight: 131, RebuttalDeadlineHeight: 141,
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRoleResync})
	for h := uint64(132); h <= 140; h++ {
		e.block(h)
	}
	if len(e.rebuts()) != 1 {
		t.Fatal("claim of the gap missed by a deferred resync")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
