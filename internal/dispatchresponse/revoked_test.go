package dispatchresponse

import (
	"fmt"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

const (
	heldLog    = "rebuttals and challenge answers held: this Builder's service key is revoked"
	resumedLog = "rebuttals and challenge answers go out again: this Builder's service key signs again"
)

// While this Builder's service key is revoked its service account signs no transaction: a
// rebuttal and a challenge answer are held and tried again every block, logged once for the
// revocation instead of a warning per block, and counted once each. They go out once a
// replacement key signs again.
func TestAnswersAreHeldWhileTheServiceKeyIsRevoked(t *testing.T) {
	e := newEnv(t)
	e.put(evidenceOrder(t, false, []attemptSpec{{op: op7, sent: true, outcome: outcomeTimeout}}))
	e.claim(ticketHash(0, 0), op7, 200)
	o := recordedOrder(t)
	e.put(o)
	e.challenge(0xc1, &taskv1.DispatchChallengeState{
		Kind: kindSkip, BuilderAddress: self, ChallengedTicketHash: ticketHash(0, 0), AttemptRank: u32(0),
		ProofDeadlineHeight: u64(190), Status: awaitingProof,
	})
	e.tx.err = fmt.Errorf("submit MsgRebutDispatchCompensation: txbuild: sign: %w", servicekey.ErrRevoked)
	for h := uint64(151); h < 156; h++ {
		e.block(h)
	}
	if n := len(e.rebuts()) + len(e.responds()); n != 0 {
		t.Fatalf("%d answers sent while revoked", n)
	}
	if n := e.logs.count(heldLog); n != 1 {
		t.Fatalf("held logged %d times, want once", n)
	}
	if n := e.logs.count("compensation rebuttal not sent; tried again next block") + e.logs.count("dispatch challenge response not sent; tried again next block"); n != 0 {
		t.Fatalf("%d per-block warnings while revoked", n)
	}
	if got := e.r.Counts().AnswersHeldRevoked; got != 2 {
		t.Fatalf("answers held = %d, want one per item", got)
	}

	e.tx.err = nil
	e.block(156)
	if len(e.rebuts()) != 1 || len(e.responds()) != 1 {
		t.Fatalf("after the replacement: %d rebuttals, %d responses", len(e.rebuts()), len(e.responds()))
	}
	if n := e.logs.count(resumedLog); n != 1 {
		t.Fatalf("resume logged %d times, want once", n)
	}
}
