package coordinator

import (
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// A Builder that has not received the Worker's receipt does not send the assignment notification.
//
// The Worker's receipt goes to only one Builder; in the other Builders' FSMs output_hash stays
// empty. They still sent notifications when they saw OpenVerifyAccepted from the chain, and the
// Verifier rejected frames with an empty output_hash and kept redelivering until the envelope
// expired. The notification is only an early wake-up; the obligation follows the on-chain
// snapshot, so simply not sending is fine here; local state must still follow the chain into Verifying.
func TestVerifierAssignmentNotifySkippedWithoutOutputHash(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	_, link := enableTestBuilderMessages(c)
	c.submit = &fakeSubmitter{}

	const (
		session = "sess-notify-without-output-hash"
		task    = "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f"
	)
	verifySelect := assignmentCounter{link: link}

	if err := trackTestOrder(c, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, testOperator("worker"), 101)
	// The receipt went to another Builder: no OnInferReceipt locally, output_hash is empty.

	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
		SessionID: session, TaskID: task, Verifiers: verifiers,
		Deadlines: types.Deadlines{Commit: 1, WorkerReveal: 2, Reveal: 3, Verify: 4}, Height: 200,
	})
	if n := verifySelect.count(); n != 0 {
		t.Fatalf("assignment notification sent without output_hash: %d frames", n)
	}
	assertState(t, c, session, task, types.Verifying)
	assertPhase(t, c, session, task, types.PhaseOpenVerify)
}
