package coordinator

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Submitting the receipt on-chain must not wait for Verifier hand-raises.
//
// MsgSubmitInferReceipt carries only the receipt and the submitter, no hand-raise list; hand-raises
// go separately via MsgSubmitVerifierHandraises. And the chain accepting this receipt is exactly the
// step that "freezes the VERIFIER eligibility bitmap and the whole verification clock", i.e. the
// precondition for a Verifier candidate to read the authoritative snapshot.
//
// Blocking the other way round is a deadlock: the Verifier must read the on-chain receipt before
// raising its hand, while the receipt waits for hand-raises. Local integration stalled exactly here
// at the verification phase -- the Verifier received OPEN_VERIFY but found no receipt on-chain.
func TestInferReceiptGoesOnChainWithoutWaitingForVerifierHandraises(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := &fakeSubmitter{}

	workerService, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("worker service signer: %v", err)
	}
	winner := workerService.Address()

	c := New(log, chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		testBuilderSelf, testChainID)
	enableTestBuilderMessages(c)
	c.submit = fake

	const (
		session = "sess-chain-first"
		task    = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d"
	)
	outputHashSum := sha256.Sum256([]byte("canonical output"))
	outputHash := outputHashSum[:]

	ctx := context.Background()
	if err := trackTestOrder(c, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("trackTestOrder: %v", err)
	}
	recordTestWinner(c, session, task, winner, 101)

	receipt := testInferReceipt(session, task, winner, outputHash)
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(receipt)
	if err != nil {
		t.Fatalf("derive receipt digest: %v", err)
	}
	receipt.InferReceiptHash = digest[:]
	signature, err := workerService.Sign(digest[:])
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	receipt.WorkerServiceSignature = signature

	if err := c.OnInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.openVerify) != 1 {
		t.Fatalf("OpenVerifyTx submitted %d times, want 1 -- the receipt must go on-chain even without Verifier hand-raises", len(fake.openVerify))
	}
	if fake.openVerify[0].InferReceipt == nil {
		t.Fatal("submitted tx carries no receipt")
	}
}
