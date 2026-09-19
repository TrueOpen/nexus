// Regression cases for gh #42 acceptance 4/6: now that Task identity is unified on the canonical
// task_hash, "the same candidate hash throughout" must be an executable assertion rather than a
// verbal agreement.
//
// This covers the four fail-closed situations the issue names:
//  1. a hand-raise carrying the wrong candidate hash;
//  2. different hashes mixed inside a single proposal;
//  3. a hand-raise bound to a stale RBF version (an older quote version of the same task_id);
//  4. the envelope's payload digest passed off as the task_hash.
package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

// TestWorkerHandraiseWithForeignTaskHashIsDropped covers situations 1, 3 and 4: when the task_hash
// a hand-raise declares does not match the candidate identity of this broadcast, it never even
// reaches f.workerHR, let alone reaches the minimum that would trigger a submission.
func TestWorkerHandraiseWithForeignTaskHashIsDropped(t *testing.T) {
	session := "sess-foreign-hash"
	task := testTaskID("task-foreign-hash")
	order := testCurrentOrder(session, task, testUserAddress)

	// A stale RBF version: another quote version of the same task_id with a different
	// order_sequence, hence a different task_hash. This is exactly the criterion by which an old
	// hand-raise drops out after an RBF replacement.
	staleOrder := proto.Clone(testSignedOrder(testUserAddress)).(*taskv1.SignedOrderV2)
	staleOrder.Order.OrderSequence++
	staleHashRaw, err := nodecontract.TaskOrderHashHexV2(staleOrder.GetOrder())
	if err != nil {
		t.Fatalf("stale task order hash: %v", err)
	}
	if staleHashRaw == order.TaskHash {
		t.Fatal("a changed order_sequence produced the same task_hash: RBF versions are not distinguished by identity")
	}

	// The envelope's payload digest passed off as the task_hash: structurally valid (32 bytes of
	// hex), but it can never equal the result of H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V2", ...).
	envelopeDigest := sha256.Sum256([]byte(order.OrderEnvelope))

	cases := map[string][]byte{
		"wrong candidate hash":       mustHex32(testHash32("some-other-order")),
		"stale rbf version":          mustHex32(staleHashRaw),
		"envelope digest as taskish": envelopeDigest[:],
		"empty":                      nil,
	}
	for name, taskHash := range cases {
		t.Run(name, func(t *testing.T) {
			sub := &fakeSubmitter{}
			c, _ := newTestCoordinator(t)
			c.submit = sub
			if err := c.OnOrder(context.Background(), order); err != nil {
				t.Fatalf("OnOrder: %v", err)
			}
			fsm, ok := c.getFSM(session, task)
			if !ok {
				t.Fatal("task FSM was not created")
			}
			for _, candidate := range []string{testOperator("foreign-a"), testOperator("foreign-b"), testOperator("foreign-c")} {
				handraise := testWorkerHandraise(session, task, candidate)
				handraise.TaskHash = taskHash
				fsm.onWorkerHandraise(handraise)
			}
			fsm.mu.Lock()
			collected := len(fsm.workerHR)
			fsm.mu.Unlock()
			if collected != 0 {
				t.Fatalf("%s: accepted %d hand-raises with a mismatched task_hash", name, collected)
			}
			sub.mu.Lock()
			defer sub.mu.Unlock()
			if len(sub.assign) != 0 {
				t.Fatalf("%s: submitted %d AssignTx", name, len(sub.assign))
			}
		})
	}
}

// TestCanonicalWorkerHandraisesRejectsMixedTaskHash covers situation 2: mixing different task_hash
// values inside a single proposal must fail while the canonical set is being assembled; the chain
// must not be relied on as a fallback.
func TestWorkerAssignmentFactsRejectMixedTaskHash(t *testing.T) {
	session := "sess-mixed"
	task := testTaskID("task-mixed")
	first := testWorkerHandraise(session, task, testOperator("mixed-a"))
	second := testWorkerHandraise(session, task, testOperator("mixed-b"))
	second.TaskHash = mustHex32(testHash32("a-different-order-version"))

	if _, err := workerAssignmentFactsFrom(map[string]*taskv1.WorkerHandraiseV1{
		first.GetMember().GetOperatorAddress():  first,
		second.GetMember().GetOperatorAddress(): second,
	}); err == nil {
		t.Fatal("mixing different task_hash values inside a single proposal was accepted")
	}
}

// TestSubmitAssignRejectsHandraisesThatDoNotMatchScope is the last gate before the chain
// (validateScopeTaskHash): even if a hand-raise was admitted at the FSM layer, it is never sent as
// long as it does not match the order version bound to the proposal scope. This path holds for both
// scope branches.
func TestSubmitAssignRejectsHandraisesThatDoNotMatchScope(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	newSubmitter := func() (*captureChain, Submitter) {
		chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
		return chain, NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
			ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
		})
	}

	t.Run("signed_order scope", func(t *testing.T) {
		chain, sub := newSubmitter()
		handraises := testWorkerHandraises(sg.Address())
		// Change only one: all the others stay correct, proving the gate compares every entry rather
		// than sampling.
		handraises[1].TaskHash = bytes.Repeat([]byte{0x77}, 32)
		if _, err := sub.SubmitAssign(context.Background(), chaincli.AssignTx{
			SignedOrder: testSignedOrder(sg.Address()), WorkerHandraises: handraises, Submitter: sg.Address(),
		}); err == nil {
			t.Fatal("a hand-raise whose task_hash does not match signed_order was submitted")
		}
		if len(chain.broadcast) != 0 {
			t.Fatalf("broadcast=%d, want 0", len(chain.broadcast))
		}
	})

	t.Run("existing_task scope", func(t *testing.T) {
		chain, sub := newSubmitter()
		accepted := bytes.Repeat([]byte{0xab}, 32)
		if _, err := sub.SubmitAssign(context.Background(), chaincli.AssignTx{
			ExistingTask: &taskv1.ExistingTaskRefV1{
				TaskId: bytes.Repeat([]byte{0x66}, 32), TaskHash: accepted,
			},
			WorkerHandraises: testWorkerHandraises(sg.Address()),
			Submitter:        sg.Address(),
		}); err == nil {
			t.Fatal("a hand-raise whose task_hash does not match the on-chain accepted_task_hash was submitted")
		}
		if len(chain.broadcast) != 0 {
			t.Fatalf("broadcast=%d, want 0", len(chain.broadcast))
		}
	})

	t.Run("existing_task scope accepts the authoritative hash", func(t *testing.T) {
		chain, sub := newSubmitter()
		handraises := testWorkerHandraises(sg.Address())
		accepted := append([]byte(nil), handraises[0].GetTaskHash()...)
		if _, err := sub.SubmitAssign(context.Background(), chaincli.AssignTx{
			ExistingTask: &taskv1.ExistingTaskRefV1{
				TaskId: bytes.Repeat([]byte{0x66}, 32), TaskHash: accepted,
			},
			WorkerHandraises: handraises,
			Submitter:        sg.Address(),
		}); err != nil {
			t.Fatalf("SubmitAssign: %v", err)
		}
		if len(chain.broadcast) != 1 {
			t.Fatalf("broadcast=%d, want 1", len(chain.broadcast))
		}
	})
}
