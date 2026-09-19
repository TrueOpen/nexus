package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

// seqChain is a programmable chain fake: it records the number of AccountInfo queries and the
// sequence of each broadcast, and can inject CheckTx results / broadcast errors by script.
type seqChain struct {
	chaincli.Client
	accQueries int
	accSeq     uint64 // sequence returned by AccountInfo (tests may change it to simulate external consumption)
	broadcasts []uint64
	results    []chaincli.TxResult // popped in order; returns Code 0 once exhausted
	errs       []error             // aligned with results; nil = no error
}

func (c *seqChain) AccountInfo(_ context.Context, _ string) (chaincli.AccountInfo, error) {
	c.accQueries++
	return chaincli.AccountInfo{AccountNumber: 7, Sequence: c.accSeq}, nil
}

func (c *seqChain) BroadcastTx(_ context.Context, tx []byte) (chaincli.TxResult, error) {
	var raw txv1beta1.TxRaw
	if err := proto.Unmarshal(tx, &raw); err != nil {
		return chaincli.TxResult{}, err
	}
	var auth txv1beta1.AuthInfo
	if err := proto.Unmarshal(raw.AuthInfoBytes, &auth); err != nil {
		return chaincli.TxResult{}, err
	}
	c.broadcasts = append(c.broadcasts, auth.SignerInfos[0].Sequence)

	if len(c.results) > 0 {
		res, err := c.results[0], c.errs[0]
		c.results, c.errs = c.results[1:], c.errs[1:]
		return res, err
	}
	return chaincli.TxResult{Code: 0}, nil
}

func (c *seqChain) push(res chaincli.TxResult, err error) {
	c.results = append(c.results, res)
	c.errs = append(c.errs, err)
}

func newSeqSubmitter(t *testing.T, chain chaincli.Client) (Submitter, string) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000}), sg.Address()
}

// sequenceAssign builds a MsgSubmitWorkerHandraises proposal whose only
// chain-visible data is the scope oneof, the signed handraises and the
// submitter (Keeper Interface Contract §4.2.1).
func sequenceAssign(address, taskID string) chaincli.AssignTx {
	return chaincli.AssignTx{
		SessionID: "sess-1", TaskID: taskID,
		SignedOrder:      testSignedOrder(address),
		WorkerHandraises: testWorkerHandraises(address),
		Submitter:        address,
	}
}

// TestSequenceCachedAcrossSubmits consecutive submits query the account only once; the sequence increments locally.
func TestSequenceCachedAcrossSubmits(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, address := newSeqSubmitter(t, chain)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t")); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	if chain.accQueries != 1 {
		t.Fatalf("account queried %d times, want 1 (cached)", chain.accQueries)
	}
	if len(chain.broadcasts) != 3 || chain.broadcasts[0] != 42 || chain.broadcasts[1] != 43 || chain.broadcasts[2] != 44 {
		t.Fatalf("broadcast sequences = %v, want [42 43 44]", chain.broadcasts)
	}
}

// TestSequenceMismatchRefreshesAndRetries sequence conflict (code 32) -> refresh account -> replay once with the new sequence.
func TestSequenceMismatchRefreshesAndRetries(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, address := newSeqSubmitter(t, chain)
	ctx := context.Background()

	// First tx is normal (seq 42 consumed, local cache 43).
	if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t1")); err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	// On-chain sequence taken to 50 by an external tool; next tx uses local 43 -> conflict -> refresh -> replay with 50 succeeds.
	chain.accSeq = 50
	chain.push(chaincli.TxResult{Code: 32, RawLog: "account sequence mismatch, expected 50, got 43"}, nil)

	res, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t2"))
	if err != nil || res.Code != 0 {
		t.Fatalf("submit 2: res=%+v err=%v", res, err)
	}
	if chain.accQueries != 2 {
		t.Fatalf("account queried %d times, want 2 (initial + refresh)", chain.accQueries)
	}
	want := []uint64{42, 43, 50}
	if len(chain.broadcasts) != 3 || chain.broadcasts[1] != want[1] || chain.broadcasts[2] != want[2] {
		t.Fatalf("broadcast sequences = %v, want %v", chain.broadcasts, want)
	}

	// After the successful replay the cache continues at 51, no further account query.
	if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t3")); err != nil {
		t.Fatalf("submit 3: %v", err)
	}
	if chain.accQueries != 2 || chain.broadcasts[len(chain.broadcasts)-1] != 51 {
		t.Fatalf("queries=%d last_seq=%d, want 2/51", chain.accQueries, chain.broadcasts[len(chain.broadcasts)-1])
	}
}

// TestSequenceNetworkErrorInvalidatesCache broadcast network error -> unknown whether consumed -> next submit refreshes first.
func TestSequenceNetworkErrorInvalidatesCache(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, address := newSeqSubmitter(t, chain)
	ctx := context.Background()

	chain.push(chaincli.TxResult{}, errors.New("connection refused"))
	if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t1")); err == nil {
		t.Fatal("want broadcast error")
	}

	// Assume that tx actually made it into a block (on-chain sequence is now 43).
	chain.accSeq = 43
	if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t2")); err != nil {
		t.Fatalf("submit after error: %v", err)
	}
	if chain.accQueries != 2 {
		t.Fatalf("account queried %d times, want 2 (cache invalidated)", chain.accQueries)
	}
	if last := chain.broadcasts[len(chain.broadcasts)-1]; last != 43 {
		t.Fatalf("last broadcast seq = %d, want refreshed 43", last)
	}
}

// TestSequenceOtherRejectionKeepsCache non-sequence CheckTx rejection (e.g. same stage already submitted by someone else):
// surfaced as an error (the state machine resets the per-stage dedup flag on it); sequence not consumed,
// cache unchanged, no increment, no retry.
func TestSequenceOtherRejectionKeepsCache(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, address := newSeqSubmitter(t, chain)
	ctx := context.Background()

	chain.push(chaincli.TxResult{Code: 5, RawLog: "stage already submitted"}, nil)
	res, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t1"))
	if err == nil || res.Code != 5 {
		t.Fatalf("res=%+v err=%v, want code 5 surfaced as error", res, err)
	}
	// Next tx still uses 42 (not consumed) and does not re-query the account.
	if _, err := sub.SubmitAssign(ctx, sequenceAssign(address, "t2")); err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	if chain.accQueries != 1 {
		t.Fatalf("account queried %d times, want 1", chain.accQueries)
	}
	if want := []uint64{42, 42}; chain.broadcasts[0] != want[0] || chain.broadcasts[1] != want[1] {
		t.Fatalf("broadcast sequences = %v, want %v", chain.broadcasts, want)
	}
}
