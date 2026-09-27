package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/types"
)

// txChainFake answers block result queries by tx hash and holds the Verifier commits and
// receipts "already on chain".
type txChainFake struct {
	mu        sync.Mutex
	results   map[string]chaincli.TxResult // absent: not in a block
	queries   map[string]int
	gate      chan struct{} // when set, QueryTx waits for it to close
	entered   chan struct{} // receives one value per QueryTx call when set
	commits   map[string]chaincli.AcceptedVerifyCommit
	receipts  map[string]chaincli.AcceptedResultReceipt
	lookupErr error
}

func newTxChainFake() *txChainFake {
	return &txChainFake{
		results: make(map[string]chaincli.TxResult), queries: make(map[string]int),
		commits: make(map[string]chaincli.AcceptedVerifyCommit), receipts: make(map[string]chaincli.AcceptedResultReceipt),
	}
}

func (f *txChainFake) QueryTx(_ context.Context, txHash []byte) (chaincli.TxResult, error) {
	f.mu.Lock()
	f.queries[string(txHash)]++
	gate, entered := f.gate, f.entered
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	result, ok := f.results[string(txHash)]
	if !ok {
		return chaincli.TxResult{}, chaincli.ErrNotFound
	}
	result.TxHash = txHash
	return result, nil
}

func (f *txChainFake) setResult(txHash string, result chaincli.TxResult) {
	f.mu.Lock()
	f.results[txHash] = result
	f.mu.Unlock()
}

func (f *txChainFake) queryCount(txHash string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[txHash]
}

func (f *txChainFake) QueryVerifyCommit(_ context.Context, _ string, _ uint32, verifier string) (chaincli.AcceptedVerifyCommit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return chaincli.AcceptedVerifyCommit{}, f.lookupErr
	}
	commit, ok := f.commits[verifier]
	if !ok {
		return chaincli.AcceptedVerifyCommit{}, chaincli.ErrNotFound
	}
	return commit, nil
}

func (f *txChainFake) QueryResultReceipt(_ context.Context, _ string, _ uint32, verifier string) (chaincli.AcceptedResultReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return chaincli.AcceptedResultReceipt{}, f.lookupErr
	}
	receipt, ok := f.receipts[verifier]
	if !ok {
		return chaincli.AcceptedResultReceipt{}, chaincli.ErrNotFound
	}
	return receipt, nil
}

// confirmSubmitter hands out one tx hash per broadcast, "<kind>-<n>", and can refuse a kind at
// CheckTx. Broadcasts that pass are recorded by the embedded fakeSubmitter.
type confirmSubmitter struct {
	*fakeSubmitter
	hashMu  sync.Mutex
	counts  map[string]int
	refusal map[string]*SubmissionError
}

func newConfirmSubmitter() *confirmSubmitter {
	return &confirmSubmitter{fakeSubmitter: &fakeSubmitter{}, counts: make(map[string]int), refusal: make(map[string]*SubmissionError)}
}

func (s *confirmSubmitter) next(kind string) (chaincli.TxResult, error) {
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if refusal := s.refusal[kind]; refusal != nil {
		return refusal.Result, refusal
	}
	s.counts[kind]++
	return chaincli.TxResult{TxHash: []byte(fmt.Sprintf("%s-%d", kind, s.counts[kind]))}, nil
}

func (s *confirmSubmitter) refuse(kind string, result chaincli.TxResult) {
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if result.Code == 0 {
		delete(s.refusal, kind)
		return
	}
	s.refusal[kind] = &SubmissionError{Phase: SubmissionBroadcast, Definitive: true, Result: result,
		Err: fmt.Errorf("rejected by CheckTx (code %d)", result.Code)}
}

func (s *confirmSubmitter) broadcasts(kind string) int {
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	return s.counts[kind]
}

func (s *confirmSubmitter) SubmitOpenVerify(ctx context.Context, tx chaincli.OpenVerifyTx) (chaincli.TxResult, error) {
	s.fakeSubmitter.SubmitOpenVerify(ctx, tx)
	return s.next("receipt")
}

func (s *confirmSubmitter) SubmitVerifyCommit(ctx context.Context, tx chaincli.VerifyCommitTx) (chaincli.TxResult, error) {
	res, err := s.next("commit")
	if err == nil {
		s.fakeSubmitter.SubmitVerifyCommit(ctx, tx)
	}
	return res, err
}

func (s *confirmSubmitter) SubmitVerifyResult(ctx context.Context, tx chaincli.VerifyResultTx) (chaincli.TxResult, error) {
	res, err := s.next("result")
	if err == nil {
		s.fakeSubmitter.SubmitVerifyResult(ctx, tx)
	}
	return res, err
}

func (s *confirmSubmitter) SubmitSettle(ctx context.Context, tx chaincli.SettleTx) (chaincli.TxResult, error) {
	s.fakeSubmitter.SubmitSettle(ctx, tx)
	return s.next("settle")
}

// logSink collects JSON log records written concurrently.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// find returns the records at level whose message contains text.
func (s *logSink) find(t *testing.T, level, text string) []map[string]any {
	t.Helper()
	s.mu.Lock()
	raw := s.buf.String()
	s.mu.Unlock()
	var found []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var record map[string]any
		if line == "" || json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		if record["level"] == level && strings.Contains(fmt.Sprint(record["msg"]), text) {
			found = append(found, record)
		}
	}
	return found
}

// newConfirmCoordinator builds a coordinator that reads block results from a txChainFake, with a
// relay wait of 10 intervals of 2 ms.
func newConfirmCoordinator(t *testing.T, self string) (*Coordinator, *confirmSubmitter, *txChainFake, *logSink) {
	t.Helper()
	sink := &logSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
	chain := newTxChainFake()
	c := New(log, msgbus.NewStub(log, nil), chaincli.NewStub(log, config.ChainConfig{}), relay.NewMem(log), kv.NewMemStore(),
		self, testChainID, WithTxQuerier(chain), WithTxConfirmPolicy(TxConfirmPolicy{BlockInterval: 2 * time.Millisecond, WaitBlocks: 10}))
	c.verifyState = chain
	enableTestBusEnvelopes(c)
	sub := newConfirmSubmitter()
	c.submit = sub
	return c, sub, chain, sink
}

// signedShapeVerifyResult is testVerifyResult with every field its signing digest covers, so
// it can be compared with the digest the chain stores.
func signedShapeVerifyResult(task, verifier string, vals [][]byte) *taskv1.ResultReceiptV3 {
	vr := testVerifyResult(task, verifier, vals)
	vr.AggregateProofHash = bytes.Repeat([]byte{0xa1}, 32)
	vr.VerifierValueRoot = bytes.Repeat([]byte{0xa2}, 32)
	vr.VerifierEvidenceKeyCommitment = make([]byte, 32)
	return vr
}

func verifyCommitRecorded(c *Coordinator, session, task, verifier string) bool {
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	_, ok := fsm.verifyCommits[verifier]
	return ok
}

func verifyResultRecorded(c *Coordinator, session, task, verifier string) bool {
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	_, ok := fsm.verifyResults[verifier]
	return ok
}

// A commit or result relay answers from the block result: executed → recorded and acknowledged;
// refused by a chain module → invalid; refused otherwise → temporary; no result within the wait
// → temporary. Only an executed one is recorded.
func TestVerifyRelayRecordsOnlyWhatTheBlockExecuted(t *testing.T) {
	c, _, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-relay-block"
	task := testTaskID("relay-block")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	ctx := context.Background()

	chain.setResult("commit-1", chaincli.TxResult{Height: 50})
	ack, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[0]))
	if err != nil || ack.Idempotent || string(ack.TxHash) != "commit-1" || !verifyCommitRecorded(c, session, task, verifiers[0]) {
		t.Fatalf("executed commit: ack = %+v, err = %v", ack, err)
	}

	chain.setResult("commit-2", chaincli.TxResult{Code: 1150, Codespace: "task", RawLog: "invalid commit signature"})
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("refused by the task module: err = %v, want invalid", err)
	}
	chain.setResult("commit-3", chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"})
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, errRelayTemporary) ||
		errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("refused by sdk: err = %v, want temporary", err)
	}
	// commit-4 never reaches a block.
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, errRelayUnconfirmed) ||
		errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("no block result: err = %v, want temporary", err)
	}
	if verifyCommitRecorded(c, session, task, verifiers[1]) {
		t.Fatal("a commit the chain does not hold was recorded")
	}
	if len(sink.find(t, "WARN", "tx failed in block execution")) != 2 {
		t.Fatal("each block execution failure must be logged once at WARN")
	}

	vals := [][]byte{[]byte("v0"), []byte("v1")}
	chain.setResult("result-1", chaincli.TxResult{Height: 51})
	if ack, err := c.OnVerifyResult(ctx, session, task, testVerifyResult(task, verifiers[0], vals)); err != nil ||
		string(ack.TxHash) != "result-1" || !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatalf("executed result: ack = %+v, err = %v", ack, err)
	}
	chain.setResult("result-2", chaincli.TxResult{Code: 111222, Codespace: "undefined", RawLog: "panic: " + strings.Repeat("x", 4096)})
	if _, err := c.OnVerifyResult(ctx, session, task, testVerifyResult(task, verifiers[1], vals)); !errors.Is(err, errRelayTemporary) {
		t.Fatalf("recovered panic: err = %v, want temporary", err)
	}
	for _, record := range sink.find(t, "WARN", "tx failed in block execution") {
		if logged := fmt.Sprint(record["raw_log"]); len(logged) > chaincli.RawLogLimit {
			t.Fatalf("raw_log logged with %d bytes", len(logged))
		}
	}
	// The JetStream path: a temporary failure is redelivered, a refusal of the content is dropped.
	fsm, _ := c.getFSM(session, task)
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[1], vals)); err == nil {
		t.Fatal("a result without a block result was acknowledged on the bus")
	}
	chain.setResult("result-4", chaincli.TxResult{Code: 1160, Codespace: "task", RawLog: "bad metric root"})
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[1], vals)); err != nil {
		t.Fatalf("a result refused by the task module must be dropped, got %v", err)
	}
	if verifyResultRecorded(c, session, task, verifiers[1]) {
		t.Fatal("a result the chain does not hold was recorded")
	}
}

// While a relay waits for its block result the task lock is free: other operations run, other
// Verifiers relay, an identical resubmission shares the outcome without a second broadcast, and
// different content from the same Verifier is refused at once.
func TestVerifyRelayWaitDoesNotHoldTheTask(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-relay-wait"
	task := testTaskID("relay-wait")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	ctx := context.Background()
	chain.mu.Lock()
	chain.gate, chain.entered = make(chan struct{}), make(chan struct{}, 16)
	chain.mu.Unlock()
	chain.setResult("commit-1", chaincli.TxResult{Height: 60})
	chain.setResult("commit-2", chaincli.TxResult{Height: 60})

	type outcome struct {
		ack types.VerifyRelayAck
		err error
	}
	relay := func(commit *taskv1.VerifyCommitV1) chan outcome {
		done := make(chan outcome, 1)
		go func() {
			ack, err := c.OnVerifyCommit(ctx, session, task, commit)
			done <- outcome{ack, err}
		}()
		return done
	}
	within := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s blocked behind a relay waiting for its block result", what)
		}
	}

	commit := testVerifyCommit(task, verifiers[0])
	first := relay(commit)
	<-chain.entered // the first relay is waiting for its block result

	fsm, _ := c.getFSM(session, task)
	within("a new block", func() { fsm.onHeight(70) })
	within("a task status read", func() { _, _ = c.TaskStatus(ctx, session, task) })
	other := relay(testVerifyCommit(task, verifiers[1]))
	<-chain.entered // another Verifier's relay broadcast and waits too

	joined := relay(proto.Clone(commit).(*taskv1.VerifyCommitV1))
	changed := testVerifyCommit(task, verifiers[0])
	changed.CommitHash = bytes.Repeat([]byte{7}, 32)
	within("a conflicting resubmission", func() {
		if _, err := c.OnVerifyCommit(ctx, session, task, changed); !errors.Is(err, types.ErrInvalidArgument) {
			t.Errorf("different content while in flight: err = %v, want conflict", err)
		}
	})
	select {
	case got := <-joined:
		t.Fatalf("identical resubmission answered before the block result: %+v", got)
	case <-time.After(20 * time.Millisecond):
	}

	close(chain.gate)
	firstOutcome, joinedOutcome, otherOutcome := <-first, <-joined, <-other
	if firstOutcome.err != nil || string(firstOutcome.ack.TxHash) != "commit-1" {
		t.Fatalf("first relay: %+v", firstOutcome)
	}
	if joinedOutcome.err != nil || string(joinedOutcome.ack.TxHash) != "commit-1" {
		t.Fatalf("identical resubmission must share the first outcome: %+v", joinedOutcome)
	}
	if otherOutcome.err != nil || string(otherOutcome.ack.TxHash) != "commit-2" {
		t.Fatalf("other verifier: %+v", otherOutcome)
	}
	if sub.broadcasts("commit") != 2 {
		t.Fatalf("broadcasts = %d, want one per verifier", sub.broadcasts("commit"))
	}
	if !verifyCommitRecorded(c, session, task, verifiers[0]) || !verifyCommitRecorded(c, session, task, verifiers[1]) {
		t.Fatal("executed commits were not recorded")
	}
}

// A refusal may mean the Verifier's item is already on chain (a redelivery, a crash before the
// acknowledgement, the Verifier's own submission). The chain's record decides: the same content
// is a success and is recorded, different content is invalid.
func TestVerifyRelayDecidesAlreadyOnChainFromTheChainRecord(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-relay-exists"
	task := testTaskID("relay-exists")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	ctx := context.Background()
	exists := chaincli.TxResult{Code: 1151, Codespace: "task", RawLog: "verify commit already exists"}

	same := testVerifyCommit(task, verifiers[0])
	chain.commits[verifiers[0]] = chaincli.AcceptedVerifyCommit{CommitHash: same.GetCommitHash()}
	chain.setResult("commit-1", exists)
	ack, err := c.OnVerifyCommit(ctx, session, task, same)
	if err != nil || !ack.Idempotent || !verifyCommitRecorded(c, session, task, verifiers[0]) {
		t.Fatalf("same commit on chain: ack = %+v, err = %v", ack, err)
	}

	chain.commits[verifiers[1]] = chaincli.AcceptedVerifyCommit{CommitHash: bytes.Repeat([]byte{9}, 32)}
	chain.setResult("commit-2", exists)
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, types.ErrInvalidArgument) ||
		verifyCommitRecorded(c, session, task, verifiers[1]) {
		t.Fatalf("different commit on chain: err = %v", err)
	}

	// A redelivered result after a crash: CheckTx already refuses it, the chain holds the same receipt.
	vals := [][]byte{[]byte("v0"), []byte("v1")}
	vr := signedShapeVerifyResult(task, verifiers[0], vals)
	digest, err := nodecontract.ResultReceiptSigningDigest(vr)
	if err != nil {
		t.Fatal(err)
	}
	chain.receipts[verifiers[0]] = chaincli.AcceptedResultReceipt{SigningDigest: digest[:]}
	sub.refuse("result", chaincli.TxResult{Code: 1161, Codespace: "task", RawLog: "result receipt already exists"})
	fsm, _ := c.getFSM(session, task)
	if err := fsm.onVerifyResult(vr); err != nil || !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatalf("same receipt on chain: err = %v", err)
	}

	other := signedShapeVerifyResult(task, verifiers[1], [][]byte{[]byte("other")})
	chain.receipts[verifiers[1]] = chaincli.AcceptedResultReceipt{SigningDigest: digest[:]}
	if _, err := c.OnVerifyResult(ctx, session, task, other); !errors.Is(err, types.ErrInvalidArgument) ||
		verifyResultRecorded(c, session, task, verifiers[1]) {
		t.Fatalf("different receipt on chain: err = %v", err)
	}

	// No block result within the wait, but the chain holds the same receipt (it came in another way).
	sub.refuse("result", chaincli.TxResult{})
	third := signedShapeVerifyResult(task, verifiers[2], vals)
	thirdDigest, _ := nodecontract.ResultReceiptSigningDigest(third)
	chain.receipts[verifiers[2]] = chaincli.AcceptedResultReceipt{SigningDigest: thirdDigest[:]}
	if ack, err := c.OnVerifyResult(ctx, session, task, third); err != nil || !ack.Idempotent ||
		!verifyResultRecorded(c, session, task, verifiers[2]) {
		t.Fatalf("unconfirmed but on chain: ack = %+v, err = %v", ack, err)
	}

	// The chain record cannot be read: nothing is decided from the error text, the caller retries.
	chain.mu.Lock()
	chain.lookupErr = errors.New("node unavailable")
	chain.mu.Unlock()
	sub.refuse("commit", exists)
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[2])); !errors.Is(err, errRelayTemporary) {
		t.Fatalf("unreadable chain record: err = %v, want temporary", err)
	}
}

// receiptTask drives a task to Assigned with its receipt broadcast as receipt-1. The infer
// deadline is inferDeadline.
func receiptTask(t *testing.T, c *Coordinator, session, task string, inferDeadline uint64) *taskFSM {
	t.Helper()
	ctx := context.Background()
	if err := c.OnOrder(ctx, testCurrentOrder(session, task, testUserAddress)); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	c.OnAssignAccepted(chaincli.AssignAccepted{SessionID: session, TaskID: task, Height: 1})
	c.OnAssignmentFinalized(chaincli.AssignmentFinalized{SessionID: session, TaskID: task, Winner: "worker-1",
		Height: 2, InferDeadlineHeight: inferDeadline})
	if err := c.OnInferReceipt(ctx, testInferReceipt(session, task, "worker-1", []byte("h"))); err != nil {
		t.Fatalf("OnInferReceipt: %v", err)
	}
	fsm, _ := c.getFSM(session, task)
	return fsm
}

func receiptSubmissions(sub *confirmSubmitter) int {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return len(sub.openVerify)
}

// A receipt refused by a chain module is resubmitted once, then given up with an ERROR.
func TestReceiptRefusedByTheChainIsRetriedOnceThenStops(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-receipt-module"
	task := testTaskID("receipt-module")
	fsm := receiptTask(t, c, session, task, 100)
	refused := chaincli.TxResult{Code: 1138, Codespace: "task", RawLog: "receipt refused: " + strings.Repeat("x", 2048)}
	chain.setResult("receipt-1", refused)

	c.onNewBlock(10)
	c.confirmSubmittedTxs(fsm)
	if receiptSubmissions(sub) != 1 {
		t.Fatal("resubmitted before the backoff")
	}
	c.onNewBlock(11)
	if receiptSubmissions(sub) != 2 {
		t.Fatalf("receipt submissions = %d, want one resubmission", receiptSubmissions(sub))
	}
	chain.setResult("receipt-2", refused)
	c.confirmSubmittedTxs(fsm)
	for height := int64(12); height < 20; height++ {
		c.onNewBlock(height)
		fsm.onVerifierHandraise(testVerifierHandraise(session, task, testOperator("late-verifier"), []byte("h"), []byte("infer-receipt")))
	}
	if receiptSubmissions(sub) != 2 {
		t.Fatalf("receipt submissions = %d after giving up", receiptSubmissions(sub))
	}
	stops := sink.find(t, "ERROR", "MsgSubmitInferReceipt failed on chain; stopped resubmitting")
	if len(stops) != 1 {
		t.Fatalf("ERROR records = %d, want 1", len(stops))
	}
	if stops[0]["code"] != float64(1138) || stops[0]["codespace"] != "task" || stops[0]["task_id"] != task ||
		len(fmt.Sprint(stops[0]["raw_log"])) > chaincli.RawLogLimit {
		t.Fatalf("ERROR record = %v", stops[0])
	}
}

// Temporary failures (a codespace outside the chain modules, or a transaction that never reaches a
// block) are resubmitted with a doubling wait until the infer deadline, then given up.
func TestReceiptTemporaryFailureBacksOffUntilTheDeadline(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-receipt-temporary"
	task := testTaskID("receipt-temporary")
	fsm := receiptTask(t, c, session, task, 20)

	c.onNewBlock(4)
	c.confirmSubmittedTxs(fsm) // receipt-1 not in a block yet
	c.onNewBlock(9)
	c.confirmSubmittedTxs(fsm) // five blocks later still nowhere: dropped, resubmit from 10
	submittedAt := map[int64]int{}
	for height := int64(10); height <= 30; height++ {
		c.onNewBlock(height)
		if n := receiptSubmissions(sub); n > 1+len(submittedAt) {
			submittedAt[height] = n
			chain.setResult(fmt.Sprintf("receipt-%d", n), chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"})
			c.confirmSubmittedTxs(fsm)
		}
	}
	// Failures at 9, 10, 12, 16 are followed by waits of 1, 2, 4 and 8 blocks; the last would end
	// at 24, past the infer deadline 20.
	want := map[int64]int{10: 2, 12: 3, 16: 4}
	if fmt.Sprint(submittedAt) != fmt.Sprint(want) {
		t.Fatalf("resubmitted at %v, want %v", submittedAt, want)
	}
	if len(sink.find(t, "ERROR", "MsgSubmitInferReceipt failed on chain; stopped resubmitting")) != 1 {
		t.Fatal("giving up at the deadline must be logged at ERROR once")
	}
}

// Once the chain shows the receipt accepted, nothing more is queried or resubmitted.
func TestReceiptStopsOnceTheChainAcceptedIt(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-receipt-accepted"
	task := testTaskID("receipt-accepted")
	fsm := receiptTask(t, c, session, task, 100)
	chain.setResult("receipt-1", chaincli.TxResult{Code: 11, Codespace: "sdk", RawLog: "out of gas"})
	c.onNewBlock(10)
	c.confirmSubmittedTxs(fsm) // retry due at 11

	fsm.onInferReceiptAccepted() // another Builder's receipt made it
	for height := int64(11); height < 20; height++ {
		c.onNewBlock(height)
	}
	if receiptSubmissions(sub) != 1 {
		t.Fatalf("receipt resubmitted after the chain accepted one: %d", receiptSubmissions(sub))
	}

	// A receipt still awaiting its block result is no longer queried either.
	c2, _, chain2, _ := newConfirmCoordinator(t, testBuilderSelf)
	fsm2 := receiptTask(t, c2, session, task, 100)
	fsm2.onInferReceiptAccepted()
	c2.confirmSubmittedTxs(fsm2)
	if chain2.queryCount("receipt-1") != 0 {
		t.Fatal("queried a receipt the chain already accepted")
	}
}

// settleTask drives a task to the settlement window with this Builder as the only one selected,
// so every block from the reveal deadline to the verify deadline is open to it.
func settleTask(t *testing.T, c *Coordinator, session, task string, verifyDeadline int64) *taskFSM {
	t.Helper()
	chain := c.txQuery.(*txChainFake)
	chain.setResult("result-1", chaincli.TxResult{Height: 2})
	chain.setResult("result-2", chaincli.TxResult{Height: 2})
	selection := settleSelection(session, task, testBuilderSelf)
	driveToSettleReady(t, c, session, task, &selection)
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.deadlines.Verify = verifyDeadline
	fsm.mu.Unlock()
	return fsm
}

// The settlement is resubmitted only after its block result failed -- not on every block -- and a
// refusal by a chain module is retried once, then given up with an ERROR naming the fallbacks.
func TestSettleRefusedByTheChainIsRetriedOnceThenStops(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-settle-module"
	task := testTaskID("settle-module")
	fsm := settleTask(t, c, session, task, rankVerifyDeadline)

	c.onNewBlock(rankRevealDeadline)
	c.onNewBlock(rankRevealDeadline + 1)
	if settleCount(sub.fakeSubmitter) != 1 {
		t.Fatalf("settle submissions = %d; a settlement awaiting its block result is not resent", settleCount(sub.fakeSubmitter))
	}
	refused := chaincli.TxResult{Code: 1170, Codespace: "task", RawLog: "settlement inputs incomplete"}
	chain.setResult("settle-1", refused)
	c.confirmSubmittedTxs(fsm)
	c.onNewBlock(rankRevealDeadline + 2)
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("settle submissions = %d, want one resubmission", settleCount(sub.fakeSubmitter))
	}
	chain.setResult("settle-2", refused)
	c.confirmSubmittedTxs(fsm)
	for height := int64(rankRevealDeadline + 3); height < rankRevealDeadline+20; height++ {
		c.onNewBlock(height)
	}
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("settle submissions = %d after giving up", settleCount(sub.fakeSubmitter))
	}
	stops := sink.find(t, "ERROR", "Another Builder or the chain's own fallback may still settle the task")
	if len(stops) != 1 || stops[0]["code"] != float64(1170) {
		t.Fatalf("ERROR records = %v", stops)
	}
}

// Temporary settlement failures are resubmitted with a doubling wait until the verify deadline
// that closes the settlement window.
func TestSettleTemporaryFailureBacksOffUntilTheDeadline(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-settle-temporary"
	task := testTaskID("settle-temporary")
	fsm := settleTask(t, c, session, task, 20)

	submittedAt := map[int64]int{}
	for height := int64(rankRevealDeadline); height <= 30; height++ {
		c.onNewBlock(height)
		if n := settleCount(sub.fakeSubmitter); n > len(submittedAt) {
			submittedAt[height] = n
			chain.setResult(fmt.Sprintf("settle-%d", n), chaincli.TxResult{Code: 32, Codespace: "sdk", RawLog: "account sequence mismatch"})
			c.confirmSubmittedTxs(fsm)
		}
	}
	want := map[int64]int{3: 1, 4: 2, 6: 3, 10: 4, 18: 5}
	if fmt.Sprint(submittedAt) != fmt.Sprint(want) {
		t.Fatalf("settle submitted at %v, want %v", submittedAt, want)
	}
	if len(sink.find(t, "ERROR", "MsgSettleTask failed on chain")) != 1 {
		t.Fatal("giving up at the deadline must be logged at ERROR once")
	}
}

// Once the chain shows the task settled, a failed settlement of this Builder is not resubmitted.
func TestSettleStopsOnceTheChainSettled(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-settle-settled"
	task := testTaskID("settle-settled")
	fsm := settleTask(t, c, session, task, rankVerifyDeadline)
	c.onNewBlock(rankRevealDeadline)
	chain.setResult("settle-1", chaincli.TxResult{Code: 1171, Codespace: "task", RawLog: "task already settled"})

	c.OnSettleAccepted(chaincli.SettleAccepted{SessionID: session, TaskID: task, TaskVerdict: types.VerdictPass,
		Settlement: chaincli.TaskSettlementState{SettlementStatus: "SETTLED_PASS", SettlementHeight: 4}, Height: 4})
	c.confirmSubmittedTxs(fsm)
	for height := int64(rankRevealDeadline + 1); height < rankRevealDeadline+10; height++ {
		c.onNewBlock(height)
	}
	if settleCount(sub.fakeSubmitter) != 1 || chain.queryCount("settle-1") != 0 {
		t.Fatalf("settle submissions = %d, queries = %d after the chain settled",
			settleCount(sub.fakeSubmitter), chain.queryCount("settle-1"))
	}
}
