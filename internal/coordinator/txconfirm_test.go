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
	queryErrs map[string]error // QueryTx fails for these hashes
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
	if err := f.queryErrs[string(txHash)]; err != nil {
		return chaincli.TxResult{}, err
	}
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
	refusal map[string]error
}

func newConfirmSubmitter() *confirmSubmitter {
	return &confirmSubmitter{fakeSubmitter: &fakeSubmitter{}, counts: make(map[string]int), refusal: make(map[string]error)}
}

func (s *confirmSubmitter) next(kind string) (chaincli.TxResult, error) {
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if refusal := s.refusal[kind]; refusal != nil {
		var submission *SubmissionError
		if errors.As(refusal, &submission) {
			return submission.Result, refusal
		}
		return chaincli.TxResult{}, refusal
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

// fail makes the next broadcasts of a kind fail with err (nil: succeed again).
func (s *confirmSubmitter) fail(kind string, err error) {
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if err == nil {
		delete(s.refusal, kind)
		return
	}
	s.refusal[kind] = err
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

// Only three cosmos-sdk refusals clear by themselves; every other refusal fails the same way
// again and counts as final.
func TestTemporaryTxFailureClassification(t *testing.T) {
	for _, test := range []struct {
		result    chaincli.TxResult
		temporary bool
	}{
		{chaincli.TxResult{Code: 19, Codespace: "sdk"}, true},  // tx already in mempool cache
		{chaincli.TxResult{Code: 20, Codespace: "sdk"}, true},  // mempool full
		{chaincli.TxResult{Code: 32, Codespace: "sdk"}, true},  // sequence mismatch
		{chaincli.TxResult{Code: 11, Codespace: "sdk"}, false}, // out of gas
		{chaincli.TxResult{Code: 13, Codespace: "sdk"}, false}, // insufficient fee
		{chaincli.TxResult{Code: 111222, Codespace: "undefined"}, false},
		{chaincli.TxResult{Code: 1138, Codespace: "task"}, false},
		{chaincli.TxResult{Code: 32, Codespace: "task"}, false},
		{chaincli.TxResult{Code: 5}, false},
	} {
		if got := temporaryTxFailure(test.result); got != test.temporary {
			t.Errorf("%+v: temporary = %v, want %v", test.result, got, test.temporary)
		}
	}
}

// A unary commit or result relay answers from the block result: executed → recorded and
// acknowledged; refused temporarily (sdk 19/20/32) → temporary; any other refusal → invalid;
// no result within the wait → temporary. Only an executed one is recorded.
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

	refusals := []struct {
		result  chaincli.TxResult
		invalid bool
	}{
		{chaincli.TxResult{Code: 1150, Codespace: "task", RawLog: "invalid commit signature"}, true},
		{chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"}, true},
		{chaincli.TxResult{Code: 11, Codespace: "sdk", RawLog: "out of gas"}, true},
		{chaincli.TxResult{Code: 111222, Codespace: "undefined", RawLog: "panic: " + strings.Repeat("x", 4096)}, true},
		{chaincli.TxResult{Code: 20, Codespace: "sdk", RawLog: "mempool is full"}, false},
		{chaincli.TxResult{Code: 32, Codespace: "sdk", RawLog: "account sequence mismatch"}, false},
	}
	for i, refusal := range refusals {
		chain.setResult(fmt.Sprintf("commit-%d", i+2), refusal.result)
		_, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1]))
		if refusal.invalid && !errors.Is(err, types.ErrInvalidArgument) ||
			!refusal.invalid && (!errors.Is(err, errRelayTemporary) || errors.Is(err, types.ErrInvalidArgument)) {
			t.Fatalf("refusal %+v: err = %v, want invalid = %v", refusal.result, err, refusal.invalid)
		}
	}
	// The next commit never reaches a block.
	if _, err := c.OnVerifyCommit(ctx, session, task, testVerifyCommit(task, verifiers[1])); !errors.Is(err, errRelayUnconfirmed) ||
		errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("no block result: err = %v, want temporary", err)
	}
	if verifyCommitRecorded(c, session, task, verifiers[1]) {
		t.Fatal("a commit the chain does not hold was recorded")
	}
	failures := sink.find(t, "WARN", "tx failed in block execution")
	if len(failures) != len(refusals) {
		t.Fatalf("block execution failures logged = %d, want one each", len(failures))
	}
	for _, record := range failures {
		if logged := fmt.Sprint(record["raw_log"]); len(logged) > chaincli.RawLogLimit {
			t.Fatalf("raw_log logged with %d bytes", len(logged))
		}
	}

	vals := [][]byte{[]byte("v0"), []byte("v1")}
	chain.setResult("result-1", chaincli.TxResult{Height: 51})
	if ack, err := c.OnVerifyResult(ctx, session, task, testVerifyResult(task, verifiers[0], vals)); err != nil ||
		string(ack.TxHash) != "result-1" || !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatalf("executed result: ack = %+v, err = %v", ack, err)
	}
	chain.setResult("result-2", chaincli.TxResult{Code: 1160, Codespace: "task", RawLog: "bad metric root"})
	if _, err := c.OnVerifyResult(ctx, session, task, testVerifyResult(task, verifiers[1], vals)); !errors.Is(err, types.ErrInvalidArgument) ||
		verifyResultRecorded(c, session, task, verifiers[1]) {
		t.Fatalf("refused result: err = %v, want invalid and not recorded", err)
	}
}

// The bus handler does not wait for the block: it broadcasts, acknowledges at once and leaves the
// block result to reconciliation. The result is recorded -- and counted towards settlement -- only
// once reconciliation confirms it; it survives a restart in the snapshot meanwhile.
func TestBusResultIsAcknowledgedAtOnceAndRecordedAfterConfirmation(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-bus-result"
	task := testTaskID("bus-result")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	fsm, _ := c.getFSM(session, task)
	chain.mu.Lock()
	chain.gate = make(chan struct{}) // any block result read in the handler would hang it
	chain.mu.Unlock()

	vals := [][]byte{[]byte("v0"), []byte("v1")}
	done := make(chan error, 1)
	go func() { done <- fsm.onVerifyResult(testVerifyResult(task, verifiers[0], vals)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bus handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the bus handler waited for the block result")
	}
	if chain.queryCount("result-1") != 0 || verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("the handler read the block result or recorded an unconfirmed result")
	}
	// Redelivery of the same result while it is pending: acknowledged, not broadcast again.
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[0], vals)); err != nil || sub.broadcasts("result") != 1 {
		t.Fatalf("redelivery while pending: err = %v, broadcasts = %d", err, sub.broadcasts("result"))
	}
	raw, ok := c.kv.Get(kv.NSTask, taskKey(session, task))
	var snapshot taskSnapshot
	if !ok || json.Unmarshal(raw, &snapshot) != nil || len(snapshot.PendingVerifyResults) != 1 ||
		string(snapshot.PendingVerifyResults[0].TxHash) != "result-1" {
		t.Fatalf("pending result not persisted: %+v", snapshot.PendingVerifyResults)
	}
	close(chain.gate)
	chain.mu.Lock()
	chain.gate = nil
	chain.mu.Unlock()

	c.confirmSubmittedTxs(fsm) // result-1 not in a block yet
	if verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("recorded before the block executed it")
	}
	chain.setResult("result-1", chaincli.TxResult{Height: 70})
	c.confirmSubmittedTxs(fsm)
	if !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("not recorded once the block executed it")
	}

	// A result the block refuses for good is dropped with an ERROR and never recorded.
	chain.setResult("result-2", chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"})
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[1], vals)); err != nil {
		t.Fatalf("bus handler: %v", err)
	}
	c.confirmSubmittedTxs(fsm)
	for height := int64(300); height < 320; height++ {
		c.onNewBlock(height)
	}
	if verifyResultRecorded(c, session, task, verifiers[1]) || sub.broadcasts("result") != 2 {
		t.Fatalf("refused result: recorded = %v, broadcasts = %d", verifyResultRecorded(c, session, task, verifiers[1]),
			sub.broadcasts("result"))
	}

	// A temporary refusal is rebroadcast once its backoff has passed, then confirmed.
	fsm.mu.Lock()
	fsm.deadlines.Reveal = 1000
	fsm.mu.Unlock()
	chain.setResult("result-3", chaincli.TxResult{Code: 20, Codespace: "sdk", RawLog: "mempool is full"})
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[2], vals)); err != nil {
		t.Fatalf("bus handler: %v", err)
	}
	c.confirmSubmittedTxs(fsm) // refused temporarily: rebroadcast from 320
	c.onNewBlock(320)
	if sub.broadcasts("result") != 4 {
		t.Fatalf("broadcasts = %d, want the temporary refusal rebroadcast", sub.broadcasts("result"))
	}
	chain.setResult("result-4", chaincli.TxResult{Height: 321})
	c.confirmSubmittedTxs(fsm)
	if !verifyResultRecorded(c, session, task, verifiers[2]) {
		t.Fatal("rebroadcast result not recorded after confirmation")
	}
}

// When the bus path must redeliver -- a broadcast that did not reach the mempool for a reason
// that may clear -- it asks for a delayed redelivery that doubles per Verifier, never an
// immediate one. A final refusal is acknowledged instead.
func TestBusResultTemporaryBroadcastFailureDelaysRedelivery(t *testing.T) {
	c, sub, _, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-bus-delay"
	task := testTaskID("bus-delay")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	fsm, _ := c.getFSM(session, task)
	vals := [][]byte{[]byte("v0"), []byte("v1")}
	interval := fsm.blockInterval()

	sub.refuse("result", chaincli.TxResult{Code: 20, Codespace: "sdk", RawLog: "mempool is full"})
	for i, want := range []time.Duration{interval, 2 * interval, 4 * interval} {
		err := fsm.onVerifyResult(testVerifyResult(task, verifiers[0], vals))
		if delay, ok := msgbus.RetryDelay(err); err == nil || !ok || delay != want {
			t.Fatalf("attempt %d: err = %v, delay = %v, want a delayed redelivery after %v", i+1, err, delay, want)
		}
	}
	sub.fail("result", errors.New("connection refused"))
	if delay, ok := msgbus.RetryDelay(fsm.onVerifyResult(testVerifyResult(task, verifiers[1], vals))); !ok || delay != interval {
		t.Fatalf("unreachable node: delay = %v, %v", delay, ok)
	}

	// A final CheckTx refusal is kept for a chain lookup and acknowledged, not redelivered.
	sub.refuse("result", chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"})
	if err := fsm.onVerifyResult(testVerifyResult(task, verifiers[2], vals)); err != nil {
		t.Fatalf("final refusal must be acknowledged, got %v", err)
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
	if err := fsm.onVerifyResult(vr); err != nil {
		t.Fatalf("bus handler: %v", err)
	}
	c.confirmSubmittedTxs(fsm) // reconciliation reads the chain's record
	if !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("same receipt on chain was not recorded")
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
			chain.setResult(fmt.Sprintf("receipt-%d", n), chaincli.TxResult{Code: 20, Codespace: "sdk", RawLog: "mempool is full"})
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

// settleTask drives a task ready to settle with this Builder as the only one selected, so every
// block is open to it until the settlement deadline.
func settleTask(t *testing.T, c *Coordinator, session, task string, settlementDeadline uint64) *taskFSM {
	t.Helper()
	chain := c.txQuery.(*txChainFake)
	chain.setResult("result-1", chaincli.TxResult{Height: 2})
	chain.setResult("result-2", chaincli.TxResult{Height: 2})
	selection := settleSelection(session, task, testBuilderSelf)
	driveToSettleReady(t, c, session, task, &selection)
	fsm, _ := c.getFSM(session, task)
	c.confirmSubmittedTxs(fsm) // the two results arrived on the bus: confirm them
	markSettleReady(fsm, settlementDeadline)
	return fsm
}

// The settlement is resubmitted only after its block result failed -- not on every block. A
// refusal does not end it: the chain judges a settlement at the height it executes, so one sent in
// the last block of this Builder's slot is refused for its timing. It goes again at the next
// height this Builder may settle at -- here the permissionless phase -- and keeps going until the
// chain settles.
func TestSettleRefusalDefersToTheNextAllowedHeight(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-settle-refused"
	task := testTaskID("settle-refused")
	chain.setResult("result-1", chaincli.TxResult{Height: 2})
	chain.setResult("result-2", chaincli.TxResult{Height: 2})
	selection := settleSelection(session, task, testBuilderSelf, testOperator("builder-b"), testOperator("builder-c"))
	driveToSettleReady(t, c, session, task, &selection)
	fsm, _ := c.getFSM(session, task)
	c.confirmSubmittedTxs(fsm)

	lastOwnBlock := int64(rankRevealDeadline + rankGraceBlocks - 1) // executes in the last block of this slot
	c.onNewBlock(lastOwnBlock)
	c.onNewBlock(lastOwnBlock + 1)
	if settleCount(sub.fakeSubmitter) != 1 {
		t.Fatalf("settle submissions = %d; a settlement awaiting its block result is not resent", settleCount(sub.fakeSubmitter))
	}
	refused := chaincli.TxResult{Code: 1172, Codespace: "task", RawLog: "submitter is not the Builder of the current slot"}
	chain.setResult("settle-1", refused)
	c.confirmSubmittedTxs(fsm)
	for height := lastOwnBlock + 2; height < rankPermissionless; height++ {
		c.onNewBlock(height)
	}
	if settleCount(sub.fakeSubmitter) != 1 {
		t.Fatalf("settle resent inside other Builders' slots: %d", settleCount(sub.fakeSubmitter))
	}
	c.onNewBlock(rankPermissionless)
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("settle submissions = %d, want a resend once anyone may settle", settleCount(sub.fakeSubmitter))
	}
	chain.setResult("settle-2", refused)
	c.confirmSubmittedTxs(fsm) // a second refusal backs off two blocks, and still does not stop
	c.onNewBlock(rankPermissionless + 1)
	c.onNewBlock(rankPermissionless + 2)
	if settleCount(sub.fakeSubmitter) != 3 {
		t.Fatalf("settle submissions = %d after a second refusal", settleCount(sub.fakeSubmitter))
	}
	if len(sink.find(t, "ERROR", "MsgSettleTask")) != 0 {
		t.Fatal("a refused settlement was given up before the deadline")
	}
}

// A block result that cannot be read (tx indexing off, result pruned, the query failing) gives
// no verdict; after txVerdictBlocks the transaction counts as lost and goes out again.
func TestSettleWithUnreadableResultIsResentAfterVerdictBlocks(t *testing.T) {
	c, sub, chain, sink := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-settle-unreadable"
	task := testTaskID("settle-unreadable")
	fsm := settleTask(t, c, session, task, rankVerifyDeadline)
	chain.mu.Lock()
	chain.queryErrs = map[string]error{"settle-1": errors.New("transaction indexing is disabled")}
	chain.mu.Unlock()

	c.onNewBlock(rankRevealDeadline) // settle-1
	for height := int64(rankRevealDeadline + 1); height < rankRevealDeadline+txVerdictBlocks; height++ {
		c.onNewBlock(height)
		c.confirmSubmittedTxs(fsm)
	}
	if settleCount(sub.fakeSubmitter) != 1 {
		t.Fatalf("settle resent before %d blocks without a verdict: %d", txVerdictBlocks, settleCount(sub.fakeSubmitter))
	}
	c.onNewBlock(rankRevealDeadline + txVerdictBlocks)
	c.confirmSubmittedTxs(fsm) // no verdict for txVerdictBlocks: lost
	c.onNewBlock(rankRevealDeadline + txVerdictBlocks + 1)
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("settle submissions = %d, want a resend after the result stayed unreadable", settleCount(sub.fakeSubmitter))
	}
	if len(sink.find(t, "WARN", "MsgSettleTask block result query failed")) == 0 {
		t.Fatal("the failing block result query left no trace")
	}
}

// Temporary settlement failures are resubmitted with a doubling wait until the settlement deadline,
// at which the chain settles the task by itself.
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
	// The chain settles the task by itself after its deadline, so giving up is a WARN, not an ERROR.
	if len(sink.find(t, "WARN", "gave up settling early")) != 1 {
		t.Fatal("giving up at the deadline must be logged at WARN once")
	}
	if len(sink.find(t, "ERROR", "")) != 0 {
		t.Fatal("giving up settling early must not log an ERROR")
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

// A rebroadcast the chain refuses at CheckTx -- here because it already holds the result -- is
// not rebroadcast again on every block: reconciliation reads the chain's record and, finding the
// same content, records it.
func TestPendingResultRebroadcastRefusedButOnChainIsConfirmed(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-rebroadcast-exists"
	task := testTaskID("rebroadcast-exists")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	fsm, _ := c.getFSM(session, task)
	fsm.mu.Lock()
	fsm.deadlines.Reveal = 1000
	fsm.mu.Unlock()
	c.onNewBlock(10)

	vr := signedShapeVerifyResult(task, verifiers[0], [][]byte{[]byte("v0")})
	chain.setResult("result-1", chaincli.TxResult{Code: 20, Codespace: "sdk", RawLog: "mempool is full"})
	if err := fsm.onVerifyResult(vr); err != nil {
		t.Fatalf("bus handler: %v", err)
	}
	c.confirmSubmittedTxs(fsm) // refused temporarily, not on chain: rebroadcast from 11

	digest, err := nodecontract.ResultReceiptSigningDigest(vr)
	if err != nil {
		t.Fatal(err)
	}
	chain.mu.Lock()
	chain.receipts[verifiers[0]] = chaincli.AcceptedResultReceipt{SigningDigest: digest[:]}
	chain.mu.Unlock()
	sub.refuse("result", chaincli.TxResult{Code: 1161, Codespace: "task", RawLog: "result receipt already exists"})
	c.onNewBlock(11) // the rebroadcast is refused at CheckTx
	fsm.mu.Lock()
	retry := fsm.pendingResults[verifiers[0]] != nil && fsm.pendingResults[verifiers[0]].tx.retry
	fsm.mu.Unlock()
	if retry {
		t.Fatal("a refused rebroadcast stays due for another rebroadcast and is never checked")
	}
	c.confirmSubmittedTxs(fsm)
	if !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("the result the chain holds was not recorded")
	}
}

// A unary relay that fails temporarily leaves its result to reconciliation, like a bus result:
// a bus redelivery acknowledged on the strength of that relay is not lost.
func TestFailedUnaryResultRelayIsFollowedByReconciliation(t *testing.T) {
	c, sub, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	const session = "sess-unary-follow"
	task := testTaskID("unary-follow")
	verifiers := []string{testOperator("verifier-1"), testOperator("verifier-2"), testOperator("verifier-3")}
	verifyingTask(t, c, session, task, verifiers)
	fsm, _ := c.getFSM(session, task)
	ctx := context.Background()

	// No block result within the wait: the transaction is still followed.
	vr := testVerifyResult(task, verifiers[0], [][]byte{[]byte("v0")})
	if _, err := c.OnVerifyResult(ctx, session, task, vr); !errors.Is(err, errRelayUnconfirmed) {
		t.Fatalf("unary relay: err = %v, want no block result yet", err)
	}
	if err := fsm.onVerifyResult(proto.Clone(vr).(*taskv1.ResultReceiptV3)); err != nil || sub.broadcasts("result") != 1 {
		t.Fatalf("bus redelivery: err = %v, broadcasts = %d", err, sub.broadcasts("result"))
	}
	chain.setResult("result-1", chaincli.TxResult{Height: 30})
	c.confirmSubmittedTxs(fsm)
	if !verifyResultRecorded(c, session, task, verifiers[0]) {
		t.Fatal("the unconfirmed unary result was not recorded once its block executed it")
	}

	// The broadcast never reached the node: the chain's record is read, and it holds the result.
	other := signedShapeVerifyResult(task, verifiers[1], [][]byte{[]byte("v0")})
	sub.fail("result", errors.New("connection refused"))
	if _, err := c.OnVerifyResult(ctx, session, task, other); err == nil || errors.Is(err, types.ErrInvalidArgument) {
		t.Fatalf("unary relay: err = %v, want temporary", err)
	}
	sub.fail("result", nil)
	digest, _ := nodecontract.ResultReceiptSigningDigest(other)
	chain.mu.Lock()
	chain.receipts[verifiers[1]] = chaincli.AcceptedResultReceipt{SigningDigest: digest[:]}
	chain.mu.Unlock()
	c.confirmSubmittedTxs(fsm)
	if !verifyResultRecorded(c, session, task, verifiers[1]) {
		t.Fatal("the failed unary result was not recorded once the chain held it")
	}
}

// simulatingSubmitter also dry-runs settlements.
type simulatingSubmitter struct {
	*confirmSubmitter
	simMu    sync.Mutex
	simCalls int
	sim      chaincli.SimResult
	simErr   error
}

func (s *simulatingSubmitter) SimulateSettle(context.Context, chaincli.SettleTx) (chaincli.SimResult, error) {
	s.simMu.Lock()
	defer s.simMu.Unlock()
	s.simCalls++
	return s.sim, s.simErr
}

func (s *simulatingSubmitter) setSimulation(result chaincli.SimResult, err error) {
	s.simMu.Lock()
	s.sim, s.simErr = result, err
	s.simMu.Unlock()
}

func (s *simulatingSubmitter) simulations() int {
	s.simMu.Lock()
	defer s.simMu.Unlock()
	return s.simCalls
}

// refusedSettle drives a settlement that the block refused, due for a resend from the next block.
func refusedSettle(t *testing.T, name string) (*Coordinator, *simulatingSubmitter, *taskFSM) {
	t.Helper()
	c, confirm, chain, _ := newConfirmCoordinator(t, testBuilderSelf)
	sub := &simulatingSubmitter{confirmSubmitter: confirm, sim: chaincli.SimResult{OK: true}}
	c.submit = sub
	fsm := settleTask(t, c, "sess-"+name, testTaskID(name), rankVerifyDeadline)
	c.onNewBlock(rankRevealDeadline)
	if settleCount(sub.fakeSubmitter) != 1 || sub.simulations() != 1 {
		t.Fatalf("first settlement: submissions = %d, simulations = %d", settleCount(sub.fakeSubmitter), sub.simulations())
	}
	chain.setResult("settle-1", chaincli.TxResult{Code: 1170, Codespace: "task", RawLog: "settlement inputs incomplete"})
	c.confirmSubmittedTxs(fsm)
	return c, sub, fsm
}

// Every settlement is simulated before it is broadcast; one the chain refuses in simulation is not
// broadcast. It is simulated again at the next height this Builder may settle at, and broadcast
// once the simulation passes.
func TestSettleRefusedInSimulationIsNotBroadcast(t *testing.T) {
	c, sub, _ := refusedSettle(t, "settle-sim-refused")
	sub.setSimulation(chaincli.SimResult{OK: false, Error: "failed to execute message: settlement inputs incomplete"}, nil)
	for height := int64(rankRevealDeadline + 1); height < rankRevealDeadline+10; height++ {
		c.onNewBlock(height)
	}
	if settleCount(sub.fakeSubmitter) != 1 || sub.simulations() != 10 {
		t.Fatalf("submissions = %d, simulations = %d; want no broadcast and one simulation per block",
			settleCount(sub.fakeSubmitter), sub.simulations())
	}
	sub.setSimulation(chaincli.SimResult{OK: true}, nil)
	c.onNewBlock(rankRevealDeadline + 10)
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("submissions = %d, want a broadcast once the simulation passes", settleCount(sub.fakeSubmitter))
	}
}

// A simulation that cannot be run is not a pass: nothing is broadcast, and the next block
// simulates again.
func TestSettleNotBroadcastWhenSimulationFails(t *testing.T) {
	c, sub, _ := refusedSettle(t, "settle-sim-unavailable")
	sub.setSimulation(chaincli.SimResult{}, errors.New("node unavailable"))
	c.onNewBlock(rankRevealDeadline + 1)
	c.onNewBlock(rankRevealDeadline + 2)
	if settleCount(sub.fakeSubmitter) != 1 || sub.simulations() != 3 {
		t.Fatalf("submissions = %d, simulations = %d; want no broadcast and one simulation per block",
			settleCount(sub.fakeSubmitter), sub.simulations())
	}
	sub.setSimulation(chaincli.SimResult{OK: true}, nil)
	c.onNewBlock(rankRevealDeadline + 3)
	if settleCount(sub.fakeSubmitter) != 2 {
		t.Fatalf("submissions = %d, want a broadcast once the simulation passes", settleCount(sub.fakeSubmitter))
	}
}
