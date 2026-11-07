package recorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sort"
	"sync"
	"testing"

	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	testChainID     = "trueopen-recorder-test"
	testGasBase     = 1000
	testGasPerEntry = 100
	testGasPerByte  = 2
	worker          = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8"
	builder         = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3"
)

var (
	applied  = sharedv1.MutationStatusV1_MUTATION_STATUS_V1_APPLIED
	noop     = sharedv1.MutationStatusV1_MUTATION_STATUS_V1_NOOP
	rejected = sharedv1.MutationStatusV1_MUTATION_STATUS_V1_REJECTED

	codeBalance  = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_BALANCE_INSUFFICIENT
	codeConsumed = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_CONSUMED
	codeNotNext  = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_NOT_NEXT
	codeLate     = taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
)

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// testTicketNonce is the Builder nonce the test tickets were issued under; testServiceNonce the
// nonce of the key that signs now, a later generation.
const (
	testTicketNonce  = 1
	testServiceNonce = 2
)

func sessionHex(id byte) string { return hex.EncodeToString(fill(id)) }

func taskIDOf(session byte, seq uint64) string {
	return fmt.Sprintf("%02x%062x", session, seq)
}

// bundle is an accepted order's dispatch entry; ticket tells winner tickets of the same order
// apart.
func bundle(session byte, seq uint64, ticket byte, deadline uint64) *dispatcher.Bundle {
	taskID, _ := hex.DecodeString(taskIDOf(session, seq))
	member := &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: fill(0x66), Slot: 1, SlotVersion: 1, OperatorAddress: worker}
	entry := &taskv1.DispatchEntryV1{
		SignedOrder: &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{ChainId: testChainID, SessionId: fill(session), OrderSequence: seq}},
		Record: &taskv1.DispatchRecordV1{
			SchemaVersion: 1, ChainId: testChainID, TaskId: taskID, TaskHash: fill(0x70 + ticket), SessionId: fill(session), OrderSequence: seq,
			BuilderAddress: builder, CandidatePoolSnapshotId: fill(0x66), VrfOutput: fill(0x0f), DispatchTicketHash: fill(ticket),
			BuilderServiceSignature: bytes.Repeat([]byte{0x5a}, 64),
		},
		WinnerTicket: &taskv1.DispatchTicketV1{ChainId: testChainID, BuilderAddress: builder, TaskId: taskID, TaskHash: fill(0x70 + ticket), SessionId: fill(session), OrderSequence: seq, Target: member,
			ServiceAuthorizationNonce: testTicketNonce},
		Accept: &taskv1.DispatchAcceptV1{SchemaVersion: 1, ChainId: testChainID, TaskId: taskID, TaskHash: fill(0x70 + ticket), DispatchTicketHash: fill(ticket), Member: member},
	}
	return &dispatcher.Bundle{SessionID: sessionHex(session), Sequence: seq, TaskID: taskIDOf(session, seq), Deadline: deadline, DeadlineBlocks: 10, Entry: entry}
}

func objectID(t *testing.T, b *dispatcher.Bundle) [32]byte {
	t.Helper()
	id, err := chaincli.DispatchEntryObjectID(testChainID, b.Entry)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type result struct {
	status sharedv1.MutationStatusV1
	code   taskv1.DispatchRejectCodeV1
}

func ok() result                                   { return result{status: applied} }
func refused(c taskv1.DispatchRejectCodeV1) result { return result{status: rejected, code: c} }

// executed is the block result of a record tx whose entries got results.
func executed(t *testing.T, msg *taskv1.MsgRecordDispatch, height int64, results ...result) chaincli.TxResult {
	t.Helper()
	resp := &taskv1.MsgRecordDispatchResponse{}
	for i, e := range msg.GetEntries() {
		id := entryID(t, e)
		resp.Results = append(resp.Results, &taskv1.BatchItemResultV1{ItemIndex: uint32(i), ObjectId: id[:], Status: results[i].status, RejectCode: results[i].code})
	}
	digest := chaincli.RecordDispatchBatchDigest(testChainID, resp.GetResults())
	resp.BatchDigest = digest[:]
	return txWith(t, height, resp)
}

// entryID is the result key of a sent entry; takeover entries are registered under
// testBoundChange.
func entryID(t *testing.T, e *taskv1.DispatchRecordEntryV1) [32]byte {
	t.Helper()
	var id [32]byte
	var err error
	if takeover := e.GetTakeover(); takeover != nil {
		id, err = chaincli.TakeoverEntryObjectID(testChainID, builder, takeover, testBoundChange)
	} else {
		id, err = chaincli.DispatchEntryObjectID(testChainID, e.GetDispatch())
	}
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func txWith(t *testing.T, height int64, resp *taskv1.MsgRecordDispatchResponse) chaincli.TxResult {
	t.Helper()
	value, err := proto.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(&abciv1beta1.TxMsgData{MsgResponses: []*anypb.Any{{TypeUrl: "/task.v1.MsgRecordDispatchResponse", Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	return chaincli.TxResult{Height: height, Data: data}
}

type orderKey struct {
	session string
	seq     uint64
}

// fakeChain answers QueryTx from txs by hash and QueryDispatchRecordByOrder from records.
type fakeChain struct {
	mu        sync.Mutex
	txs       map[[32]byte]chaincli.TxResult
	records   map[orderKey]*taskv1.DispatchRecordState
	recordErr error
	queries   int
	// next holds each session's next_expected_sequence; a session not in it is not found.
	next           map[string]uint64
	sessionErr     error
	sessionQueries int
}

func (c *fakeChain) QuerySession(_ context.Context, sessionID string) (chaincli.SessionState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionQueries++
	if c.sessionErr != nil {
		return chaincli.SessionState{}, c.sessionErr
	}
	next, ok := c.next[sessionID]
	if !ok {
		return chaincli.SessionState{}, fmt.Errorf("query session: %w", chaincli.ErrNotFound)
	}
	return chaincli.SessionState{SessionID: sessionID, NextExpectedSequence: next}, nil
}

func (c *fakeChain) setNext(sessionID string, next uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next == nil {
		c.next = map[string]uint64{}
	}
	c.next[sessionID] = next
}

func (c *fakeChain) QueryTx(_ context.Context, hash []byte) (chaincli.TxResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, ok := c.txs[[32]byte(hash)]
	if !ok {
		return chaincli.TxResult{}, fmt.Errorf("query tx: %w", chaincli.ErrNotFound)
	}
	return res, nil
}

func (c *fakeChain) QueryDispatchRecordByOrder(_ context.Context, sessionID string, seq uint64) (*taskv1.DispatchRecordState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries++
	// As the client: the session id must be a Hash32; any sequence, 0 included, is asked.
	if _, err := nodecontract.Hash32Bytes("session_id", sessionID); err != nil {
		return nil, fmt.Errorf("query dispatch record: %w", err)
	}
	if c.recordErr != nil {
		return nil, c.recordErr
	}
	rec, ok := c.records[orderKey{sessionID, seq}]
	if !ok {
		return nil, fmt.Errorf("query dispatch record: %w", chaincli.ErrNotFound)
	}
	return rec, nil
}

func (c *fakeChain) execute(raw []byte, res chaincli.TxResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.txs[sha256.Sum256(raw)] = res
}

// fakeSubmitter "signs" a record tx as the message bytes plus the account sequence.
type fakeSubmitter struct {
	mu       sync.Mutex
	sequence uint64
	msgs     []*taskv1.MsgRecordDispatch
	raws     [][]byte
	gas      []uint64
	// next scripts the outcome of the next submissions (default: CheckTx passes).
	next        []error
	rebroadcast []chaincli.TxResult
	resent      [][]byte
	// beforeSign, when set, runs once a transaction's entries are chosen, before it is signed and
	// persisted (the submitter reads the account sequence there).
	beforeSign func()
}

func (s *fakeSubmitter) SubmitRecordDispatch(_ context.Context, msg *taskv1.MsgRecordDispatch, gasLimit uint64, persist func([]byte) error) (chaincli.TxResult, error) {
	if s.beforeSign != nil {
		s.beforeSign()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return chaincli.TxResult{}, err
	}
	raw := binary.BigEndian.AppendUint64(body, s.sequence)
	if err := persist(raw); err != nil {
		return chaincli.TxResult{}, &coordinator.SubmissionError{Phase: coordinator.SubmissionPrepare, Err: err}
	}
	s.msgs = append(s.msgs, proto.Clone(msg).(*taskv1.MsgRecordDispatch))
	s.raws = append(s.raws, raw)
	s.gas = append(s.gas, gasLimit)
	if len(s.next) > 0 {
		err := s.next[0]
		s.next = s.next[1:]
		if err != nil {
			return chaincli.TxResult{}, err
		}
	}
	s.sequence++
	hash := sha256.Sum256(raw)
	return chaincli.TxResult{TxHash: hash[:]}, nil
}

func (s *fakeSubmitter) BroadcastTx(_ context.Context, raw []byte) (chaincli.TxResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resent = append(s.resent, bytes.Clone(raw))
	if len(s.rebroadcast) > 0 {
		res := s.rebroadcast[0]
		s.rebroadcast = s.rebroadcast[1:]
		return res, nil
	}
	return chaincli.TxResult{}, nil
}

func (s *fakeSubmitter) sent() ([]*taskv1.MsgRecordDispatch, [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*taskv1.MsgRecordDispatch(nil), s.msgs...), append([][]byte(nil), s.raws...)
}

type suspension struct {
	session string
	from    uint64
	reason  error
}

// calls is the order of the suspension and rejection effects across the fakes.
type calls struct {
	mu  sync.Mutex
	log []string
}

func (c *calls) add(name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, name)
}

type fakeLedger struct {
	calls     *calls
	mu        sync.Mutex
	recorded  []orderKey
	heights   []uint64
	suspended []orderKey
}

func (l *fakeLedger) MarkRecorded(sessionID string, seq uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recorded = append(l.recorded, orderKey{sessionID, seq})
	return nil
}

func (l *fakeLedger) Suspend(sessionID string, from uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suspended = append(l.suspended, orderKey{sessionID, from})
	l.calls.add("ledger.suspend")
	return nil
}

type fakeOrders struct {
	calls     *calls
	mu        sync.Mutex
	recorded  []orderKey
	heights   []uint64
	suspended []suspension
}

func (o *fakeOrders) Recorded(sessionID string, seq, height uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.recorded = append(o.recorded, orderKey{sessionID, seq})
	o.heights = append(o.heights, height)
	return nil
}

func (o *fakeOrders) Suspend(_ context.Context, sessionID string, from uint64, reason error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.suspended = append(o.suspended, suspension{sessionID, from, reason})
	o.calls.add("orders.suspend")
}

type taskReport struct {
	taskID string
	height uint64
	code   taskv1.DispatchRejectCodeV1
}

type fakeTasks struct {
	calls    *calls
	mu       sync.Mutex
	recorded []taskReport
	rejected []taskReport
	// rejectedTickets is the ticket each rejected task was reported with.
	rejectedTickets map[string][32]byte
}

func (f *fakeTasks) DispatchRecorded(_, taskID string, height uint64) {
	f.calls.add("tasks.recorded")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, taskReport{taskID: taskID, height: height})
}

func (f *fakeTasks) RecordRejected(_, taskID string, ticket [32]byte, code taskv1.DispatchRejectCodeV1) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, taskReport{taskID: taskID, code: code})
	if f.rejectedTickets == nil {
		f.rejectedTickets = map[string][32]byte{}
	}
	f.rejectedTickets[taskID] = ticket
	f.calls.add("tasks.rejected")
}

// attemptReport is one record outcome told to the attempt book.
type attemptReport struct {
	taskID   string
	ticket   [32]byte
	recorded bool
}

type fakeAttempts struct {
	calls   *calls
	mu      sync.Mutex
	reports []attemptReport
}

func (f *fakeAttempts) Recorded(taskID string, ticket [32]byte) {
	f.calls.add("attempts.recorded")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, attemptReport{taskID: taskID, ticket: ticket, recorded: true})
}

func (f *fakeAttempts) Rejected(taskID string, ticket [32]byte) {
	f.calls.add("attempts.rejected")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, attemptReport{taskID: taskID, ticket: ticket})
}

type notice struct {
	operator string
	n        *nexusv1.RecordResultNoticeV1
}

type fakeStreams struct {
	mu   sync.Mutex
	sent []notice
}

func (s *fakeStreams) Send(_ context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, notice{operator, frame.GetRecordResult()})
	return nil
}

type env struct {
	t        *testing.T
	calls    *calls
	store    kv.Store
	signer   signer.Signer
	chain    *fakeChain
	tx       *fakeSubmitter
	ledger   *fakeLedger
	orders   *fakeOrders
	tasks    *fakeTasks
	streams  *fakeStreams
	attempts *fakeAttempts
	// book, when set, is the attempt book the recorder tells instead of attempts.
	book     Attempts
	gate     *Gate
	keys     *fakeKeys
	evidence *fakeEvidence
	account  *accountReader
	metrics  *opsmetrics.Registry
	r        *Recorder
	params   Params
	// gasBase, gasPerEntry and gasPerByte are the record gas formula the recorder is built with,
	// gasMax its cap (0 none).
	gasBase, gasPerEntry, gasPerByte, gasMax uint64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{0x01}, 32), "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t: t, store: kv.NewMemStore(), signer: s,
		chain: &fakeChain{txs: map[[32]byte]chaincli.TxResult{}, records: map[orderKey]*taskv1.DispatchRecordState{}},
		tx:    &fakeSubmitter{}, account: &accountReader{balance: "1000"},
		params:  Params{MaxEntries: 16, MaxBytes: 1 << 20, MinCompensation: big.NewInt(100)},
		gasBase: testGasBase, gasPerEntry: testGasPerEntry, gasPerByte: testGasPerByte,
	}
	e.open()
	return e
}

type evidenceMark struct {
	ticket string
	height uint64
}

type fakeEvidence struct{ marks []evidenceMark }

func (f *fakeEvidence) MarkRecorded(ticketHash []byte, height uint64) error {
	f.marks = append(f.marks, evidenceMark{string(ticketHash), height})
	return nil
}

// open builds the recorder over the env's store, as after a start.
func (e *env) open() {
	e.t.Helper()
	e.calls = &calls{}
	e.ledger, e.orders, e.tasks, e.streams = &fakeLedger{calls: e.calls}, &fakeOrders{calls: e.calls}, &fakeTasks{calls: e.calls}, &fakeStreams{}
	e.attempts = &fakeAttempts{calls: e.calls}
	var book Attempts = e.attempts
	if e.book != nil {
		book = e.book
	}
	e.evidence = &fakeEvidence{}
	e.keys = &fakeKeys{}
	e.gate = NewGate(GateConfig{Keys: e.keys, Builder: builder, Account: e.account.read, MinBalance: e.params.MinCompensation})
	r, err := New(Config{
		ChainID: testChainID, Builder: builder, Signer: servicekey.Static(e.signer, testServiceNonce), Store: e.store, Ledger: e.ledger, Chain: e.chain, Tx: e.tx,
		Tasks: e.tasks, Attempts: book, Streams: e.streams, Gate: e.gate, Evidence: e.evidence, GasBase: e.gasBase, GasPerEntry: e.gasPerEntry, GasPerByte: e.gasPerByte,
		GasMax: e.gasMax, Metrics: e.metrics, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, e.params)
	if err != nil {
		e.t.Fatal(err)
	}
	r.SetOrders(e.orders)
	e.r = r
	_ = e.gate.Refresh(context.Background())
}

func (e *env) record(bs ...*dispatcher.Bundle) {
	e.t.Helper()
	for _, b := range bs {
		if err := e.r.Record(context.Background(), b); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) block(h uint64) { e.r.onBlock(context.Background(), h) }

// lastSent returns the latest record message and its tx bytes.
func (e *env) lastSent() (*taskv1.MsgRecordDispatch, []byte) {
	e.t.Helper()
	msgs, raws := e.tx.sent()
	if len(msgs) == 0 {
		e.t.Fatal("nothing submitted")
	}
	return msgs[len(msgs)-1], raws[len(raws)-1]
}

// entriesOf lists (session byte, sequence) of a record message's entries.
func entriesOf(msg *taskv1.MsgRecordDispatch) []string {
	var out []string
	for _, e := range msg.GetEntries() {
		order, kind := e.GetDispatch().GetSignedOrder().GetOrder(), ""
		if takeover := e.GetTakeover(); takeover != nil {
			order, kind = takeover.GetSignedOrder().GetOrder(), "T"
		}
		out = append(out, fmt.Sprintf("%02x/%d%s", order.GetSessionId()[0], order.GetOrderSequence(), kind))
	}
	return out
}

// outboxKeys lists the record outbox keys by prefix.
func (e *env) outboxKeys() []string {
	var keys []string
	if err := e.store.Scan(kv.NSRecordOutbox, func(key string, _ []byte) bool {
		keys = append(keys, key[:len(key)-64])
		return true
	}); err != nil {
		e.t.Fatal(err)
	}
	sort.Strings(keys)
	return keys
}

// notices verifies the notices' Builder signatures, under the signing key's nonce, and returns them.
func (e *env) notices() []notice {
	e.t.Helper()
	e.streams.mu.Lock()
	defer e.streams.mu.Unlock()
	for _, n := range e.streams.sent {
		sig := n.n.GetBuilderServiceSignature()
		unsigned := proto.Clone(n.n).(*nexusv1.RecordResultNoticeV1)
		unsigned.BuilderServiceSignature = nil
		raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(unsigned)
		digest, err := dispatch.SigningDigest("nexus.v1.RecordResultNoticeV1", raw)
		if err != nil || dispatch.VerifyDigestSignature(e.signer.PubKeyCompressed(), digest[:], sig) != nil {
			e.t.Fatalf("notice %v is not signed by the Builder", n.n)
		}
		if n.n.GetServiceAuthorizationNonce() != testServiceNonce {
			e.t.Fatalf("notice signed under nonce %d, the key's is %d", n.n.GetServiceAuthorizationNonce(), testServiceNonce)
		}
	}
	return append([]notice(nil), e.streams.sent...)
}

type fakeKeys struct {
	mu  sync.Mutex
	err error
}

func (k *fakeKeys) CheckBuilderKey(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.err
}

func (k *fakeKeys) CortexRotation(context.Context, string) (uint64, error) { return 0, nil }

// accountReader answers the compensation account read.
type accountReader struct {
	mu      sync.Mutex
	balance string // "" is no account
	err     error
	reads   int
}

func (a *accountReader) read(context.Context) (*hubv1.BuilderCompensationAccountState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reads++
	if a.err != nil {
		return nil, a.err
	}
	if a.balance == "" {
		return nil, fmt.Errorf("query builder compensation account: %w", chaincli.ErrNotFound)
	}
	return &hubv1.BuilderCompensationAccountState{BuilderAddress: builder, Balance: &sharedv1.Amount{AtomicUnits: a.balance}}, nil
}

func (a *accountReader) set(balance string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.balance, a.err = balance, err
}

var errUnreadable = errors.New("node unreachable")

func sha(raw []byte) [32]byte { return sha256.Sum256(raw) }

func errorsIs(err, target error) bool { return errors.Is(err, target) }
