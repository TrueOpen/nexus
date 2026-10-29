package dispatchresponse

import (
	"bytes"
	"context"
	"encoding/hex"
	"sort"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	testChainID = "trueopen-phase1-vector-1"
	// Valid operator addresses (the wire vector operators): pool slots 1, 3 and 7.
	op1 = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8"
	op3 = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3"
	op7 = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

	self      = "trueopen1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"
	responder = "trueopen1responderservice"
	other     = "trueopen1otherbuilder"

	outcomeAccepted = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_ACCEPTED
	outcomeRejected = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED
	outcomeTimeout  = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_TIMEOUT
	outcomeVoided   = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_VOIDED
	outcomeRevoked  = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REVOKED

	statusPending   = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL
	statusPaid      = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID
	statusDismissed = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_DISMISSED

	kindOmission = sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION
	kindDraw     = sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_DRAW
	kindSkip     = sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP
	kindRoster   = sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE
	kindDouble   = sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_DOUBLE_DISPATCH

	awaitingProof  = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF
	awaitingRoster = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_ROSTER
	upheld         = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD
)

const (
	testGasBase    = 100_000
	testGasPerByte = 10
)

var (
	testParams = dispatchevidence.Params{
		RecordDeadlineBlocks: 20, ClaimWindowBlocks: 30, RebuttalBlocks: 10,
		ChallengeWindowBlocks: 50, ChallengeResponseBlocks: 5, RetentionBlocks: 100,
	}
	testTask     = fill(0xaa)
	testSession  = fill(0x01)
	testSnapshot = fill(0x66)
)

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func slotOf(op string) uint32 {
	switch op {
	case op1:
		return 1
	case op3:
		return 3
	default:
		return 7
	}
}

func memberRef(op string) *taskv1.CandidateMemberRefV1 {
	return &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: testSnapshot, Slot: slotOf(op), SlotVersion: 1, OperatorAddress: op}
}

func mustMarshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// attemptSpec is one attempt of a test order.
type attemptSpec struct {
	op      string
	sent    bool
	outcome taskv1.DispatchAttemptOutcomeV1
	// recordOutcome, when set, is the outcome the signed record shows instead.
	recordOutcome taskv1.DispatchAttemptOutcomeV1
	noReject      bool
}

func ticketHash(round, rank int) []byte { return fill(byte(0x10 + round*8 + rank)) }

// roster is a DispatchRosterV1 of the task holding ops, and its roster_hash.
func roster(t testing.TB, ops ...string) ([]byte, []byte) {
	t.Helper()
	msg := &taskv1.DispatchRosterV1{TaskId: testTask, ReferenceHeight: 90, CandidatePoolSnapshotId: testSnapshot}
	for _, op := range []string{op1, op3, op7} {
		for _, want := range ops {
			if op == want {
				msg.Members = append(msg.Members, &taskv1.DispatchRosterMemberV1{Slot: slotOf(op), SlotVersion: 1, OperatorAddress: op, CandidateWeight: 1})
			}
		}
	}
	r, err := dispatchdraw.RestoreRoster(testChainID, [32]byte(fill(0xd1)), msg)
	if err != nil {
		t.Fatal(err)
	}
	return mustMarshal(t, msg), r.Hash[:]
}

// evidenceOrder builds an order's evidence: one round per element of rounds, ranks continuing
// across rounds, each round with the roster of its operators.
func evidenceOrder(t testing.TB, recorded bool, rounds ...[]attemptSpec) *dispatchevidence.Order {
	t.Helper()
	o := &dispatchevidence.Order{
		SessionID: hex.EncodeToString(testSession), Sequence: 3, TaskID: hex.EncodeToString(testTask), TaskHash: hex.EncodeToString(fill(0xbb)),
		Epoch: 1, SignedOrder: mustMarshal(t, &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{EarliestSubmitHeight: 100}}), DeadlineBase: 100,
	}
	record := &taskv1.DispatchRecordV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: testTask, TaskHash: fill(0xbb), SessionId: testSession, OrderSequence: 3,
		BuilderAddress: self, DispatchTicketHash: make([]byte, 32), BuilderServiceSignature: []byte("sig"),
	}
	rank := uint32(0)
	for ri, specs := range rounds {
		var ops []string
		for _, s := range specs {
			ops = append(ops, s.op)
		}
		rosterRaw, rosterHash := roster(t, ops...)
		round := dispatchevidence.Round{Number: uint32(ri), RootDigest: fill(0xd1 + byte(ri)), Roster: rosterRaw, RosterHash: rosterHash}
		recRound := &taskv1.DispatchRoundV1{DispatchRound: uint32(ri), HandraiseRootDigest: round.RootDigest, RosterHash: rosterHash}
		for ai, s := range specs {
			hash := ticketHash(ri, ai)
			a := dispatchevidence.Attempt{
				Ticket: mustMarshal(t, &taskv1.DispatchTicketV1{ChainId: testChainID, TaskId: testTask, Rank: rank, Target: memberRef(s.op)}),
				Hash:   hash, Rank: rank, Operator: s.op, Sent: s.sent, Outcome: s.outcome,
			}
			digest := make([]byte, 32)
			if s.outcome == outcomeRejected && !s.noReject {
				a.Reject = mustMarshal(t, &taskv1.DispatchRejectV1{
					SchemaVersion: 1, ChainId: testChainID, TaskId: testTask, TaskHash: fill(0xbb), DispatchTicketHash: hash,
					Member: memberRef(s.op), ServiceAuthorizationNonce: 3, ServiceSignature: []byte("cortex sig"),
				})
				digest = fill(0xee)
			}
			outcome := s.outcome
			if s.recordOutcome != 0 {
				outcome = s.recordOutcome
			}
			if outcome == outcomeAccepted {
				record.DispatchTicketHash = hash
				o.Accept = []byte("accept")
			}
			recRound.Attempts = append(recRound.Attempts, &taskv1.DispatchAttemptV1{
				DispatchTicketHash: hash, Rank: rank, Member: memberRef(s.op), Outcome: outcome, RejectDigestOrZero32: digest,
			})
			round.Attempts = append(round.Attempts, a)
			rank++
		}
		o.Rounds = append(o.Rounds, round)
		record.Rounds = append(record.Rounds, recRound)
	}
	o.Record = mustMarshal(t, record)
	if recorded {
		o.Recorded, o.RecordedHeight = true, 115
	}
	return o
}

// ---- fakes ----

type fakeChain struct {
	mu         sync.Mutex
	claims     map[string]*taskv1.DispatchCompensationClaimState
	challenges map[string]*taskv1.DispatchChallengeState
	records    map[string]*taskv1.DispatchRecordState // by session/sequence
	claimReads []string
	chalReads  int
	// txResults are the executed results QueryTx returns by tx hash.
	txResults map[string]chaincli.TxResult
	// pageReads lists every open-item page read as "claims|builder" or "challenges|builder", with
	// "|next" for a page after the first; pageErr fails them.
	pageReads []string
	pageErr   error
}

// QueryDispatchCompensationClaimsByBuilder serves the pending claims on builder's tickets, one per
// page, so a walk spans pages.
func (c *fakeChain) QueryDispatchCompensationClaimsByBuilder(_ context.Context, builder string, token []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pageReads = append(c.pageReads, pageRead("claims", builder, token))
	if c.pageErr != nil {
		return nil, nil, c.pageErr
	}
	var open []*taskv1.DispatchCompensationClaimState
	for _, claim := range c.claims {
		if claim.GetBuilderAddress() == builder && claim.GetStatus() == statusPending {
			open = append(open, proto.Clone(claim).(*taskv1.DispatchCompensationClaimState))
		}
	}
	sort.Slice(open, func(i, j int) bool {
		return bytes.Compare(open[i].GetDispatchTicketHash(), open[j].GetDispatchTicketHash()) < 0
	})
	page, next := onePage(len(open), token)
	if page < 0 {
		return nil, nil, nil
	}
	return open[page : page+1], next, nil
}

// QueryDispatchChallengesByBuilder serves the open challenges against builder, one per page.
func (c *fakeChain) QueryDispatchChallengesByBuilder(_ context.Context, builder string, token []byte) ([]*taskv1.DispatchChallengeState, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pageReads = append(c.pageReads, pageRead("challenges", builder, token))
	if c.pageErr != nil {
		return nil, nil, c.pageErr
	}
	var open []*taskv1.DispatchChallengeState
	for _, ch := range c.challenges {
		if ch.GetBuilderAddress() == builder && (ch.GetStatus() == awaitingProof || ch.GetStatus() == awaitingRoster) {
			open = append(open, proto.Clone(ch).(*taskv1.DispatchChallengeState))
		}
	}
	sort.Slice(open, func(i, j int) bool { return bytes.Compare(open[i].GetChallengeId(), open[j].GetChallengeId()) < 0 })
	page, next := onePage(len(open), token)
	if page < 0 {
		return nil, nil, nil
	}
	return open[page : page+1], next, nil
}

func pageRead(kind, builder string, token []byte) string {
	if len(token) > 0 {
		return kind + "|" + builder + "|next"
	}
	return kind + "|" + builder
}

// onePage returns the index of the one row the page at token holds (-1 for none) and the next
// token.
func onePage(rows int, token []byte) (int, []byte) {
	index := 0
	if len(token) > 0 {
		index = int(token[0])
	}
	if index >= rows {
		return -1, nil
	}
	if index+1 < rows {
		return index, []byte{byte(index + 1)}
	}
	return index, nil
}

// pageWalks counts the open-item recoveries: each starts with the first page of this Builder's
// claims.
func (c *fakeChain) pageWalks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	walks := 0
	for _, read := range c.pageReads {
		if read == "claims|"+self {
			walks++
		}
	}
	return walks
}

func (c *fakeChain) QueryTx(_ context.Context, hash []byte) (chaincli.TxResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res, ok := c.txResults[string(hash)]
	if !ok {
		return chaincli.TxResult{}, chaincli.ErrNotFound
	}
	return res, nil
}

func (c *fakeChain) QueryDispatchCompensationClaim(_ context.Context, hash []byte) (*taskv1.DispatchCompensationClaimState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claimReads = append(c.claimReads, hex.EncodeToString(hash))
	claim, ok := c.claims[string(hash)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return proto.Clone(claim).(*taskv1.DispatchCompensationClaimState), nil
}

func (c *fakeChain) QueryDispatchChallenge(_ context.Context, id []byte) (*taskv1.DispatchChallengeState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chalReads++
	ch, ok := c.challenges[string(id)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return proto.Clone(ch).(*taskv1.DispatchChallengeState), nil
}

func (c *fakeChain) QueryDispatchRecordByOrder(_ context.Context, sessionID string, seq uint64) (*taskv1.DispatchRecordState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.records[sessionID]
	if !ok || seq != 3 {
		return nil, chaincli.ErrNotFound
	}
	return proto.Clone(rec).(*taskv1.DispatchRecordState), nil
}

type fakeTx struct {
	mu       sync.Mutex
	rebuts   []*taskv1.MsgRebutDispatchCompensation
	responds []*taskv1.MsgRespondDispatchChallenge
	gas      []uint64
	hashes   [][]byte
	err      error
}

func (f *fakeTx) sent(gas uint64) chaincli.TxResult {
	f.gas = append(f.gas, gas)
	hash := bytes.Repeat([]byte{byte(len(f.gas))}, 32)
	f.hashes = append(f.hashes, hash)
	return chaincli.TxResult{TxHash: hash}
}

func (f *fakeTx) SubmitRebutDispatchCompensation(_ context.Context, m *taskv1.MsgRebutDispatchCompensation, gas uint64) (chaincli.TxResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return chaincli.TxResult{}, f.err
	}
	f.rebuts = append(f.rebuts, proto.Clone(m).(*taskv1.MsgRebutDispatchCompensation))
	return f.sent(gas), nil
}

func (f *fakeTx) SubmitRespondDispatchChallenge(_ context.Context, m *taskv1.MsgRespondDispatchChallenge, gas uint64) (chaincli.TxResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return chaincli.TxResult{}, f.err
	}
	f.responds = append(f.responds, proto.Clone(m).(*taskv1.MsgRespondDispatchChallenge))
	return f.sent(gas), nil
}

type fakeRoots struct {
	height uint64
	kept   map[[32]byte]bool
}

func (f *fakeRoots) PruneRootsBelow(height uint64, keep func([32]byte) bool) (int, error) {
	f.height = height
	f.kept = map[[32]byte]bool{}
	for _, b := range []byte{0xd1, 0xd2, 0xd9} {
		d := [32]byte(fill(b))
		f.kept[d] = keep(d)
	}
	return 0, nil
}

// ---- environment ----

type env struct {
	t        *testing.T
	store    kv.Store
	evidence *dispatchevidence.Store
	chain    *fakeChain
	tx       *fakeTx
	roots    *fakeRoots
	live     map[[32]byte]bool
	r        *Responder
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, store: kv.NewMemStore(),
		chain: &fakeChain{claims: map[string]*taskv1.DispatchCompensationClaimState{}, challenges: map[string]*taskv1.DispatchChallengeState{},
			records: map[string]*taskv1.DispatchRecordState{}, txResults: map[string]chaincli.TxResult{}},
		tx: &fakeTx{}, roots: &fakeRoots{}, live: map[[32]byte]bool{},
	}
	e.evidence = dispatchevidence.New(e.store, testParams)
	e.open()
	return e
}

// open builds the Responder over the store, as after a start.
func (e *env) open() {
	e.t.Helper()
	var err error
	e.r, err = New(Config{
		ChainID: testChainID, Builder: self, Responder: responder, Store: e.store, Evidence: e.evidence,
		Chain: e.chain, Tx: e.tx, Roots: e.roots, LiveRoots: func() map[[32]byte]bool { return e.live },
		GasBase: testGasBase, GasPerByte: testGasPerByte,
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) put(o *dispatchevidence.Order) {
	e.t.Helper()
	if err := e.evidence.Put(o); err != nil {
		e.t.Fatal(err)
	}
}

// claim files a pending claim on a ticket on chain and delivers its event.
func (e *env) claim(hash []byte, worker string, deadline uint64) {
	e.t.Helper()
	e.chain.mu.Lock()
	e.chain.claims[string(hash)] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: hash, TaskId: testTask, SessionId: testSession, OrderSequence: 3, BuilderAddress: self,
		WorkerOperatorAddress: worker, Status: statusPending, ClaimedHeight: deadline - testParams.RebuttalBlocks, RebuttalDeadlineHeight: deadline,
	}
	e.chain.mu.Unlock()
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Height: int64(deadline - testParams.RebuttalBlocks), Typed: chaincli.DispatchCompensationClaimed{
		TicketHash: hash, TaskID: hex.EncodeToString(testTask), Builder: self, Worker: worker, RebuttalDeadlineHeight: deadline,
	}})
}

func (e *env) setClaim(hash []byte, f func(*taskv1.DispatchCompensationClaimState)) {
	e.chain.mu.Lock()
	defer e.chain.mu.Unlock()
	f(e.chain.claims[string(hash)])
}

// challenge opens a challenge on chain and delivers its event.
func (e *env) challenge(id byte, state *taskv1.DispatchChallengeState) []byte {
	e.t.Helper()
	cid := fill(id)
	state.ChallengeId, state.TaskId = cid, testTask
	e.chain.mu.Lock()
	e.chain.challenges[string(cid)] = state
	e.chain.mu.Unlock()
	e.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Height: 120, Typed: chaincli.DispatchChallengeOpened{
		ChallengeID: cid, TaskID: hex.EncodeToString(testTask), Kind: state.GetKind(), Challenger: op3, ProofDeadlineHeight: state.GetProofDeadlineHeight(),
	}})
	return cid
}

func (e *env) block(h uint64) {
	e.t.Helper()
	e.r.onBlock(context.Background(), h)
}

func (e *env) rebuts() []*taskv1.MsgRebutDispatchCompensation {
	e.tx.mu.Lock()
	defer e.tx.mu.Unlock()
	return append([]*taskv1.MsgRebutDispatchCompensation(nil), e.tx.rebuts...)
}

func (e *env) responds() []*taskv1.MsgRespondDispatchChallenge {
	e.tx.mu.Lock()
	defer e.tx.mu.Unlock()
	return append([]*taskv1.MsgRespondDispatchChallenge(nil), e.tx.responds...)
}

func u32(v uint32) *uint32 { return &v }
func u64(v uint64) *uint64 { return &v }
