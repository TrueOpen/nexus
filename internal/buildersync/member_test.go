package buildersync

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/dispatchresponse"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// answerChain is the chain a member's responder reads.
type answerChain struct {
	*fakeRecords
	claims     map[string]*taskv1.DispatchCompensationClaimState
	challenges map[string]*taskv1.DispatchChallengeState
}

func (c *answerChain) QueryDispatchCompensationClaim(_ context.Context, hash []byte) (*taskv1.DispatchCompensationClaimState, error) {
	claim, ok := c.claims[string(hash)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return claim, nil
}

func (c *answerChain) QueryDispatchChallenge(_ context.Context, id []byte) (*taskv1.DispatchChallengeState, error) {
	ch, ok := c.challenges[string(id)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return ch, nil
}

// The open-item pages are only read after a role stream gap, which these tests do not have.
func (c *answerChain) QueryDispatchChallengesByBuilder(context.Context, string, []byte) ([]*taskv1.DispatchChallengeState, []byte, error) {
	return nil, nil, nil
}

func (c *answerChain) QueryDispatchCompensationClaimsByBuilder(context.Context, string, []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error) {
	return nil, nil, nil
}

func (c *answerChain) QueryTx(context.Context, []byte) (chaincli.TxResult, error) {
	return chaincli.TxResult{}, chaincli.ErrNotFound
}

type answerTx struct {
	rebuts   []*taskv1.MsgRebutDispatchCompensation
	responds []*taskv1.MsgRespondDispatchChallenge
}

func (a *answerTx) SubmitRebutDispatchCompensation(_ context.Context, m *taskv1.MsgRebutDispatchCompensation, _ uint64) (chaincli.TxResult, error) {
	a.rebuts = append(a.rebuts, m)
	return chaincli.TxResult{TxHash: fill(byte(len(a.rebuts)))}, nil
}

func (a *answerTx) SubmitRespondDispatchChallenge(_ context.Context, m *taskv1.MsgRespondDispatchChallenge, _ uint64) (chaincli.TxResult, error) {
	a.responds = append(a.responds, m)
	return chaincli.TxResult{TxHash: fill(byte(0x80 + len(a.responds)))}, nil
}

// syncedMember has D sync the recorded order to M and returns M's responder over its copy.
func syncedMember(t *testing.T) (*env, *dispatchresponse.Responder, *answerChain, *answerTx) {
	t.Helper()
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	e.s.OrderChanged(f.issued())
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	if c := e.copyOf(); c == nil || !c.Recorded {
		t.Fatal("order not synced")
	}
	chain := &answerChain{fakeRecords: e.records, claims: map[string]*taskv1.DispatchCompensationClaimState{}, challenges: map[string]*taskv1.DispatchChallengeState{}}
	tx := &answerTx{}
	r, err := dispatchresponse.New(dispatchresponse.Config{
		ChainID: testChainID, Builder: e.m.op, Responder: e.m.key.Address, Store: e.member.store, Evidence: e.member.evidence,
		Chain: chain, Tx: tx, BuilderSet: e.groups, GasBase: 1, GasPerByte: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop(context.Background()) })
	return e, r, chain, tx
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A member rebuts a claim on D's rejected ticket with D's record and the Worker's reject from its
// synced copy, once the dispatching Builder's half of the window passed.
func TestMemberRebutsFromTheSyncedCopy(t *testing.T) {
	e, r, chain, tx := syncedMember(t)
	f := e.fx
	chain.claims[string(f.hashes[0][:])] = &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: f.hashes[0][:], TaskId: f.taskID, SessionId: f.sessionID, OrderSequence: f.sequence, BuilderAddress: e.d.op,
		WorkerOperatorAddress: f.rejecter.op, Status: taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL,
		RebuttalDeadlineHeight: 160,
	}
	r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Typed: chaincli.DispatchCompensationClaimed{
		TicketHash: f.hashes[0][:], TaskID: f.taskHex(), Builder: e.d.op, Worker: f.rejecter.op, RebuttalDeadlineHeight: 160,
	}})
	r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 156})
	waitFor(t, "the rebuttal", func() bool { return r.Counts().ClaimsRebutted == 1 })
	m := tx.rebuts[0]
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(f.record, &rec); err != nil || !proto.Equal(m.GetRecord(), &rec) || m.GetReject() == nil ||
		!bytes.Equal(m.GetDispatchTicketHash(), f.hashes[0][:]) || m.GetResponderAddress() != e.m.key.Address() {
		t.Fatalf("rebuttal = %v", m)
	}
}

// A member lifts ROSTER_UNAVAILABLE with the synced roster, and serves GetDispatchRoster from its
// copy with the root D signed.
func TestMemberAnswersRosterRequestsFromTheSyncedCopy(t *testing.T) {
	e, r, chain, tx := syncedMember(t)
	f := e.fx
	round := uint32(0)
	deadline := uint64(130)
	chain.challenges[string(fill(0xc2))] = &taskv1.DispatchChallengeState{
		ChallengeId: fill(0xc2), TaskId: f.taskID, Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE,
		BuilderAddress: e.d.op, DispatchRound: &round, ProofDeadlineHeight: &deadline,
		Status: taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_ROSTER,
	}
	r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Typed: chaincli.DispatchChallengeOpened{
		ChallengeID: fill(0xc2), TaskID: f.taskHex(), Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE,
		ProofDeadlineHeight: deadline,
	}})
	r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 128})
	waitFor(t, "the roster answer", func() bool { return r.Counts().ChallengesAnswered == 1 })
	var roster taskv1.DispatchRosterV1
	if err := proto.Unmarshal(f.roster, &roster); err != nil || !proto.Equal(tx.responds[0].GetRoster(), &roster) {
		t.Fatalf("response = %v", tx.responds[0])
	}

	rosters := dispatchevidence.Rosters{ChainID: testChainID, Evidence: e.member.evidence, Chain: e.records,
		Root: func([32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) { return nil, false, nil }}
	resp, err := rosters.DispatchRoster(context.Background(), f.sessionHex(), f.taskHex())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetRounds()) != 1 || resp.GetRounds()[0].GetHandraiseRoot().GetBuilderAddress() != e.d.op ||
		!proto.Equal(resp.GetRounds()[0].GetRoster(), &roster) {
		t.Fatalf("GetDispatchRoster from the copy = %v", resp)
	}
}

// HeldAsMember answers taskdata recovery for the input copies a member stores: the stored version
// of the task's synced order, and once the chain recorded the order only the recorded winner's.
func TestHeldAsMemberNamesTheStoredCopy(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	ctx := context.Background()
	key := taskdata.ObjectKey{
		TaskHash: hexOf(f.taskHash), SessionID: f.sessionHex(), TaskID: f.taskHex(), Kind: taskdata.ObjectKindInput,
		ContentHash: taskdata.InputContentHash(hexOf(sumOf(f.input))),
	}
	held := func(k taskdata.ObjectKey) bool {
		t.Helper()
		ok, err := e.member.r.HeldAsMember(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if held(key) {
		t.Fatal("held before any sync")
	}

	e.s.OrderChanged(f.issued())
	e.sync()
	if !held(key) {
		t.Fatal("stored copy of an order not recorded yet is not held")
	}
	other := key
	other.TaskHash = hexOf(fill(0x6f))
	otherSession := key
	otherSession.SessionID = hexOf(fill(0x7a))
	otherContent := key
	otherContent.ContentHash = hexOf(fill(0x7b))
	for name, k := range map[string]taskdata.ObjectKey{"version": other, "session": otherSession, "content": otherContent} {
		if held(k) {
			t.Fatalf("another %s is held", name)
		}
	}

	f.putAccepted()
	f.recordOnChain()
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	if c := e.copyOf(); c == nil || !c.Recorded {
		t.Fatalf("copy not recorded: %+v", c)
	}
	if !held(key) {
		t.Fatal("stored copy of the recorded winner is not held")
	}

	// Recorded with another version's winner: the copy is not the accepted one.
	mk := memberKey(e.d.op, f.sessionHex(), f.sequence)
	m, found, err := e.member.r.loadMember(mk)
	if err != nil || !found {
		t.Fatalf("member stream = %v, %v", found, err)
	}
	m.Winner.TaskHash = other.TaskHash
	ops, err := memberOps(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.member.store.WriteBatch(ops...); err != nil {
		t.Fatal(err)
	}
	if held(key) {
		t.Fatal("copy of a version that is not the recorded winner is held")
	}

	// A pruned member stream holds nothing.
	if err := e.member.store.WriteBatch(kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + f.taskHex(), Delete: true}); err != nil {
		t.Fatal(err)
	}
	if held(key) {
		t.Fatal("held without a member stream")
	}
}
