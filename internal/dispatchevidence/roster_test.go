package dispatchevidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

func testRoots(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) {
	if digest[0] == 0xd9 {
		return nil, false, nil
	}
	return &taskv1.SignedHandraiseRootV1{ChainId: "c", RootHeight: uint64(digest[0])}, true, nil
}

const (
	rosterChain = "trueopen-phase1-vector-1"
	rosterOp1   = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8"
	rosterOp3   = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3"
)

// rosterOf is a valid DispatchRosterV1 of task 0xaa holding the given (slot, operator) members,
// and its roster_hash.
func rosterOf(t *testing.T, height uint64, members ...dispatch.RosterMember) ([]byte, []byte) {
	t.Helper()
	msg := &taskv1.DispatchRosterV1{TaskId: fill(0xaa), ReferenceHeight: height, CandidatePoolSnapshotId: fill(0x66)}
	for _, m := range members {
		msg.Members = append(msg.Members, &taskv1.DispatchRosterMemberV1{Slot: m.Slot, SlotVersion: m.SlotVersion, OperatorAddress: m.OperatorAddress, CandidateWeight: m.CandidateWeight})
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := dispatch.RosterDigest(rosterChain, [32]byte(fill(0xaa)), height, [32]byte(fill(0x66)), members)
	if err != nil {
		t.Fatal(err)
	}
	return raw, hash[:]
}

type fakeRecords map[string]*taskv1.DispatchRecordState

func (f fakeRecords) QueryDispatchRecordByOrder(_ context.Context, sessionID string, seq uint64) (*taskv1.DispatchRecordState, error) {
	rec, ok := f[fmt.Sprintf("%s/%d", sessionID, seq)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return rec, nil
}

// rosterFixture stores the evidence of task 0xaa with two rounds of valid rosters, not marked
// recorded, and the chain's record of it.
func rosterFixture(t *testing.T) (*Store, *Order, fakeRecords) {
	t.Helper()
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	var h0, h1 []byte
	o.Rounds[0].Roster, h0 = rosterOf(t, 90, dispatch.RosterMember{Slot: 1, SlotVersion: 1, OperatorAddress: rosterOp1, CandidateWeight: 1})
	o.Rounds[1].Roster, h1 = rosterOf(t, 90, dispatch.RosterMember{Slot: 3, SlotVersion: 1, OperatorAddress: rosterOp3, CandidateWeight: 5})
	o.Rounds[0].RosterHash, o.Rounds[1].RosterHash = h0, h1
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	records := fakeRecords{fmt.Sprintf("%s/%d", o.SessionID, o.Sequence): {
		TaskId: fill(0xaa), DispatchRecordHash: fill(0x77), Rounds: []*taskv1.DispatchRoundV1{
			{DispatchRound: 0, HandraiseRootDigest: fill(0xd1), RosterHash: h0},
			{DispatchRound: 1, HandraiseRootDigest: fill(0xd2), RosterHash: h1},
		},
	}}
	return s, o, records
}

// GetDispatchRoster serves a task the chain recorded: every round's stored roster whose hash the
// chain's record holds, with the root it binds, and the chain's dispatch_record_hash. Whether the
// evidence was marked recorded does not matter.
func TestRostersOfARecordedTask(t *testing.T) {
	s, o, records := rosterFixture(t)
	r := Rosters{ChainID: rosterChain, Evidence: s, Chain: records, Root: testRoots}
	resp, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.GetDispatchRecordHash(), fill(0x77)) || len(resp.GetRounds()) != 2 {
		t.Fatalf("response = %v", resp)
	}
	for i, round := range resp.GetRounds() {
		if round.GetDispatchRound() != uint32(i) || round.GetRoster().GetMembers()[0].GetSlot() != []uint32{1, 3}[i] ||
			round.GetHandraiseRoot().GetRootHeight() != uint64(0xd1+i) {
			t.Fatalf("round %d = %v", i, round)
		}
	}
}

// A task the chain did not record, of another session, whose stored rosters or roots are not the
// recorded ones, or without its bound root is not served.
func TestRostersNotServed(t *testing.T) {
	s, o, records := rosterFixture(t)
	r := Rosters{ChainID: rosterChain, Evidence: s, Chain: fakeRecords{}, Root: testRoots}
	if _, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("unrecorded task: %v", err)
	}
	r.Chain = records
	if _, err := r.DispatchRoster(context.Background(), "02", o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("other session: %v", err)
	}
	key := fmt.Sprintf("%s/%d", o.SessionID, o.Sequence)
	records[key].Rounds[1].RosterHash = fill(0x55)
	if _, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("other roster recorded: %v", err)
	}
	_, _, records = rosterFixture(t)
	r.Chain = records
	records[key].Rounds[1].HandraiseRootDigest = fill(0xd3)
	if _, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("other root recorded: %v", err)
	}
	records[key].Rounds[1].HandraiseRootDigest = fill(0xd9)
	o.Rounds[1].RootDigest = fill(0xd9)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID); err == nil || errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("missing bound root: %v", err)
	}
}

// A group member's evidence carries the roots the dispatching Builder signed, as synced: they are
// not in this Builder's own registry, and a member serves the roster with them.
func TestRostersOfAMemberCopy(t *testing.T) {
	_, o, records := rosterFixture(t)
	s := New(kv.NewMemStore(), testParams)
	o.Builder = "trueopen1dispatchingbuilder"
	for i := range o.Rounds {
		root := &taskv1.SignedHandraiseRootV1{ChainId: rosterChain, BuilderAddress: o.Builder, RootHeight: uint64(0x40 + i)}
		raw, err := proto.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		o.Rounds[i].SignedRoot = raw
	}
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	noRoots := func([32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) { return nil, false, nil }
	r := Rosters{ChainID: rosterChain, Evidence: s, Chain: records, Root: noRoots}
	resp, err := r.DispatchRoster(context.Background(), o.SessionID, o.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	for i, round := range resp.GetRounds() {
		if round.GetHandraiseRoot().GetRootHeight() != uint64(0x40+i) || round.GetHandraiseRoot().GetBuilderAddress() != o.Builder {
			t.Fatalf("round %d root = %v", i, round.GetHandraiseRoot())
		}
	}
}
