package dispatchevidence

import (
	"bytes"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

func testRoots(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) {
	if digest[0] == 0xd9 {
		return nil, false, nil
	}
	return &taskv1.SignedHandraiseRootV1{ChainId: "c", RootHeight: uint64(digest[0])}, true, nil
}

func rosterBytes(t *testing.T, height uint64) []byte {
	t.Helper()
	raw, err := proto.Marshal(&taskv1.DispatchRosterV1{TaskId: fill(0xaa), ReferenceHeight: height})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// GetDispatchRoster serves a recorded task: every round's roster with the root it binds, and the
// hash of the record the chain holds.
func TestRostersOfARecordedTask(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	o.Rounds[0].Roster, o.Rounds[1].Roster = rosterBytes(t, 90), rosterBytes(t, 91)
	record, err := proto.Marshal(&taskv1.DispatchRecordV1{
		ChainId: "c", TaskId: fill(0xaa), TaskHash: fill(0xbb), SessionId: fill(0x01), OrderSequence: 3,
		CandidatePoolSnapshotId: fill(0x66), VrfOutput: fill(0x05), DispatchTicketHash: fill(0x12),
		BuilderAddress: "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Record, o.Recorded, o.RecordedHeight = record, true, 120
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	r := Rosters{Evidence: s, Root: testRoots}
	resp, err := r.DispatchRoster(o.SessionID, o.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := dispatch.SigningDigest("task.v1.DispatchRecordV1", record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.GetDispatchRecordHash(), wantHash[:]) || len(resp.GetRounds()) != 2 {
		t.Fatalf("response = %v", resp)
	}
	for i, round := range resp.GetRounds() {
		if round.GetDispatchRound() != uint32(i) || round.GetRoster().GetReferenceHeight() != uint64(90+i) ||
			round.GetHandraiseRoot().GetRootHeight() != uint64(0xd1+i) {
			t.Fatalf("round %d = %v", i, round)
		}
	}
}

// A task not recorded, of another session, or without its bound root is not served.
func TestRostersNotServed(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	r := Rosters{Evidence: s, Root: testRoots}
	if _, err := r.DispatchRoster(o.SessionID, o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("unrecorded task: %v", err)
	}
	o.Recorded, o.RecordedHeight = true, 120
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DispatchRoster("02", o.TaskID); !errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("other session: %v", err)
	}
	o.Rounds[1].RootDigest = fill(0xd9)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DispatchRoster(o.SessionID, o.TaskID); err == nil || errors.Is(err, ErrRosterNotFound) {
		t.Fatalf("missing bound root: %v", err)
	}
}
