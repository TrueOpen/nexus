package dispatchevidence

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	outcomeAccepted = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_ACCEPTED
	outcomeRejected = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED
	outcomeTimeout  = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_TIMEOUT
	outcomeVoided   = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_VOIDED
	outcomeRevoked  = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REVOKED
)

var testParams = Params{
	RecordDeadlineBlocks: 20, ClaimWindowBlocks: 30, RebuttalBlocks: 10,
	ChallengeWindowBlocks: 50, ChallengeResponseBlocks: 5, RetentionBlocks: 100,
}

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func ticketBytes(t *testing.T, taskID []byte, rank uint32) []byte {
	t.Helper()
	raw, err := proto.Marshal(&taskv1.DispatchTicketV1{TaskId: taskID, Rank: rank, ChainId: "c"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testOrder is an unrecorded order of task 0xaa with two rounds bound to roots 0xd1 and 0xd2.
func testOrder(t *testing.T) *Order {
	taskID := fill(0xaa)
	return &Order{
		SessionID: hex.EncodeToString(fill(0x01)), Sequence: 3, TaskID: hex.EncodeToString(taskID), TaskHash: hex.EncodeToString(fill(0xbb)),
		Epoch: 7, SignedOrder: []byte("order"), DeadlineBase: 100,
		Rounds: []Round{
			{Number: 0, RootDigest: fill(0xd1), Roster: []byte("roster0"), RosterHash: fill(0xe0), Attempts: []Attempt{
				{Ticket: ticketBytes(t, taskID, 0), Hash: fill(0x10), Rank: 0, Operator: "op0", Sent: true, Outcome: outcomeTimeout},
				{Ticket: ticketBytes(t, taskID, 1), Hash: fill(0x11), Rank: 1, Operator: "op1", Sent: true, Outcome: outcomeRejected, Reject: []byte("reject")},
			}},
			{Number: 1, RootDigest: fill(0xd2), Roster: []byte("roster1"), RosterHash: fill(0xe1), Attempts: []Attempt{
				{Ticket: ticketBytes(t, taskID, 2), Hash: fill(0x12), Rank: 2, Operator: "op2", Sent: true, Outcome: outcomeVoided},
			}},
		},
		Record: []byte("record"),
	}
}

func TestRebuttable(t *testing.T) {
	for _, c := range []struct {
		sent    bool
		outcome taskv1.DispatchAttemptOutcomeV1
		want    bool
	}{
		{true, outcomeRejected, true},
		{true, outcomeTimeout, true},
		{true, outcomeRevoked, true},
		{true, outcomeVoided, false},
		{true, outcomeAccepted, false},
		{true, taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED, false},
		{false, outcomeTimeout, false},
		{false, outcomeRejected, false},
		{false, outcomeRevoked, false},
	} {
		if got := Rebuttable(c.sent, c.outcome); got != c.want {
			t.Errorf("Rebuttable(%v, %s) = %v, want %v", c.sent, c.outcome, got, c.want)
		}
		a := Attempt{Sent: c.sent, Outcome: c.outcome}
		if a.Rebuttable() != c.want {
			t.Errorf("Attempt.Rebuttable(%v, %s) differs", c.sent, c.outcome)
		}
	}
}

func TestPutAndLookups(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	got, a, found, err := s.ByTicket(fill(0x11))
	if err != nil || !found {
		t.Fatalf("ByTicket: %v %v", found, err)
	}
	if got.Key() != o.Key() || a.Rank != 1 || a.Outcome != outcomeRejected || string(a.Reject) != "reject" {
		t.Fatalf("ByTicket = %+v %+v", got, a)
	}
	if _, _, found, _ := s.ByTicket(fill(0x99)); found {
		t.Fatal("unknown ticket found")
	}
	byTask, err := s.ByTask(o.TaskID)
	if err != nil || len(byTask) != 1 || byTask[0].Key() != o.Key() {
		t.Fatalf("ByTask = %v %v", byTask, err)
	}
	// Unrecorded: D + claim window + rebuttal, plus the retention margin.
	if want := uint64(100 + 20 + 30 + 10 + 100); got.RetainUntil != want {
		t.Fatalf("RetainUntil = %d, want %d", got.RetainUntil, want)
	}
	for _, d := range [][]byte{fill(0xd1), fill(0xd2)} {
		if !s.ReferencesRoot([32]byte(d)) {
			t.Fatalf("root %x not referenced", d[:1])
		}
	}
	if s.ReferencesRoot([32]byte(fill(0xd3))) {
		t.Fatal("unbound root referenced")
	}
}

// A ticket of another task version kept in the order's rounds (a retry with another task_hash)
// is not indexed to it: a claim on that ticket names the ticket's own task.
func TestTicketOfAnotherTaskNotIndexed(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	o.Rounds[0].Attempts[0].Ticket = ticketBytes(t, fill(0xcc), 0)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := s.ByTicket(fill(0x10)); found {
		t.Fatal("ticket of another task indexed")
	}
	if _, _, found, _ := s.ByTicket(fill(0x11)); !found {
		t.Fatal("ticket of the task not indexed")
	}
}

func TestRecordedRetention(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	o.Recorded, o.RecordedHeight = true, 115
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	got, _, _, _ := s.ByTicket(fill(0x10))
	// max(D + claim + rebuttal, recorded + challenge window + response) + retention.
	if want := uint64(max(100+20+30+10, 115+50+5) + 100); got.RetainUntil != want {
		t.Fatalf("RetainUntil = %d, want %d", got.RetainUntil, want)
	}
}

// Putting the order again replaces it, never shortens its retention and moves its indexes.
func TestPutReplaces(t *testing.T) {
	store := kv.NewMemStore()
	s := New(store, testParams)
	o := testOrder(t)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if err := s.Extend(o.Key(), 10_000); err != nil {
		t.Fatal(err)
	}
	next := testOrder(t)
	next.Rounds = next.Rounds[:1]
	next.Rounds[0].RootDigest = fill(0xd3)
	if err := s.Put(next); err != nil {
		t.Fatal(err)
	}
	got, _, found, err := s.ByTicket(fill(0x10))
	if err != nil || !found || got.RetainUntil != 10_000 || len(got.Rounds) != 1 {
		t.Fatalf("replaced = %+v %v %v", got, found, err)
	}
	if _, _, found, _ := s.ByTicket(fill(0x12)); found {
		t.Fatal("ticket of the dropped round still indexed")
	}
	if s.ReferencesRoot([32]byte(fill(0xd1))) || s.ReferencesRoot([32]byte(fill(0xd2))) || !s.ReferencesRoot([32]byte(fill(0xd3))) {
		t.Fatal("root references not moved")
	}
	if n := countKeys(t, store, kv.NSDispatchEvidencePrune); n != 1 {
		t.Fatalf("%d prune index entries, want 1", n)
	}
}

func TestPruneDropsOnlyExpired(t *testing.T) {
	store := kv.NewMemStore()
	s := New(store, testParams)
	old := testOrder(t)
	kept := testOrder(t)
	kept.Sequence, kept.TaskID = 4, hex.EncodeToString(fill(0xab))
	kept.DeadlineBase = 500
	for i := range kept.Rounds {
		kept.Rounds[i].RootDigest = fill(0xd2)
		for j := range kept.Rounds[i].Attempts {
			a := &kept.Rounds[i].Attempts[j]
			a.Hash = fill(0x20 + byte(j) + byte(i)*4)
			a.Ticket = ticketBytes(t, fill(0xab), a.Rank)
		}
	}
	for _, o := range []*Order{old, kept} {
		if err := s.Put(o); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Prune(260)
	if err != nil || n != 0 {
		t.Fatalf("Prune(260) = %d %v", n, err)
	}
	if n, err = s.Prune(261); err != nil || n != 1 {
		t.Fatalf("Prune(261) = %d %v", n, err)
	}
	if _, _, found, _ := s.ByTicket(fill(0x10)); found {
		t.Fatal("pruned ticket still found")
	}
	if got, _ := s.ByTask(old.TaskID); len(got) != 0 {
		t.Fatal("pruned task still found")
	}
	if s.ReferencesRoot([32]byte(fill(0xd1))) {
		t.Fatal("root of pruned evidence still referenced")
	}
	if !s.ReferencesRoot([32]byte(fill(0xd2))) {
		t.Fatal("root of kept evidence released")
	}
	if _, _, found, _ := s.ByTicket(fill(0x20)); !found {
		t.Fatal("kept evidence pruned")
	}
}

func TestExtendDelaysPrune(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if err := s.Extend(o.Key(), 400); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Prune(300); n != 0 {
		t.Fatal("extended evidence pruned")
	}
	if n, _ := s.Prune(401); n != 1 {
		t.Fatal("evidence not pruned after its extension")
	}
}

func TestScan(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	if err := s.Put(testOrder(t)); err != nil {
		t.Fatal(err)
	}
	var seen int
	if err := s.Scan(func(o *Order) bool { seen++; return true }); err != nil || seen != 1 {
		t.Fatalf("Scan saw %d, %v", seen, err)
	}
}

// Extra writes go in the same batch as the evidence.
func TestPutWritesExtraOps(t *testing.T) {
	store := kv.NewMemStore()
	s := New(store, testParams)
	if err := s.Put(testOrder(t), kv.WriteOp{NS: kv.NSDispatch, Key: "x", Val: []byte("y")}); err != nil {
		t.Fatal(err)
	}
	if v, ok := store.Get(kv.NSDispatch, "x"); !ok || string(v) != "y" {
		t.Fatal("extra op not written")
	}
}

func countKeys(t *testing.T, store kv.Store, ns kv.Namespace) int {
	t.Helper()
	n := 0
	if err := store.Scan(ns, func(string, []byte) bool { n++; return true }); err != nil {
		t.Fatal(err)
	}
	return n
}

// MarkRecorded marks the evidence holding a ticket as recorded at a height, keeping it at least
// as long as before.
func TestMarkRecorded(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	o := testOrder(t)
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRecorded(fill(0x12), 200); err != nil {
		t.Fatal(err)
	}
	got, _, _, _ := s.ByTicket(fill(0x12))
	if !got.Recorded || got.RecordedHeight != 200 || got.RetainUntil != 200+50+5+100 {
		t.Fatalf("marked = recorded %v at %d, kept until %d", got.Recorded, got.RecordedHeight, got.RetainUntil)
	}
	if err := s.MarkRecorded(fill(0x99), 200); err != nil {
		t.Fatalf("unknown ticket: %v", err)
	}
}

// A later Put of a rebuilt order (the dispatcher's own state never knew of the record) keeps the
// recorded mark and height: they only move forward.
func TestPutKeepsTheRecordedMark(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	if err := s.Put(testOrder(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRecorded(fill(0x12), 200); err != nil {
		t.Fatal(err)
	}
	rebuilt := testOrder(t)
	if err := s.Put(rebuilt); err != nil {
		t.Fatal(err)
	}
	got, _, _, _ := s.ByTicket(fill(0x12))
	if !got.Recorded || got.RecordedHeight != 200 || got.RetainUntil != 200+50+5+100 {
		t.Fatalf("rebuilt = recorded %v at %d, kept until %d", got.Recorded, got.RecordedHeight, got.RetainUntil)
	}
	earlier := testOrder(t)
	earlier.Recorded, earlier.RecordedHeight = true, 150
	if err := s.Put(earlier); err != nil {
		t.Fatal(err)
	}
	if got, _, _, _ := s.ByTicket(fill(0x12)); got.RecordedHeight != 200 {
		t.Fatalf("recorded height moved back to %d", got.RecordedHeight)
	}
}

// MarkRecorded racing with Puts of the same order never loses the mark.
func TestMarkRecordedRacingPuts(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := New(kv.NewMemStore(), testParams)
		if err := s.Put(testOrder(t)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := s.Put(testOrder(t)); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.MarkRecorded(fill(0x12), 200); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if got, _, _, _ := s.ByTicket(fill(0x12)); !got.Recorded || got.RecordedHeight != 200 {
			t.Fatalf("round %d: recorded %v at %d", i, got.Recorded, got.RecordedHeight)
		}
	}
}

// A member's copy of an order and this Builder's own evidence of the same order (after it took the
// session over) are kept apart.
func TestMemberCopyIsKeptApartFromOwnEvidence(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	own := testOrder(t)
	copyOf := testOrder(t)
	copyOf.Builder = "trueopen1dispatchingbuilder"
	for i := range copyOf.Rounds {
		for j := range copyOf.Rounds[i].Attempts {
			copyOf.Rounds[i].Attempts[j].Hash = fill(byte(0x50 + i*4 + j))
		}
	}
	if own.Key() == copyOf.Key() {
		t.Fatal("a member's copy has the key of own evidence")
	}
	for _, o := range []*Order{own, copyOf} {
		if err := s.Put(o); err != nil {
			t.Fatal(err)
		}
	}
	orders, err := s.ByTask(own.TaskID)
	if err != nil || len(orders) != 2 {
		t.Fatalf("orders of the task = %d, %v", len(orders), err)
	}
	got, _, found, err := s.ByTicket(fill(0x50))
	if err != nil || !found || got.Builder != copyOf.Builder {
		t.Fatalf("copy by ticket = %v %v %v", got, found, err)
	}
}

// A takeover back to the same Builder in the same epoch restarts the order's rounds from 0 under a
// new bound_change_height: that generation's evidence is kept apart from the earlier one, whose
// tickets still resolve to it.
func TestBindingGenerationsAreKeptApart(t *testing.T) {
	s := New(kv.NewMemStore(), testParams)
	first := testOrder(t)
	first.BoundChangeHeight = 90
	second := testOrder(t)
	second.BoundChangeHeight = 120
	second.Rounds = second.Rounds[:1]
	for j := range second.Rounds[0].Attempts {
		second.Rounds[0].Attempts[j].Hash = fill(byte(0x60 + j))
	}
	if first.Key() == second.Key() {
		t.Fatal("two binding generations share a key")
	}
	for _, o := range []*Order{first, second} {
		if err := s.Put(o); err != nil {
			t.Fatal(err)
		}
	}
	orders, err := s.ByTask(first.TaskID)
	if err != nil || len(orders) != 2 {
		t.Fatalf("orders of the task = %d, %v", len(orders), err)
	}
	for hash, want := range map[byte]uint64{0x10: 90, 0x12: 90, 0x60: 120} {
		got, a, found, err := s.ByTicket(fill(hash))
		if err != nil || !found || got.BoundChangeHeight != want || a.Hash[0] != hash {
			t.Fatalf("ticket %x = %+v, %v, %v", hash, got, found, err)
		}
	}
}
