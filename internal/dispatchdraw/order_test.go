package dispatchdraw

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

const (
	stickySequence = 12
	stickyESH      = 1050
)

var stickyParams = StickyParams{MaxOrders: 3, WindowBlocks: 50}

// drawnVector is the full-pool order [7, 3, 1] of the wire weighted order vector.
func drawnVector(t *testing.T, pool *Pool) []dispatch.RosterMember {
	t.Helper()
	drawn, err := pool.Draw(vectorChainID, fill32(0x88), 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := slots(drawn); !reflect.DeepEqual(got, []uint32{7, 3, 1}) {
		t.Fatalf("drawn = %v", got)
	}
	return drawn
}

// stickySnapshot has the previous winner at slot 1, two orders into its run, anchored at 1000.
func stickySnapshot() *taskv1.DispatchStickySnapshotV1 {
	winner := vectorOp1
	return &taskv1.DispatchStickySnapshotV1{LastRecordWinner: &winner, AnchorSequence: 10, AnchorHeight: 1000, RunCount: 2}
}

// The previous recorded winner moves to the front exactly when it is in the first-round roster
// (which implies a free slot), its run is below sticky_max_orders, and the order's
// earliest_submit_height is within sticky_window_blocks of the run's anchor height.
func TestStickyPromotionBoundaries(t *testing.T) {
	pool := vectorPool(t)
	drawn := drawnVector(t, pool)
	full := vectorRoster(t, pool)
	without1 := rosterOf(t, pool, vectorOp3, vectorOp7)

	cases := []struct {
		name    string
		snap    func(s *taskv1.DispatchStickySnapshotV1)
		params  StickyParams
		esh     uint64
		roster  *Roster
		applied bool
	}{
		{name: "all conditions hold", applied: true},
		{name: "no previous winner", snap: func(s *taskv1.DispatchStickySnapshotV1) { s.LastRecordWinner = nil }},
		{name: "empty previous winner", snap: func(s *taskv1.DispatchStickySnapshotV1) { empty := ""; s.LastRecordWinner = &empty }},
		{name: "winner not in first roster", roster: without1},
		{name: "winner outside the pool", snap: func(s *taskv1.DispatchStickySnapshotV1) { other := "trueopen1elsewhere"; s.LastRecordWinner = &other }},
		{name: "run count at max", snap: func(s *taskv1.DispatchStickySnapshotV1) { s.RunCount = 3 }},
		{name: "run count above max", snap: func(s *taskv1.DispatchStickySnapshotV1) { s.RunCount = 4 }},
		{name: "run count one below max", snap: func(s *taskv1.DispatchStickySnapshotV1) { s.RunCount = 2 }, applied: true},
		{name: "stickiness disabled", params: StickyParams{MaxOrders: 0, WindowBlocks: 50}},
		{name: "window edge", esh: 1050, applied: true},
		{name: "past the window", esh: 1051},
		{name: "zero window same height", params: StickyParams{MaxOrders: 3}, esh: 1000, applied: true},
		{name: "zero window next height", params: StickyParams{MaxOrders: 3}, esh: 1001},
		{name: "order signed before the anchor was recorded", esh: 990},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := stickySnapshot()
			if tc.snap != nil {
				tc.snap(snap)
			}
			params := stickyParams
			if tc.params != (StickyParams{}) {
				params = tc.params
			}
			esh := uint64(stickyESH)
			if tc.esh != 0 {
				esh = tc.esh
			}
			roster := full
			if tc.roster != nil {
				roster = tc.roster
			}
			order, err := NewOrder(drawn, roster, snap, params, esh, stickySequence)
			if err != nil {
				t.Fatal(err)
			}
			if order.StickyApplied != tc.applied {
				t.Fatalf("sticky applied = %v, want %v", order.StickyApplied, tc.applied)
			}
			want := []uint32{7, 3, 1}
			if tc.applied {
				want = []uint32{1, 7, 3}
			}
			if got := slots(order.Members); !reflect.DeepEqual(got, want) {
				t.Fatalf("order = %v, want %v", got, want)
			}
		})
	}
}

// The sticky target's ticket continues the run; every other ticket starts a new run at this order.
func TestStickyCommitmentsPerTicket(t *testing.T) {
	pool := vectorPool(t)
	order, err := NewOrder(drawnVector(t, pool), vectorRoster(t, pool), stickySnapshot(), stickyParams, stickyESH, stickySequence)
	if err != nil {
		t.Fatal(err)
	}
	if seq, run := order.Sticky(0); seq != 10 || run != 3 {
		t.Fatalf("sticky target commitment = (%d, %d), want (10, 3)", seq, run)
	}
	for rank := uint32(1); rank < 3; rank++ {
		if seq, run := order.Sticky(rank); seq != stickySequence || run != 1 {
			t.Fatalf("rank %d commitment = (%d, %d), want (%d, 1)", rank, seq, run, stickySequence)
		}
	}

	plain, err := NewOrder(drawnVector(t, pool), vectorRoster(t, pool), &taskv1.DispatchStickySnapshotV1{}, stickyParams, stickyESH, stickySequence)
	if err != nil {
		t.Fatal(err)
	}
	if seq, run := plain.Sticky(0); plain.StickyApplied || seq != stickySequence || run != 1 {
		t.Fatalf("without stickiness rank 0 = (%d, %d) applied %v", seq, run, plain.StickyApplied)
	}
}

// Stickiness is decided once from the first round's roster. A later round whose roster lacks the
// sticky target skips it as an ordinary filter: the order and sticky_applied do not change.
func TestOrderIsFixedAcrossRoundsAndRostersOnlyFilter(t *testing.T) {
	pool := vectorPool(t)
	order, err := NewOrder(drawnVector(t, pool), vectorRoster(t, pool), stickySnapshot(), stickyParams, stickyESH, stickySequence)
	if err != nil {
		t.Fatal(err)
	}
	// Round 0: rank 0 (the sticky target, slot 1) rejected; the dispatcher resumes after it.
	round1 := rosterOf(t, pool, vectorOp3)
	c, ok := order.Next(round1, 1)
	if !ok || c.Rank != 2 || c.Member.Slot != 3 {
		t.Fatalf("next = %+v %v; want rank 2 slot 3", c, ok)
	}
	if c.StickyAnchorSequence != stickySequence || c.StickyRunCount != 1 {
		t.Fatalf("candidate after the sticky target commits (%d, %d)", c.StickyAnchorSequence, c.StickyRunCount)
	}
	if !order.StickyApplied || !reflect.DeepEqual(slots(order.Members), []uint32{1, 7, 3}) {
		t.Fatal("a later roster must not change the order or sticky_applied")
	}
	// A later roster without the sticky target, from the start: rank 0 is skipped, not an attempt.
	c, ok = order.Next(round1, 0)
	if !ok || c.Rank != 2 {
		t.Fatalf("next from 0 = %+v %v; want rank 2", c, ok)
	}
	if _, ok := order.Next(round1, 3); ok {
		t.Fatal("no rank after the last")
	}
}

func TestOrderCandidatesSkipMembersNotInTheRoster(t *testing.T) {
	pool := vectorPool(t)
	order, err := NewOrder(drawnVector(t, pool), vectorRoster(t, pool), &taskv1.DispatchStickySnapshotV1{}, stickyParams, stickyESH, stickySequence)
	if err != nil {
		t.Fatal(err)
	}
	// Order [7, 3, 1]; only 7 and 1 are available.
	roster := rosterOf(t, pool, vectorOp7, vectorOp1)
	var ranks []uint32
	for c := range order.Candidates(roster, 0) {
		ranks = append(ranks, c.Rank)
		if c.Member != order.Members[c.Rank] {
			t.Fatalf("candidate %+v is not the order's member at its rank", c)
		}
	}
	if !slices.Equal(ranks, []uint32{0, 2}) {
		t.Fatalf("ranks = %v, want [0 2]", ranks)
	}
	ranks = ranks[:0]
	for c := range order.Candidates(roster, 1) {
		ranks = append(ranks, c.Rank)
		break
	}
	if !slices.Equal(ranks, []uint32{2}) {
		t.Fatalf("ranks from 1 = %v, want [2]", ranks)
	}
}

func TestNewOrderRejectsBadInput(t *testing.T) {
	pool := vectorPool(t)
	roster := vectorRoster(t, pool)
	if _, err := NewOrder(nil, roster, stickySnapshot(), stickyParams, stickyESH, stickySequence); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("empty order: %v", err)
	}
	if _, err := NewOrder(drawnVector(t, pool), nil, stickySnapshot(), stickyParams, stickyESH, stickySequence); err == nil {
		t.Fatal("missing first roster must be rejected")
	}
}

// Drawer ties the epoch, the VRF and the pool together: the same order drawn twice gets the same
// proof and full order.
func TestDrawerDrawsTheWholePoolOnce(t *testing.T) {
	key := testKey(5)
	keys, err := NewVRFKeys([]ed25519.PrivateKey{key}, registryFor(map[uint64]ed25519.PrivateKey{1: key}))
	if err != nil {
		t.Fatal(err)
	}
	src := vectorPoolSource()
	drawer, err := NewDrawer(vectorChainID, &fakeEpochs{byHeight: map[uint64]Epoch{105: vectorEpoch}}, keys, NewPoolCache(vectorChainID, src))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session := fill32(0x5a)
	d, err := drawer.Draw(ctx, session, 7, 105, vectorProfile, 64)
	if err != nil {
		t.Fatal(err)
	}
	if d.Epoch != vectorEpoch || d.VRF.Epoch != 1 || !reflect.DeepEqual(d.Pool.Members, vectorPool(t).Members) {
		t.Fatalf("draw context = %+v", d)
	}
	if err := dispatch.VerifyDispatchVRF(key.Public().(ed25519.PublicKey), d.VRF.Alpha[:], d.VRF.Proof, d.VRF.Output[:]); err != nil {
		t.Fatal(err)
	}
	want, err := d.Pool.Draw(vectorChainID, d.VRF.Output, 64)
	if err != nil || !reflect.DeepEqual(d.Drawn, want) || len(d.Drawn) != 3 {
		t.Fatalf("drawn = %v, want the full pool order %v (%v)", slots(d.Drawn), slots(want), err)
	}
	again, err := drawer.Draw(ctx, session, 7, 105, vectorProfile, 64)
	if err != nil || again.VRF.Output != d.VRF.Output || !reflect.DeepEqual(again.Drawn, d.Drawn) {
		t.Fatalf("redraw differs: %v", err)
	}
	if src.listCalls != 1 {
		t.Fatalf("pool read %d times", src.listCalls)
	}
	if _, err := drawer.Draw(ctx, session, 7, 999, vectorProfile, 64); err == nil {
		t.Fatal("unknown epoch must fail")
	}
}

// rosterOf builds a roster admitting exactly operators (all from the vector pool).
func rosterOf(t *testing.T, pool *Pool, operators ...string) *Roster {
	t.Helper()
	var leaves []*taskv1.HandraiseRootLeafV1
	for _, op := range operators {
		m, ok := pool.Member(op)
		if !ok {
			t.Fatalf("%s not in pool", op)
		}
		leaves = append(leaves, leaf(op, m.Slot, true, 1, 200, vectorProfile))
	}
	roster, err := BuildRoster(vectorChainID, vectorTaskID, issuedRoot(leaves...), pool, 150, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return roster
}
