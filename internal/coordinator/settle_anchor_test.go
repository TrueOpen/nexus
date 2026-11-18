package coordinator

import (
	"io"
	"log/slog"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/types"
)

// newSettleScheduleFSM builds an FSM with three selected Builders and two grace blocks per rank,
// holding only the round 1 deadlines the settlement schedule reads.
func newSettleScheduleFSM(deadlines types.Deadlines) *taskFSM {
	return &taskFSM{
		log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		self:              testBuilderSelf,
		sessionID:         "sess-settle-anchor",
		taskID:            testTaskID("settle-anchor"),
		state:             types.Verifying,
		deadlines:         deadlines,
		settleGraceBlocks: 2,
		settleSelection: chaincli.StageBuilderSelectionState{
			SelectedBuilders: []string{"builder-a", "builder-b", "builder-c"},
		},
	}
}

// The chain counts the settlement submitter schedule from the round 1 reveal deadline, or from
// the commit deadline when round 1 closed without entering reveal.
func TestSettleSlotAtCountsFromTheScheduleAnchor(t *testing.T) {
	type want struct {
		slot           uint64
		permissionless bool
	}
	cases := []struct {
		name      string
		deadlines types.Deadlines
		anchor    uint64
	}{
		{"revealed round anchors on the reveal deadline", types.Deadlines{Commit: 100, Reveal: 120, Verify: 140}, 120},
		{"unrevealed round anchors on the commit deadline", types.Deadlines{Commit: 100, Verify: 140}, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleScheduleFSM(tc.deadlines)
			a := tc.anchor
			for height, w := range map[uint64]want{
				a:     {0, false}, // up to the anchor: rank 1
				a + 1: {0, false},
				a + 2: {0, false},
				a + 3: {1, false},
				a + 4: {1, false},
				a + 5: {2, false},
				a + 6: {2, false},
				a + 7: {0, true}, // every slot passed: anyone
			} {
				slot, permissionless, ok := f.settleSlotAt(height)
				if !ok || slot != w.slot || permissionless != w.permissionless {
					t.Fatalf("settleSlotAt(%d) = (%d, %v, %v), want (%d, %v, true)",
						height, slot, permissionless, ok, w.slot, w.permissionless)
				}
			}
		})
	}
}

func TestSettleSlotAtUnknownWithoutAnyDeadline(t *testing.T) {
	f := newSettleScheduleFSM(types.Deadlines{Verify: 140})
	if _, _, ok := f.settleSlotAt(200); ok {
		t.Fatal("settleSlotAt must not guess a schedule without a commit or reveal deadline")
	}
	if allowed, _ := f.settleSubmissionAllowed(1); allowed {
		t.Fatal("settlement must not be allowed without a schedule anchor")
	}
}

// With only a commit deadline the slot boundaries, and so the first-block-of-slot exception to
// simulation, follow the commit deadline.
func TestSettleSlotBoundaryFollowsTheCommitDeadlineWhenUnrevealed(t *testing.T) {
	f := newSettleScheduleFSM(types.Deadlines{Commit: 100, Verify: 140})
	for _, tc := range []struct {
		observed uint64
		changes  bool
	}{
		{100, false}, // 100 -> 101: both rank 1
		{101, false},
		{102, true}, // 102 -> 103: rank 1 -> rank 2
		{104, true}, // 104 -> 105: rank 2 -> rank 3
		{106, true}, // 106 -> 107: rank 3 -> anyone
		{107, false},
		{120, false}, // the reveal-anchored boundary 122 -> 123 must not apply
		{122, false},
	} {
		f.observedHeight = tc.observed
		if got := f.settleSlotChangesAtExecution(); got != tc.changes {
			t.Fatalf("observed %d: settleSlotChangesAtExecution = %v, want %v", tc.observed, got, tc.changes)
		}
	}
	f.observedHeight = 102 // executes at 103: rank 2's slot
	if allowed, permissionless := f.settleSubmissionAllowed(2); !allowed || permissionless {
		t.Fatalf("rank 2 at execution height 103: allowed = %v, permissionless = %v; want true, false", allowed, permissionless)
	}
	if allowed, _ := f.settleSubmissionAllowed(1); allowed {
		t.Fatal("rank 1 must not submit in rank 2's slot")
	}
}
