package recorder

import (
	"context"
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatcher"
)

// A withdrawn entry the chain admitted anyway consumed its sequence: the ledger records it, but
// the dispatcher, which opened a new round for the order, and the task are left to that round.
func TestWithdrawnEntryAdmitted(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()
	e.r.Withdraw(context.Background(), b.SessionID, 0, [32]byte(fill(1)))
	e.chain.execute(raw, executed(t, msg, 11, ok()))
	e.block(11)
	if want := []orderKey{{b.SessionID, 0}}; !reflect.DeepEqual(e.ledger.recorded, want) {
		t.Fatalf("ledger recorded = %v", e.ledger.recorded)
	}
	if len(e.orders.recorded) != 0 || len(e.tasks.recorded) != 0 {
		t.Fatalf("dispatcher %v, tasks %v told", e.orders.recorded, e.tasks.recorded)
	}
	// The evidence of the recorded ticket is marked recorded: challenges on the order may come.
	if want := []evidenceMark{{string(fill(1)), 11}}; !reflect.DeepEqual(e.evidence.marks, want) {
		t.Fatalf("evidence marks = %v", e.evidence.marks)
	}
}

// CONFLICT means the order is recorded with another entry: when the record is this Builder's the
// order is recorded (the entry's own ticket, or another of this Builder's tickets for it); a record
// of another Builder fails the entry as usual.
func TestConflictIsCheckedAgainstTheRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		record   *taskv1.DispatchRecordState
		recorded bool
		notice   taskv1.DispatchRecordStatusV1
	}{
		{"own ticket", &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(1), RecordedHeight: 9}, true, statusRecorded},
		{"another own ticket", &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(7), RecordedHeight: 9}, true, statusRejected},
		{"another Builder", &taskv1.DispatchRecordState{BuilderAddress: worker, DispatchTicketHash: fill(7), RecordedHeight: 9}, false, statusRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			b := bundle(0xaa, 0, 1, 50)
			e.record(b)
			e.block(10)
			msg, raw := e.lastSent()
			e.chain.records[orderKey{b.SessionID, 0}] = tc.record
			e.chain.execute(raw, executed(t, msg, 11, refused(codeConflict)))
			e.block(11)
			if tc.recorded {
				if want := []taskReport{{taskID: b.TaskID, height: 9}}; !reflect.DeepEqual(e.tasks.recorded, want) || len(e.orders.recorded) != 1 || len(e.ledger.recorded) != 1 {
					t.Fatalf("recorded: tasks %v, orders %v, ledger %v", e.tasks.recorded, e.orders.recorded, e.ledger.recorded)
				}
				if !reflect.DeepEqual(e.orders.heights, []uint64{9}) {
					t.Fatalf("dispatcher told recorded heights %v", e.orders.heights)
				}
				if len(e.ledger.suspended) != 0 || len(e.tasks.rejected) != 0 {
					t.Fatalf("suspended %v, rejected %v", e.ledger.suspended, e.tasks.rejected)
				}
			} else if want := []taskReport{{taskID: b.TaskID, code: codeConflict}}; !reflect.DeepEqual(e.tasks.rejected, want) || len(e.ledger.suspended) != 1 {
				t.Fatalf("rejected %v, suspended %v", e.tasks.rejected, e.ledger.suspended)
			}
			if n := e.notices(); len(n) != 1 || n[0].n.GetStatus() != tc.notice {
				t.Fatalf("notices = %v", n)
			}
		})
	}
}

// A NOOP result replays the first admission: its height is the record's, not the replay's.
func TestNoopTakesTheRecordedHeight(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 50)
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.records[orderKey{b.SessionID, 0}] = &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(1), RecordedHeight: 7}
	e.chain.execute(raw, executed(t, msg, 11, result{status: noop}))
	e.block(11)
	if want := []taskReport{{taskID: b.TaskID, height: 7}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("recorded = %v", e.tasks.recorded)
	}
}

// The record deadline is recomputed from the entry (max of earliest_submit_height and the winner
// ticket's bound_change_height, plus the current record_deadline_blocks) and never shortened.
func TestDeadlineIsRecomputedFromTheEntry(t *testing.T) {
	e := newEnv(t)
	longer := bundle(0xaa, 0, 1, 20)
	longer.Entry.SignedOrder.Order.EarliestSubmitHeight = 15
	longer.Entry.WinnerTicket.BoundChangeHeight = 25 // 25 + 10 = 35
	shorter := bundle(0xbb, 0, 2, 30)
	shorter.Entry.SignedOrder.Order.EarliestSubmitHeight = 5 // 5 + 10 = 15: the stored 30 stays
	e.record(longer, shorter)
	e.block(25)
	if msgs, _ := e.tx.sent(); len(msgs) != 1 || !reflect.DeepEqual(entriesOf(msgs[0]), []string{"aa/0", "bb/0"}) {
		t.Fatalf("submitted %v", e.tx.msgs)
	}
	e.block(31)
	if want := []taskReport{{taskID: shorter.TaskID, code: codeLate}}; !reflect.DeepEqual(e.tasks.rejected, want) {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
	e.block(36)
	if len(e.tasks.rejected) != 2 || e.tasks.rejected[1].taskID != longer.TaskID {
		t.Fatalf("rejected = %v", e.tasks.rejected)
	}
}

// A refused record suspends the session in the ledger and the dispatcher before the task hears
// of it, so a resend the SDK sends at once finds the suspension to lift.
func TestSuspensionComesBeforeTheRejection(t *testing.T) {
	e := newEnv(t)
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.execute(raw, executed(t, msg, 11, refused(codeBalance)))
	e.block(11)
	if want := []string{"ledger.suspend", "orders.suspend", "tasks.rejected"}; !reflect.DeepEqual(e.calls.log, want) {
		t.Fatalf("calls = %v", e.calls.log)
	}
}

// An account not read yet is not reported as an unconfirmed key.
func TestUnreadAccountIsItsOwnError(t *testing.T) {
	e := newEnv(t)
	e.account.set("", errUnreadable)
	e.open()
	if err := e.gate.CheckBuilderKey(context.Background()); !errorsIs(err, dispatcher.ErrCompensationUnread) {
		t.Fatalf("gate = %v", err)
	}
}
