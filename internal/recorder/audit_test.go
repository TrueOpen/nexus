package recorder

import (
	"context"
	"reflect"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/kv"
)

// A withdrawn entry the chain admitted anyway is the order's record: the chain assigned the task to
// its Worker. It is resolved like any admitted entry: the ledger, the dispatcher (which ends the new
// round it opened), the attempt book (the voided ticket comes back as the recorded attempt) and the
// task hear of it, and its Worker gets the RECORDED notice.
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
	if want := []orderKey{{b.SessionID, 0}}; !reflect.DeepEqual(e.orders.recorded, want) {
		t.Fatalf("dispatcher told %v", e.orders.recorded)
	}
	if want := []taskReport{{taskID: b.TaskID, height: 11}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("tasks told %v", e.tasks.recorded)
	}
	if want := []attemptReport{{taskID: b.TaskID, ticket: [32]byte(fill(1)), recorded: true}}; !reflect.DeepEqual(e.attempts.reports, want) {
		t.Fatalf("attempt book told %v, want %v", e.attempts.reports, want)
	}
	if n := e.notices(); len(n) != 1 || n[0].n.GetStatus() != statusRecorded {
		t.Fatalf("notices = %v", n)
	}
	if i, j := indexOf(e.calls.log, "attempts.recorded"), indexOf(e.calls.log, "tasks.recorded"); i < 0 || j < 0 || i > j {
		t.Fatalf("calls = %v", e.calls.log)
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
		attempt  attemptReport
	}{
		{"own ticket", &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(1), RecordedHeight: 9}, true, statusRecorded,
			attemptReport{ticket: [32]byte(fill(1)), recorded: true}},
		// The attempt book hears of the recorded ticket first, then of the entry's as rejected.
		{"another own ticket", &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: fill(7), RecordedHeight: 9}, true, statusRejected,
			attemptReport{ticket: [32]byte(fill(7)), recorded: true}},
		{"another Builder", &taskv1.DispatchRecordState{BuilderAddress: worker, DispatchTicketHash: fill(7), RecordedHeight: 9}, false, statusRejected,
			attemptReport{ticket: [32]byte(fill(1))}},
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
			tc.attempt.taskID = b.TaskID
			want := []attemptReport{tc.attempt}
			if tc.name == "another own ticket" {
				want = append(want, attemptReport{taskID: b.TaskID, ticket: [32]byte(fill(1))})
			}
			if !reflect.DeepEqual(e.attempts.reports, want) {
				t.Fatalf("attempt book told %v, want %v", e.attempts.reports, want)
			}
			// The attempt book settles before the task hears of the outcome.
			first, task := "attempts.rejected", "tasks.rejected"
			if tc.recorded {
				first, task = "attempts.recorded", "tasks.recorded"
			}
			if i, j := indexOf(e.calls.log, first), indexOf(e.calls.log, task); i < 0 || j < 0 || i > j {
				t.Fatalf("calls = %v", e.calls.log)
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

// A deadline moved by a later bound_change_height stops at order_expire_height: the Keeper admits
// the order up to and including that height and refuses it after.
func TestDeadlineStopsAtOrderExpireHeight(t *testing.T) {
	e := newEnv(t)
	b := bundle(0xaa, 0, 1, 20)
	b.Entry.SignedOrder.Order.EarliestSubmitHeight = 15
	b.Entry.SignedOrder.Order.OrderExpireHeight = 30
	b.Entry.WinnerTicket.BoundChangeHeight = 25 // 25 + 10 = 35, past order_expire_height
	e.record(b)
	e.block(30)
	if len(e.tasks.rejected) != 0 {
		t.Fatalf("rejected at order_expire_height = %v", e.tasks.rejected)
	}
	e.block(31)
	if want := []taskReport{{taskID: b.TaskID, code: codeLate}}; !reflect.DeepEqual(e.tasks.rejected, want) {
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
	if want := []string{"ledger.suspend", "orders.suspend", "attempts.rejected", "tasks.rejected"}; !reflect.DeepEqual(e.calls.log, want) {
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

func indexOf(log []string, name string) int {
	for i, s := range log {
		if s == name {
			return i
		}
	}
	return -1
}

// winnerOf is b's winner ticket at rank and the accept of it, with the ticket's real digest, as
// the dispatcher hands them to the attempt book.
func winnerOf(t *testing.T, b *dispatcher.Bundle, rank uint32) (attempt.Winner, [32]byte) {
	t.Helper()
	ticket := proto.Clone(b.Entry.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
	ticket.Rank = rank
	ticket.CandidatePoolSnapshotId, ticket.InputHash, ticket.VrfOutput = fill(0x66), fill(0x40), fill(0x0f)
	ticket.RosterHash, ticket.HandraiseRootDigest = fill(0x41), fill(0x42)
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := dispatch.SigningDigest("task.v1.DispatchTicketV1", raw)
	if err != nil {
		t.Fatal(err)
	}
	accept := proto.Clone(b.Entry.GetAccept()).(*taskv1.DispatchAcceptV1)
	accept.DispatchTicketHash = hash[:]
	return attempt.Winner{SessionID: b.SessionID, Sequence: b.Sequence, Ticket: ticket, Accept: accept}, hash
}

// The chain recorded the order with a ticket of this Builder that a binding change voided (its
// withdrawal came too late) and refused the new round's entry as CONFLICT: with the real attempt
// book the recorded ticket becomes the task's RECORDED attempt and the new round's is no longer
// live, so the recorded winner's output is taken and subscribers do not wait on a PENDING attempt.
func TestConflictWithAVoidedOwnTicketSettlesTheBook(t *testing.T) {
	e := newEnv(t)
	book, err := attempt.New(kv.NewMemStore(), e.signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.book = book
	e.open()
	b := bundle(0xaa, 0, 1, 50)
	first, firstHash := winnerOf(t, b, 0)
	second, secondHash := winnerOf(t, b, 1)
	if err := book.Accepted(first); err != nil {
		t.Fatal(err)
	}
	book.Voided(b.TaskID, firstHash)
	if err := book.Accepted(second); err != nil {
		t.Fatal(err)
	}
	b.Entry.WinnerTicket, b.Entry.Accept, b.Entry.Record.DispatchTicketHash = second.Ticket, second.Accept, secondHash[:]
	e.record(b)
	e.block(10)
	msg, raw := e.lastSent()
	e.chain.records[orderKey{b.SessionID, 0}] = &taskv1.DispatchRecordState{BuilderAddress: builder, DispatchTicketHash: firstHash[:], RecordedHeight: 9}
	e.chain.execute(raw, executed(t, msg, 11, refused(codeConflict)))
	e.block(11)
	a, ok := book.Current(b.TaskID)
	if !ok || a.TicketHash != firstHash || a.Status != attempt.Recorded {
		t.Fatalf("attempt = %+v, %v", a, ok)
	}
	if want := []taskReport{{taskID: b.TaskID, height: 9}}; !reflect.DeepEqual(e.tasks.recorded, want) {
		t.Fatalf("tasks recorded = %v", e.tasks.recorded)
	}
}
