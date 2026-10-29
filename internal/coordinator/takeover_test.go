package coordinator

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

// An order held for a takeover has a task and a journal from intake on, but goes to the dispatcher
// only once the takeover took effect: ORDER_RECEIVED, TAKEOVER_PENDING (chain_height is the
// activation height) and TAKEOVER_RECORDED, and the task status names the takeover stage.
func TestTakeoverJournal(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	d := &fakeDispatcher{}
	c.SetDispatcher(d)
	ctx := context.Background()
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnTakeover(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := c.OnTakeover(ctx, o); err != nil {
		t.Fatalf("again: %v", err)
	}
	if len(d.dispatched) != 0 {
		t.Fatal("a held order was dispatched")
	}
	c.TakeoverRegistered(o.SessionID, o.TaskID, 130)
	status, err := c.TaskStatus(ctx, o.SessionID, o.TaskID)
	if err != nil || status.Stage != EvTakeoverPending {
		t.Fatalf("status = %+v, %v", status, err)
	}
	events := c.journalFor(taskKey(o.SessionID, o.TaskID)).snapshot()
	if last := events[len(events)-1]; last.EventCode != EvTakeoverPending || last.ChainHeight != 130 {
		t.Fatalf("last event = %+v", last)
	}
	c.TakeoverActivated(o.SessionID, o.TaskID, 130)
	if err := c.OnOrder(ctx, o); err != nil {
		t.Fatal(err)
	}
	if len(d.dispatched) != 1 {
		t.Fatalf("dispatched %d", len(d.dispatched))
	}
	if got := strings.Join(eventCodes(c, o.SessionID, o.TaskID), ","); got != "ORDER_RECEIVED,TAKEOVER_PENDING,TAKEOVER_RECORDED" {
		t.Fatalf("events = %s", got)
	}
	if status, _ := c.TaskStatus(ctx, o.SessionID, o.TaskID); status.Stage != EvTakeoverRecorded {
		t.Fatalf("stage after activation = %q", status.Stage)
	}
	// An ordinary order has no stage.
	other := testPlaceholderOrder("session-2", "task-2")
	if err := c.OnOrder(ctx, other); err != nil {
		t.Fatal(err)
	}
	if status, _ := c.TaskStatus(ctx, other.SessionID, other.TaskID); status.Stage != "" {
		t.Fatalf("stage of an ordinary order = %q", status.Stage)
	}
}

// A takeover that ends without taking effect drops the task with its code; the journal stays. A
// voided takeover also drops the input, an expired order keeps it for the resend.
func TestTakeoverEnded(t *testing.T) {
	backend := kv.NewMemStore()
	taskStore, payloads := newCoordinatorTaskData(t, backend)
	c, _ := newTestCoordinator(t, WithPayloadStore(payloads))
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	voided := taskPayloadOrder(t, testPayloadSession, testPayloadTask, testUserAddress, []byte("voided input"), 100)
	voidedKey := stageOrderInput(t, taskStore, voided, []byte("voided input"), true)
	expired := taskPayloadOrder(t, testPayloadSession, strings.Repeat("7", 64), testUserAddress, []byte("expired input"), 100)
	expiredKey := stageOrderInput(t, taskStore, expired, []byte("expired input"), true)
	if err := c.OnTakeover(ctx, voided); err != nil {
		t.Fatal(err)
	}
	if err := c.OnTakeover(ctx, expired); err != nil {
		t.Fatal(err)
	}
	c.TakeoverEnded(voided.SessionID, voided.TaskID, EvTakeoverVoided, 120, true)
	c.TakeoverEnded(expired.SessionID, expired.TaskID, EvOrderExpired, 131, false)
	for _, o := range []string{voided.TaskID, expired.TaskID} {
		if _, ok := c.getFSM(testPayloadSession, o); ok {
			t.Fatalf("%s kept its task", o)
		}
	}
	if got := strings.Join(eventCodes(c, voided.SessionID, voided.TaskID), ","); got != "ORDER_RECEIVED,TAKEOVER_VOIDED" {
		t.Fatalf("voided events = %s", got)
	}
	if got := strings.Join(eventCodes(c, expired.SessionID, expired.TaskID), ","); got != "ORDER_RECEIVED,ORDER_EXPIRED" {
		t.Fatalf("expired events = %s", got)
	}
	if !inputDeleted(t, taskStore, voidedKey) {
		t.Fatal("the input of a voided takeover stayed")
	}
	if inputDeleted(t, taskStore, expiredKey) {
		t.Fatal("the input of an expired order was dropped")
	}
	// Ending an unknown or already ended takeover does nothing.
	c.TakeoverEnded(voided.SessionID, voided.TaskID, EvTakeoverVoided, 121, true)
}
