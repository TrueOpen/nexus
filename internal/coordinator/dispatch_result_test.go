package coordinator

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
)

// The dispatch result header OpenTask returns is the winning attempt's signed header at its
// current record status, and only for the task's own session.
func TestDispatchResultIsTheAttemptHeader(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	session, task := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	if _, ok := c.DispatchResult(context.Background(), session, task); ok {
		t.Fatal("header without an attempt book")
	}
	book := newTestBook(t, kv.NewMemStore())
	c.SetAttempts(book)
	w, hash := testWinner(t, session, task, testOperator("worker-1"), 0)
	if err := book.Accepted(w); err != nil {
		t.Fatal(err)
	}
	h, ok := c.DispatchResult(context.Background(), session, task)
	if !ok || h.GetRecordStatus() != attempt.Pending || string(h.GetAccept().GetDispatchTicketHash()) != string(hash[:]) {
		t.Fatalf("header = %v %v", h, ok)
	}
	book.Recorded(task, hash)
	if h, _ := c.DispatchResult(context.Background(), session, task); h.GetRecordStatus() != attempt.Recorded {
		t.Fatalf("status after the record = %v", h.GetRecordStatus())
	}
	if _, ok := c.DispatchResult(context.Background(), strings.Repeat("cc", 32), task); ok {
		t.Fatal("header for another session")
	}
}
