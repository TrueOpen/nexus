package attempt

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

// winnerOf builds an accepted ticket from the wire header vector; rank tells two attempts apart.
func winnerOf(t *testing.T, rank uint32) (Winner, [32]byte) {
	t.Helper()
	_, h, _, _ := vectorHeader(t)
	ticket := proto.Clone(h.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
	ticket.Rank = rank
	hash, err := digestOf(ticketName, ticket)
	if err != nil {
		t.Fatal(err)
	}
	accept := proto.Clone(h.GetAccept()).(*taskv1.DispatchAcceptV1)
	accept.DispatchTicketHash = hash[:]
	accept.TaskId, accept.TaskHash = ticket.GetTaskId(), ticket.GetTaskHash()
	return Winner{SessionID: hex.EncodeToString(ticket.GetSessionId()), Sequence: ticket.GetOrderSequence(), Ticket: ticket, Accept: accept}, hash
}

func newBook(t *testing.T, store kv.Store) *Book {
	t.Helper()
	b, err := New(store, newTestSigner(t, 0x01), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkHeader verifies the attempt's signed header: its fields, its status and the Builder signature.
func checkHeader(t *testing.T, b *Book, a Attempt, status Status) {
	t.Helper()
	h, err := a.ResultHeader()
	if err != nil {
		t.Fatal(err)
	}
	if h.GetRecordStatus() != status || hex.EncodeToString(h.GetTaskId()) != a.TaskID {
		t.Fatalf("header status %v task %x, want %v %s", h.GetRecordStatus(), h.GetTaskId(), status, a.TaskID)
	}
	if got, _ := digestOf(ticketName, h.GetWinnerTicket()); got != a.TicketHash || !bytes.Equal(h.GetAccept().GetDispatchTicketHash(), a.TicketHash[:]) {
		t.Fatalf("header names ticket %x, want %x", got, a.TicketHash)
	}
	digest, _ := digestOf(resultHeaderName, h)
	if err := dispatch.VerifyDigestSignature(b.signer.PubKeyCompressed(), digest[:], h.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("header signature: %v", err)
	}
}

func current(t *testing.T, b *Book, taskID string) Attempt {
	t.Helper()
	a, ok := b.Current(taskID)
	if !ok {
		t.Fatalf("no attempt for %s", taskID)
	}
	return a
}

// An accepted ticket is the task's PENDING attempt with a signed PENDING header; the record
// outcome moves it to RECORDED or REJECTED with a header signed again, and a watcher hears each
// change. Outcomes of another ticket change nothing.
func TestAcceptedThenRecordedOrRejected(t *testing.T) {
	for _, final := range []Status{Recorded, Rejected} {
		b := newBook(t, kv.NewMemStore())
		w, hash := winnerOf(t, 0)
		if err := b.Accepted(w); err != nil {
			t.Fatal(err)
		}
		taskID := hex.EncodeToString(w.Ticket.GetTaskId())
		a := current(t, b, taskID)
		if a.Status != Pending || a.TicketHash != hash || a.Worker != w.Ticket.GetTarget().GetOperatorAddress() ||
			a.SessionID != w.SessionID || a.TaskHash != hex.EncodeToString(w.Ticket.GetTaskHash()) ||
			a.InputHash != hex.EncodeToString(w.Ticket.GetInputHash()) || !a.Live() {
			t.Fatalf("attempt = %+v", a)
		}
		checkHeader(t, b, a, Pending)
		changed, stop := b.Watch(taskID)
		_, other := winnerOf(t, 1)
		b.Recorded(taskID, other)
		b.Rejected(taskID, other)
		if current(t, b, taskID).Status != Pending {
			t.Fatal("an outcome of another ticket moved the attempt")
		}
		if final == Recorded {
			b.Recorded(taskID, hash)
		} else {
			b.Rejected(taskID, hash)
		}
		select {
		case <-changed:
		default:
			t.Fatal("watcher not told")
		}
		stop()
		a = current(t, b, taskID)
		if a.Status != final || a.Live() != (final == Recorded) {
			t.Fatalf("attempt %+v after %v", a, final)
		}
		checkHeader(t, b, a, final)
	}
}

// A voided winner leaves the task without a live attempt; a void that overtook the accept keeps
// that accept out.
func TestVoided(t *testing.T) {
	b := newBook(t, kv.NewMemStore())
	w, hash := winnerOf(t, 0)
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	if err := b.Accepted(w); err != nil {
		t.Fatal(err)
	}
	b.Voided(taskID, hash)
	if _, ok := b.Current(taskID); ok {
		t.Fatal("voided attempt still current")
	}
	w2, hash2 := winnerOf(t, 1)
	b.Voided(taskID, hash2)
	if err := b.Accepted(w2); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Current(taskID); ok {
		t.Fatal("an accept voided before it arrived became current")
	}
}

// A retry's accept replaces a rejected attempt; a recorded attempt is never replaced.
func TestRetryReplacesRejected(t *testing.T) {
	b := newBook(t, kv.NewMemStore())
	w, hash := winnerOf(t, 0)
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	_ = b.Accepted(w)
	b.Rejected(taskID, hash)
	w2, hash2 := winnerOf(t, 1)
	if err := b.Accepted(w2); err != nil {
		t.Fatal(err)
	}
	if a := current(t, b, taskID); a.TicketHash != hash2 || a.Status != Pending {
		t.Fatalf("attempt after retry = %+v", a)
	}
	b.Recorded(taskID, hash2)
	w3, _ := winnerOf(t, 2)
	if err := b.Accepted(w3); err == nil {
		t.Fatal("a recorded attempt was replaced")
	}
	if a := current(t, b, taskID); a.TicketHash != hash2 || a.Status != Recorded {
		t.Fatalf("recorded attempt = %+v", a)
	}
}

// The book survives a restart: a new book over the same store holds the same attempts and
// headers.
func TestBookRestores(t *testing.T) {
	store := kv.NewMemStore()
	b := newBook(t, store)
	w, hash := winnerOf(t, 0)
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	_ = b.Accepted(w)
	b.Recorded(taskID, hash)
	before := current(t, b, taskID)
	restored := current(t, newBook(t, store), taskID)
	if restored.TicketHash != before.TicketHash || restored.Status != Recorded || !bytes.Equal(restored.Header, before.Header) {
		t.Fatalf("restored %+v, want %+v", restored, before)
	}
}

// An accept that does not name its ticket is refused.
func TestAcceptedChecksTheAccept(t *testing.T) {
	b := newBook(t, kv.NewMemStore())
	w, _ := winnerOf(t, 0)
	w.Accept.DispatchTicketHash = bytes.Repeat([]byte{9}, 32)
	if err := b.Accepted(w); err == nil {
		t.Fatal("accept of another ticket taken")
	}
}
