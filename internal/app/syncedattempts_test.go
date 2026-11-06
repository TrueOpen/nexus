package app

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

type recordedSink struct{ got []attempt.Attempt }

func (r *recordedSink) Recorded(a attempt.Attempt) { r.got = append(r.got, a) }

// vectorWinner is an accepted ticket built from the wire header vector; rank tells two apart.
func vectorWinner(t *testing.T, rank uint32) (attempt.Winner, [32]byte) {
	t.Helper()
	v := wirefixture.Load(t, "task/dispatch_v1.json").Vector(t, "nexus_v1_dispatchresultheaderv1", 0)
	var sv struct {
		ProtobufHex string `json:"protobuf_hex"`
	}
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(sv.ProtobufHex)
	var h nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	ticket := proto.Clone(h.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
	ticket.Rank = rank
	ticketRaw, err := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := dispatch.SigningDigest("task.v1.DispatchTicketV1", ticketRaw)
	if err != nil {
		t.Fatal(err)
	}
	accept := proto.Clone(h.GetAccept()).(*taskv1.DispatchAcceptV1)
	accept.DispatchTicketHash = hash[:]
	accept.TaskId, accept.TaskHash = ticket.GetTaskId(), ticket.GetTaskHash()
	return attempt.Winner{SessionID: hex.EncodeToString(ticket.GetSessionId()), Sequence: ticket.GetOrderSequence(), Ticket: ticket, Accept: accept}, hash
}

// The recorder's RECORDED mark reaches the group sync only when the book now holds that ticket as
// the task's RECORDED attempt.
func TestSyncedAttemptsHandOverOnlyTheRecordedTicket(t *testing.T) {
	newBook := func(t *testing.T) *attempt.Book {
		b, err := attempt.New(kv.NewMemStore(), servicekey.Static(mustSigner(t, 0x01), 1), slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("recorded ticket", func(t *testing.T) {
		book, sink := newBook(t), &recordedSink{}
		w, hash := vectorWinner(t, 0)
		if err := book.Accepted(w); err != nil {
			t.Fatal(err)
		}
		taskID := hex.EncodeToString(w.Ticket.GetTaskId())
		syncedAttempts{book, sink}.Recorded(taskID, hash)
		if len(sink.got) != 1 || sink.got[0].TicketHash != hash || sink.got[0].Status != attempt.Recorded {
			t.Fatalf("handed over %+v", sink.got)
		}
	})
	t.Run("another ticket", func(t *testing.T) {
		book, sink := newBook(t), &recordedSink{}
		w, _ := vectorWinner(t, 0)
		_, other := vectorWinner(t, 1)
		if err := book.Accepted(w); err != nil {
			t.Fatal(err)
		}
		syncedAttempts{book, sink}.Recorded(hex.EncodeToString(w.Ticket.GetTaskId()), other)
		if len(sink.got) != 0 {
			t.Fatalf("another ticket handed over: %+v", sink.got)
		}
	})
	t.Run("not recorded", func(t *testing.T) {
		book, sink := newBook(t), &recordedSink{}
		w, hash := vectorWinner(t, 0)
		if err := book.Accepted(w); err != nil {
			t.Fatal(err)
		}
		taskID := hex.EncodeToString(w.Ticket.GetTaskId())
		book.Rejected(taskID, hash)
		syncedAttempts{book, sink}.Recorded(taskID, hash)
		if len(sink.got) != 0 {
			t.Fatalf("a rejected attempt handed over: %+v", sink.got)
		}
	})
}
