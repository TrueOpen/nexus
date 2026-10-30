package attempt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
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

// A winner voided by a binding change whose entry the chain admitted anyway (the withdrawal came
// too late) becomes the task's RECORDED attempt in place of the new round's PENDING one: its
// stream is the live one, the new round's ticket is stale, and a later rejection of the new
// round's ticket changes nothing. Held aside, it survives a restart.
func TestChainRecordedVoidedWinnerReplacesThePendingOne(t *testing.T) {
	for _, restart := range []bool{false, true} {
		store := kv.NewMemStore()
		b := newBook(t, store)
		first, firstHash := winnerOf(t, 0)
		taskID := hex.EncodeToString(first.Ticket.GetTaskId())
		if err := b.Accepted(first); err != nil {
			t.Fatal(err)
		}
		b.Voided(taskID, firstHash)
		second, secondHash := winnerOf(t, 1)
		if err := b.Accepted(second); err != nil {
			t.Fatal(err)
		}
		if restart {
			b = newBook(t, store)
		}
		changed, stop := b.Watch(taskID)
		b.Recorded(taskID, firstHash)
		b.Rejected(taskID, secondHash)
		select {
		case <-changed:
		default:
			t.Fatal("watcher not told")
		}
		stop()
		a := current(t, b, taskID)
		if a.TicketHash != firstHash || a.Status != Recorded || a.Worker != first.Ticket.GetTarget().GetOperatorAddress() {
			t.Fatalf("restart %t: attempt = %+v", restart, a)
		}
		checkHeader(t, b, a, Recorded)
		if again := current(t, newBook(t, store), taskID); again.TicketHash != firstHash || again.Status != Recorded {
			t.Fatalf("restart %t: restored attempt = %+v", restart, again)
		}
	}
}

// With the new round's ticket rejected first, the chain's record of the voided winner still
// makes it the task's attempt.
func TestChainRecordedVoidedWinnerReplacesARejectedOne(t *testing.T) {
	b := newBook(t, kv.NewMemStore())
	first, firstHash := winnerOf(t, 0)
	taskID := hex.EncodeToString(first.Ticket.GetTaskId())
	_ = b.Accepted(first)
	b.Voided(taskID, firstHash)
	second, secondHash := winnerOf(t, 1)
	_ = b.Accepted(second)
	b.Rejected(taskID, secondHash)
	b.Recorded(taskID, firstHash)
	if a := current(t, b, taskID); a.TicketHash != firstHash || a.Status != Recorded {
		t.Fatalf("attempt = %+v", a)
	}
}

// An accept for a task recorded with another ticket is refused with ErrRecordedWithAnotherTicket;
// an accept over another PENDING ticket replaces it.
func TestAcceptedOverAnotherTicket(t *testing.T) {
	b := newBook(t, kv.NewMemStore())
	first, _ := winnerOf(t, 0)
	taskID := hex.EncodeToString(first.Ticket.GetTaskId())
	_ = b.Accepted(first)
	second, secondHash := winnerOf(t, 1)
	if err := b.Accepted(second); err != nil {
		t.Fatal(err)
	}
	if a := current(t, b, taskID); a.TicketHash != secondHash || a.Status != Pending {
		t.Fatalf("attempt = %+v", a)
	}
	b.Recorded(taskID, secondHash)
	third, _ := winnerOf(t, 2)
	if err := b.Accepted(third); !errors.Is(err, ErrRecordedWithAnotherTicket) {
		t.Fatalf("accept over a recorded attempt = %v", err)
	}
}

// Forget drops the task's attempt and its voided ones, from memory and the store.
func TestForget(t *testing.T) {
	store := kv.NewMemStore()
	b := newBook(t, store)
	first, firstHash := winnerOf(t, 0)
	taskID := hex.EncodeToString(first.Ticket.GetTaskId())
	_ = b.Accepted(first)
	b.Voided(taskID, firstHash)
	second, _ := winnerOf(t, 1)
	_ = b.Accepted(second)
	changed, stop := b.Watch(taskID)
	defer stop()
	b.Forget(taskID)
	select {
	case <-changed:
	default:
		t.Fatal("watcher not told")
	}
	b.Recorded(taskID, firstHash)
	if _, ok := b.Current(taskID); ok {
		t.Fatal("forgotten task still has an attempt")
	}
	if _, ok := newBook(t, store).Current(taskID); ok {
		t.Fatal("forgotten task restored")
	}
	n := 0
	_ = store.Scan(kv.NSDispatchAttemptVoided, func(string, []byte) bool { n++; return true })
	if n != 0 {
		t.Fatalf("%d voided attempts left in the store", n)
	}
}

// Uploads stop past the attempt's upload height and once closed; the attempt itself, its header
// and its user stay until it expires, and Sweep then forgets it.
func TestUploadLimitsAndExpiry(t *testing.T) {
	store := kv.NewMemStore()
	b := newBook(t, store)
	w, hash := winnerOf(t, 0)
	w.User = "trueopen1user"
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	_ = b.Accepted(w)
	b.Recorded(taskID, hash)
	header := current(t, b, taskID).Header
	_, other := winnerOf(t, 1)
	b.LimitUploads(taskID, other, 10)
	if a := current(t, b, taskID); a.UploadUntil != 0 {
		t.Fatal("another ticket's limit applied")
	}
	b.LimitUploads(taskID, hash, 120)
	if a := current(t, b, taskID); !a.AcceptsUploads(120) || a.AcceptsUploads(121) || a.User != "trueopen1user" {
		t.Fatalf("attempt = %+v", a)
	}
	b.CloseUploads(taskID)
	b.ExpireAt(taskID, 200)
	a := current(t, newBook(t, store), taskID)
	if a.AcceptsUploads(100) || !a.Live() || !bytes.Equal(a.Header, header) || a.ExpireHeight != 200 {
		t.Fatalf("closed attempt = %+v", a)
	}
	b.Sweep(199)
	if _, ok := b.Current(taskID); !ok {
		t.Fatal("swept before its expiry")
	}
	b.Sweep(200)
	if _, ok := b.Current(taskID); ok {
		t.Fatal("expired attempt kept")
	}
}

// switchSigner signs with whichever key it currently holds, as the service key ring does across a
// cutover.
type switchSigner struct {
	mu  sync.Mutex
	cur signer.Signer
}

func (s *switchSigner) key() signer.Signer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}
func (s *switchSigner) set(k signer.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = k
}
func (s *switchSigner) PubKeyCompressed() []byte              { return s.key().PubKeyCompressed() }
func (s *switchSigner) Address() string                       { return s.key().Address() }
func (s *switchSigner) Sign(m []byte) ([]byte, error)         { return s.key().Sign(m) }
func (s *switchSigner) SignDigest(d [32]byte) ([]byte, error) { return s.key().SignDigest(d) }

// The result header is transport the Builder's current key vouches for: after a cutover the
// attempt is served with its header signed again by the new key, at the same status, and that
// header is stored.
func TestHeaderIsSignedAgainAfterACutover(t *testing.T) {
	store := kv.NewMemStore()
	keys := &switchSigner{cur: newTestSigner(t, 0x01)}
	b, err := New(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := winnerOf(t, 0)
	if err := b.Accepted(w); err != nil {
		t.Fatal(err)
	}
	taskID := hex.EncodeToString(w.Ticket.GetTaskId())
	b.Recorded(taskID, mustTicketHash(t, w))
	before := current(t, b, taskID)
	checkHeader(t, b, before, Recorded)

	keys.set(newTestSigner(t, 0x02))
	after := current(t, b, taskID)
	checkHeader(t, b, after, Recorded)
	if bytes.Equal(after.Header, before.Header) {
		t.Fatal("header not signed again after the cutover")
	}
	if again := current(t, b, taskID); !bytes.Equal(again.Header, after.Header) {
		t.Fatal("header signed again under an unchanged key")
	}
	restored, err := New(store, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := current(t, restored, taskID); !bytes.Equal(a.Header, after.Header) {
		t.Fatal("the header signed again was not stored")
	}
}

func mustTicketHash(t *testing.T, w Winner) [32]byte {
	t.Helper()
	hash, err := digestOf(ticketName, w.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
