package ingress

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// staticAttempts is a book holding one fixed attempt, for tests that do not exercise the record
// status.
type staticAttempts struct{ a attempt.Attempt }

func (s staticAttempts) Current(taskID string) (attempt.Attempt, bool) {
	return s.a, s.a.TaskID == taskID
}
func (staticAttempts) Watch(string) (<-chan struct{}, func()) { return nil, func() {} }
func (staticAttempts) MaxPrerecordTokens() uint64             { return 0 }

// recordedAttempt is a RECORDED attempt of (session, task) won by worker with ticket.
func recordedAttempt(t *testing.T, session, task, taskHash, worker string, ticket []byte) staticAttempts {
	t.Helper()
	raw, _ := hex.DecodeString(task)
	header, err := proto.Marshal(&nexusv1.DispatchResultHeaderV1{TaskId: raw, RecordStatus: attempt.Recorded})
	if err != nil {
		t.Fatal(err)
	}
	return staticAttempts{attempt.Attempt{
		SessionID: session, TaskID: task, TaskHash: taskHash, Worker: worker, TicketHash: [32]byte(ticket),
		Status: attempt.Recorded, Header: header,
	}}
}

// memoryFrames is the stored output stream: frames in order, as persisted before they are published.
type memoryFrames struct {
	mu     sync.Mutex
	frames []taskdata.OutputFrame
}

func (m *memoryFrames) OpenOutputStream(context.Context, taskdata.RequestAuth, taskdata.OutputStreamHeader) (*taskdata.OutputStreamSession, taskdata.OutputStreamProgress, error) {
	return nil, taskdata.OutputStreamProgress{}, errors.New("not used")
}

func (m *memoryFrames) OutputFrames(_ context.Context, _ taskdata.ObjectKey, after *uint64) ([]taskdata.OutputFrame, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []taskdata.OutputFrame
	for _, f := range m.frames {
		if f.Chunk != nil && after != nil && f.Chunk.Seq <= *after {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// subscription drives serveOutput with in-memory parts: the attempt book, the stored frames and
// the fan-out the upload publishes to.
type subscription struct {
	t       *testing.T
	book    *attempt.Book
	frames  *memoryFrames
	fanout  *taskdata.OutputDispatcher
	svc     *service
	owner   string
	session string // internal spelling
	task    string
	key     taskdata.ObjectKey
}

func newSubscription(t *testing.T) *subscription {
	t.Helper()
	builder := mustSigner(t, "0000000000000000000000000000000000000000000000000000000000000002")
	book, err := attempt.New(kv.NewMemStore(), builder, nil)
	if err != nil {
		t.Fatal(err)
	}
	book.SetMaxPrerecordTokens(10)
	session := testSessionID("session-output")
	task := mustDeriveTaskID(t, session, 1)
	owner := mustSigner(t, testKeyHex).Address()
	frames := &memoryFrames{}
	fanout := taskdata.NewOutputDispatcher(16)
	svc := newService(&fakeHandler{taskOwner: owner}, AuthParams{}, withOutputStream(&outputStreamRuntime{
		service: frames, dispatcher: fanout, acks: kv.NewMemStore(), attempts: book,
	}))
	return &subscription{
		t: t, book: book, frames: frames, fanout: fanout, svc: svc, owner: owner, session: session, task: task,
		key: taskdata.ObjectKey{SessionID: session, TaskID: task, Kind: taskdata.ObjectKindOutput},
	}
}

// accept makes a ticket of rank the task's PENDING attempt and returns its hash.
func (s *subscription) accept(rank uint32) [32]byte {
	s.t.Helper()
	v := wirefixture.Load(s.t, "task/dispatch_v1.json").Vector(s.t, "nexus_v1_dispatchresultheaderv1", 0)
	var sv struct {
		ProtobufHex string `json:"protobuf_hex"`
	}
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		s.t.Fatal(err)
	}
	raw, _ := hex.DecodeString(sv.ProtobufHex)
	var h nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(raw, &h); err != nil {
		s.t.Fatal(err)
	}
	taskID, _ := hex.DecodeString(s.task)
	sessionID, _ := hex.DecodeString(s.session)
	ticket := proto.Clone(h.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
	ticket.TaskId, ticket.SessionId, ticket.Rank = taskID, sessionID, rank
	tb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	hash, err := dispatch.SigningDigest("task.v1.DispatchTicketV1", tb)
	if err != nil {
		s.t.Fatal(err)
	}
	accept := proto.Clone(h.GetAccept()).(*taskv1.DispatchAcceptV1)
	accept.TaskId, accept.DispatchTicketHash = taskID, hash[:]
	if err := s.book.Accepted(attempt.Winner{SessionID: s.session, Sequence: 1, Ticket: ticket, Accept: accept}); err != nil {
		s.t.Fatal(err)
	}
	return hash
}

// push stores a frame and publishes it, as the upload does.
func (s *subscription) push(f taskdata.OutputFrame) {
	s.frames.mu.Lock()
	s.frames.frames = append(s.frames.frames, f)
	s.frames.mu.Unlock()
	s.fanout.Publish(s.key, f)
}

func chunkOf(ticket [32]byte, seq, tokens uint64) taskdata.OutputFrame {
	return taskdata.OutputFrame{Chunk: &taskdata.OutputChunk{
		Seq: seq, Text: []byte("text"), MMRRoot: make([]byte, 32), WorkerSignature: make([]byte, 64),
		DispatchTicketHash: ticket[:], CumulativeGeneratedTokens: tokens,
	}}
}

func finOf(ticket [32]byte, finalSeq uint64) taskdata.OutputFrame {
	return taskdata.OutputFrame{Fin: &taskdata.OutputFin{
		FinalSeq: finalSeq, OutputMMRRoot: make([]byte, 32), FinishReason: 1, WorkerSignature: make([]byte, 64),
		DispatchTicketHash: ticket[:],
	}}
}

// running is one serveOutput call: what it sent and how it ended. Everything a call sent is
// read before its end.
type running struct {
	t     *testing.T
	sent  chan *nexusv1.SubscribeOutputResponse
	done  chan error
	ended bool
	err   error
}

func (s *subscription) serve(ctx context.Context, requester string, after *uint64, ticket []byte) *running {
	r := &running{t: s.t, sent: make(chan *nexusv1.SubscribeOutputResponse, 64), done: make(chan error, 1)}
	go func() {
		r.done <- s.svc.serveOutput(ctx, wireID(s.session), wireID(s.task), requester, after, ticket,
			func(m *nexusv1.SubscribeOutputResponse) error { r.sent <- m; return nil })
	}()
	return r
}

// wait returns the next message, or nil once the call ended with nothing left, or nil after d.
func (r *running) wait(d time.Duration) *nexusv1.SubscribeOutputResponse {
	select {
	case m := <-r.sent:
		return m
	default:
	}
	if r.ended {
		return nil
	}
	select {
	case m := <-r.sent:
		return m
	case err := <-r.done:
		r.ended, r.err = true, err
		select {
		case m := <-r.sent:
			return m
		default:
			return nil
		}
	case <-time.After(d):
		return nil
	}
}

func (r *running) next() *nexusv1.SubscribeOutputResponse {
	r.t.Helper()
	m := r.wait(5 * time.Second)
	if m == nil {
		r.t.Fatalf("no message (ended %t: %v)", r.ended, r.err)
	}
	return m
}

func (r *running) quiet() {
	r.t.Helper()
	if m := r.wait(50 * time.Millisecond); m != nil {
		r.t.Fatalf("unexpected message %v", m)
	}
	if r.ended {
		r.t.Fatalf("subscription ended early: %v", r.err)
	}
}

func (r *running) end() error {
	r.t.Helper()
	if m := r.wait(5 * time.Second); m != nil {
		r.t.Fatalf("unexpected message %v before the end", m)
	}
	if !r.ended {
		r.t.Fatal("subscription did not end")
	}
	return r.err
}

func (r *running) header(status attempt.Status, ticket [32]byte) {
	r.t.Helper()
	m := r.next()
	h := m.GetDispatchResult()
	if h == nil || m.GetFrame() != nil || h.GetRecordStatus() != status || string(h.GetAccept().GetDispatchTicketHash()) != string(ticket[:]) {
		r.t.Fatalf("want a %v result header of %x, got %v", status, ticket, m)
	}
}

func (r *running) chunk(seq, tokens uint64) {
	r.t.Helper()
	m := r.next()
	if c := m.GetChunk(); c == nil || c.GetSeq() != seq || c.GetCumulativeGeneratedTokens() != tokens {
		r.t.Fatalf("want chunk %d (%d tokens), got %v", seq, tokens, m)
	}
}

func (r *running) fin(finalSeq uint64) {
	r.t.Helper()
	if m := r.next(); m.GetFin() == nil || m.GetFin().GetFinalSeq() != finalSeq {
		r.t.Fatalf("want fin %d, got %v", finalSeq, m)
	}
}

// A subscriber that comes before the accept waits for it, then gets the PENDING result header first.
// Before the record only chunks within max_prerecord_output_tokens are forwarded, with their
// cumulative token counts; the rest (and the Fin after them) is held. The record sends the RECORDED
// header and releases the held frames; the subscription ends after the Fin.
func TestOutputHeaderFirstCapHoldsUntilTheRecord(t *testing.T) {
	s := newSubscription(t)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.quiet()
	ticket := s.accept(0)
	r.header(attempt.Pending, ticket)
	s.push(chunkOf(ticket, 0, 4))
	s.push(chunkOf(ticket, 1, 10))
	r.chunk(0, 4)
	r.chunk(1, 10)
	s.push(chunkOf(ticket, 2, 11))
	s.push(chunkOf(ticket, 3, 12))
	s.push(finOf(ticket, 3))
	r.quiet()
	s.book.Recorded(s.task, ticket)
	r.header(attempt.Recorded, ticket)
	r.chunk(2, 11)
	r.chunk(3, 12)
	r.fin(3)
	if err := r.end(); err != nil {
		t.Fatalf("end = %v", err)
	}
}

// A rejected record sends the REJECTED header and ends the subscription with RECORD_REJECTED; held
// frames are never forwarded.
func TestOutputRejectionEndsTheSubscription(t *testing.T) {
	s := newSubscription(t)
	ticket := s.accept(0)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.header(attempt.Pending, ticket)
	s.push(chunkOf(ticket, 0, 3))
	r.chunk(0, 3)
	s.push(chunkOf(ticket, 1, 20))
	r.quiet()
	s.book.Rejected(s.task, ticket)
	r.header(attempt.Rejected, ticket)
	if err := r.end(); !errors.Is(err, errRecordRejected) {
		t.Fatalf("end = %v", err)
	}
	// A later subscriber gets the REJECTED header and the same end.
	late := s.serve(context.Background(), s.owner, nil, nil)
	late.header(attempt.Rejected, ticket)
	if err := late.end(); !errors.Is(err, errRecordRejected) {
		t.Fatalf("late end = %v", err)
	}
}

// When every chunk fits under the cap the Fin is forwarded before the record; the subscription
// stays open for the RECORDED header and then ends.
func TestOutputFinBeforeTheRecordWaitsForIt(t *testing.T) {
	s := newSubscription(t)
	ticket := s.accept(0)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.header(attempt.Pending, ticket)
	s.push(chunkOf(ticket, 0, 2))
	s.push(finOf(ticket, 0))
	r.chunk(0, 2)
	r.fin(0)
	r.quiet()
	s.book.Recorded(s.task, ticket)
	r.header(attempt.Recorded, ticket)
	if err := r.end(); err != nil {
		t.Fatalf("end = %v", err)
	}
}

// A subscription naming a ticket that is not the current attempt is NEXUS_INGRESS_ATTEMPT_STALE,
// and so is a running one whose attempt is voided. Frames of an older attempt still stored are
// never delivered for the current one.
func TestOutputStaleAttempt(t *testing.T) {
	s := newSubscription(t)
	old := [32]byte{0x0d}
	if err := s.serve(context.Background(), s.owner, nil, old[:]).end(); !errors.Is(err, errAttemptStale) {
		t.Fatalf("ticket before any accept: %v", err)
	}
	s.push(chunkOf(old, 0, 1))
	ticket := s.accept(0)
	if err := s.serve(context.Background(), s.owner, nil, old[:]).end(); !errors.Is(err, errAttemptStale) {
		t.Fatalf("older ticket: %v", err)
	}
	if connect.CodeOf(errAttemptStale) != connect.CodeFailedPrecondition {
		t.Fatalf("stale code = %v", connect.CodeOf(errAttemptStale))
	}
	r := s.serve(context.Background(), s.owner, nil, ticket[:])
	r.header(attempt.Pending, ticket)
	r.quiet() // the older attempt's chunk is not this attempt's
	s.book.Voided(s.task, ticket)
	if err := r.end(); !errors.Is(err, errAttemptStale) {
		t.Fatalf("voided attempt: %v", err)
	}
}

// After the record a subscriber resuming after seq 0 gets the RECORDED header, the stored chunks
// after it and the Fin, uncapped, and the subscription ends.
func TestOutputResumeAfterTheRecord(t *testing.T) {
	s := newSubscription(t)
	ticket := s.accept(0)
	s.push(chunkOf(ticket, 0, 40))
	s.push(chunkOf(ticket, 1, 80))
	s.push(finOf(ticket, 1))
	s.book.Recorded(s.task, ticket)
	after := uint64(0)
	r := s.serve(context.Background(), s.owner, &after, ticket[:])
	r.header(attempt.Recorded, ticket)
	r.chunk(1, 80)
	r.fin(1)
	if err := r.end(); err != nil {
		t.Fatalf("end = %v", err)
	}
}

// Only the order user subscribes.
func TestOutputOnlyTheOrderUser(t *testing.T) {
	s := newSubscription(t)
	s.accept(0)
	err := s.serve(context.Background(), mustSigner(t, workerKeyHex).Address(), nil, nil).end()
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-owner = %v", err)
	}
}

// A max_prerecord_output_tokens of 0 holds every chunk until the record, one reporting 0 tokens
// included.
func TestOutputZeroCapHoldsEverything(t *testing.T) {
	s := newSubscription(t)
	s.book.SetMaxPrerecordTokens(0)
	ticket := s.accept(0)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.header(attempt.Pending, ticket)
	s.push(chunkOf(ticket, 0, 0))
	s.push(chunkOf(ticket, 1, 1))
	r.quiet()
	s.book.Recorded(s.task, ticket)
	r.header(attempt.Recorded, ticket)
	r.chunk(0, 0)
	r.chunk(1, 1)
}

// Before the record a chunk that carries text but reports 0 generated tokens is held: its count
// does not show it within the cap.
func TestOutputTextWithZeroTokensIsHeld(t *testing.T) {
	s := newSubscription(t)
	ticket := s.accept(0)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.header(attempt.Pending, ticket)
	s.push(chunkOf(ticket, 0, 0))
	r.quiet()
	s.book.Recorded(s.task, ticket)
	r.header(attempt.Recorded, ticket)
	r.chunk(0, 0)
}
