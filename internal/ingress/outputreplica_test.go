package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/buildersync"
	"github.com/TrueOpen/nexus/internal/config"
)

// fakeReplicas holds the synced attempts of a group member.
type fakeReplicas map[string]attempt.Attempt // session|task

func (f fakeReplicas) Replica(sessionID, taskID string) (attempt.Attempt, bool) {
	a, ok := f[sessionID+"|"+taskID]
	return a, ok
}

// memberSubscription is a subscription on a Builder that holds the task only as a group member.
func memberSubscription(t *testing.T, status attempt.Status) (*subscription, [32]byte) {
	t.Helper()
	s := newSubscription(t)
	ticket := [32]byte(bytes.Repeat([]byte{0x7b}, 32))
	a := attempt.Attempt{SessionID: s.session, Sequence: 1, TaskID: s.task, Status: attempt.Pending, User: s.owner}
	if status == attempt.Recorded {
		header, err := proto.Marshal(&nexusv1.DispatchResultHeaderV1{
			Accept: &taskv1.DispatchAcceptV1{DispatchTicketHash: ticket[:]}, RecordStatus: attempt.Recorded,
		})
		if err != nil {
			t.Fatal(err)
		}
		a.Status, a.TicketHash, a.User, a.Header = attempt.Recorded, ticket, s.owner, header
	}
	s.svc.memberReplicas = fakeReplicas{s.session + "|" + s.task: a}
	return s, ticket
}

// Before the chain recorded the order a member does not serve its output: SESSION_UNBOUND, told
// only to the order user.
func TestMemberResumeBeforeTheRecord(t *testing.T) {
	s, ticket := memberSubscription(t, attempt.Pending)
	if err := s.serve(context.Background(), "trueopen1someoneelse", nil, ticket[:]).end(); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another requester before the record: %v", err)
	}
	err := s.serve(context.Background(), s.owner, nil, ticket[:]).end()
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !bytes.Contains([]byte(err.Error()), []byte("NEXUS_INGRESS_SESSION_UNBOUND")) {
		t.Fatalf("resume before the record = %v", err)
	}
}

// After the record a member serves the order user from its replica: the dispatching Builder's
// RECORDED header first, the stored frames after the cursor, then the frames synced in, until the
// Fin. The request must name the recorded winner's ticket.
func TestMemberResumeAfterTheRecord(t *testing.T) {
	s, ticket := memberSubscription(t, attempt.Recorded)
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{0x01}, 32)} {
		if err := s.serve(context.Background(), s.owner, nil, bad).end(); !errors.Is(err, errAttemptStale) {
			t.Fatalf("ticket %x: %v", bad, err)
		}
	}
	if err := s.serve(context.Background(), "trueopen1someoneelse", nil, ticket[:]).end(); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another requester: %v", err)
	}

	s.push(chunkOf(ticket, 0, 4))
	s.push(chunkOf(ticket, 1, 400))
	after := uint64(0)
	r := s.serve(context.Background(), s.owner, &after, ticket[:])
	r.header(attempt.Recorded, ticket)
	r.chunk(1, 400)
	r.quiet() // the replica is behind: the stream waits
	s.push(chunkOf(ticket, 2, 401))
	r.chunk(2, 401)
	s.push(finOf(ticket, 2))
	r.fin(2)
	if err := r.end(); err != nil {
		t.Fatalf("end = %v", err)
	}
}

// A Builder holding the task's own attempt serves it as the dispatching Builder, whatever a
// member copy says.
func TestOwnAttemptGoesBeforeAMemberCopy(t *testing.T) {
	s, _ := memberSubscription(t, attempt.Pending)
	own := s.accept(0)
	r := s.serve(context.Background(), s.owner, nil, nil)
	r.header(attempt.Pending, own)
}

// GetDispatchRoster asked with the user's envelope is answered on a member for the user of the
// recorded order it holds.
func TestRosterOwnerOnAMember(t *testing.T) {
	s, _ := memberSubscription(t, attempt.Recorded)
	s.svc.h = &fakeHandler{} // the member's coordinator does not know the task
	if err := s.svc.requireTaskOrReplicaOwner(context.Background(), s.session, s.task, s.owner); err != nil {
		t.Fatalf("order user on a member: %v", err)
	}
	if err := s.svc.requireTaskOrReplicaOwner(context.Background(), s.session, s.task, "trueopen1someoneelse"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another requester: %v", err)
	}
}

type fakeBuilderSync struct {
	resp *nexusv1.SyncResponse
	err  error
	got  *[]byte
}

func (f fakeBuilderSync) Sync(_ context.Context, raw []byte) (*nexusv1.SyncResponse, error) {
	if f.got != nil {
		*f.got = raw
	}
	return f.resp, f.err
}

// The sync service maps the receiver's refusals to status codes.
func TestBuilderSyncErrors(t *testing.T) {
	for err, want := range map[error]connect.Code{
		buildersync.ErrMalformed:       connect.CodeInvalidArgument,
		buildersync.ErrUnauthenticated: connect.CodeUnauthenticated,
		buildersync.ErrNotGroupMember:  connect.CodePermissionDenied,
		buildersync.ErrUnavailable:     connect.CodeUnavailable,
		errors.New("disk"):             connect.CodeInternal,
	} {
		_, got := builderSyncService{sync: fakeBuilderSync{err: err}}.Sync(context.Background(), connect.NewRequest(&rawSyncRequest{}))
		if connect.CodeOf(got) != want {
			t.Fatalf("%v -> %v, want %v", err, connect.CodeOf(got), want)
		}
	}
}

// builderSyncServer is an ingress server with a sync receiver fake, served through its HTTP
// handler without a listener.
func builderSyncServer(t *testing.T, sync fakeBuilderSync) http.Handler {
	t.Helper()
	srv, err := New(slog.New(slog.DiscardHandler), config.IngressConfig{APIKeys: []string{"sdk-key"}}, AuthParams{}, &fakeHandler{},
		WithBuilderSync(sync, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return srv.handler()
}

func postSync(h http.Handler, contentType string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, nexusv1connect.BuilderSyncServiceSyncProcedure, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The ingress server mounts the sync service next to IngressAPI and hands the receiver the
// request bytes exactly as they arrived, unknown and duplicate fields included.
func TestBuilderSyncIsServedNextToIngress(t *testing.T) {
	var got []byte
	h := builderSyncServer(t, fakeBuilderSync{resp: &nexusv1.SyncResponse{AppliedThrough: 7}, got: &got})
	body, _ := proto.Marshal(&nexusv1.SyncRequest{Batch: &nexusv1.BuilderSyncBatchV1{ChainId: "c"}})
	body = append(body, 0x12, 0x01, 0x01, 0x78, 0x01) // a second sender_signature and unknown field 15
	rec := postSync(h, "application/proto", bytes.NewReader(body))
	var resp nexusv1.SyncResponse
	if rec.Code == http.StatusNotFound {
		t.Fatalf("%s is not mounted", nexusv1connect.BuilderSyncServiceSyncProcedure)
	}
	if rec.Code != http.StatusOK || proto.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.GetAppliedThrough() != 7 {
		t.Fatalf("sync over the ingress handler = %d %q", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("receiver got %x, want the request bytes %x", got, body)
	}
}

// A JSON request is refused as an unsupported encoding before the receiver: it cannot be
// validated byte for byte.
func TestBuilderSyncRefusesJSON(t *testing.T) {
	var got []byte
	h := builderSyncServer(t, fakeBuilderSync{resp: &nexusv1.SyncResponse{}, got: &got})
	rec := postSync(h, "application/json", strings.NewReader(`{"batch":{}}`))
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "unsupported encoding") || got != nil {
		t.Fatalf("JSON sync request = %d %q, receiver got %q", rec.Code, rec.Body.String(), got)
	}
}

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// A request over the 1 MiB contract cap is refused, and a body over twice the cap is cut off
// unread; neither reaches the receiver.
func TestBuilderSyncBoundsTheBody(t *testing.T) {
	for _, size := range []int{builderSyncReadMaxBytes + 1, 4 * builderSyncReadMaxBytes} {
		var got []byte
		h := builderSyncServer(t, fakeBuilderSync{resp: &nexusv1.SyncResponse{}, got: &got})
		body := &countingReader{r: bytes.NewReader(make([]byte, size))}
		rec := postSync(h, "application/proto", body)
		if rec.Code == http.StatusOK || got != nil {
			t.Fatalf("%d-byte body = %d %q, receiver got %d bytes", size, rec.Code, rec.Body.String(), len(got))
		}
		if body.n > 2*builderSyncReadMaxBytes+1 {
			t.Fatalf("%d bytes of a %d-byte body were read", body.n, size)
		}
	}
}

// Sync requests are limited per source address: the endpoint takes no API key.
func TestBuilderSyncIsRateLimitedPerAddress(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	limiter := newAddressLimiter(1, 2, func() time.Time { return now })
	for i, want := range []bool{true, true, false} {
		if got := limiter.allow("10.0.0.1"); got != want {
			t.Fatalf("request %d allowed %v", i, got)
		}
	}
	if !limiter.allow("10.0.0.2") {
		t.Fatal("another address was limited")
	}
	now = now.Add(time.Second)
	if !limiter.allow("10.0.0.1") {
		t.Fatal("the address was not let through again after a second")
	}
	_, err := builderSyncService{sync: fakeBuilderSync{}, limit: newAddressLimiter(0, 0, time.Now)}.Sync(context.Background(),
		connect.NewRequest(&rawSyncRequest{}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("over the limit: %v", err)
	}
}

// The sync rate limit comes from the configuration; zero takes the defaults.
func TestBuilderSyncRateLimitIsConfigured(t *testing.T) {
	limit := func(perSecond, burst uint32) *addressLimiter {
		srv := &Server{}
		WithBuilderSync(fakeBuilderSync{}, perSecond, burst)(srv)
		return srv.builderSync.limit
	}
	if l := limit(0, 0); l.perSecond != 1000 || l.burst != 2000 {
		t.Fatalf("defaults %v/s burst %v", l.perSecond, l.burst)
	}
	if l := limit(50, 70); l.perSecond != 50 || l.burst != 70 {
		t.Fatalf("configured %v/s burst %v", l.perSecond, l.burst)
	}
}
