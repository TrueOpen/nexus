package ingress

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	"github.com/TrueOpen/nexus/gen/buildersync/v1/buildersyncv1connect"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
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
	a := attempt.Attempt{SessionID: s.session, Sequence: 1, TaskID: s.task, Status: attempt.Pending}
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

// Before the chain recorded the order a member does not serve its output: SESSION_UNBOUND.
func TestMemberResumeBeforeTheRecord(t *testing.T) {
	s, ticket := memberSubscription(t, attempt.Pending)
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
	resp *buildersyncv1.SyncResponse
	err  error
}

func (f fakeBuilderSync) Sync(context.Context, *buildersyncv1.SyncRequest) (*buildersyncv1.SyncResponse, error) {
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
		_, got := builderSyncService{fakeBuilderSync{err: err}}.Sync(context.Background(), connect.NewRequest(&buildersyncv1.SyncRequest{}))
		if connect.CodeOf(got) != want {
			t.Fatalf("%v -> %v, want %v", err, connect.CodeOf(got), want)
		}
	}
}

// The ingress server serves the sync service on its own handler, next to IngressAPI.
func TestBuilderSyncIsServedNextToIngress(t *testing.T) {
	srv, err := New(slog.New(slog.DiscardHandler), config.IngressConfig{APIKeys: []string{"sdk-key"}}, AuthParams{}, &fakeHandler{},
		WithBuilderSync(fakeBuilderSync{resp: &buildersyncv1.SyncResponse{AppliedThrough: 7}}))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := proto.Marshal(&buildersyncv1.SyncRequest{Batch: []byte("b")})
	req := httptest.NewRequest(http.MethodPost, buildersyncv1connect.BuilderSyncServiceSyncProcedure, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)
	var resp buildersyncv1.SyncResponse
	if rec.Code != http.StatusOK || proto.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.GetAppliedThrough() != 7 {
		t.Fatalf("sync over the ingress handler = %d %q", rec.Code, rec.Body.String())
	}
}
