package chaincli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
)

// cortexNodeHubQuery implements only the CortexNode method used by QueryCortexNode; the
// other methods fall through the embedded hubv1connect.QueryClient to a nil call and
// panic, which none of the cases in this file reach.
type cortexNodeHubQuery struct {
	hubv1connect.QueryClient
	got  *hubv1.QueryCortexNodeRequest
	resp *hubv1.QueryCortexNodeResponse
	err  error
}

func (q *cortexNodeHubQuery) CortexNode(_ context.Context, req *connect.Request[hubv1.QueryCortexNodeRequest]) (*connect.Response[hubv1.QueryCortexNodeResponse], error) {
	q.got = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.resp), nil
}

func testCortexNodeClient(hub *cortexNodeHubQuery) *client {
	return &client{log: slog.New(slog.NewTextHandler(io.Discard, nil)), hubQuery: hub}
}

// QueryCortexNode maps the frozen contract's CortexNodeState to the local CortexNodeState:
// pubkey becomes lowercase hex, status is the ServiceKeyStatus short name;
// operator_address must pass through verbatim.
func TestQueryCortexNodeMapsFrozenRow(t *testing.T) {
	hub := &cortexNodeHubQuery{resp: &hubv1.QueryCortexNodeResponse{Node: &hubv1.CortexNodeState{
		SchemaVersion: 1, OperatorAddress: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
		CurrentServiceAddress: "trueopen1svc", CurrentServicePubkey: []byte{0x02, 0xaa},
		ServiceAuthorizationNonce: 7, ServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
		RegisteredHeight: 10, UpdatedHeight: 12,
	}}}
	c := testCortexNodeClient(hub)

	got, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man")
	if err != nil {
		t.Fatal(err)
	}
	if hub.got.GetOperatorAddress() != "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man" {
		t.Fatalf("request operator_address = %q, want it sent on the wire", hub.got.GetOperatorAddress())
	}
	if got.OperatorAddress != "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man" || got.ServiceAuthorizationNonce != 7 ||
		got.ServiceKeyStatus != "ACTIVE" || got.CurrentServicePubKey != "02aa" || got.RegisteredHeight != 10 {
		t.Fatalf("unexpected mapping: %+v", got)
	}
}

func TestQueryCortexNodeNotFound(t *testing.T) {
	hub := &cortexNodeHubQuery{err: connect.NewError(connect.CodeNotFound, nil)}
	c := testCortexNodeClient(hub)

	if _, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// An empty row (Node present but operator_address empty) counts as absent; default values must not admit.
func TestQueryCortexNodeEmptyRowIsNotFound(t *testing.T) {
	hub := &cortexNodeHubQuery{resp: &hubv1.QueryCortexNodeResponse{Node: &hubv1.CortexNodeState{}}}
	c := testCortexNodeClient(hub)

	if _, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// When the Node field itself is nil (not an empty struct) it must also be ErrNotFound, without panicking or passing through.
func TestQueryCortexNodeNilNodeIsNotFound(t *testing.T) {
	hub := &cortexNodeHubQuery{resp: &hubv1.QueryCortexNodeResponse{Node: nil}}
	c := testCortexNodeClient(hub)

	if _, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// A transport error (not CodeNotFound) must not be mistaken for "absent"; that would make
// the auth callback service treat "cannot query" as "not registered" during an off-chain
// network failure and reject a Cortex that should be admitted.
func TestQueryCortexNodeTransportErrorIsNotErrNotFound(t *testing.T) {
	hub := &cortexNodeHubQuery{err: connect.NewError(connect.CodeUnavailable, errors.New("dial"))}
	c := testCortexNodeClient(hub)

	_, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man")
	if err == nil {
		t.Fatal("want an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a transport error must not be reported as ErrNotFound: %v", err)
	}
}

// When the response row's operator_address does not match the request it must error; another
// operator's row must not be admitted as the result of the current request.
func TestQueryCortexNodeRejectsMismatchedOperator(t *testing.T) {
	hub := &cortexNodeHubQuery{resp: &hubv1.QueryCortexNodeResponse{Node: &hubv1.CortexNodeState{
		OperatorAddress: "trueopen1other",
	}}}
	c := testCortexNodeClient(hub)

	_, err := c.QueryCortexNode(context.Background(), "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man")
	if err == nil || !strings.Contains(err.Error(), "does not match request") {
		t.Fatalf("want a response-key-mismatch error, got %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a key mismatch must not be reported as ErrNotFound: %v", err)
	}
}
