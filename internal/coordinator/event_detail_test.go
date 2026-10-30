package coordinator

import (
	"context"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func lastDetail(t *testing.T, c *Coordinator, sessionID, taskID string) (string, *types.TaskEventDetail) {
	t.Helper()
	events := c.journalFor(taskKey(sessionID, taskID)).snapshot()
	if len(events) == 0 {
		t.Fatal("no events")
	}
	last := events[len(events)-1]
	return last.EventCode, last.Detail
}

// Dispatch events carry the routing facts the contract names: DISPATCH_ACCEPTED the ticket and
// its Worker, RECORD_REJECTED the ticket and the nonzero rejection category.
func TestDispatchEventsCarryTheirDetail(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	o := testPlaceholderOrder("session-1", "task-1")
	later := testPlaceholderOrder("session-1", "task-2")
	late := testPlaceholderOrder("session-2", "task-3")
	for _, order := range []types.Order{o, later, late} {
		if err := c.OnOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
	}
	ticket := [32]byte{0xab}
	c.DispatchAccepted(o.SessionID, o.TaskID, ticket, "worker-1")
	code, d := lastDetail(t, c, o.SessionID, o.TaskID)
	if code != EvDispatchAccepted || d == nil || *d != (types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket[:]), WorkerOperatorAddress: "worker-1"}) {
		t.Fatalf("%s detail = %+v", code, d)
	}
	balance := taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SESSION_BALANCE_INSUFFICIENT
	c.RecordRejected(o.SessionID, o.TaskID, ticket, balance)
	code, d = lastDetail(t, c, o.SessionID, o.TaskID)
	if code != EvRecordRejected || d == nil || *d != (types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket[:]), RejectCode: int32(balance)}) {
		t.Fatalf("%s detail = %+v", code, d)
	}
	c.DispatchFailed(later.SessionID, later.TaskID, fmt.Errorf("%w: sequence 0", dispatcher.ErrRecordRejected))
	code, d = lastDetail(t, c, later.SessionID, later.TaskID)
	if code != EvRecordRejected || d == nil || d.RejectCode != int32(taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_SEQUENCE_CONSUMED) {
		t.Fatalf("later %s detail = %+v", code, d)
	}
	c.DispatchFailed(late.SessionID, late.TaskID, fmt.Errorf("%w: deadline 120", dispatcher.ErrRecordDeadline))
	code, d = lastDetail(t, c, late.SessionID, late.TaskID)
	if code != EvRecordRejected || d == nil || d.RejectCode != int32(taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE) {
		t.Fatalf("late %s detail = %+v", code, d)
	}
}

// A takeover's events name this Builder: as candidate with the activation height while pending,
// as bound Builder once it took effect.
func TestTakeoverEventsCarryTheirDetail(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.active = newActiveSet(testBuilderSelf)
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.OnTakeover(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	c.TakeoverRegistered(o.SessionID, o.TaskID, 70)
	code, d := lastDetail(t, c, o.SessionID, o.TaskID)
	if code != EvTakeoverPending || d == nil || *d != (types.TaskEventDetail{CandidateBuilder: testBuilderSelf, TakeoverActivationHeight: 70}) {
		t.Fatalf("%s detail = %+v", code, d)
	}
	c.TakeoverActivated(o.SessionID, o.TaskID, 70)
	code, d = lastDetail(t, c, o.SessionID, o.TaskID)
	if code != EvTakeoverRecorded || d == nil || *d != (types.TaskEventDetail{BoundBuilder: testBuilderSelf}) {
		t.Fatalf("%s detail = %+v", code, d)
	}
}

// The event codes (the Ev constants) are exactly the closed Nexus lifecycle set the wire contract
// lists above GetTaskEventsResponse.
func TestEventCodesAreTheWireLifecycleSet(t *testing.T) {
	proto := string(wirefixture.ReadFile(t, "proto/nexus/v1/ingress.proto"))
	start := strings.Index(proto, "The closed event_code set is:")
	end := strings.Index(proto, "message GetTaskEventsResponse")
	if start < 0 || end < start {
		t.Fatal("wire ingress.proto has no closed event_code set above GetTaskEventsResponse")
	}
	block := proto[start:end]
	block = block[:strings.Index(block, ".\n")]
	wire := regexp.MustCompile(`[A-Z][A-Z_]+[A-Z]`).FindAllString(strings.TrimPrefix(block, "The closed event_code set is:"), -1)
	slices.Sort(wire)
	got := eventConstants(t)
	slices.Sort(got)
	if !slices.Equal(got, wire) {
		t.Fatalf("event codes = %v, wire = %v", got, wire)
	}
}

// eventConstants are the values of the Ev constants of events.go.
func eventConstants(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "events.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || !strings.HasPrefix(spec.Names[0].Name, "Ev") || len(spec.Values) != 1 {
			return true
		}
		lit, ok := spec.Values[0].(*ast.BasicLit)
		if !ok {
			t.Fatalf("%s is not a string literal", spec.Names[0].Name)
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
		return true
	})
	return out
}
