package coordinator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

type fakeDispatcher struct {
	mu         sync.Mutex
	probeErr   error
	dispatchEr error
	dispatched []types.Order
	header     *nexusv1.DispatchResultHeaderV1
	// deadlines are the record deadlines by order sequence.
	deadlines map[uint64]uint64
}

func (f *fakeDispatcher) RecordDeadline(_ string, sequence uint64) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deadlines[sequence]
	return d, ok
}

func (f *fakeDispatcher) Probe(context.Context, types.Order) error { return f.probeErr }

func (f *fakeDispatcher) Dispatch(_ context.Context, o types.Order) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dispatchEr != nil {
		return f.dispatchEr
	}
	f.dispatched = append(f.dispatched, o)
	return nil
}

func (f *fakeDispatcher) DispatchResult(string, string) (*nexusv1.DispatchResultHeaderV1, bool) {
	return f.header, f.header != nil
}

func eventCodes(c *Coordinator, sessionID, taskID string) []string {
	var out []string
	for _, ev := range c.journalFor(taskKey(sessionID, taskID)).snapshot() {
		out = append(out, ev.EventCode)
	}
	return out
}

// Without direct dispatch every order is refused before and after its input upload.
func TestOrdersNeedADispatcher(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.CheckOrder(context.Background(), o); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("CheckOrder = %v", err)
	}
	if err := c.OnOrder(context.Background(), o); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("OnOrder = %v", err)
	}
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("a refused order created a task")
	}
}

// OnOrder starts the task (ORDER_RECEIVED) and hands the order over; the dispatcher's accept and
// failure become task events. A failed task is dropped, and a retry of its sequence starts again
// on the same journal.
func TestOnOrderHandsTheOrderToTheDispatcher(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	d := &fakeDispatcher{}
	c.SetDispatcher(d)
	ctx := context.Background()
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.CheckOrder(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := c.OnOrder(ctx, o); err != nil {
		t.Fatal(err)
	}
	if len(d.dispatched) != 1 || d.dispatched[0].TaskHash != o.TaskHash {
		t.Fatalf("dispatched = %+v", d.dispatched)
	}
	c.DispatchFailed(o.SessionID, o.TaskID, dispatchdraw.ErrNoCapacity)
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("a failed dispatch kept its task")
	}
	retry := o
	retry.TaskHash = strings.Repeat("b", 64)
	if err := c.OnOrder(ctx, retry); err != nil {
		t.Fatalf("retry: %v", err)
	}
	c.DispatchAccepted(o.SessionID, o.TaskID, [32]byte{1}, "worker-1")
	want := []string{EvOrderReceived, EvNoCapacity, EvOrderReceived, EvDispatchAccepted}
	if got := eventCodes(c, o.SessionID, o.TaskID); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", got, want)
	}
	fsm, ok := c.getFSM(o.SessionID, o.TaskID)
	if !ok || fsm.order.TaskHash != retry.TaskHash || fsm.state != types.Pending {
		t.Fatal("the retry is not the tracked Pending task")
	}
}

// A refusal of the dispatcher leaves no task; a probe refusal is CheckOrder's answer.
func TestDispatcherRefusals(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	d := &fakeDispatcher{probeErr: dispatchdraw.ErrNoCapacity, dispatchEr: errors.New("not reserved")}
	c.SetDispatcher(d)
	o := testPlaceholderOrder("session-1", "task-1")
	if err := c.CheckOrder(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("CheckOrder = %v", err)
	}
	if err := c.OnOrder(context.Background(), o); err == nil {
		t.Fatal("OnOrder ignored the dispatcher's refusal")
	}
	if _, ok := c.getFSM(o.SessionID, o.TaskID); ok {
		t.Fatal("a refused order kept its task")
	}
}

// The same order re-signed under another signature_chain_id has the same task_hash: the tracked
// task keeps the first SignedOrderV2.
func TestOnOrderRetryUnderAnotherSignatureChainIDKeepsFirstOrder(t *testing.T) {
	c, _ := newTaskTrackingCoordinator(t, kv.NewMemStore())
	c.SetDispatcher(&fakeDispatcher{})
	ctx := context.Background()
	first := testPlaceholderOrder("session-1", "task-1")
	resigned := testSignedOrder(testUserAddress)
	resigned.SignatureChainId = 1
	resigned.UserSignature = append(bytes.Repeat([]byte{0x66}, 64), 28)
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(resigned)
	if err != nil {
		t.Fatal(err)
	}
	retry := first
	retry.SignedOrder = raw
	if err := c.OnOrder(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := c.OnOrder(ctx, retry); err != nil {
		t.Fatalf("OnOrder(retry under another signature_chain_id) = %v", err)
	}
	fsm, ok := c.getFSM(first.SessionID, first.TaskID)
	if !ok || !bytes.Equal(fsm.order.SignedOrder, first.SignedOrder) {
		t.Fatal("the retry replaced the first stored SignedOrderV2")
	}
}
