package dispatchstream

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/kv/kvtest"
)

// TestDownlinkSyncCount pins the synced and deferred writes of one downlink message: storing it
// before it is queued, and releasing it once the Cortex acknowledged it.
func TestDownlinkSyncCount(t *testing.T) {
	store := kvtest.New()
	h := newHarnessOn(t, store, newTestKeys())
	s := h.connect(cortexA, "1")
	type cost struct{ synced, deferred int }
	last := cost{store.Synced(), store.Deferred()}
	step := func(name string, want cost) {
		t.Helper()
		now := cost{store.Synced(), store.Deferred()}
		if got := (cost{now.synced - last.synced, now.deferred - last.deferred}); got != want {
			t.Fatalf("%s cost %+v, want %+v", name, got, want)
		}
		last = now
	}
	mustSend(t, h, cortexA, "a")
	step("send", cost{synced: 1})
	receiveOffers(t, s, 1)
	s.ack(1)
	waitPending(t, h, cortexA, 0)
	step("ack", cost{deferred: 1})
}

// gatedStore holds every synced write whose first key starts with prefix until release is
// closed, and reports on blocked when it starts waiting.
type gatedStore struct {
	*kvtest.Store
	prefix  string
	blocked chan struct{}
	release chan struct{}
}

func (s *gatedStore) WriteBatch(ops ...kv.WriteOp) error {
	if len(ops) > 0 && strings.HasPrefix(ops[0].Key, s.prefix) {
		s.blocked <- struct{}{}
		<-s.release
	}
	return s.Store.WriteBatch(ops...)
}

// A downlink message being stored for one Cortex holds up no other stream: another Cortex's
// message is stored, queued and written meanwhile, and the slow one follows once its store is
// done.
func TestStoringAMessageBlocksNoOtherStream(t *testing.T) {
	store := &gatedStore{Store: kvtest.New(), prefix: outKey(cortexA, 0)[:len(outKeyPrefix)+len(cortexA)],
		blocked: make(chan struct{}, 1), release: make(chan struct{})}
	h := newHarnessOn(t, store, newTestKeys())
	a := h.connect(cortexA, "a")
	b := h.connect(cortexB, "b")
	slow := make(chan error, 1)
	go func() { slow <- h.hub.Send(context.Background(), cortexA, offer("slow")) }()
	select {
	case <-store.blocked:
	case <-time.After(waitFor):
		t.Fatal("the message for cortex A was not stored")
	}
	done := make(chan error, 1)
	go func() { done <- h.hub.Send(context.Background(), cortexB, offer("fast")) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(waitFor):
		close(store.release)
		t.Fatal("a message for cortex B waited for cortex A's store")
	}
	if got := receiveOffers(t, b, 1); got[0] != "fast" {
		t.Fatalf("cortex B got %v", got)
	}
	if !h.hub.Connected(cortexA) {
		t.Fatal("cortex A not connected")
	}
	close(store.release)
	if err := <-slow; err != nil {
		t.Fatal(err)
	}
	if got := receiveOffers(t, a, 1); got[0] != "slow" {
		t.Fatalf("cortex A got %v", got)
	}
}

// SendBatch stores its messages in one synced write and queues them in order with consecutive
// cursors.
func TestSendBatchStoresOnceAndQueuesInOrder(t *testing.T) {
	store := kvtest.New()
	h := newHarnessOn(t, store, newTestKeys())
	s := h.connect(cortexA, "1")
	before := store.Synced()
	if err := h.hub.SendBatch(context.Background(), cortexA, []*nexusv1.DispatchStreamFrameV1{offer("1"), offer("2"), offer("3")}); err != nil {
		t.Fatal(err)
	}
	if n := store.Synced() - before; n != 1 {
		t.Fatalf("%d synced writes for a batch of 3, want 1", n)
	}
	if got := receiveOffers(t, s, 3); strings.Join(got, ",") != "1,2,3" {
		t.Fatalf("batch received as %v", got)
	}
	waitPending(t, h, cortexA, 3)
	if err := h.hub.SendBatch(context.Background(), cortexB, []*nexusv1.DispatchStreamFrameV1{offer("x")}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("batch to a Cortex without a stream = %v", err)
	}
}

// Releasing acknowledged messages does not wait for the disk: a crash before the next synced write
// sends them again on the Cortex's next stream, as an ack in flight at a crash always did, and one
// after it does not.
func TestReleasedMessagesAfterACrash(t *testing.T) {
	store, keys := kvtest.New(), newTestKeys()
	h := newHarnessOn(t, store, keys)
	s := h.connect(cortexA, "1")
	mustSend(t, h, cortexA, "a")
	receiveOffers(t, s, 1)
	s.ack(1)
	waitPending(t, h, cortexA, 0)

	replayed := func(crashed kv.Store, nonce string) []string {
		t.Helper()
		restarted := newHarnessOn(t, crashed, keys)
		s2 := restarted.connect(cortexA, nonce)
		var labels []string
		for {
			select {
			case f := <-s2.stream.out:
				if f.GetOffer() != nil {
					labels = append(labels, offerLabelOf(t, f))
				}
				continue
			case <-time.After(50 * time.Millisecond):
			}
			return labels
		}
	}
	if got := replayed(store.Crash(), "2"); strings.Join(got, ",") != "a" {
		t.Fatalf("after a crash before any later synced write the stream got %v, want the acknowledged a again", got)
	}
	mustSend(t, h, cortexA, "b")
	if got := replayed(store.Crash(), "3"); strings.Join(got, ",") != "b" {
		t.Fatalf("after a crash past a later synced write the stream got %v, want only b", got)
	}
}
