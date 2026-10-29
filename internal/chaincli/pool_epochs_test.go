package chaincli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

func poolPublishedEvent(cursor string, epoch uint64, snapshot []byte) *hubv1.SubscribeProtocolEventsResponse {
	return &hubv1.SubscribeProtocolEventsResponse{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: &hubv1.ProtocolEvent{
		Cursor: cursor, ChainHeight: 100 + epoch, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_CANDIDATE_POOL_PUBLISHED,
		Payload: &hubv1.ProtocolEventPayloadV1{TypedEvent: &hubv1.ProtocolEventPayloadV1_CandidatePoolPublished{
			CandidatePoolPublished: &hubv1.EventCandidatePoolPublished{Epoch: epoch, SnapshotId: snapshot, ActiveCount: 3, EffectiveHeight: 10 * epoch},
		}},
	}}}
}

func poolExpiredEvent(cursor string, epoch uint64, snapshot []byte) *hubv1.SubscribeProtocolEventsResponse {
	return &hubv1.SubscribeProtocolEventsResponse{Item: &hubv1.SubscribeProtocolEventsResponse_Event{Event: &hubv1.ProtocolEvent{
		Cursor: cursor, ChainHeight: 200 + epoch, Code: sharedv1.ProtocolEventCodeV1_PROTOCOL_EVENT_CODE_V1_CANDIDATE_POOL_EXPIRED,
		Payload: &hubv1.ProtocolEventPayloadV1{TypedEvent: &hubv1.ProtocolEventPayloadV1_CandidatePoolExpired{
			CandidatePoolExpired: &hubv1.EventCandidatePoolExpired{Epoch: epoch, SnapshotId: snapshot},
		}},
	}}}
}

// Candidate pool events fill the epoch -> snapshot table, which survives a restart; a malformed
// snapshot id is delivered untyped and not recorded.
func TestProtocolStreamRecordsCandidatePoolEpochs(t *testing.T) {
	store := kv.NewMemStore()
	c := newRoleTestClient(store)
	stream := &fakeProtocolStream{items: []*hubv1.SubscribeProtocolEventsResponse{
		poolPublishedEvent("p1", 4, mustHash32("44")),
		poolExpiredEvent("p2", 3, mustHash32("33")),
		poolPublishedEvent("p3", 5, []byte{5}),
	}}
	_, _ = c.consumeProtocolEvents(context.Background(), stream)
	events := drainEvents(c)
	if len(events) != 3 || events[2].Typed != nil {
		t.Fatalf("events = %+v", events)
	}
	if typed, ok := events[0].Typed.(CandidatePoolPublished); !ok || typed.Epoch != 4 || typed.ActiveCount != 3 || typed.EffectiveHeight != 40 {
		t.Fatalf("published = %#v", events[0].Typed)
	}

	restarted := newRoleTestClient(store)
	for epoch, want := range map[uint64][]byte{4: mustHash32("44"), 3: mustHash32("33")} {
		got, err := restarted.CandidatePoolSnapshotOfEpoch(context.Background(), epoch)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("epoch %d = %x, %v", epoch, got, err)
		}
	}
	if _, err := restarted.CandidatePoolSnapshotOfEpoch(context.Background(), 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed epoch 5: err = %v", err)
	}
}

func TestPoolEpochTableForgetsTheOldestEpochs(t *testing.T) {
	store := kv.NewMemStore()
	table := &poolEpochTable{store: store, chainID: "chain-a"}
	for epoch := uint64(1); epoch <= maxPoolEpochs+2; epoch++ {
		if err := table.record(epoch, mustHash32("ab")); err != nil {
			t.Fatal(err)
		}
	}
	for epoch, want := range map[uint64]bool{1: false, 2: false, 3: true, maxPoolEpochs + 2: true} {
		if _, ok, _ := table.lookup(epoch); ok != want {
			t.Fatalf("epoch %d kept = %v, want %v", epoch, ok, want)
		}
	}
	reloaded := &poolEpochTable{store: store, chainID: "chain-a"}
	if _, ok, _ := reloaded.lookup(2); ok {
		t.Fatal("a forgotten epoch came back from the store")
	}
	if _, ok, _ := (&poolEpochTable{store: store, chainID: "chain-b"}).lookup(3); ok {
		t.Fatal("another chain's epochs were read")
	}
	if err := table.record(9, []byte{1}); err == nil {
		t.Fatal("a short snapshot id was recorded")
	}
}
