package buildersync

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/taskgroup"
	"github.com/TrueOpen/wire/dispatch"
)

// From the first ticket on, the member holds the round with its roster and the root it binds, the
// input copy and every attempt as it changes; the signed record once a Worker accepted. The
// user's order only follows once the chain recorded the order, with D's RECORDED header.
func TestSyncContentsAndTiming(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.s.OrderChanged(f.issued())
	e.sync()
	c := e.copyOf()
	if c == nil || len(c.Rounds) != 1 || len(c.Rounds[0].Attempts) != 1 || !bytes.Equal(c.Rounds[0].SignedRoot, f.root) ||
		!bytes.Equal(c.Rounds[0].RootDigest, f.rootDigest[:]) || !bytes.Equal(c.Rounds[0].Roster, f.roster) {
		t.Fatalf("copy after the first ticket = %+v", c)
	}
	if c.SignedOrder != nil || c.DeadlineBase != testESH || c.Rounds[0].Attempts[0].Outcome != outcomeOut {
		t.Fatalf("copy after the first ticket = %+v", c)
	}
	inputKey := taskdata.ObjectKey{TaskHash: c.TaskHash, SessionID: c.SessionID, TaskID: c.TaskID, Kind: taskdata.ObjectKindInput,
		ContentHash: taskdata.InputContentHash(hexOf(sumOf(f.input)))}
	if meta, err := e.member.data.Metadata(context.Background(), inputKey); err != nil || meta.State != taskdata.StateReady {
		t.Fatalf("input copy = %+v, %v", meta, err)
	}
	if a, held := e.member.r.Replica(f.sessionHex(), f.taskHex()); !held || a.Status != attempt.Pending || a.Header != nil || a.User != f.user {
		t.Fatalf("replica before the record = %+v, %v", a, held)
	}

	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	c = e.copyOf()
	if a := c.Rounds[0].Attempts; len(a) != 2 || a[0].Outcome != outcomeRejected || !bytes.Equal(a[0].Reject, f.reject) || !a[0].Rebuttable() {
		t.Fatalf("attempts after the reject = %+v", a)
	}

	f.putAccepted()
	e.s.OrderChanged(f.accepted())
	e.sync()
	c = e.copyOf()
	if !bytes.Equal(c.Record, f.record) || !bytes.Equal(c.Accept, f.accept) || c.Rounds[0].Attempts[1].Outcome != outcomeAccepted || c.SignedOrder != nil {
		t.Fatalf("copy after the accept = %+v", c)
	}

	// Recorded before the chain holds the record: the member refuses the order and keeps asking.
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	if c = e.copyOf(); c.SignedOrder != nil || c.Recorded {
		t.Fatal("the member took the order before the chain recorded it")
	}
	f.recordOnChain()
	e.clock.advance(time.Minute)
	e.s.deliverPeer(context.Background(), e.m.op)
	c = e.copyOf()
	if !bytes.Equal(c.SignedOrder, f.signed) || !c.Recorded || c.RecordedHeight != 110 {
		t.Fatalf("copy after the record = %+v", c)
	}
	a, held := e.member.r.Replica(f.sessionHex(), f.taskHex())
	if !held || a.Status != attempt.Recorded || a.TicketHash != f.hashes[1] || a.User != f.user || a.Worker != e.worker.op ||
		!bytes.Equal(a.Header, f.recordedAttempt().Header) {
		t.Fatalf("replica after the record = %+v", a)
	}
}

// Only the order item ever carries the user's order, and it is queued only on Recorded.
func TestOrderIsNeverQueuedBeforeTheRecord(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	for _, v := range []func() *dispatchevidence.Order{f.issued, f.rejectedThenOut, f.accepted} {
		e.s.OrderChanged(v())
	}
	e.s.drain()
	err := e.dStore.Scan(kv.NSBuilderSyncOutbox, func(key string, val []byte) bool {
		if strings.HasPrefix(key, outItemPrefix) {
			var item nexusv1.BuilderSyncItemV1
			if proto.Unmarshal(val, &item) == nil && item.GetOrder() != nil {
				t.Fatalf("order item %s queued before the record", key)
			}
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The recorded winner's frames follow the order item frame by frame, with the Fin; the member
// writes its replica and hands each frame to its live subscribers.
func TestOutputFramesFollowTheRecord(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello, ", "world"}, false)
	e.s.OrderChanged(f.issued())
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	key := taskdata.ObjectKey{SessionID: f.sessionHex(), TaskID: f.taskHex(), Kind: taskdata.ObjectKindOutput}
	frames, err := e.member.data.OutputFrames(context.Background(), key, nil)
	if err != nil || len(frames) != 2 || string(frames[1].Chunk.Text) != "world" {
		t.Fatalf("replica = %+v, %v", frames, err)
	}
	f.writeOutput(e.dData, e.worker, []string{"hello, ", "world", "!!"}, true)
	e.s.deliverPeer(context.Background(), e.m.op)
	frames, _ = e.member.data.OutputFrames(context.Background(), key, nil)
	if len(frames) != 4 || frames[3].Fin == nil || frames[3].Fin.FinalSeq != 2 {
		t.Fatalf("replica after the Fin = %+v", frames)
	}
	if got := e.member.frames(); len(got) != 4 || got[3].Fin == nil {
		t.Fatalf("published frames = %+v", got)
	}
	// Nothing more is due once the member holds the Fin.
	before := len(e.peers.requests[e.m.op])
	e.s.deliverPeer(context.Background(), e.m.op)
	if len(e.peers.requests[e.m.op]) != before {
		t.Fatal("a member holding the Fin was sent more")
	}
}

// A member that cannot be reached is retried with backoff until it takes the items, and the
// items stay in the outbox until then; a restart goes on from the stored outbox. A member that
// stays failing past the alarm threshold is counted as an alarm.
func TestRetryUntilAckedAcrossARestart(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.peers.setFail(e.m.op, errors.New("M is down"))
	e.s.OrderChanged(f.issued())
	e.sync()
	if e.copyOf() != nil || e.s.Counts().Failures != 1 {
		t.Fatalf("copy %v, counts %+v", e.copyOf(), e.s.Counts())
	}
	e.s.deliverPeer(context.Background(), e.m.op)
	if e.s.Counts().Failures != 1 {
		t.Fatal("a failed member was retried before its backoff")
	}
	e.clock.advance(2 * time.Minute)
	e.s.deliverPeer(context.Background(), e.m.op)
	if c := e.s.Counts(); c.Failures != 2 || c.Alarms != 1 {
		t.Fatalf("counts after failing past the threshold = %+v", c)
	}

	e.openSender() // restart
	e.peers.setFail(e.m.op, nil)
	e.s.deliverPeer(context.Background(), e.m.op)
	if c := e.copyOf(); c == nil || len(c.Rounds[0].Attempts) != 1 {
		t.Fatalf("copy after the restart = %+v", c)
	}
	// X never took the items: they stay for it, while M's progress is stored.
	st := e.s.streams[streamKey(f.sessionHex(), f.sequence)]
	if st.Acked[e.m.op] != st.Last || st.Acked[e.x.op] != 0 || st.Pruned != 0 {
		t.Fatalf("stream after M acked = %+v", st)
	}
	e.peers.receivers[e.x.op] = e.newMember(e.x).r
	e.peers.setFail(e.x.op, nil)
	e.s.deliverPeer(context.Background(), e.x.op)
	st = e.s.streams[streamKey(f.sessionHex(), f.sequence)]
	if st.Pruned != st.Last {
		t.Fatalf("items acknowledged by every member are kept: %+v", st)
	}
	if _, found, _ := e.dStore.GetWithError(kv.NSBuilderSyncOutbox, outItemKey(st.key(), 1)); found {
		t.Fatal("acknowledged item still stored")
	}
}

// A batch sent again is applied once; a batch that skips items is refused and the sender starts
// again from what the member holds.
func TestRedeliveryAndOutOfOrderItems(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.s.OrderChanged(f.issued())
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	resp, err := e.member.r.Sync(context.Background(), e.raw(reqs[len(reqs)-1]))
	if err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != e.s.streams[streamKey(f.sessionHex(), f.sequence)].Last {
		t.Fatalf("redelivery = %v, %v", resp, err)
	}
	if c := e.copyOf(); len(c.Rounds[0].Attempts) != 2 {
		t.Fatalf("redelivery changed the copy: %+v", c.Rounds[0].Attempts)
	}

	// A fresh member gets only the items from 3 on: refused, and it holds nothing.
	fresh := e.newMember(e.m)
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	batch.Items = batch.Items[2:]
	resp, err = fresh.r.Sync(context.Background(), e.signed(batch))
	if err != nil || !strings.Contains(resp.GetRefused(), "out of order") || resp.GetAppliedThrough() != 0 {
		t.Fatalf("out of order batch = %v, %v", resp, err)
	}
}

// signed is a batch signed as D, as the bytes a member receives.
func (e *env) signed(batch *nexusv1.BuilderSyncBatchV1) []byte {
	e.t.Helper()
	return e.signedBy(e.d.key, batch)
}

// signedBy is a batch signed with key, as the bytes a member receives.
func (e *env) signedBy(key signer.Signer, batch *nexusv1.BuilderSyncBatchV1) []byte {
	e.t.Helper()
	req, err := SignRequest(key, batch)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.raw(req)
}

// raw is a request as the bytes a member receives.
func (e *env) raw(req *nexusv1.SyncRequest) []byte {
	e.t.Helper()
	return mustMarshal(e.t, req)
}

// inputOnly is a copy of batch with only its first input piece: a batch whose sender or order can be
// changed without breaking the identities the wire contract checks inside the items.
func inputOnly(batch *nexusv1.BuilderSyncBatchV1) *nexusv1.BuilderSyncBatchV1 {
	b := proto.Clone(batch).(*nexusv1.BuilderSyncBatchV1)
	for _, item := range b.Items {
		if item.GetInputChunk() != nil {
			b.Items = []*nexusv1.BuilderSyncItemV1{item}
			return b
		}
	}
	panic("batch has no input piece")
}

// firstBatch is the batch D sends M for the order's first ticket.
func (e *env) firstBatch() *nexusv1.BuilderSyncBatchV1 {
	e.t.Helper()
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.s.OrderChanged(e.fx.issued())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	return batch
}

// A batch from a Builder outside the group, for a stale BuilderSet, signed by another key or not
// addressed to this Builder is refused as a whole.
func TestReceiverRefusesBatchesNotFromTheGroup(t *testing.T) {
	e := newEnv(t)
	batch := e.firstBatch()
	ctx := context.Background()

	outsider := newParty(t, 0x07, 0x17)
	e.keys.set("BUILDER", outsider)
	b := inputOnly(batch)
	b.SenderOperatorAddress = outsider.op
	if _, err := e.member.r.Sync(ctx, e.signedBy(outsider.key, b)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("outsider: %v", err)
	}

	if _, err := e.member.r.Sync(ctx, e.signedBy(e.x.key, batch)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("another key's signature: %v", err)
	}

	b = proto.Clone(batch).(*nexusv1.BuilderSyncBatchV1)
	b.BuilderSetId = "set-0"
	if _, err := e.member.r.Sync(ctx, e.signed(b)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("stale BuilderSet: %v", err)
	}

	b = proto.Clone(batch).(*nexusv1.BuilderSyncBatchV1)
	b.ReceiverOperatorAddress = e.x.op
	if _, err := e.member.r.Sync(ctx, e.signed(b)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("batch for another member: %v", err)
	}

	e.keys.fails = true
	if _, err := e.member.r.Sync(ctx, e.signed(batch)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unreadable key: %v", err)
	}
	e.keys.fails = false
	if e.copyOf() != nil {
		t.Fatal("a refused batch left a copy")
	}
	if resp, err := e.member.r.Sync(ctx, e.signed(batch)); err != nil || resp.GetRefused() != "" {
		t.Fatalf("the genuine batch = %v, %v", resp, err)
	}
}

// Items that do not stand up are refused, and nothing after them is applied: an input that does
// not hash to its input_hash, a ticket D did not sign, a roster that is not the roster_hash.
func TestReceiverRefusesBadItems(t *testing.T) {
	for name, spoil := range map[string]func(*env, *nexusv1.BuilderSyncBatchV1){
		"input hash": func(_ *env, b *nexusv1.BuilderSyncBatchV1) {
			for _, item := range b.Items {
				if c := item.GetInputChunk(); c != nil && c.GetOffset() == 0 {
					c.Data = append([]byte("H"), c.Data[1:]...)
				}
			}
		},
		"ticket signature": func(e *env, b *nexusv1.BuilderSyncBatchV1) {
			for _, item := range b.Items {
				if a := item.GetAttempt(); a != nil {
					signWith(e.t, e.x.key, ticketName, a.Ticket, func(s []byte) { a.Ticket.BuilderServiceSignature = s })
				}
			}
		},
		"roster": func(_ *env, b *nexusv1.BuilderSyncBatchV1) {
			b.Items[0].GetRound().RosterHash = fill(0x01)
		},
		"round task_hash": func(_ *env, b *nexusv1.BuilderSyncBatchV1) {
			b.Items[0].GetRound().TaskHash = fill(0x02)
			for _, item := range b.Items {
				if c := item.GetInputChunk(); c != nil {
					c.TaskHash = fill(0x02)
				}
			}
		},
		"input piece out of order": func(_ *env, b *nexusv1.BuilderSyncBatchV1) {
			for _, item := range b.Items {
				if c := item.GetInputChunk(); c != nil && c.GetOffset() > 0 {
					c.Offset++
					break
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			batch := e.firstBatch()
			spoil(e, batch)
			resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
			if err != nil || resp.GetRefused() == "" {
				t.Fatalf("spoiled batch = %v, %v", resp, err)
			}
			if c := e.copyOf(); c != nil && len(c.Rounds) > 0 && len(c.Rounds[0].Attempts) > 0 {
				t.Fatalf("items after the refused one were applied: %+v", c)
			}
		})
	}
}

// recordedBatch has D sync the recorded order with its output, held back from M, and returns the
// last batch.
func (e *env) recordedBatch(texts []string) *nexusv1.BuilderSyncBatchV1 {
	e.t.Helper()
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, texts, true)
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.sync()
	reqs := e.peers.requests[e.m.op]
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	if batch.Output == nil || len(batch.Output.Chunks) != len(texts) {
		e.t.Fatalf("recorded batch has no output: %v", batch.Output)
	}
	return batch
}

// Output frames are checked against the recorded winner: a frame another Cortex signed, or a batch
// naming another accept digest, is refused and not written.
func TestReceiverRefusesForeignOutput(t *testing.T) {
	t.Run("frame signed by another Worker", func(t *testing.T) {
		e := newEnv(t)
		other := newDataStore(t, kv.NewMemStore())
		e.fx.writeOutput(other, e.other, []string{"hello, ", "world"}, false)
		batch := e.recordedBatch([]string{"hello, ", "world"})
		forged, err := other.OutputFrames(context.Background(), taskdata.ObjectKey{SessionID: e.fx.sessionHex(), TaskID: e.fx.taskHex(), Kind: taskdata.ObjectKindOutput}, nil)
		if err != nil {
			t.Fatal(err)
		}
		batch.Output.Chunks[1] = chunkToPB(forged[1].Chunk)
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		if err != nil || !strings.Contains(resp.GetRefused(), "not signed by the winner") || resp.GetOutputLastSeq() != 0 {
			t.Fatalf("forged frame = %v, %v", resp, err)
		}
	})
	t.Run("accept digest", func(t *testing.T) {
		e := newEnv(t)
		batch := e.recordedBatch([]string{"hello, "})
		batch.Output.DispatchAcceptDigest = fill(0x01)
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		if err != nil || !strings.Contains(resp.GetRefused(), "accept") || resp.GetOutputReceived() {
			t.Fatalf("other accept digest = %v, %v", resp, err)
		}
		if resp.GetAppliedThrough() == 0 {
			t.Fatal("the items before the output were not applied")
		}
	})
}

func sumOf(b []byte) []byte {
	s := sum(b)
	return s[:]
}

// A started sender delivers on its own: the queue and the member workers run in the background.
func TestStartedSenderDelivers(t *testing.T) {
	e := newEnv(t)
	if err := e.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.s.Stop(context.Background()) }()
	e.s.OrderChanged(e.fx.issued())
	deadline := time.Now().Add(5 * time.Second)
	for e.copyOf() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the started sender did not deliver")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An order whose sync stream began under the then current BuilderSet keeps syncing after the
// snapshot is replaced (a recorded task keeps the group it was locked with); a new order of a
// snapshot older than the previous one is refused.
func TestReceiverKeepsAnOrderAcrossASnapshotChange(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.s.OrderChanged(f.issued())
	e.sync()
	e.groups.mu.Lock()
	e.groups.snapshot = taskgroupSnapshot("set-2", 0x5f, e.d.op, e.m.op)
	e.groups.mu.Unlock()
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	if c := e.copyOf(); len(c.Rounds[0].Attempts) != 2 {
		t.Fatalf("the order stopped syncing after the snapshot changed: %+v", c.Rounds[0].Attempts)
	}
	// Two replacements later a new order of the first snapshot is refused.
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 100})
	e.groups.mu.Lock()
	e.groups.snapshot = taskgroupSnapshot("set-3", 0x60, e.d.op, e.m.op)
	e.groups.mu.Unlock()
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 101})
	batch := inputOnly(e.peers.requests[e.m.op][0].GetBatch())
	batch.SessionId = fill(0xab)
	batch.BuilderSetId, batch.BuilderSetHash = "set-1", fill(0x5e)
	if _, err := e.member.r.Sync(context.Background(), e.signed(batch)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("new order of a snapshot two replacements back: %v", err)
	}
}

// A batch naming a sender outside the BuilderSet is refused from local state alone: the endpoint
// takes no API key, so a made-up sender must never cost a chain read of its key.
func TestNonMemberCostsNoKeyLookup(t *testing.T) {
	e := newEnv(t)
	batch := inputOnly(e.firstBatch())
	e.keys.mu.Lock()
	e.keys.lookups = nil
	e.keys.mu.Unlock()
	batch.SenderOperatorAddress = newParty(t, 0x08, 0x18).op
	req := e.signed(batch)
	if _, err := e.member.r.Sync(context.Background(), req); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("made-up sender: %v", err)
	}
	e.keys.mu.Lock()
	defer e.keys.mu.Unlock()
	if len(e.keys.lookups) != 0 {
		t.Fatalf("a made-up sender cost key lookups: %v", e.keys.lookups)
	}
}

// A REJECTED attempt's reject must verify under the target's current key, so a member never sends
// a rebuttal the chain would refuse. One that does not (the Worker rotated its key since) is
// dropped: the attempt is kept as REJECTED without a reject and the order's later items still apply.
func TestReceiverChecksTheRejectSignature(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.s.OrderChanged(f.issued())
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	for _, item := range batch.Items {
		if a := item.GetAttempt(); a != nil && a.Reject != nil {
			signWith(t, e.other.key, rejectName, a.Reject, func(s []byte) { a.Reject.ServiceSignature = s })
		}
	}
	resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
	if err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != uint64(len(batch.Items)) {
		t.Fatalf("reject under another key = %v, %v", resp, err)
	}
	a := e.copyOf().Rounds[0].Attempts
	if len(a) != 2 || a[0].Outcome != outcomeRejected || len(a[0].Reject) != 0 {
		t.Fatalf("attempts after a reject under another key = %+v", a)
	}
}

// After the dispatching Builder's cutover its batches are signed with its new key while the roots,
// tickets and records it signed before keep its previous key: they still apply for an order whose
// earliest_submit_height is below the retirement height, and are refused for a later one. A
// Worker's reject signed with its previous key is kept on the same terms.
func TestReceiverTakesPreviousKeyMaterialOfOrdersBeforeTheCutover(t *testing.T) {
	for _, tc := range []struct {
		name    string
		retired uint64
		applied bool
	}{{"order before the cutover", testESH + 1, true}, {"order at the cutover", testESH, false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			f := e.fx
			e.peers.setFail(e.m.op, errors.New("held back"))
			e.s.OrderChanged(f.accepted())
			e.sync()
			reqs := e.peers.requests[e.m.op]
			batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
			next := newSigner(t, 0x21)
			e.keys.rotate("BUILDER", e.d, next, tc.retired)
			e.keys.rotate("CORTEX", f.rejecter, newSigner(t, 0x22), tc.retired)
			resp, err := e.member.r.Sync(context.Background(), e.signedBy(next, batch))
			if err != nil {
				t.Fatal(err)
			}
			if applied := resp.GetRefused() == "" && resp.GetAppliedThrough() == uint64(len(batch.Items)); applied != tc.applied {
				t.Fatalf("batch = %v; applied %v, want %v", resp, applied, tc.applied)
			}
			if !tc.applied {
				return
			}
			c := e.copyOf()
			if len(c.Record) == 0 || len(c.Rounds[0].Attempts) != 2 || len(c.Rounds[0].Attempts[0].Reject) == 0 {
				t.Fatalf("copy = %+v", c)
			}
		})
	}
}

// A winner later voided (a binding change) leaves no accept in the copy.
func TestVoidedWinnerDropsTheAccept(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.s.OrderChanged(f.accepted())
	e.sync()
	if len(e.copyOf().Accept) == 0 {
		t.Fatal("accept not synced")
	}
	voided := f.rejectedThenOut()
	voided.Rounds[0].Attempts[1].Outcome = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_VOIDED
	e.s.OrderChanged(voided)
	e.sync()
	if c := e.copyOf(); len(c.Accept) != 0 || c.Rounds[0].Attempts[1].Outcome != taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_VOIDED {
		t.Fatalf("copy after the void = accept %x, attempts %+v", c.Accept, c.Rounds[0].Attempts)
	}
}

// An input over what this member can store is not held, and the rest of the order still syncs:
// the input copy is a fallback, the evidence is a duty.
func TestOversizedInputDoesNotStopTheOrder(t *testing.T) {
	e := newEnv(t)
	small := e.newMember(e.m)
	small.r.cfg.MaxInputBytes = 4
	e.member = small
	e.peers.receivers[e.m.op] = small.r
	e.s.OrderChanged(e.fx.rejectedThenOut())
	e.sync()
	if c := e.copyOf(); c == nil || len(c.Rounds[0].Attempts) != 2 {
		t.Fatalf("copy with an oversized input = %+v", c)
	}
	m, _, _ := small.r.loadMember(memberKey(e.d.op, e.fx.sessionHex(), e.fx.sequence))
	if in := m.Inputs[hexOf(e.fx.taskHash)]; in == nil || in.Stored || !in.Skipped {
		t.Fatalf("oversized input = %+v", in)
	}
}

// A Fin the winner did not sign is refused and does not seal the replica.
func TestReceiverRefusesAForgedFin(t *testing.T) {
	e := newEnv(t)
	batch := e.recordedBatch([]string{"hello, "})
	if batch.Output.Fin == nil {
		t.Fatal("no fin in the batch")
	}
	batch.Output.Fin.WorkerSignature = bytes.Repeat([]byte{1}, 64)
	resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
	if err != nil || !strings.Contains(resp.GetRefused(), "fin") || resp.GetOutputSealed() || !resp.GetOutputReceived() {
		t.Fatalf("forged fin = %v, %v", resp, err)
	}
}

// A chain read that fails is not a refusal of the order: the member answers it cannot judge yet,
// and takes the order once the chain answers.
func TestOrderWaitsForAReadableChain(t *testing.T) {
	e := newEnv(t)
	batch := e.recordedBatch([]string{"hello, "})
	e.records.mu.Lock()
	e.records.err = errors.New("node unreachable")
	e.records.mu.Unlock()
	resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
	if err != nil || !strings.Contains(resp.GetRefused(), "UNAVAILABLE") || e.copyOf().Recorded {
		t.Fatalf("unreadable chain = %v, %v", resp, err)
	}
	e.records.mu.Lock()
	e.records.err = nil
	e.records.mu.Unlock()
	if resp, err = e.member.r.Sync(context.Background(), e.signed(batch)); err != nil || resp.GetRefused() != "" || !e.copyOf().Recorded {
		t.Fatalf("readable chain = %v, %v", resp, err)
	}
}

// A member that keeps no output replicas (streaming output off) says so: the sender stops
// sending it output, without failures or alarms, and the rest of the order still syncs.
func TestMemberWithoutOutputReplicas(t *testing.T) {
	e := newEnv(t)
	plain := e.newMember(e.m)
	plain.r.cfg.OutputConfig = taskdata.OutputStreamConfig{}
	e.member = plain
	e.peers.receivers[e.m.op] = plain.r
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello, "}, true)
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	if c := e.copyOf(); c == nil || !c.Recorded {
		t.Fatalf("copy = %+v", c)
	}
	if c := e.s.Counts(); c.Failures != 0 || c.Alarms != 0 {
		t.Fatalf("counts = %+v", c)
	}
	before := len(e.peers.requests[e.m.op])
	e.clock.advance(time.Minute)
	e.s.deliverPeer(context.Background(), e.m.op)
	if len(e.peers.requests[e.m.op]) != before {
		t.Fatal("output was sent again to a member that holds none")
	}
}

// A recorded order whose order item never got queued (a crash after the attempt book marked it,
// or a failed evidence read) is found again from the attempt book on a start and on later blocks.
func TestRecordedOrderIsFoundAgain(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	e.s.OrderChanged(f.accepted())
	e.sync()
	e.book[f.taskHex()] = f.recordedAttempt()
	e.openSender() // restart
	if err := e.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.s.Stop(context.Background()) }()
	deadline := time.Now().Add(5 * time.Second)
	for c := e.copyOf(); c == nil || !c.Recorded; c = e.copyOf() {
		if time.Now().After(deadline) {
			t.Fatal("the recorded order was not found again on a start")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The snapshot may be replaced between the dispatch of an order and its first batch: the sender
// builds the order's group from the chain's copy of the snapshot the order names, and a member
// takes a new order of the snapshot it saw just before the current one.
func TestFirstBatchAfterASnapshotChange(t *testing.T) {
	e := newEnv(t)
	set1 := e.groups.snapshot
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 100})
	e.groups.mu.Lock()
	e.groups.snapshot = taskgroupSnapshot("set-2", 0x5f, e.d.op, e.m.op)
	e.groups.mu.Unlock()
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 101})
	var asked uint64
	e.s.cfg.SnapshotAt = func(_ context.Context, height uint64) (taskgroup.Snapshot, error) {
		asked = height
		return set1, nil
	}
	e.s.OrderChanged(e.fx.issued())
	e.sync()
	if asked != testESH {
		t.Fatalf("snapshot asked at height %d", asked)
	}
	if c := e.copyOf(); c == nil || len(c.Rounds) != 1 {
		t.Fatalf("copy after the snapshot changed = %+v", c)
	}
}

// Items every member acknowledged are deleted. A member that later holds fewer items than were
// deleted (it lost its store) cannot be caught up from the outbox: it is marked lost on the order
// and alarmed once, and only probed every lostProbeEvery with the items still held. Once it holds
// what was deleted again (its store restored), the mark is cleared and it syncs as before.
func TestMemberBehindDeletedItemsIsMarkedLost(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.peers.receivers[e.x.op] = e.newMember(e.x).r
	e.peers.setFail(e.x.op, nil)
	e.s.OrderChanged(f.issued())
	e.s.drain()
	e.s.deliverPeer(context.Background(), e.m.op)
	key := streamKey(f.sessionHex(), f.sequence)
	if st := e.s.streams[key]; st.Pruned != 0 {
		t.Fatalf("items deleted before every member acknowledged them: %+v", st)
	}
	e.s.deliverPeer(context.Background(), e.x.op)
	if st := e.s.streams[key]; st.Pruned != st.Last || st.Last == 0 {
		t.Fatalf("items acknowledged by both members kept: %+v", st)
	}

	restored := e.member
	fresh := e.newMember(e.m) // M lost its store
	e.member = fresh
	e.peers.receivers[e.m.op] = fresh.r
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	st := e.s.streams[key]
	if !st.Lost[e.m.op] || e.s.Counts().Alarms != 1 {
		t.Fatalf("lost member: lost %v, counts %+v", st.Lost, e.s.Counts())
	}
	before := len(e.peers.requests[e.m.op])
	e.clock.advance(lostProbeEvery / 2)
	e.s.deliverPeer(context.Background(), e.m.op)
	if len(e.peers.requests[e.m.op]) != before {
		t.Fatal("a lost member was sent more before its probe")
	}
	// X goes on.
	e.s.deliverPeer(context.Background(), e.x.op)
	if st := e.s.streams[key]; st.Acked[e.x.op] != st.Last {
		t.Fatalf("X after M was lost: %+v", st)
	}
	e.clock.advance(lostProbeEvery)
	e.s.deliverPeer(context.Background(), e.m.op)
	if len(e.peers.requests[e.m.op]) != before+1 || !e.s.streams[key].Lost[e.m.op] || e.s.Counts().Alarms != 1 {
		t.Fatalf("probe of a member still without its store: %d requests, lost %v, %+v",
			len(e.peers.requests[e.m.op])-before, e.s.streams[key].Lost, e.s.Counts())
	}

	e.member = restored // M's store is restored from a backup
	e.peers.receivers[e.m.op] = restored.r
	e.clock.advance(lostProbeEvery)
	e.s.deliverPeer(context.Background(), e.m.op)
	if st := e.s.streams[key]; st.Lost[e.m.op] || st.Acked[e.m.op] != st.Last {
		t.Fatalf("restored member: %+v", st)
	}
}

// countingOutputs records how many frames each read of the winner's stream returned.
type countingOutputs struct {
	*taskdata.Store
	reads []int
}

func (c *countingOutputs) OutputFrames(ctx context.Context, key taskdata.ObjectKey, after *uint64) ([]taskdata.OutputFrame, error) {
	frames, err := c.Store.OutputFrames(ctx, key, after)
	c.reads = append(c.reads, len(frames))
	return frames, err
}

func (c *countingOutputs) OutputFramesUpTo(ctx context.Context, key taskdata.ObjectKey, after *uint64, maxBytes int) ([]taskdata.OutputFrame, error) {
	frames, err := c.Store.OutputFramesUpTo(ctx, key, after, maxBytes)
	c.reads = append(c.reads, len(frames))
	return frames, err
}

// A long output is read from the store a batch at a time, not whole for every batch.
func TestOutputIsReadABatchAtATime(t *testing.T) {
	e := newEnv(t)
	outputs := &countingOutputs{Store: e.dData}
	e.s.cfg.Outputs = outputs
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	texts := make([]string, 40)
	for i := range texts {
		texts[i] = strings.Repeat(string(rune('a'+i%26)), 60)
	}
	f.writeOutput(e.dData, e.worker, texts, true)
	// Room for the batch header, the winner ticket and about two frames.
	st := e.s.streams[streamKey(f.sessionHex(), f.sequence)]
	header := &nexusv1.SyncRequest{SenderSignature: make([]byte, 64), Batch: &nexusv1.BuilderSyncBatchV1{
		SchemaVersion: schemaVersion, ChainId: testChainID, SenderOperatorAddress: e.d.op, ReceiverOperatorAddress: e.m.op,
		SessionId: f.sessionID, OrderSequence: f.sequence, BuilderSetId: st.BuilderSetID, BuilderSetHash: st.BuilderSetHash,
		Output: &nexusv1.BuilderSyncOutputV1{DispatchTicketHash: st.Winner.TicketHash, WinnerTicket: &taskv1.DispatchTicketV1{},
			DispatchAcceptDigest: st.Winner.AcceptDigest},
	}}
	if err := proto.Unmarshal(st.Winner.Ticket, header.Batch.Output.WinnerTicket); err != nil {
		t.Fatal(err)
	}
	e.s.cfg.MaxBatchBytes = proto.Size(header) + 2*230
	outputs.reads = nil
	for range 40 {
		e.clock.advance(time.Minute)
		e.s.deliverPeer(context.Background(), e.m.op)
	}
	if got := e.member.frames(); len(got) != len(texts)+1 || got[len(got)-1].Fin == nil {
		t.Fatalf("member frames: %d", len(got))
	}
	for _, n := range outputs.reads {
		if n > 10 {
			t.Fatalf("a read returned %d frames for a batch of about two: %v", n, outputs.reads)
		}
	}
}

// Handing the sender a change never waits for a batch being built or a chain read under the
// stream lock: the dispatcher calls OrderChanged on its own path.
func TestOrderChangedDoesNotWaitForTheStreamLock(t *testing.T) {
	e := newEnv(t)
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		e.s.OrderChanged(e.fx.issued())
		e.s.Recorded(e.fx.recordedAttempt())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OrderChanged waited for the stream lock")
	}
}

// staleSnapshot has the BuilderSet replaced after the fixture's order was signed, so the sender
// asks SnapshotAt for the order's group.
func (e *env) staleSnapshot() taskgroup.Snapshot {
	e.t.Helper()
	set1 := e.groups.snapshot
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 100})
	e.groups.mu.Lock()
	e.groups.snapshot = taskgroupSnapshot("set-2", 0x5f, e.d.op, e.m.op)
	e.groups.mu.Unlock()
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 101})
	return set1
}

// The chain read of an order's group runs outside the stream lock and within RequestTimeout: a
// stuck node holds up neither the delivery workers nor the pruning.
func TestGroupReadDoesNotHoldTheStreamLock(t *testing.T) {
	e := newEnv(t)
	e.staleSnapshot()
	e.s.cfg.RequestTimeout = 50 * time.Millisecond
	entered := make(chan bool, 1)
	e.s.cfg.SnapshotAt = func(ctx context.Context, _ uint64) (taskgroup.Snapshot, error) {
		_, bounded := ctx.Deadline()
		entered <- bounded
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
		return taskgroup.Snapshot{}, errors.New("node stuck")
	}
	e.s.OrderChanged(e.fx.issued())
	done := make(chan struct{})
	go func() {
		e.s.drain()
		close(done)
	}()
	var bounded bool
	select {
	case bounded = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("SnapshotAt not called")
	}
	locked := e.s.mu.TryLock()
	if locked {
		e.s.mu.Unlock()
	}
	<-done
	if !locked || !bounded {
		t.Fatalf("group read: stream lock free %v, bounded by a deadline %v", locked, bounded)
	}
}

// A change that failed (the chain could not be read) is applied again a few blocks later instead
// of being dropped.
func TestFailedChangeIsAppliedAgain(t *testing.T) {
	e := newEnv(t)
	set1 := e.staleSnapshot()
	var down atomic.Bool
	down.Store(true)
	e.s.cfg.SnapshotAt = func(context.Context, uint64) (taskgroup.Snapshot, error) {
		if down.Load() {
			return taskgroup.Snapshot{}, errors.New("node unavailable")
		}
		return set1, nil
	}
	e.s.OrderChanged(e.fx.issued())
	e.sync()
	if c := e.copyOf(); c != nil {
		t.Fatalf("copy while the chain was down = %+v", c)
	}
	down.Store(false)
	e.s.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: pruneEveryBlocks})
	e.sync()
	if c := e.copyOf(); c == nil || len(c.Rounds) != 1 {
		t.Fatalf("copy after the chain came back = %+v", c)
	}
}

// A later round of a task held already must carry the task_hash the copy holds: it never
// replaces it.
func TestLaterRoundKeepsTheTaskHash(t *testing.T) {
	e := newEnv(t)
	batch := e.firstBatch()
	if resp, err := e.member.r.Sync(context.Background(), e.signed(batch)); err != nil || resp.GetRefused() != "" {
		t.Fatalf("first batch = %v, %v", resp, err)
	}
	last := batch.Items[len(batch.Items)-1].GetSequence()
	next := proto.Clone(batch).(*nexusv1.BuilderSyncBatchV1)
	round := proto.Clone(batch.Items[0]).(*nexusv1.BuilderSyncItemV1)
	round.Sequence = last + 1
	round.GetRound().DispatchRound = 1
	round.GetRound().TaskHash = fill(0x02)
	next.Items = []*nexusv1.BuilderSyncItemV1{round}
	resp, err := e.member.r.Sync(context.Background(), e.signed(next))
	if err != nil || !strings.Contains(resp.GetRefused(), "task_hash") {
		t.Fatalf("round with another task_hash = %v, %v", resp, err)
	}
	if c := e.copyOf(); c == nil || c.TaskHash != hex.EncodeToString(e.fx.taskHash) {
		t.Fatalf("copy task_hash = %+v", c)
	}
}

// The order item's signed order must be the order the chain recorded (its task_hash is the
// winner's) signed by its user's wallet or the session's registered key: another signer, or another
// order, is refused. A registered key set after the order may have replaced its signer: kept.
func TestOrderItemIsTheUsersSignedOrder(t *testing.T) {
	sessionKey := bytes.Repeat([]byte{0x22}, 32)
	for name, tc := range map[string]struct {
		signed  func(*fixture) []byte
		key     []byte // the session's registered key
		setAt   uint64 // its set height
		applies bool
	}{
		"wallet":         {signed: func(f *fixture) []byte { return f.signed }, applies: true},
		"registered key": {signed: func(f *fixture) []byte { return signOrder(f.e.t, sessionKey, f.order) }, key: sessionKey, applies: true},
		"another signer": {signed: func(f *fixture) []byte { return signOrder(f.e.t, sessionKey, f.order) }, key: bytes.Repeat([]byte{0x23}, 32)},
		"no session key": {signed: func(f *fixture) []byte { return signOrder(f.e.t, sessionKey, f.order) }},
		"key set later":  {signed: func(f *fixture) []byte { return signOrder(f.e.t, sessionKey, f.order) }, key: bytes.Repeat([]byte{0x23}, 32), setAt: 1 << 40, applies: true},
		"another order": {signed: func(f *fixture) []byte {
			order := proto.Clone(f.order).(*taskv1.TaskOrderV3)
			order.OrderExpireHeight++
			return signOrder(f.e.t, userKey, order)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if tc.key != nil {
				key := keyAddress(tc.key)
				e.sessions.state = registeredkey.State{Found: true, Owner: e.fx.user, Key: &key, SetHeight: tc.setAt}
			}
			batch := e.recordedBatch([]string{"hello, "})
			for _, item := range batch.Items {
				if o := item.GetOrder(); o != nil {
					o.SignedOrder = &taskv1.SignedOrderV2{}
					if err := proto.Unmarshal(tc.signed(e.fx), o.SignedOrder); err != nil {
						t.Fatal(err)
					}
				}
			}
			batch.Output = nil
			resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
			if err != nil || (resp.GetRefused() == "") != tc.applies {
				t.Fatalf("order item = %v, %v", resp, err)
			}
			a, held := e.member.r.Replica(e.fx.sessionHex(), e.fx.taskHex())
			if recorded := held && a.Status == attempt.Recorded; recorded != tc.applies {
				t.Fatalf("order item applied %v: %+v", recorded, a)
			}
		})
	}
}

// The snapshot current before the last replacement is accepted for a new order only for
// PreviousSnapshotBlocks after the replacement.
func TestPreviousSnapshotHasAWindow(t *testing.T) {
	e := newEnv(t)
	set1 := e.staleSnapshot() // replaced at height 101
	e.s.cfg.SnapshotAt = func(context.Context, uint64) (taskgroup.Snapshot, error) { return set1, nil }
	batch := e.firstBatch()
	e.member.r.cfg.PreviousSnapshotBlocks = 10
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 111})
	if resp, err := e.member.r.Sync(context.Background(), e.signed(batch)); err != nil || resp.GetRefused() != "" {
		t.Fatalf("within the window: %v, %v", resp, err)
	}
	e.member.r.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 112})
	other := inputOnly(batch)
	other.SessionId = fill(0xab)
	if _, err := e.member.r.Sync(context.Background(), e.signed(other)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("past the window: %v", err)
	}
}

// A reject whose target has no usable CORTEX key any more (deregistered or revoked since) is
// dropped like one that does not verify: the attempt is kept as REJECTED without it and the order's
// later items still apply. Only a chain that cannot be read leaves the batch to be sent again.
func TestRejectOfATargetWithoutAKey(t *testing.T) {
	heldBatch := func(e *env) *nexusv1.BuilderSyncBatchV1 {
		e.peers.setFail(e.m.op, errors.New("held back"))
		e.s.OrderChanged(e.fx.issued())
		e.s.OrderChanged(e.fx.rejectedThenOut())
		e.sync()
		reqs := e.peers.requests[e.m.op]
		batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
		return batch
	}
	t.Run("no key", func(t *testing.T) {
		e := newEnv(t)
		batch := heldBatch(e)
		e.keys.mu.Lock()
		delete(e.keys.keys, "CORTEX|"+e.fx.rejecter.op)
		e.keys.mu.Unlock()
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		if err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != uint64(len(batch.Items)) {
			t.Fatalf("reject of a target without a key = %v, %v", resp, err)
		}
		if a := e.copyOf().Rounds[0].Attempts; len(a) != 2 || a[0].Outcome != outcomeRejected || len(a[0].Reject) != 0 {
			t.Fatalf("attempts = %+v", a)
		}
	})
	t.Run("chain unreachable", func(t *testing.T) {
		e := newEnv(t)
		batch := heldBatch(e)
		e.keys.mu.Lock()
		e.keys.failsFor = "CORTEX"
		e.keys.mu.Unlock()
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		retried := errors.Is(err, ErrUnavailable) || err == nil && resp.GetRefused() != "" && resp.GetAppliedThrough() < uint64(len(batch.Items))
		if !retried {
			t.Fatalf("reject with the chain unreachable = %v, %v", resp, err)
		}
		if c := e.copyOf(); c != nil && len(c.Rounds) > 0 && len(c.Rounds[0].Attempts) > 0 && c.Rounds[0].Attempts[0].Outcome == outcomeRejected {
			t.Fatalf("the reject's attempt was stored with the chain unreachable: %+v", c.Rounds[0].Attempts)
		}
	})
}

// A Worker's accept is a dispatch proof: one not signed by its target, as an attempt's accept or
// in the result header of the recorded order, is refused.
func TestReceiverChecksTheAcceptSignature(t *testing.T) {
	t.Run("attempt", func(t *testing.T) {
		e := newEnv(t)
		f := e.fx
		e.peers.setFail(e.m.op, errors.New("held back"))
		e.s.OrderChanged(f.accepted())
		e.sync()
		reqs := e.peers.requests[e.m.op]
		batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
		spoiled := false
		for _, item := range batch.Items {
			if a := item.GetAttempt(); a != nil && a.Accept != nil {
				signWith(t, e.other.key, acceptName, a.Accept, func(s []byte) { a.Accept.ServiceSignature = s })
				spoiled = true
			}
		}
		if !spoiled {
			t.Fatal("no accept in the batch")
		}
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		if err != nil || resp.GetRefused() == "" {
			t.Fatalf("accept under another key = %v, %v", resp, err)
		}
		if c := e.copyOf(); c != nil && len(c.Accept) != 0 {
			t.Fatal("a forged accept was kept")
		}
	})
	t.Run("result header", func(t *testing.T) {
		e := newEnv(t)
		f := e.fx
		batch := e.recordedBatch([]string{"hello, "})
		spoiled := false
		for _, item := range batch.Items {
			if o := item.GetOrder(); o != nil {
				h := o.ResultHeader
				signWith(t, e.other.key, acceptName, h.Accept, func(s []byte) { h.Accept.ServiceSignature = s })
				signWith(t, f.e.d.key, resultHeaderName, h, func(s []byte) { h.BuilderServiceSignature = s })
				spoiled = true
			}
		}
		if !spoiled {
			t.Fatal("no order item in the batch")
		}
		batch.Output = nil
		resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
		if err != nil || resp.GetRefused() == "" {
			t.Fatalf("header with a forged accept = %v, %v", resp, err)
		}
	})
}

// The earliest_submit_height a round names selects which key generation proves the order's
// material; it is checked against the user's signed order once that is synced: a round that named
// another height is refused.
func TestOrderItemPinsTheRoundsEarliestSubmitHeight(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello, "}, true)
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.sync()
	reqs := e.peers.requests[e.m.op]
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	rounds, orders := 0, 0
	for _, item := range batch.Items {
		if r := item.GetRound(); r != nil {
			r.EarliestSubmitHeight--
			rounds++
		}
		if item.GetOrder() != nil {
			orders++
		}
	}
	if rounds == 0 || orders == 0 {
		t.Fatalf("batch holds %d rounds and %d orders", rounds, orders)
	}
	batch.Output = nil
	resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
	if err != nil || resp.GetRefused() == "" {
		t.Fatalf("round naming another earliest_submit_height = %v, %v", resp, err)
	}
	if a, held := e.member.r.Replica(f.sessionHex(), f.taskHex()); held && a.Status == attempt.Recorded {
		t.Fatal("the order was recorded")
	}
}

// A cutover between signing the RECORDED result header and syncing the order: the header carries
// no key generation, so the sender signs it again with its current key at every send, and the
// member, which checks it against the sender's current key, takes it.
func TestResultHeaderIsSignedWithTheCurrentKeyAtSend(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello, "}, true)
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.s.drain()
	next := newSigner(t, 0x21)
	e.keys.rotate("BUILDER", e.d, next, testESH+1)
	e.s.cfg.Signer = servicekey.Static(next, 2)
	e.s.deliverPeer(context.Background(), e.m.op)
	if a, held := e.member.r.Replica(f.sessionHex(), f.taskHex()); !held || a.Status != attempt.Recorded {
		t.Fatalf("order synced after the cutover = %+v, held %v", a, held)
	}
}

// cutoverSigner is a service key ring whose cutover comes right after its first signature.
type cutoverSigner struct {
	mu       sync.Mutex
	cur      signer.Signer
	next     signer.Signer
	switched bool
}

type cutoverKey struct {
	signer.Signer
	ring *cutoverSigner
}

func (k cutoverKey) SignDigest(d [32]byte) ([]byte, error) {
	sig, err := k.Signer.SignDigest(d)
	k.ring.mu.Lock()
	if !k.ring.switched {
		k.ring.cur, k.ring.switched = k.ring.next, true
	}
	k.ring.mu.Unlock()
	return sig, err
}

func (c *cutoverSigner) key() signer.Signer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}
func (c *cutoverSigner) Key() servicekey.Key {
	return servicekey.Key{Signer: cutoverKey{c.key(), c}, Nonce: 1}
}
func (c *cutoverSigner) PubKeyCompressed() []byte      { return c.key().PubKeyCompressed() }
func (c *cutoverSigner) Address() string               { return c.key().Address() }
func (c *cutoverSigner) Sign(m []byte) ([]byte, error) { return cutoverKey{c.key(), c}.Sign(m) }
func (c *cutoverSigner) SignDigest(d [32]byte) ([]byte, error) {
	return cutoverKey{c.key(), c}.SignDigest(d)
}

// A send signs its result headers and the request from one key snapshot: a cutover in between
// does not leave a header and its request signed by different keys.
func TestSendSignsHeaderAndRequestWithOneKey(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello, "}, true)
	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.s.drain()
	e.s.cfg.Signer = &cutoverSigner{cur: e.d.key, next: newSigner(t, 0x21)}
	e.s.deliverPeer(context.Background(), e.m.op)
	reqs := e.peers.requests[e.m.op]
	if len(reqs) == 0 {
		t.Fatal("nothing sent")
	}
	req := reqs[0]
	unsigned := &nexusv1.SyncRequest{Batch: req.GetBatch()}
	digest := digestOf(t, requestName, mustMarshal(t, unsigned))
	if dispatch.VerifyDigestSignature(e.d.key.PubKeyCompressed(), digest[:], req.GetSenderSignature()) != nil {
		t.Fatal("request not signed by the key of the snapshot")
	}
	for _, item := range req.GetBatch().GetItems() {
		if h := item.GetOrder().GetResultHeader(); h != nil {
			c := proto.Clone(h).(*nexusv1.DispatchResultHeaderV1)
			c.BuilderServiceSignature = nil
			hd := digestOf(t, resultHeaderName, mustMarshal(t, c))
			if dispatch.VerifyDigestSignature(e.d.key.PubKeyCompressed(), hd[:], h.GetBuilderServiceSignature()) != nil {
				t.Fatal("result header and request signed by different keys")
			}
		}
	}
}

// A winner accept whose signer has no resolvable key any more (deregistered, or rotated twice
// since) cannot be checked, and never will be: the attempt applies, with the accept marked
// unverified, rather than stopping the order's sync for good. A forged accept is still refused.
func TestWinnerAcceptWithoutAResolvableKeyIsMarkedUnverified(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.s.OrderChanged(f.accepted())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	batch := proto.Clone(reqs[len(reqs)-1].GetBatch()).(*nexusv1.BuilderSyncBatchV1)
	e.keys.mu.Lock()
	delete(e.keys.keys, "CORTEX|"+e.worker.op)
	e.keys.mu.Unlock()
	resp, err := e.member.r.Sync(context.Background(), e.signed(batch))
	if err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != uint64(len(batch.Items)) {
		t.Fatalf("batch with an unresolvable winner key = %v, %v", resp, err)
	}
	if c := e.copyOf(); len(c.Accept) == 0 || !c.AcceptUnverified {
		t.Fatalf("copy accept %x, unverified %v", c.Accept, c.AcceptUnverified)
	}
}
