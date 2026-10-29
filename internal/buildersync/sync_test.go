package buildersync

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/taskdata"
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
	if a, held := e.member.r.Replica(f.sessionHex(), f.taskHex()); !held || a.Status != attempt.Pending || a.Header != nil || a.User != "trueopen1user" {
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
	if !held || a.Status != attempt.Recorded || a.TicketHash != f.hashes[1] || a.User != "trueopen1user" || a.Worker != e.worker.op ||
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
			var item buildersyncv1.BuilderSyncItemV1
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
	resp, err := e.member.r.Sync(context.Background(), reqs[len(reqs)-1])
	if err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != e.s.streams[streamKey(f.sessionHex(), f.sequence)].Last {
		t.Fatalf("redelivery = %v, %v", resp, err)
	}
	if c := e.copyOf(); len(c.Rounds[0].Attempts) != 2 {
		t.Fatalf("redelivery changed the copy: %+v", c.Rounds[0].Attempts)
	}

	// A fresh member gets only the items from 3 on: refused, and it holds nothing.
	fresh := e.newMember(e.m)
	var batch buildersyncv1.BuilderSyncBatchV1
	if err := proto.Unmarshal(reqs[len(reqs)-1].GetBatch(), &batch); err != nil {
		t.Fatal(err)
	}
	batch.Items = batch.Items[2:]
	resp, err = fresh.r.Sync(context.Background(), e.signed(&batch))
	if err != nil || !strings.Contains(resp.GetRefused(), "out of order") || resp.GetAppliedThrough() != 0 {
		t.Fatalf("out of order batch = %v, %v", resp, err)
	}
}

// signed signs a batch as D.
func (e *env) signed(batch *buildersyncv1.BuilderSyncBatchV1) *buildersyncv1.SyncRequest {
	e.t.Helper()
	raw := mustMarshal(e.t, batch)
	sig, err := SignBatch(e.d.key, testChainID, batch.GetSenderOperatorAddress(), raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return &buildersyncv1.SyncRequest{Batch: raw, SenderSignature: sig}
}

// firstBatch is the batch D sends M for the order's first ticket.
func (e *env) firstBatch() *buildersyncv1.BuilderSyncBatchV1 {
	e.t.Helper()
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.s.OrderChanged(e.fx.issued())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	var batch buildersyncv1.BuilderSyncBatchV1
	if err := proto.Unmarshal(reqs[len(reqs)-1].GetBatch(), &batch); err != nil {
		e.t.Fatal(err)
	}
	return &batch
}

// A batch from a Builder outside the group, for a stale BuilderSet, signed by another key or not
// addressed to this Builder is refused as a whole.
func TestReceiverRefusesBatchesNotFromTheGroup(t *testing.T) {
	e := newEnv(t)
	batch := e.firstBatch()
	ctx := context.Background()

	outsider := newParty(t, 0x07, 0x17)
	e.keys.set("BUILDER", outsider)
	b := proto.Clone(batch).(*buildersyncv1.BuilderSyncBatchV1)
	b.SenderOperatorAddress = outsider.op
	raw := mustMarshal(t, b)
	sig, _ := SignBatch(outsider.key, testChainID, outsider.op, raw)
	if _, err := e.member.r.Sync(ctx, &buildersyncv1.SyncRequest{Batch: raw, SenderSignature: sig}); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("outsider: %v", err)
	}

	req := e.signed(batch)
	req.SenderSignature, _ = SignBatch(e.x.key, testChainID, e.d.op, req.GetBatch())
	if _, err := e.member.r.Sync(ctx, req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("another key's signature: %v", err)
	}

	b = proto.Clone(batch).(*buildersyncv1.BuilderSyncBatchV1)
	b.BuilderSetId = "set-0"
	if _, err := e.member.r.Sync(ctx, e.signed(b)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("stale BuilderSet: %v", err)
	}

	b = proto.Clone(batch).(*buildersyncv1.BuilderSyncBatchV1)
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
	for name, spoil := range map[string]func(*env, *buildersyncv1.BuilderSyncBatchV1){
		"input hash": func(_ *env, b *buildersyncv1.BuilderSyncBatchV1) {
			for _, item := range b.Items {
				if c := item.GetInputChunk(); c != nil && c.GetOffset() == 0 {
					c.Data = append([]byte("H"), c.Data[1:]...)
				}
			}
		},
		"ticket signature": func(e *env, b *buildersyncv1.BuilderSyncBatchV1) {
			for _, item := range b.Items {
				if a := item.GetAttempt(); a != nil {
					var ticket taskv1.DispatchTicketV1
					_ = proto.Unmarshal(a.Ticket, &ticket)
					a.Ticket, _ = signWith(e.t, e.x.key, ticketName, &ticket, func(s []byte) { ticket.BuilderServiceSignature = s })
				}
			}
		},
		"roster": func(_ *env, b *buildersyncv1.BuilderSyncBatchV1) {
			b.Items[0].GetRound().RosterHash = fill(0x01)
		},
		"round task_hash": func(_ *env, b *buildersyncv1.BuilderSyncBatchV1) {
			b.Items[0].GetRound().TaskHash = fill(0x02)
			for _, item := range b.Items {
				if c := item.GetInputChunk(); c != nil {
					c.TaskHash = fill(0x02)
				}
			}
		},
		"input piece out of order": func(_ *env, b *buildersyncv1.BuilderSyncBatchV1) {
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
func (e *env) recordedBatch(texts []string) *buildersyncv1.BuilderSyncBatchV1 {
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
	var batch buildersyncv1.BuilderSyncBatchV1
	if err := proto.Unmarshal(reqs[len(reqs)-1].GetBatch(), &batch); err != nil {
		e.t.Fatal(err)
	}
	if batch.Output == nil || len(batch.Output.Chunks) != len(texts) {
		e.t.Fatalf("recorded batch has no output: %v", batch.Output)
	}
	return &batch
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
// snapshot is replaced (a recorded task keeps the group it was locked with); a new order of the
// replaced snapshot is refused.
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
	batch := e.firstBatch()
	batch.SessionId = fill(0xab)
	if _, err := e.member.r.Sync(context.Background(), e.signed(batch)); !errors.Is(err, ErrNotGroupMember) {
		t.Fatalf("new order of the replaced snapshot: %v", err)
	}
}

// A batch naming a sender outside the BuilderSet is refused from local state alone: the endpoint
// takes no API key, so a made-up sender must never cost a chain read of its key.
func TestNonMemberCostsNoKeyLookup(t *testing.T) {
	e := newEnv(t)
	batch := e.firstBatch()
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

// A REJECTED attempt's reject must be the target's own: one the target did not sign is refused,
// so a member never sends a rebuttal the chain would refuse.
func TestReceiverChecksTheRejectSignature(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	e.peers.setFail(e.m.op, errors.New("held back"))
	e.s.OrderChanged(f.issued())
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	reqs := e.peers.requests[e.m.op]
	var batch buildersyncv1.BuilderSyncBatchV1
	if err := proto.Unmarshal(reqs[len(reqs)-1].GetBatch(), &batch); err != nil {
		t.Fatal(err)
	}
	for _, item := range batch.Items {
		if a := item.GetAttempt(); a != nil && len(a.Reject) > 0 {
			var reject taskv1.DispatchRejectV1
			_ = proto.Unmarshal(a.Reject, &reject)
			a.Reject, _ = signWith(t, e.other.key, rejectName, &reject, func(s []byte) { reject.ServiceSignature = s })
		}
	}
	resp, err := e.member.r.Sync(context.Background(), e.signed(&batch))
	if err != nil || !strings.Contains(resp.GetRefused(), "reject") {
		t.Fatalf("forged reject = %v, %v", resp, err)
	}
	e.peers.setFail(e.m.op, nil)
	e.clock.advance(time.Minute)
	e.s.deliverPeer(context.Background(), e.m.op)
	if a := e.copyOf().Rounds[0].Attempts; len(a) != 2 || a[0].Outcome != outcomeRejected {
		t.Fatalf("genuine reject = %+v", a)
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
