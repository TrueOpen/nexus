package buildersync

import (
	"context"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/attempt"
)

// A watch on a task is signalled whenever a batch applied items of it, so a member waiting for
// its replica to catch up wakes when the order item lands; a stopped watch is not.
func TestReplicaWatchSignalsAppliedItems(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	changed, stop := e.member.r.Watch(f.taskHex())
	signalled := func() bool {
		select {
		case <-changed:
			return true
		default:
			return false
		}
	}
	if signalled() {
		t.Fatal("signalled before any item")
	}
	e.s.OrderChanged(f.issued())
	e.sync()
	if !signalled() {
		t.Fatal("not signalled after the first round")
	}
	f.putAccepted()
	e.s.OrderChanged(f.accepted())
	e.sync()
	e.s.Recorded(f.recordedAttempt())
	f.recordOnChain()
	e.sync()
	e.clock.advance(time.Minute)
	e.s.deliverPeer(context.Background(), e.m.op)
	if !signalled() {
		t.Fatal("not signalled after the order item")
	}
	if a, held := e.member.r.Replica(f.sessionHex(), f.taskHex()); !held || a.Status != attempt.Recorded {
		t.Fatalf("replica after the signal = %+v, %v", a, held)
	}
	stop()
	e.s.OrderChanged(f.rejectedThenOut())
	e.sync()
	if signalled() {
		t.Fatal("a stopped watch was signalled")
	}
}
