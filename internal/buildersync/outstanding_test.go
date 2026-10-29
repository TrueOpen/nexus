package buildersync

import (
	"context"
	"reflect"
	"testing"
)

// What is outstanding: a change still queued, then per member the items it has not acknowledged,
// and once the order is recorded the winner's output until the member holds its Fin.
func TestOutstandingListsWhatMembersHaveNotAcknowledged(t *testing.T) {
	e := newEnv(t)
	f := e.fx
	f.putAccepted()
	f.recordOnChain()
	f.writeOutput(e.dData, e.worker, []string{"hello"}, false)
	e.s.OrderChanged(f.issued())
	order := Outstanding{SessionID: f.sessionHex(), Sequence: f.sequence, TaskID: f.taskHex()}
	if got := e.s.Outstanding(); !reflect.DeepEqual(got, []Outstanding{order}) {
		t.Fatalf("queued change = %+v", got)
	}
	e.s.drain()
	last := e.s.streams[streamKey(f.sessionHex(), f.sequence)].Last
	got := e.s.Outstanding()
	if len(got) != 2 || got[0].Items != last || got[1].Items != last || got[0].Output || got[1].Output {
		t.Fatalf("items for both members = %+v", got)
	}
	e.s.deliverPeer(context.Background(), e.m.op)
	if got := e.s.Outstanding(); len(got) != 1 || got[0].Peer != e.x.op {
		t.Fatalf("after M acknowledged = %+v", got)
	}

	e.s.OrderChanged(f.accepted())
	e.s.Recorded(f.recordedAttempt())
	e.sync()
	for _, o := range e.s.Outstanding() {
		if o.Peer == e.m.op && (o.Items != 0 || !o.Output) {
			t.Fatalf("M with the output unsealed = %+v", o)
		}
	}
	f.writeOutput(e.dData, e.worker, []string{"hello", "!"}, true)
	e.s.deliverPeer(context.Background(), e.m.op)
	for _, o := range e.s.Outstanding() {
		if o.Peer == e.m.op {
			t.Fatalf("M holds everything but is listed: %+v", o)
		}
	}
}
