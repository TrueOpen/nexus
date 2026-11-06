package dispatcher

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// An order whose epoch cannot dispatch yet is refused before its input is stored as
// NEXUS_INGRESS_DISPATCH_NOT_READY, never NO_CAPACITY, even with no handraise to take it: the user
// waits and retries this Builder. Once the epoch is ready the same order passes.
func TestProbeRefusesAnEpochNotReady(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	root := e.handraises.root
	e.handraises.root = nil
	e.drawer.epochErr = &dispatchdraw.NotReadyError{Epoch: testEpoch.Number, DispatchableHeight: 812, Reason: "snapshot not effective"}
	err := e.d.Probe(context.Background(), o)
	if !errors.Is(err, dispatchdraw.ErrDispatchNotReady) || errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe = %v, want DISPATCH_NOT_READY", err)
	}
	e.handraises.root = root
	e.drawer.epochErr = nil
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe once ready = %v", err)
	}
}

// An epoch the chain could not be read for is unavailable, neither ready nor not ready.
func TestProbeEpochReadFailureIsUnavailable(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.drawer.epochErr = errors.New("node unreachable")
	err := e.d.Probe(context.Background(), o)
	if !errors.Is(err, inflight.ErrUnavailable) || errors.Is(err, dispatchdraw.ErrDispatchNotReady) {
		t.Fatalf("probe = %v, want unavailable", err)
	}
}

// An order already accepted whose epoch is not ready is parked, not failed, and goes on once it is.
func TestWalkParksAnOrderWhileItsEpochIsNotReady(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.drawer.err = &dispatchdraw.NotReadyError{Epoch: testEpoch.Number, Reason: "beacon not verified"}
	e.dispatch(o)
	if n, failed := len(e.streams.offers()), e.observer.snapshot().failed; n != 0 || len(failed) != 0 {
		t.Fatalf("%d offers, failures %v while the epoch is not ready", n, failed)
	}
	e.drawer.mu.Lock()
	e.drawer.err = nil
	e.drawer.mu.Unlock()
	e.d.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: testESH + 1})
	if got := operatorsOf(e.streams.offers()); !reflect.DeepEqual(got, []string{op7}) {
		t.Fatalf("offers once ready = %v", got)
	}
}
