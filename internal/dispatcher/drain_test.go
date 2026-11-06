package dispatcher

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// While the Builder drains, Probe refuses new orders as NO_CAPACITY; after the drain they pass.
func TestDrainRefusesNewOrders(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.draining.Store(true)
	err := e.d.Probe(context.Background(), o)
	if !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.Is(err, ErrDraining) {
		t.Fatalf("Probe while draining = %v", err)
	}
	e.draining.Store(false)
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("Probe after the drain = %v", err)
	}
}

// A ticket out when the drain began still wins and its entry goes to the recorder.
func TestDrainLetsATicketOutWin(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.draining.Store(true)
	e.accept()
	e.onlyBundle()
	if got := e.ledgerState(o); got != inflight.StateAccepted {
		t.Fatalf("ledger state = %s", got)
	}
}

// An order that needs another ticket while the Builder drains fails as NO_CAPACITY without one:
// its sequence is not used and its in-flight entry no longer counts.
func TestDrainIssuesNoNewTicket(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.draining.Store(true)
	e.reject()
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers: a ticket was issued while draining", n)
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], dispatchdraw.ErrNoCapacity) || !errors.Is(got[0], ErrDraining) {
		t.Fatalf("failed = %v", got)
	}
	if got := e.ledgerState(o); got != inflight.StateFailed {
		t.Fatalf("ledger state = %s", got)
	}
	if left := e.ledger.Unfinished(); len(left) != 0 {
		t.Fatalf("unfinished orders = %+v", left)
	}
}

// The order of a takeover registered before the drain is work the drain waits for: once the
// takeover took effect it is walked as usual, tickets included, and can be recorded.
func TestDrainWalksTheOrderOfATakeover(t *testing.T) {
	e := newEnv(t)
	e.takeoverOrders = true
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.draining.Store(true)
	e.dispatch(o)
	e.reject()
	if n := len(e.streams.offers()); n != 2 {
		t.Fatalf("%d offers: the takeover's order got no next ticket while draining", n)
	}
	e.accept()
	e.onlyBundle()
	if got := e.observer.snapshot().failed; len(got) != 0 {
		t.Fatalf("failed = %v", got)
	}
}
