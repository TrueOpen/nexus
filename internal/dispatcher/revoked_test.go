package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// While this Builder's current service key is revoked nothing new is dispatched: Probe refuses a
// new order as DISPATCH_NOT_READY at the replacement's effective height when one is registered,
// and as NO_CAPACITY, like a drain, when none is. Once the replacement is current orders pass.
func TestOwnKeyRevokedRefusesNewOrders(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.revokeBuilder(true, 0)
	if err := e.d.Probe(context.Background(), o); !errors.Is(err, dispatchdraw.ErrNoCapacity) || !errors.Is(err, servicekey.ErrRevoked) {
		t.Fatalf("probe while revoked = %v, want NO_CAPACITY", err)
	}
	e.revokeBuilder(true, testESH+40)
	var notReady *dispatchdraw.NotReadyError
	if err := e.d.Probe(context.Background(), o); !errors.As(err, &notReady) || notReady.DispatchableHeight != testESH+40 {
		t.Fatalf("probe while revoked with a replacement = %v, want DISPATCH_NOT_READY at %d", err, testESH+40)
	}
	e.revokeBuilder(false, 0)
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe after the replacement = %v", err)
	}
}

// An order that needs another ticket after the revocation fails as NO_CAPACITY without one.
func TestOwnKeyRevokedIssuesNoNewTicket(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.dispatch(o)
	e.revokeBuilder(true, testESH+40)
	e.reject()
	if n := len(e.streams.offers()); n != 1 {
		t.Fatalf("%d offers: a ticket was issued while revoked", n)
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], dispatchdraw.ErrNoCapacity) || !errors.Is(got[0], servicekey.ErrRevoked) {
		t.Fatalf("failed = %v", got)
	}
	if got := e.ledgerState(o); got != inflight.StateFailed {
		t.Fatalf("ledger state = %s", got)
	}
}

// An accept of a ticket signed before the revocation cannot be recorded: no record is signed, the
// accept is DISPATCH_TICKET_CLOSED, the attempt is VOIDED with the accept kept as received (a
// compensation claim on the ticket is matched against it) and the order fails as NO_CAPACITY.
// The Worker's timeout is not counted.
func TestOwnKeyRevokedVoidsAnAccept(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	_, ticket, hash := e.lastOffer()
	e.revokeBuilder(true, 0)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("accept while revoked = %v, want DISPATCH_TICKET_CLOSED", err)
	}
	p, st := e.phaseOf(s, 0)
	if p != phaseFailed || st.Skips != 0 || len(st.Record) != 0 {
		t.Fatalf("phase %s, skips %d, record %d bytes", p, st.Skips, len(st.Record))
	}
	if a := st.Rounds[0].Attempts[0]; a.Outcome != outcomeVoided || !bytes.Equal(a.LateAccept, from.Raw) || !bytes.Equal(a.LateAcceptDigest, from.Digest[:]) {
		t.Fatalf("attempt = %s, accept kept %v", a.Outcome, bytes.Equal(a.LateAccept, from.Raw))
	}
	if got := e.observer.snapshot().failed; len(got) != 1 || !errors.Is(got[0], dispatchdraw.ErrNoCapacity) || !errors.Is(got[0], servicekey.ErrRevoked) {
		t.Fatalf("failed = %v", got)
	}
	if n := len(e.recorder.bundles); n != 0 {
		t.Fatalf("%d bundles went to the recorder", n)
	}
}
