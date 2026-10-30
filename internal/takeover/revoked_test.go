package takeover

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// A submitted takeover judged again while this Builder's service key is revoked, and not
// registered on chain, ends as NO_CAPACITY with its input dropped: its entry could not be signed
// before a replacement is current. It is not retried every block.
func TestSettleEndsAnUnregisteredTakeoverWhileRevoked(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.keys.err = &servicekey.RevokedError{Nonce: 1}
	e.m.TakeoverUnsettled(session, 5)
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
	if e.m.Pending() != 0 || e.stored() != 0 {
		t.Fatalf("an ended takeover is still held (pending %d)", e.m.Pending())
	}
	e.m.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 61})
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")
}

// One the chain already registered goes on: it was admitted before the revocation.
func TestSettleKeepsARegisteredTakeoverWhileRevoked(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.keys.err = &servicekey.RevokedError{Nonce: 1}
	e.registerAt(70)
	e.m.TakeoverUnsettled(session, 5)
	e.wantCalls("held task5", "registered task5 70")
}

// A revocation ends the takeovers whose entry has not gone out, as a drain does; one whose entry
// went out stays and finishes on chain.
func TestKeyRevokedEndsUnsentTakeovers(t *testing.T) {
	e := newEnv(t)
	e.submit(5)
	e.m.KeyRevoked()
	e.wantCalls("held task5", "ended task5 NO_CAPACITY drop=true")

	sent := newEnv(t)
	sent.rec.sent = map[string]bool{session: true}
	sent.submit(5)
	sent.m.KeyRevoked()
	if sent.m.Pending() != 1 {
		t.Fatal("a takeover whose entry went out was ended")
	}
}
