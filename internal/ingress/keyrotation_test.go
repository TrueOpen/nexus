package ingress

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/takeover"
)

// These tests open no listener: validateOpenTaskHeader is called directly.

type fakeRotation struct {
	effective uint64
	err       error
	calls     int
}

func (f *fakeRotation) BuilderRotation(context.Context) (uint64, error) {
	f.calls++
	return f.effective, f.err
}

// rotationHeader is the vector OpenTask (sequence 7) in front of the real precheck, with the
// session bound to this Builder (trueopen1builder) since bound and next expected sequence next.
// The registered key has room for exactly that order's max_fee.
func rotationHeader(t *testing.T, bound, next uint64) (*registeredKeyHeader, *inflight.Prechecker, *inflight.Ledger) {
	t.Helper()
	h := newRegisteredKeyHeader(t)
	key := *h.keys.state.Key
	p, ledger := newPrechecker(t, chaincli.SessionState{
		Owner: h.file.Account.Bech32, Key: key[:], ExpiryHeight: 1100, SetHeight: 980, SpendCap: "1150000", Spent: "1000000",
		NextExpectedSequence: next, Balance: "100000000", FrozenTotal: "0", BoundBuilder: "trueopen1builder", BoundChangeHeight: bound,
	})
	h.svc.auth.Precheck = p
	return h, p, ledger
}

// wantRotating checks a refusal is Unavailable NEXUS_INGRESS_BUILDER_KEY_ROTATING carrying the
// effective height as service_key_rotation_effective_height, and no dispatch_available_height.
func wantRotating(t *testing.T, err error, effective uint64) {
	t.Helper()
	wantConnectErr(t, err, connect.CodeUnavailable, "NEXUS_INGRESS_BUILDER_KEY_ROTATING")
	if d := openTaskDetail(t, err); d.ServiceKeyRotationEffectiveHeight == nil || d.GetServiceKeyRotationEffectiveHeight() != effective || d.DispatchAvailableHeight != nil {
		t.Fatalf("detail = %v, want service_key_rotation_effective_height %d alone", d, effective)
	}
}

// While this Builder's key rotation is pending every new order is refused before any other
// precheck, and nothing is reserved: the first order of a session bound here since the
// registration, the next sequence of a session bound here before it, and a resend of a sequence
// whose attempt failed. Once the rotation activated the same order is reserved as usual.
func TestOpenTaskHeaderRefusesNewOrdersWhileTheKeyRotates(t *testing.T) {
	const effective = 1200
	t.Run("first order of a new session", func(t *testing.T) {
		h, _, ledger := rotationHeader(t, 995, 7)
		h.svc.auth.Rotation = &fakeRotation{effective: effective}
		wantRotating(t, h.validate(), effective)
		if _, ok := ledger.Get(h.header.GetSessionId()[2:], 7); ok {
			t.Fatal("a refused order was reserved")
		}
	})
	t.Run("next sequence of a bound session", func(t *testing.T) {
		h, p, ledger := rotationHeader(t, 1, 6)
		sessionID := h.header.GetSessionId()[2:]
		res, err := p.Reserve(context.Background(), inflight.Order{
			SessionID: sessionID, Sequence: 6, TaskID: "t6", TaskHash: hex.EncodeToString([]byte{6}), User: h.file.Account.Bech32,
			MaxFee: 1, EarliestSubmitHeight: 1000, ExpireHeight: 2000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Commit(res.Reservation); err != nil {
			t.Fatal(err)
		}
		h.svc.auth.Rotation = &fakeRotation{effective: effective}
		wantRotating(t, h.validate(), effective)
		if _, ok := ledger.Get(sessionID, 7); ok {
			t.Fatal("a refused order was reserved")
		}
	})
	t.Run("retry after a failed attempt", func(t *testing.T) {
		h, _, ledger := rotationHeader(t, 1, 7)
		if err := h.validate(); err != nil {
			t.Fatal(err)
		}
		sessionID := h.header.GetSessionId()[2:]
		if err := ledger.MarkFailed(sessionID, 7); err != nil {
			t.Fatal(err)
		}
		h.svc.auth.Rotation = &fakeRotation{effective: effective}
		wantRotating(t, h.validate(), effective)
		if e, _ := ledger.Get(sessionID, 7); e.State != inflight.StateFailed {
			t.Fatalf("entry = %+v, want the failed attempt left alone", e)
		}
	})
	t.Run("an order the precheck would refuse otherwise", func(t *testing.T) {
		h, _, _ := rotationHeader(t, 1, 3) // sequence 7 is out of sequence
		h.svc.auth.Rotation = &fakeRotation{effective: effective}
		wantRotating(t, h.validate(), effective)
	})
	t.Run("after the activation", func(t *testing.T) {
		h, _, ledger := rotationHeader(t, 995, 7)
		rotation := &fakeRotation{effective: effective}
		h.svc.auth.Rotation = rotation
		wantRotating(t, h.validate(), effective)
		rotation.effective = 0
		if err := h.validate(); err != nil {
			t.Fatalf("order after the activation = %v", err)
		}
		if e, ok := ledger.Get(h.header.GetSessionId()[2:], 7); !ok || e.State != inflight.StateDispatching {
			t.Fatalf("entry = %+v, %v", e, ok)
		}
	})
}

// An order this Builder already holds is answered while the rotation is pending, so the SDK keeps
// following it here: the exact resend of an order dispatching, accepted or recorded, without the
// rotation being read.
func TestOpenTaskHeaderAnswersHeldOrdersWhileTheKeyRotates(t *testing.T) {
	h, p, ledger := rotationHeader(t, 1, 7)
	_, _, first, err := h.svc.validateOpenTaskHeader(context.Background(), h.header)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Commit(first.Reservation); err != nil {
		t.Fatal(err)
	}
	rotation := &fakeRotation{effective: 1200}
	h.svc.auth.Rotation = rotation
	sessionID := h.header.GetSessionId()[2:]
	for _, mark := range []func() error{
		func() error { return nil },
		func() error { return ledger.MarkAccepted(sessionID, 7) },
		func() error { return ledger.MarkRecorded(sessionID, 7) },
	} {
		if err := mark(); err != nil {
			t.Fatal(err)
		}
		_, _, res, err := h.svc.validateOpenTaskHeader(context.Background(), h.header)
		if err != nil || res.Existing == nil {
			t.Fatalf("resend = %+v, %v; want the existing order", res, err)
		}
	}
	if rotation.calls != 0 {
		t.Fatalf("rotation read %d times for held orders", rotation.calls)
	}
}

// A takeover request is a new order too: refused before the takeover is judged. An exact resend of
// an order already held for a takeover is still answered.
func TestOpenTaskHeaderRefusesTakeoversWhileTheKeyRotates(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.svc.auth.Precheck = boundElsewhere()
	takeovers := &fakeTakeovers{}
	h.svc.auth.Takeovers = takeovers
	h.svc.auth.Rotation = &fakeRotation{effective: 1200}
	wantRotating(t, h.validate(), 1200)
	if len(takeovers.admitted) != 0 || len(h.svc.auth.Precheck.(*fakePrechecker).orders) != 0 {
		t.Fatal("a refused takeover reached the precheck or the takeover")
	}
	takeovers.held = &takeover.Admission{Existing: true, ActivationHeight: 1030}
	if _, _, res, err := h.svc.validateOpenTaskHeader(context.Background(), h.header); err != nil || res.Takeover == nil || !res.Takeover.Existing {
		t.Fatalf("held takeover = %+v, %v", res, err)
	}
}

// Without knowing whether a rotation is pending a new order is not taken: Unavailable, retryable.
func TestOpenTaskHeaderUnreadableRotationIsUnavailable(t *testing.T) {
	h, _, ledger := rotationHeader(t, 1, 7)
	h.svc.auth.Rotation = &fakeRotation{err: errors.New("node down")}
	err := h.validate()
	wantConnectErr(t, err, connect.CodeUnavailable, "node down")
	if _, ok := ledger.Get(h.header.GetSessionId()[2:], 7); ok {
		t.Fatal("an order was reserved without the rotation read")
	}
}
