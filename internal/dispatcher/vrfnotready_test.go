package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/inflight"
)

// While this Builder's VRF key is pending a new order is refused before its input is stored as
// NEXUS_INGRESS_DISPATCH_NOT_READY naming the height from which it can dispatch, even with an
// admitted handraise to take it: the draw could not prove its randomness until then.
func TestProbeRefusesAnOrderWhileTheVRFKeyIsPending(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	e.drawer.readyErr = &dispatchdraw.NotReadyError{Epoch: testEpoch.Number, DispatchableHeight: 180, Reason: "VRF key pending"}
	err := e.d.Probe(context.Background(), o)
	var notReady *dispatchdraw.NotReadyError
	if !errors.As(err, &notReady) || notReady.DispatchableHeight != 180 || errors.Is(err, dispatchdraw.ErrNoCapacity) {
		t.Fatalf("probe = %v, want DISPATCH_NOT_READY until height 180", err)
	}
	if len(e.drawer.readyAsked) != 1 || e.drawer.readyAsked[0] != testEpoch {
		t.Fatalf("ready asked for %v, want the order's epoch", e.drawer.readyAsked)
	}
	e.drawer.readyErr = nil
	if err := e.d.Probe(context.Background(), o); err != nil {
		t.Fatalf("probe once the key is active = %v", err)
	}
}

// Without any VRF key, or without a local key the chain registered, this Builder cannot dispatch
// and no known height changes that: the order is NO_CAPACITY and the user goes to another Builder.
// A key that could not be read leaves the order unavailable.
func TestProbeWithoutAUsableVRFKey(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"no key":   {fmt.Errorf("read builder VRF key of epoch 1: %w", dispatchdraw.ErrNoVRFKey), dispatchdraw.ErrNoCapacity},
		"mismatch": {fmt.Errorf("epoch 1: %w", dispatchdraw.ErrVRFKeyMismatch), dispatchdraw.ErrNoCapacity},
		"read":     {errors.New("node unreachable"), inflight.ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := e.session(0xaa, 0)
			o := e.order(s, 0, 1)
			e.drawer.readyErr = tc.err
			err := e.d.Probe(context.Background(), o)
			if !errors.Is(err, tc.want) || errors.Is(err, dispatchdraw.ErrDispatchNotReady) {
				t.Fatalf("probe = %v, want %v", err, tc.want)
			}
		})
	}
}
