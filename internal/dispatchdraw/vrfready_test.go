package dispatchdraw

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
)

// A pending Builder VRF key only readies an epoch when a local key matches it.
func TestVRFKeysReadinessWithAPendingKey(t *testing.T) {
	local := testKey(1)
	ctx := context.Background()
	pendingOf := func(key ed25519.PrivateKey) *fakeRegistry {
		return &fakeRegistry{err: fmt.Errorf("builder b: %w", &PendingVRFKeyError{FromEpoch: 6, PubKey: key.Public().(ed25519.PublicKey)})}
	}
	keys, _ := NewVRFKeys([]ed25519.PrivateKey{local}, pendingOf(local))
	var pending *PendingVRFKeyError
	if err := keys.Ready(ctx, 5); !errors.As(err, &pending) || pending.FromEpoch != 6 {
		t.Fatalf("pending local key: err = %v", err)
	}
	keys, _ = NewVRFKeys([]ed25519.PrivateKey{local}, pendingOf(testKey(9)))
	if err := keys.Ready(ctx, 5); !errors.Is(err, ErrVRFKeyMismatch) {
		t.Fatalf("pending key no local key matches: err = %v", err)
	}
}

// Drawer.Ready answers DISPATCH_NOT_READY while this Builder's VRF key is pending, naming the
// first height of the epoch it becomes active in when that epoch is still ahead; no key or no
// matching local key are not "not ready", and a failed chain read stays a failed read.
func TestDrawerReadyWithTheBuilderVRFKey(t *testing.T) {
	local := testKey(1)
	ctx := context.Background()
	epochs := &fakeEpochs{length: 100}
	ep := Epoch{Number: 5, ReferenceHeight: 500}
	drawer := func(reg VRFKeyRegistry) *Drawer {
		t.Helper()
		keys, err := NewVRFKeys([]ed25519.PrivateKey{local}, reg)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDrawer(vectorChainID, epochs, keys, NewPoolCache(vectorChainID, vectorPoolSource()))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	pendingFrom := func(epoch uint64) *fakeRegistry {
		return &fakeRegistry{err: fmt.Errorf("builder b: %w", &PendingVRFKeyError{FromEpoch: epoch, PubKey: local.Public().(ed25519.PublicKey)})}
	}

	if err := drawer(registryFor(map[uint64]ed25519.PrivateKey{5: local})).Ready(ctx, ep); err != nil {
		t.Fatalf("active key: %v", err)
	}

	err := drawer(pendingFrom(7)).Ready(ctx, ep)
	var notReady *NotReadyError
	if !errors.As(err, &notReady) || notReady.Epoch != 5 || notReady.DispatchableHeight != 700 {
		t.Fatalf("pending from epoch 7: err = %v, want not ready until height 700", err)
	}

	err = drawer(pendingFrom(5)).Ready(ctx, ep)
	if !errors.As(err, &notReady) || notReady.DispatchableHeight != 0 {
		t.Fatalf("pending key due, activation not seen yet: err = %v, want not ready with no height", err)
	}

	err = drawer(registryFor(nil)).Ready(ctx, ep)
	if !errors.Is(err, ErrNoVRFKey) || errors.Is(err, ErrDispatchNotReady) {
		t.Fatalf("no key: err = %v", err)
	}
	err = drawer(registryFor(map[uint64]ed25519.PrivateKey{5: testKey(9)})).Ready(ctx, ep)
	if !errors.Is(err, ErrVRFKeyMismatch) || errors.Is(err, ErrDispatchNotReady) {
		t.Fatalf("mismatch: err = %v", err)
	}
	chainDown := errors.New("chain unavailable")
	err = drawer(&fakeRegistry{err: chainDown}).Ready(ctx, ep)
	if !errors.Is(err, chainDown) || errors.Is(err, ErrDispatchNotReady) || errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("chain read error: err = %v", err)
	}

	epochs.length = 0
	err = drawer(pendingFrom(7)).Ready(ctx, ep)
	if err == nil || errors.Is(err, ErrDispatchNotReady) || errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("epoch length unreadable: err = %v, want a failed read", err)
	}
}
