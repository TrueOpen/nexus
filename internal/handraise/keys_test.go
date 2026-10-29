package handraise

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

type fakeResolver map[string]chaincli.ServiceKeyState // participant/operator -> state

func (f fakeResolver) QueryCurrentServiceKey(_ context.Context, participant, operator string) (chaincli.ServiceKeyState, error) {
	state, ok := f[participant+"/"+operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func keyState(t *testing.T, participant, operator string, seed byte, nonce uint64) chaincli.ServiceKeyState {
	key := newSigner(t, seed)
	return chaincli.ServiceKeyState{
		ParticipantType: participant, OperatorAddress: operator, ServiceAddress: key.Address(),
		ServicePubKey: hex.EncodeToString(key.PubKeyCompressed()), AuthorizationNonce: nonce, Status: servicekey.StatusActive,
	}
}

func TestChainServiceKeys(t *testing.T) {
	builder := newSigner(t, 0x01)
	builderOperator := newSigner(t, 0x02).Address()
	cortexOperator := newSigner(t, 0x03).Address()
	resolver := fakeResolver{
		servicekey.ParticipantBuilder + "/" + builderOperator: keyState(t, servicekey.ParticipantBuilder, builderOperator, 0x01, 4),
		servicekey.ParticipantCortex + "/" + cortexOperator:   keyState(t, servicekey.ParticipantCortex, cortexOperator, 0x05, 9),
	}
	keys := ChainServiceKeys{Resolver: resolver, AddressPrefix: testPrefix, BuilderAddress: builderOperator, Signer: builder}

	pub, nonce, err := keys.CurrentCortexKey(context.Background(), cortexOperator)
	if err != nil || nonce != 9 || hex.EncodeToString(pub) != hex.EncodeToString(newSigner(t, 0x05).PubKeyCompressed()) {
		t.Fatalf("cortex key = %x %d %v", pub, nonce, err)
	}
	if _, _, err := keys.CurrentCortexKey(context.Background(), builderOperator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("missing cortex key err = %v, want ErrUnavailable", err)
	}
	if err := keys.CheckBuilderKey(context.Background()); err != nil {
		t.Fatalf("builder key check: %v", err)
	}
	keys.Signer = newSigner(t, 0x06)
	if err := keys.CheckBuilderKey(context.Background()); err == nil {
		t.Fatal("builder key accepted for a key the local signer does not hold")
	}

	// A registered replacement leaves the current key in force, but a pending Builder issues no
	// new roots until the replacement activates.
	keys.Signer = builder
	pending := resolver[servicekey.ParticipantBuilder+"/"+builderOperator]
	pending.PendingRotation = &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: 5, EffectiveHeight: 400}
	resolver[servicekey.ParticipantBuilder+"/"+builderOperator] = pending
	if err := keys.CheckBuilderKey(context.Background()); !errors.Is(err, ErrBuilderRotationPending) {
		t.Fatalf("builder key check with a pending rotation = %v, want ErrBuilderRotationPending", err)
	}
	// A pending Cortex keeps its current key for messages it already owes.
	cortexPending := resolver[servicekey.ParticipantCortex+"/"+cortexOperator]
	cortexPending.PendingRotation = &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: 10, EffectiveHeight: 400}
	resolver[servicekey.ParticipantCortex+"/"+cortexOperator] = cortexPending
	if _, nonce, err := keys.CurrentCortexKey(context.Background(), cortexOperator); err != nil || nonce != 9 {
		t.Fatalf("cortex key with a pending rotation = %d, %v", nonce, err)
	}
}

func TestRunIssuesRootsOnInterval(t *testing.T) {
	e := newEnv(t)
	e.cfg.HandraiseRootIntervalMs = 1
	e.reg = e.open()
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	roots := make(chan *IssuedRoot, 1)
	done := make(chan error, 1)
	go func() { done <- e.reg.Run(ctx, func(root *IssuedRoot) { roots <- root }) }()
	select {
	case root := <-roots:
		if root.Root.GetLeafCount() != 1 {
			t.Fatalf("root = %v", root.Root)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no root issued")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}
