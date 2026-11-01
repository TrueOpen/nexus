package handraise

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

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
	ring, err := servicekey.NewRing(resolver, testPrefix, builderOperator, nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	keys := ChainServiceKeys{Resolver: resolver, AddressPrefix: testPrefix, Ring: ring}

	pub, nonce, err := keys.CurrentCortexKey(context.Background(), cortexOperator)
	if err != nil || nonce != 9 || hex.EncodeToString(pub) != hex.EncodeToString(newSigner(t, 0x05).PubKeyCompressed()) {
		t.Fatalf("cortex key = %x %d %v", pub, nonce, err)
	}
	if _, _, err := keys.CurrentCortexKey(context.Background(), builderOperator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("missing cortex key err = %v, want ErrUnavailable", err)
	}
	if err := keys.CheckBuilderKey(context.Background()); err != nil || ring.Key().Nonce != 4 {
		t.Fatalf("builder key check: %v (nonce %d)", err, ring.Key().Nonce)
	}
	other, err := servicekey.NewRing(resolver, testPrefix, builderOperator, nil, newSigner(t, 0x06))
	if err != nil {
		t.Fatal(err)
	}
	if err := (ChainServiceKeys{Resolver: resolver, AddressPrefix: testPrefix, Ring: other}).CheckBuilderKey(context.Background()); err == nil {
		t.Fatal("builder key accepted for a key the local signer does not hold")
	}

	// A registered replacement leaves the current key in force, but a pending Builder issues no
	// new roots until the replacement activates.
	pending := resolver[servicekey.ParticipantBuilder+"/"+builderOperator]
	pending.PendingRotation = &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: 5, EffectiveHeight: 400}
	resolver[servicekey.ParticipantBuilder+"/"+builderOperator] = pending
	var rotation *RotationPendingError
	if err := keys.CheckBuilderKey(context.Background()); !errors.Is(err, ErrBuilderRotationPending) || !errors.As(err, &rotation) ||
		rotation.EffectiveHeight != 400 || rotation.NextNonce != 5 {
		t.Fatalf("builder key check with a pending rotation = %v, want a RotationPendingError", err)
	}
	// A revoked current key is told apart from a pending rotation: it signs nothing, and the
	// replacement registered after the revocation names when that ends.
	revoked := resolver[servicekey.ParticipantBuilder+"/"+builderOperator]
	revoked.Status = servicekey.StatusRevoked
	resolver[servicekey.ParticipantBuilder+"/"+builderOperator] = revoked
	var revocation *servicekey.RevokedError
	if err := keys.CheckBuilderKey(context.Background()); errors.Is(err, ErrBuilderRotationPending) || !errors.As(err, &revocation) ||
		revocation.NextEffectiveHeight != 400 || revocation.Nonce != 4 {
		t.Fatalf("builder key check with a revoked key = %v, want a RevokedError", err)
	}
	// A pending Cortex keeps its current key for messages it already owes.
	cortexPending := resolver[servicekey.ParticipantCortex+"/"+cortexOperator]
	cortexPending.PendingRotation = &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: 10, EffectiveHeight: 400}
	resolver[servicekey.ParticipantCortex+"/"+cortexOperator] = cortexPending
	if _, nonce, err := keys.CurrentCortexKey(context.Background(), cortexOperator); err != nil || nonce != 9 {
		t.Fatalf("cortex key with a pending rotation = %d, %v", nonce, err)
	}
	// ...and its replacement's effective height is known.
	if effective, err := keys.CortexRotation(context.Background(), cortexOperator); err != nil || effective != 400 {
		t.Fatalf("CortexRotation = %d, %v; want 400", effective, err)
	}
	cortexPending.PendingRotation = nil
	resolver[servicekey.ParticipantCortex+"/"+cortexOperator] = cortexPending
	if effective, err := keys.CortexRotation(context.Background(), cortexOperator); err != nil || effective != 0 {
		t.Fatalf("CortexRotation without a rotation = %d, %v", effective, err)
	}
	if _, err := keys.CortexRotation(context.Background(), builderOperator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("CortexRotation without a key = %v", err)
	}
}

// BuilderRotation reads this Builder's pending rotation from the chain binding on every call, so a
// process started during the wait (a fresh ring) knows it at once and sees it end at activation.
// A revoked current key is no rotation here, and a binding that cannot be read is an error.
func TestBuilderRotation(t *testing.T) {
	builder := newSigner(t, 0x01)
	operator := newSigner(t, 0x02).Address()
	key := servicekey.ParticipantBuilder + "/" + operator
	resolver := fakeResolver{key: keyState(t, servicekey.ParticipantBuilder, operator, 0x01, 4)}
	pending := resolver[key]
	pending.PendingRotation = &chaincli.PendingServiceKeyRotation{NextAuthorizationNonce: 5, RegisteredHeight: 200, EffectiveHeight: 400}
	resolver[key] = pending
	ring, err := servicekey.NewRing(resolver, testPrefix, operator, nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	keys := ChainServiceKeys{Resolver: resolver, AddressPrefix: testPrefix, Ring: ring}
	if effective, err := keys.BuilderRotation(context.Background()); err != nil || effective != 400 {
		t.Fatalf("BuilderRotation of a fresh ring = %d, %v; want 400", effective, err)
	}
	active := resolver[key]
	active.PendingRotation = nil
	resolver[key] = active
	if effective, err := keys.BuilderRotation(context.Background()); err != nil || effective != 0 {
		t.Fatalf("BuilderRotation after the activation = %d, %v", effective, err)
	}
	revoked := pending
	revoked.Status = servicekey.StatusRevoked
	resolver[key] = revoked
	if effective, err := keys.BuilderRotation(context.Background()); err != nil || effective != 0 {
		t.Fatalf("BuilderRotation with a revoked key = %d, %v", effective, err)
	}
	delete(resolver, key)
	if _, err := keys.BuilderRotation(context.Background()); err == nil {
		t.Fatal("BuilderRotation without a binding passed")
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

// messageCounter counts log lines by message.
type messageCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (h *messageCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *messageCounter) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.counts == nil {
		h.counts = map[string]int{}
	}
	h.counts[r.Message]++
	return nil
}
func (h *messageCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *messageCounter) WithGroup(string) slog.Handler      { return h }

func (h *messageCounter) count(message string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[message]
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// While the Builder's own key rotation is pending, IssueRoot refuses with ErrBuilderRotationPending
// and the last root stays the latest; Run says so once and issues again once the rotation clears.
func TestRegistryPausesRootsDuringBuilderRotation(t *testing.T) {
	e := newEnv(t)
	e.cfg.HandraiseRootIntervalMs = 1
	e.reg = e.open()
	logs := &messageCounter{}
	e.reg.log = slog.New(logs)
	c1 := e.addCortex(0x11, 1)
	e.mustAccept(c1, e.handraise(c1, 100, 1))
	old := e.mustIssue()

	e.keys.mu.Lock()
	e.keys.builderErr = fmt.Errorf("%w: nonce 5 effective at height 400", ErrBuilderRotationPending)
	e.keys.mu.Unlock()
	c2 := e.addCortex(0x12, 2)
	e.mustAccept(c2, e.handraise(c2, 100, 1))
	if _, err := e.reg.IssueRoot(context.Background()); !errors.Is(err, ErrBuilderRotationPending) {
		t.Fatalf("IssueRoot during the rotation = %v, want ErrBuilderRotationPending", err)
	}
	if latest, _, ok := e.reg.Latest(); !ok || !proto.Equal(latest, old.Root) {
		t.Fatal("the latest root changed during the rotation")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	roots := make(chan *IssuedRoot, 4)
	done := make(chan error, 1)
	go func() { done <- e.reg.Run(ctx, func(root *IssuedRoot) { roots <- root }) }()
	const paused = "handraise roots paused until the Builder service key rotation activates"
	waitFor(t, "the pause log", func() bool { return logs.count(paused) > 0 })
	time.Sleep(30 * time.Millisecond) // many intervals
	if n := logs.count(paused); n != 1 {
		t.Fatalf("pause logged %d times, want once", n)
	}
	if n := logs.count("issue handraise root"); n != 0 {
		t.Fatalf("a pending rotation was logged as a failure %d times", n)
	}
	select {
	case <-roots:
		t.Fatal("a root was issued during the rotation")
	default:
	}

	e.keys.mu.Lock()
	e.keys.builderErr = nil
	e.keys.mu.Unlock()
	select {
	case root := <-roots:
		if root.Root.GetLeafCount() != 2 {
			t.Fatalf("root after the rotation = %v", root.Root)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no root after the rotation cleared")
	}
	cancel()
	<-done
	if n := logs.count(paused); n != 1 {
		t.Fatalf("pause logged %d times, want once", n)
	}
}

// While this Builder's current key is revoked no root is issued; Run says so once, not as a
// failure, and issues again once a replacement is current.
func TestRegistryPausesRootsWhileTheBuilderKeyIsRevoked(t *testing.T) {
	e := newEnv(t)
	e.cfg.HandraiseRootIntervalMs = 1
	e.reg = e.open()
	logs := &messageCounter{}
	e.reg.log = slog.New(logs)
	c1 := e.addCortex(0x11, 1)
	e.mustAccept(c1, e.handraise(c1, 100, 1))
	e.keys.mu.Lock()
	e.keys.builderErr = &servicekey.RevokedError{Nonce: 4}
	e.keys.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	roots := make(chan *IssuedRoot, 4)
	done := make(chan error, 1)
	go func() { done <- e.reg.Run(ctx, func(root *IssuedRoot) { roots <- root }) }()
	const paused = "handraise roots paused while this Builder's service key is revoked"
	waitFor(t, "the pause log", func() bool { return logs.count(paused) > 0 })
	time.Sleep(30 * time.Millisecond) // many intervals
	if n, failed := logs.count(paused), logs.count("issue handraise root"); n != 1 || failed != 0 {
		t.Fatalf("pause logged %d times, failures %d; want once and none", n, failed)
	}
	select {
	case <-roots:
		t.Fatal("a root was issued while revoked")
	default:
	}
	e.keys.mu.Lock()
	e.keys.builderErr = nil
	e.keys.mu.Unlock()
	select {
	case <-roots:
	case <-time.After(5 * time.Second):
		t.Fatal("no root once the replacement is current")
	}
	cancel()
	<-done
}

// A failure that repeats every interval (here a local signer that does not hold the on-chain key)
// is logged at most once per issueFailureLogEvery.
func TestRunRateLimitsRepeatedIssueFailures(t *testing.T) {
	e := newEnv(t)
	e.cfg.HandraiseRootIntervalMs = 1
	e.reg = e.open()
	logs := &messageCounter{}
	e.reg.log = slog.New(logs)
	e.keys.mu.Lock()
	e.keys.builderErr = errors.New("on-chain BUILDER service key does not match the local signer")
	e.keys.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.reg.Run(ctx, nil) }()
	const failed = "issue handraise root"
	waitFor(t, "the failure log", func() bool { return logs.count(failed) > 0 })
	time.Sleep(30 * time.Millisecond)
	if n := logs.count(failed); n != 1 {
		t.Fatalf("failure logged %d times within the limit, want once", n)
	}
	e.clock.advance(issueFailureLogEvery)
	waitFor(t, "the next failure log", func() bool { return logs.count(failed) == 2 })
	cancel()
	<-done
}

// A Cortex whose stream ended has its current handraise withdrawn: the next root leaves it out, so
// later rounds pay no skip for a Worker that cannot get the ticket. The watermark stays, so only a
// newer handraise brings it back, and the withdrawal survives a restart.
func TestWithdrawDropsTheLeafFromTheNextRoot(t *testing.T) {
	e := newEnv(t)
	c1, c2 := e.addCortex(0x11, 1), e.addCortex(0x12, 2)
	h1 := e.handraise(c1, 100, 1)
	e.mustAccept(c1, h1)
	e.mustAccept(c2, e.handraise(c2, 100, 1))
	if root := e.mustIssue(); root.Root.GetLeafCount() != 2 {
		t.Fatalf("leaves = %d", root.Root.GetLeafCount())
	}
	if !e.reg.Withdraw(c1.operator()) {
		t.Fatal("no handraise withdrawn")
	}
	if e.reg.Withdraw(c1.operator()) {
		t.Fatal("withdrew twice")
	}
	if _, ok := e.reg.Current(c1.operator()); ok {
		t.Fatal("the withdrawn handraise is still current")
	}
	root := e.mustIssue()
	if root.Root.GetLeafCount() != 1 || leafOf(t, root, c2.operator()) == nil {
		t.Fatalf("root after the withdrawal = %v", root.Root)
	}
	e.reg = e.open()
	if _, ok := e.reg.Current(c1.operator()); ok {
		t.Fatal("the withdrawn handraise came back after a restart")
	}
	if err := e.accept(c1, h1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed withdrawn handraise = %v, want ErrInvalid", err)
	}
	e.clock.advance(time.Second)
	e.mustAccept(c1, e.handraise(c1, 100, 2))
	if root := e.mustIssue(); root.Root.GetLeafCount() != 2 {
		t.Fatalf("leaves after a newer handraise = %d", root.Root.GetLeafCount())
	}
}
