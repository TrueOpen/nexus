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
	// ...but takes no new Worker duty: dispatch leaves it out of rosters.
	if pending, err := keys.CortexRotationPending(context.Background(), cortexOperator); err != nil || !pending {
		t.Fatalf("CortexRotationPending = %v, %v; want true", pending, err)
	}
	cortexPending.PendingRotation = nil
	resolver[servicekey.ParticipantCortex+"/"+cortexOperator] = cortexPending
	if pending, err := keys.CortexRotationPending(context.Background(), cortexOperator); err != nil || pending {
		t.Fatalf("CortexRotationPending without a rotation = %v, %v", pending, err)
	}
	if _, err := keys.CortexRotationPending(context.Background(), builderOperator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("CortexRotationPending without a key = %v", err)
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
