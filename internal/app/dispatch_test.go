package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskgroup"
)

const (
	wiringChainID = "trueopen-wiring-1"
	wiringPrefix  = "trueopen"
)

var wiringSnapshot = bytes.Repeat([]byte{0x53}, 32)

// wiringChain answers the Hub reads of direct dispatch from fixed rows; anything else is the stub.
type wiringChain struct {
	chaincli.Client
	mu      sync.Mutex
	keys    map[string]chaincli.ServiceKeyState // participant/operator -> key
	keyErr  error
	vrf     []byte
	members map[string]*hubv1.CandidatePoolSnapshotMemberViewV1 // operator/model -> view
}

func (c *wiringChain) QueryCurrentServiceKey(_ context.Context, participant, operator string) (chaincli.ServiceKeyState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keyErr != nil {
		return chaincli.ServiceKeyState{}, c.keyErr
	}
	key, ok := c.keys[participant+"/"+operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return key, nil
}

func (c *wiringChain) QueryCurrentCandidatePool(context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	return &hubv1.CandidatePoolSnapshotViewV1{Epoch: 1, SnapshotId: wiringSnapshot}, nil
}

func (c *wiringChain) QueryCandidatePoolSnapshotMember(_ context.Context, key chaincli.CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	view, ok := c.members[key.Operator+"/"+string(key.ModelID)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return view, nil
}

func (c *wiringChain) QueryEpochLengthBlocks(context.Context) (uint64, error) { return 100, nil }

func (c *wiringChain) QueryVrfKey(context.Context, string, string) (chaincli.VrfKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return chaincli.VrfKey{ActivePubKey: c.vrf, ActiveFromEpoch: 1}, nil
}

func serviceKeyState(participant, operator string, s signer.Signer, nonce uint64) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: participant, OperatorAddress: operator, ServiceAddress: s.Address(),
		ServicePubKey: hex.EncodeToString(s.PubKeyCompressed()), AuthorizationNonce: nonce, Status: "ACTIVE",
	}
}

type fixedHeight uint64

func (h fixedHeight) LatestHeight(context.Context) (uint64, error) { return uint64(h), nil }

type groupSource struct{ snapshot *taskgroup.Snapshot }

func (g *groupSource) CurrentBuilderSet() (taskgroup.Snapshot, bool) {
	if g.snapshot == nil {
		return taskgroup.Snapshot{}, false
	}
	return *g.snapshot, true
}

type sentFrame struct {
	operator string
	frame    *nexusv1.DispatchStreamFrameV1
}

type recordingStreams struct {
	operators []string
	sent      []sentFrame
}

func (s *recordingStreams) Operators() []string { return s.operators }

func (s *recordingStreams) Send(_ context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error {
	s.sent = append(s.sent, sentFrame{operator, frame})
	return nil
}

type noCortexKeys struct{}

func (noCortexKeys) CurrentCortexKey(context.Context, string) (dispatchstream.CortexKey, error) {
	return dispatchstream.CortexKey{}, errors.New("unused")
}

func mustSigner(t *testing.T, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{seed}, 32), wiringPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writePrivate(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// countingHandler counts log records by level.
type countingHandler struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.counts == nil {
		h.counts = map[slog.Level]int{}
	}
	h.counts[r.Level]++
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) count(level slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[level]
}

// failingStore fails every batch write while err is set.
type failingStore struct {
	kv.Store
	mu  sync.Mutex
	err error
}

func (s *failingStore) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *failingStore) WriteBatch(ops ...kv.WriteOp) error {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.Store.WriteBatch(ops...)
}

type wiringFixture struct {
	store   *failingStore
	logs    *countingHandler
	chain   *wiringChain
	builder signer.Signer
	// ring is builder as the service key ring the dispatch path signs with.
	ring    *servicekey.Ring
	cortex  signer.Signer
	groups  *groupSource
	streams *recordingStreams
	d       *directDispatch
}

func newWiringFixture(t *testing.T) *wiringFixture {
	t.Helper()
	builder, cortex := mustSigner(t, 0x01), mustSigner(t, 0x02)
	vrfKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	dir := t.TempDir()
	armored, err := signer.EncryptEd25519KeystoreArmor(vrfKey, []byte("vrf-pass"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writePrivate(t, filepath.Join(dir, "vrf.key"), armored)
	passFile := writePrivate(t, filepath.Join(dir, "vrf.pass"), []byte("vrf-pass\n"))
	fresh := true
	model := bytes.Repeat([]byte{0x4d}, 32)
	chain := &wiringChain{
		Client: chaincli.NewStub(slog.New(slog.DiscardHandler), config.ChainConfig{}),
		keys: map[string]chaincli.ServiceKeyState{
			"BUILDER/" + builder.Address(): serviceKeyState("BUILDER", builder.Address(), builder, 7),
			"CORTEX/" + cortex.Address():   serviceKeyState("CORTEX", cortex.Address(), cortex, 3),
		},
		vrf: []byte(vrfKey.Public().(ed25519.PublicKey)),
		members: map[string]*hubv1.CandidatePoolSnapshotMemberViewV1{
			cortex.Address() + "/": {InPool: true, Slot: 4, SlotVersion: 1,
				WeightInputs: &hubv1.CandidateWeightInputsV1{CandidateJailFactorPpm: 1_000_000}},
			cortex.Address() + "/" + string(model): {InPool: true, Slot: 4, SlotVersion: 1, ProfileSupportFresh: &fresh},
		},
	}
	store := &failingStore{Store: kv.NewMemStore()}
	logs := &countingHandler{}
	hub, err := dispatchstream.New(nil, dispatchstream.Config{ChainID: wiringChainID, BuilderOperator: builder.Address()}, noCortexKeys{}, store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Load().Dispatch
	ring, err := servicekey.NewRing(chain, wiringPrefix, builder.Address(), nil, builder)
	if err != nil {
		t.Fatal(err)
	}
	f := &wiringFixture{store: store, logs: logs, chain: chain, builder: builder, ring: ring, cortex: cortex, groups: &groupSource{},
		streams: &recordingStreams{}, d: &directDispatch{log: slog.New(logs)}}
	if err := newDirectDispatch(f.d, directDispatchDeps{
		ChainID: wiringChainID, BuilderAddress: builder.Address(), AddressPrefix: wiringPrefix, Config: cfg,
		VRFKeyFiles: []string{keyFile}, VRFKeyPassword: passFile, Store: store, Chain: chain, Keys: chain,
		Height: fixedHeight(150), Signer: ring, Streams: hub, Groups: f.groups,
	}); err != nil {
		t.Fatal(err)
	}
	f.d.streams = f.streams
	return f
}

func (f *wiringFixture) handraise(t *testing.T) *taskv1.StandingHandraiseV1 {
	t.Helper()
	h := &taskv1.StandingHandraiseV1{
		SchemaVersion: 1, ChainId: wiringChainID, BuilderAddress: f.builder.Address(),
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: wiringSnapshot, Slot: 4, SlotVersion: 1, OperatorAddress: f.cortex.Address(),
		},
		Profiles:      []*taskv1.DispatchProfileV1{{ModelId: bytes.Repeat([]byte{0x4d}, 32), ProfileVersion: 1}},
		FreeSlotCount: 1, IssuedHeight: 150, ExpiryHeight: 200, HandraiseNonce: 1, ServiceAuthorizationNonce: 3,
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest("task.v1.StandingHandraiseV1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServiceSignature, err = f.cortex.SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	return h
}

// A standing handraise arriving on a stream reaches the registry through the chain adapters; the
// signed root goes to a (re)bound stream with that Cortex's proof; readiness follows the
// BuilderSet snapshot, the root and the epoch's VRF key.
func TestDirectDispatchWiring(t *testing.T) {
	f := newWiringFixture(t)
	ctx := context.Background()
	if err := f.d.Ready(ctx); !errors.Is(err, taskgroup.ErrNoSnapshot) {
		t.Fatalf("ready without a BuilderSet: %v", err)
	}
	f.groups.snapshot = &taskgroup.Snapshot{ID: "set-1", Members: []string{f.builder.Address()}}
	if err := f.d.Ready(ctx); !errors.Is(err, errNoHandraiseRoot) {
		t.Fatalf("ready without a root: %v", err)
	}

	from := dispatchstream.Origin{Operator: f.cortex.Address()}
	if err := f.d.HandleStandingHandraise(ctx, from, f.handraise(t)); err != nil {
		t.Fatalf("handraise refused: %v", err)
	}
	issued, err := f.d.Registry.IssueRoot(ctx)
	if err != nil || issued == nil || !issued.Leaves[0].GetAdmitted() {
		t.Fatalf("root = %v, %v", issued, err)
	}
	if err := dispatch.VerifyDigestSignature(f.builder.PubKeyCompressed(), issued.Digest[:], issued.Root.GetBuilderServiceSignature()); err != nil {
		t.Fatalf("root is not signed by the Builder's current key: %v", err)
	}

	f.d.onConnection(f.cortex.Address(), true)
	f.d.onConnection("trueopen1other", true) // no leaf, nothing sent
	f.d.onConnection(f.cortex.Address(), false)
	if len(f.streams.sent) != 1 || f.streams.sent[0].operator != f.cortex.Address() {
		t.Fatalf("sent = %+v", f.streams.sent)
	}
	notice := f.streams.sent[0].frame.GetHandraiseRoot()
	if !proto.Equal(notice.GetRoot(), issued.Root) || notice.GetProof().GetLeafIndex() != 0 {
		t.Fatalf("notice = %v", notice)
	}
	f.streams.operators = []string{f.cortex.Address(), "trueopen1other"}
	f.d.pushRoot(ctx, issued, f.streams.Operators())
	if len(f.streams.sent) != 2 {
		t.Fatalf("root pushed to %d streams, want only the one with a leaf", len(f.streams.sent)-1)
	}

	if err := f.d.Ready(ctx); err != nil {
		t.Fatalf("not ready: %v", err)
	}
	other := newWiringFixture(t)
	other.groups.snapshot = f.groups.snapshot
	if err := other.d.HandleStandingHandraise(ctx, dispatchstream.Origin{Operator: other.cortex.Address()}, other.handraise(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := other.d.Registry.IssueRoot(ctx); err != nil {
		t.Fatal(err)
	}
	other.chain.mu.Lock()
	other.chain.vrf = bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize)
	other.chain.mu.Unlock()
	if err := other.d.Ready(ctx); !errors.Is(err, dispatchdraw.ErrVRFKeyMismatch) {
		t.Fatalf("ready with another registered VRF key: %v", err)
	}
	if f.d.Drawer == nil || f.d.Pools == nil {
		t.Fatal("drawer and pool cache are not exposed")
	}
}

// Refused handraises keep the stream, and so does a chain read failure: the handraise is dropped
// and re-signed at the next heartbeat. Only a failed store write ends the stream.
func TestHandraiseSinkErrorMapping(t *testing.T) {
	f := newWiringFixture(t)
	ctx := context.Background()
	from := dispatchstream.Origin{Operator: f.cortex.Address()}

	malformed := f.handraise(t)
	malformed.ChainId = "other-chain"
	err := f.d.HandleStandingHandraise(ctx, from, malformed)
	if !errors.Is(err, handraise.ErrInvalid) || errors.Is(err, dispatchstream.ErrTransient) {
		t.Fatalf("malformed: err = %v", err)
	}
	ahead := f.handraise(t)
	ahead.IssuedHeight = 150 + config.Load().Dispatch.HandraiseIssuedHeightToleranceBlocks + 1
	if err := f.d.HandleStandingHandraise(ctx, from, ahead); !errors.Is(err, handraise.ErrAhead) || errors.Is(err, dispatchstream.ErrTransient) {
		t.Fatalf("ahead of the chain: err = %v", err)
	}
	f.chain.mu.Lock()
	f.chain.keyErr = errors.New("endpoint unavailable")
	f.chain.mu.Unlock()
	for range 2 {
		if err := f.d.HandleStandingHandraise(ctx, from, f.handraise(t)); err != nil {
			t.Fatalf("chain failure: err = %v, want the handraise dropped", err)
		}
	}
	if got := f.logs.count(slog.LevelWarn); got != 1 {
		t.Fatalf("chain failures logged %d warnings, want 1", got)
	}
	if _, ok := f.d.Registry.Current(f.cortex.Address()); ok {
		t.Fatal("a handraise was accepted without its chain reads")
	}
	f.chain.mu.Lock()
	f.chain.keyErr = nil
	f.chain.mu.Unlock()
	f.store.setErr(errors.New("disk full"))
	if err := f.d.HandleStandingHandraise(ctx, from, f.handraise(t)); !errors.Is(err, dispatchstream.ErrTransient) {
		t.Fatalf("store failure: err = %v, want ErrTransient", err)
	}
}

func TestReplayDropsSupersededRoots(t *testing.T) {
	root := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_HandraiseRoot{HandraiseRoot: &nexusv1.HandraiseRootNoticeV1{}}}
	open := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: &nexusv1.OpenVerifyV1{}}}
	if keepOnReplay("op", root) || !keepOnReplay("op", open) {
		t.Fatal("replay must drop stored roots and keep other messages")
	}
}

func TestDispatchModuleStartsBeforeTheStreams(t *testing.T) {
	names := func(ms []module) []string {
		out := make([]string, len(ms))
		for i, m := range ms {
			out[i] = m.name
		}
		return out
	}
	base := []module{{name: "coordinator"}, {name: "output-delivery"}, {name: "dispatch-stream"}, {name: "ingress"}}
	got := names(insertBefore(base, "dispatch-stream", module{name: "handraise-roots"}))
	if want := []string{"coordinator", "output-delivery", "handraise-roots", "dispatch-stream", "ingress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("modules = %v", got)
	}
	if len(base) != 4 {
		t.Fatal("insertBefore changed its input")
	}
}

func TestCachedHeightReadsOncePerInterval(t *testing.T) {
	reads, height := 0, uint64(10)
	now := time.Unix(1_800_000_000, 0)
	h := newCachedHeight(func(context.Context) (uint64, error) { reads++; return height, nil })
	h.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if got, _ := h.LatestHeight(context.Background()); got != 10 {
			t.Fatalf("height = %d", got)
		}
	}
	now, height = now.Add(heightCacheTTL), 12
	if got, _ := h.LatestHeight(context.Background()); got != 12 || reads != 2 {
		t.Fatalf("height = %d after %d reads", got, reads)
	}
}

// The height roots and handraises are judged at never trails the head the dispatcher opens rounds
// at: a root signed after a round opened must not carry a height below that round's head.
func TestRootHeightNeverTrailsTheDispatchHead(t *testing.T) {
	f := newWiringFixture(t) // chain height 150
	f.d.SetDispatchHead(func() uint64 { return 152 })
	ctx := context.Background()
	if err := f.d.HandleStandingHandraise(ctx, dispatchstream.Origin{Operator: f.cortex.Address()}, f.handraise(t)); err != nil {
		t.Fatal(err)
	}
	root, err := f.d.Registry.IssueRoot(ctx)
	if err != nil || root == nil {
		t.Fatalf("root = %v, %v", root, err)
	}
	if got := root.Root.GetRootHeight(); got != 152 {
		t.Fatalf("root height = %d, want the dispatch head 152", got)
	}
}

// The root loop does not start before the dispatch head is wired: no root may be judged without it.
func TestDirectDispatchStartNeedsTheDispatchHead(t *testing.T) {
	f := newWiringFixture(t)
	if err := f.d.Start(context.Background()); err == nil {
		_ = f.d.Stop(context.Background())
		t.Fatal("root loop started without the dispatch head")
	}
	f.d.SetDispatchHead(func() uint64 { return 0 })
	if err := f.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = f.d.Stop(context.Background())
}

// A Cortex whose stream ended loses its leaf at once: its handraise is withdrawn and a new root is
// issued, so rounds built after it pay no skip for that Worker.
func TestDisconnectWithdrawsTheHandraise(t *testing.T) {
	f := newWiringFixture(t)
	ctx := context.Background()
	if err := f.d.HandleStandingHandraise(ctx, dispatchstream.Origin{Operator: f.cortex.Address()}, f.handraise(t)); err != nil {
		t.Fatal(err)
	}
	first, err := f.d.Registry.IssueRoot(ctx)
	if err != nil || first == nil {
		t.Fatalf("root = %v, %v", first, err)
	}
	f.d.onConnection(f.cortex.Address(), false)
	if _, ok := f.d.Registry.Current(f.cortex.Address()); ok {
		t.Fatal("the disconnected Cortex keeps its handraise")
	}
	latest, ok := f.d.Registry.LatestRoot()
	if !ok || latest.Digest == first.Digest || latest.Root.GetLeafCount() != 0 {
		t.Fatalf("latest root after the disconnect = %v", latest.Root)
	}
}
