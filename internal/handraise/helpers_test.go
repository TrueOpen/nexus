package handraise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	testChainID = "trueopen-test-1"
	testPrefix  = "trueopen"
)

var (
	testModel    = bytes.Repeat([]byte{0x4d}, 32)
	testSnapshot = bytes.Repeat([]byte{0x53}, 32)
)

type fakeKeys struct {
	mu         sync.Mutex
	cortex     map[string]*fakeKey
	pending    map[string]bool // operators with a pending CORTEX key rotation
	pendingErr error
	// unusable lists operators whose CORTEX key the chain reports unusable (revoked, missing).
	unusable   map[string]bool
	builderErr error
	err        error
}

type fakeKey struct {
	pub   []byte
	nonce uint64
}

func (k *fakeKeys) CurrentCortexKey(_ context.Context, operator string) ([]byte, uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return nil, 0, k.err
	}
	key, ok := k.cortex[operator]
	if !ok {
		return nil, 0, fmt.Errorf("no key: %w", servicekey.ErrUnavailable)
	}
	return key.pub, key.nonce, nil
}

func (k *fakeKeys) CortexRotationPending(_ context.Context, operator string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.unusable[operator] {
		return false, fmt.Errorf("revoked: %w", servicekey.ErrUnavailable)
	}
	return k.pending[operator], k.pendingErr
}

func (k *fakeKeys) setPending(operator string, pending bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pending == nil {
		k.pending = map[string]bool{}
	}
	k.pending[operator] = pending
}

func (k *fakeKeys) CheckBuilderKey(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.builderErr
}

type fakePool struct {
	mu      sync.Mutex
	members map[string]bool            // operator -> eligible
	support map[string]map[string]bool // operator -> profile key -> fresh
	err     error

	supportErr error
}

func profileKey(p *taskv1.DispatchProfileV1) string {
	return fmt.Sprintf("%x/%d", p.GetModelId(), p.GetProfileVersion())
}

func (p *fakePool) IsEligibleMember(_ context.Context, member *taskv1.CandidateMemberRefV1) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return false, p.err
	}
	return p.members[member.GetOperatorAddress()], nil
}

func (p *fakePool) HasFreshSupport(_ context.Context, operator string, profile *taskv1.DispatchProfileV1) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.supportErr != nil {
		return false, p.supportErr
	}
	return p.support[operator][profileKey(profile)], nil
}

type fakeHeight struct {
	mu  sync.Mutex
	h   uint64
	err error
}

func (f *fakeHeight) LatestHeight(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.h, f.err
}

// failingStore fails every batch write while err is set.
type failingStore struct {
	kv.Store
	err error
}

func (s *failingStore) WriteBatch(ops ...kv.WriteOp) error {
	if s.err != nil {
		return s.err
	}
	return s.Store.WriteBatch(ops...)
}

func (f *fakeHeight) set(h uint64) {
	f.mu.Lock()
	f.h = h
	f.mu.Unlock()
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// cortex is one test Cortex operator with its current service key.
type cortex struct {
	key   signer.Signer
	nonce uint64
	slot  uint32
}

func (c cortex) operator() string { return c.key.Address() }

type env struct {
	t       *testing.T
	store   kv.Store
	keys    *fakeKeys
	pool    *fakePool
	height  *fakeHeight
	clock   *fakeClock
	builder servicekey.Signer
	cfg     config.DispatchConfig
	reg     *Registry
}

// minRejectRateSamples is gpu_reject_rate_min_samples of testDispatchConfig.
const minRejectRateSamples = 10

func testDispatchConfig() config.DispatchConfig {
	return config.DispatchConfig{
		HandraiseHeartbeatMs:          2000,
		HandraiseTTLMs:                6000,
		HandraiseMinChangeIntervalMs:  200,
		HandraiseRootIntervalMs:       500,
		AcceptTimeoutMsByRTTTier:      []config.RTTTierConfig{{MaxRTTMs: 100, AcceptTimeoutMs: 500}},
		BuilderRTTAdmitMs:             150,
		GPURejectRateThreshold:        0.5,
		GPURejectRateSuspensionBlocks: 100,
		GPURejectRateMinSamples:       minRejectRateSamples,
		BuilderTimeoutRateThreshold:   0.2,

		HandraiseIssuedHeightToleranceBlocks: 3,
		RecordGasBase:                        200_000,
		RecordGasPerEntry:                    300_000,
		AnswerGasBase:                        300_000,
		AnswerGasPerByte:                     30,
	}
}

// testBuilderNonce is the authorization nonce of the test Builder's service key.
const testBuilderNonce = 4

func newSigner(t *testing.T, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{seed}, 32), testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:       t,
		store:   kv.NewMemStore(),
		keys:    &fakeKeys{cortex: map[string]*fakeKey{}},
		pool:    &fakePool{members: map[string]bool{}, support: map[string]map[string]bool{}},
		height:  &fakeHeight{h: 100},
		clock:   &fakeClock{now: time.Unix(1_800_000_000, 0)},
		builder: servicekey.Static(newSigner(t, 0x01), testBuilderNonce),
		cfg:     testDispatchConfig(),
	}
	e.reg = e.open()
	return e
}

// open builds a Registry over the env's store, as a restart would.
func (e *env) open() *Registry {
	e.t.Helper()
	reg, err := New(Options{
		ChainID:        testChainID,
		BuilderAddress: e.builder.Address(),
		Config:         e.cfg,
		Store:          e.store,
		Keys:           e.keys,
		Pool:           e.pool,
		Height:         e.height,
		Signer:         e.builder,
		Now:            e.clock.Now,
		Log:            slog.New(slog.DiscardHandler),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return reg
}

// addCortex registers an eligible Cortex with fresh support for the test profile.
func (e *env) addCortex(seed byte, slot uint32) cortex {
	e.t.Helper()
	c := cortex{key: newSigner(e.t, seed), nonce: 3, slot: slot}
	e.keys.mu.Lock()
	e.keys.cortex[c.operator()] = &fakeKey{pub: c.key.PubKeyCompressed(), nonce: c.nonce}
	e.keys.mu.Unlock()
	e.pool.mu.Lock()
	e.pool.members[c.operator()] = true
	e.pool.support[c.operator()] = map[string]bool{profileKey(testProfile()): true}
	e.pool.mu.Unlock()
	return c
}

func testProfile() *taskv1.DispatchProfileV1 {
	return &taskv1.DispatchProfileV1{ModelId: testModel, ProfileVersion: 1}
}

// handraise returns a handraise of c signed with its current key.
func (e *env) handraise(c cortex, issued, nonce uint64) *taskv1.StandingHandraiseV1 {
	e.t.Helper()
	h := &taskv1.StandingHandraiseV1{
		SchemaVersion:  1,
		ChainId:        testChainID,
		BuilderAddress: e.builder.Address(),
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: testSnapshot, Slot: c.slot, SlotVersion: 1, OperatorAddress: c.operator(),
		},
		Profiles:                  []*taskv1.DispatchProfileV1{testProfile()},
		FreeSlotCount:             2,
		IssuedHeight:              issued,
		ExpiryHeight:              issued + 50,
		HandraiseNonce:            nonce,
		ServiceAuthorizationNonce: c.nonce,
	}
	return signHandraise(e.t, c.key, h)
}

func signHandraise(t *testing.T, key signer.Signer, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
	t.Helper()
	h = proto.Clone(h).(*taskv1.StandingHandraiseV1)
	h.ServiceSignature = nil
	digest := standingDigest(t, h)
	sig, err := key.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	h.ServiceSignature = sig
	return h
}

func standingDigest(t *testing.T, h *taskv1.StandingHandraiseV1) [32]byte {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(standingName, raw)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func (e *env) accept(c cortex, h *taskv1.StandingHandraiseV1) error {
	return e.reg.Accept(context.Background(), c.operator(), h)
}

func (e *env) mustAccept(c cortex, h *taskv1.StandingHandraiseV1) {
	e.t.Helper()
	if err := e.accept(c, h); err != nil {
		e.t.Fatalf("accept: %v", err)
	}
}

func (e *env) issue() *IssuedRoot {
	e.t.Helper()
	root, err := e.reg.IssueRoot(context.Background())
	if err != nil {
		e.t.Fatalf("issue root: %v", err)
	}
	return root
}

func (e *env) mustIssue() *IssuedRoot {
	e.t.Helper()
	root := e.issue()
	if root == nil {
		e.t.Fatal("no root issued")
	}
	return root
}

// leafOf returns the leaf of operator in root that is not an invalid-handraise trace.
func leafOf(t *testing.T, root *IssuedRoot, operator string) *taskv1.HandraiseRootLeafV1 {
	t.Helper()
	for _, leaf := range root.Leaves {
		if leaf.GetHandraise().GetMember().GetOperatorAddress() == operator &&
			leaf.GetAdmitRejectReason() != taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_INVALID_HANDRAISE {
			return leaf
		}
	}
	t.Fatalf("no leaf for %s", operator)
	return nil
}

func wantCode(t *testing.T, err, code error) {
	t.Helper()
	if !errors.Is(err, code) {
		t.Fatalf("err = %v, want %v", err, code)
	}
}
