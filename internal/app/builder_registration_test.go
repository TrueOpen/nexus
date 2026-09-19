package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// End-to-end run of the builder-registration module: MsgRegisterBuilder really is broadcast carrying the three
// ServiceEndpointV1 entries derived from public_endpoint (in Phase 0 BuilderBond is fixed at zero, so there is no bond step).
// `nexus start` only checks and never submits (ADR-0015): if the Builder is not registered, startup fails with zero broadcasts and no observation left behind;
// registration and descriptor submission go through `nexus builder register`.
func TestBuilderRegistrationModuleDoesNotSubmitAtStart(t *testing.T) {
	sg := appTestSigner(t)
	chain := &registrationChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	store := kv.NewMemStore()
	m := newBuilderRegistrationModule(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		store,
		chain,
		sg,
		sg,
		config.IdentityConfig{
			PublicEndpoint: "https://builder.example:8080",
		},
		config.BuilderAuthority{Mode: config.AuthorityHub, Chain: config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000}},
		"",
	)
	if m == nil {
		t.Fatal("registration module is nil")
	}
	if m.name != "builder-registration" {
		t.Fatalf("module name = %q", m.name)
	}
	err := m.start(context.Background())
	if !errors.Is(err, builderreg.ErrNotRegistered) {
		t.Fatalf("module start = %v, want ErrNotRegistered", err)
	}
	if len(chain.broadcasts) != 0 {
		t.Fatalf("broadcasts = %d, want 0: start must not register", len(chain.broadcasts))
	}
	if _, ok := store.Get(kv.NSBuilderReg, "trueopen-hub\x1f"+sg.Address()); ok {
		t.Fatal("an unregistered Builder must not be recorded as ensured")
	}
}

// With the endpoint config missing it must fail during startup and broadcast nothing at all -- empty endpoints must never be submitted.
func TestBuilderRegistrationModuleFailsFastWithoutEndpoints(t *testing.T) {
	sg := appTestSigner(t)
	chain := &registrationChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	m := newBuilderRegistrationModule(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kv.NewMemStore(),
		chain,
		sg,
		sg,
		config.IdentityConfig{},
		config.BuilderAuthority{Mode: config.AuthorityHub, Chain: config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000}},
		"",
	)
	err := m.start(context.Background())
	if err == nil {
		t.Fatal("a descriptor with no endpoints must not start")
	}
	if !strings.Contains(err.Error(), "identity.service_endpoints") {
		t.Fatalf("error = %v, want it to name the missing configuration", err)
	}
	if len(chain.broadcasts) != 0 {
		t.Fatalf("broadcasts = %d, want 0", len(chain.broadcasts))
	}
}

func decodeRegistrationTxBody(t *testing.T, rawBytes []byte) *txv1beta1.TxBody {
	t.Helper()
	var raw txv1beta1.TxRaw
	if err := proto.Unmarshal(rawBytes, &raw); err != nil {
		t.Fatalf("unmarshal TxRaw: %v", err)
	}
	var body txv1beta1.TxBody
	if err := proto.Unmarshal(raw.BodyBytes, &body); err != nil {
		t.Fatalf("unmarshal TxBody: %v", err)
	}
	if len(body.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(body.Messages))
	}
	return &body
}

func TestBuilderRegistrationModuleSkippedWithoutSigner(t *testing.T) {
	m := newBuilderRegistrationModule(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kv.NewMemStore(),
		&registrationChain{},
		nil,
		nil,
		config.IdentityConfig{},
		config.BuilderAuthority{},
		"",
	)
	if m != nil {
		t.Fatalf("module = %+v, want nil", m)
	}
}

func TestChainEventOptions(t *testing.T) {
	store := kv.NewMemStore()
	compatibility := newChainEventOptions(store, config.AuthorityCompatibility)
	if len(compatibility.task) != 3 || len(compatibility.hub) != 0 || compatibility.protocolOnHub {
		t.Fatalf("compatibility event options = %+v", compatibility)
	}
	hub := newChainEventOptions(store, config.AuthorityHub)
	if len(hub.task) != 2 || len(hub.hub) != 2 || !hub.protocolOnHub {
		t.Fatalf("hub event options = %+v", hub)
	}
}

func TestStage1AdmissionOptionSkippedWithoutSigner(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := chaincli.NewStub(log, config.ChainConfig{})
	coord := coordinator.New(
		log,
		msgbus.NewStub(log, nil),
		chain,
		relay.NewMem(log),
		kv.NewMemStore(),
		"",
		"task-chain-1",
		stage1AdmissionOption(nil, nil, "task-chain-1"),
	)

	if err := coord.OnOrder(context.Background(), types.Order{TaskHash: "f8a56f8bfe3164e9945e062e842293979f5a8d09a4c81bef81f26c7c4cd947d2", SessionID: "session-1", TaskID: "task-1", ModelID: "model-1", PayloadCID: "cid-1", SignedOrder: appTestSignedOrderBytes(t)}); err != nil {
		t.Fatalf("unsigned development order: %v", err)
	}
}

// stage1RegistryHeight is the latest height the fake registry reports: admission must use it to look up the
// BuilderSet, and term may only come from the returned value.
const stage1RegistryHeight = uint64(1234)

func TestStage1AdmissionOptionUsesSignerAndTaskChain(t *testing.T) {
	const (
		taskChainID = "task-chain-1"
		termID      = uint64(7)
	)
	sg := appTestSigner(t)
	builders := []string{sg.Address()}
	for index := 1; index <= 3; index++ {
		builder, err := signer.NewFromHex(fmt.Sprintf("%064x", index), "trueopen")
		if err != nil {
			t.Fatal(err)
		}
		builders = append(builders, builder.Address())
	}
	const setHash = "7c1d3e5a9b2f4068d1c3e5a7b9f20416d8c3e5a7b9f20416d8c3e5a7b9f20416"
	taskID := taskOutsideSelection(t, termID, taskChainID, setHash, sg.Address(), builders)
	registry := &stage1Registry{
		builder: chaincli.BuilderState{Address: sg.Address(), ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1},
		height:  stage1RegistryHeight,
		set: chaincli.BuilderSet{
			Epoch: termID, BuilderSetID: "7", SetHash: setHash,
			ActiveBuilderCount: uint32(len(builders)), BodyStatus: "ACTIVE",
			Members: appBuilderRefs(builders...),
		},
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	chain := chaincli.NewStub(log, config.ChainConfig{})
	coord := coordinator.New(
		log,
		msgbus.NewStub(log, nil),
		chain,
		relay.NewMem(log),
		kv.NewMemStore(),
		sg.Address(),
		taskChainID,
		stage1AdmissionOption(sg, registry, taskChainID),
	)

	if err := coord.OnOrder(context.Background(), types.Order{TaskHash: "f8a56f8bfe3164e9945e062e842293979f5a8d09a4c81bef81f26c7c4cd947d2", SessionID: "session-1", TaskID: taskID, ModelID: "model-1", PayloadCID: "cid-1", SignedOrder: appTestSignedOrderBytes(t)}); err != nil {
		t.Fatalf("OnOrder: %v", err)
	}
	if registry.address != sg.Address() || registry.queriedHeight != stage1RegistryHeight {
		t.Fatalf("registry query address=%q height=%d", registry.address, registry.queriedHeight)
	}
	if !strings.Contains(logs.String(), "code="+coordinator.ErrNotSelectedBuilder.Error()) {
		t.Fatalf("stage1 warning log=%q", logs.String())
	}
}

// appTestSignedOrderBytes gives the admission cases a minimal proto SignedOrderV2: the broadcast gate in onOrder
// only requires it to be non-empty and decodable (content validity is decided by the Keeper and the broadcast receivers).
func appTestSignedOrderBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := proto.Marshal(&taskv1.SignedOrderV2{SignatureScheme: "eip712"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func taskOutsideSelection(t *testing.T, termID uint64, chainID, setHash, self string, builders []string) string {
	t.Helper()
	sessionID := sha256.Sum256([]byte("session-stage1"))
	for sequence := 1; sequence <= 100; sequence++ {
		taskIDRaw, err := nodecontract.DeriveTaskIDFromRawSession(sessionID[:], uint64(sequence))
		if err != nil {
			t.Fatal(err)
		}
		taskID := hex.EncodeToString(taskIDRaw[:])
		selection, err := nodecontract.ComputeBuilderSelection(termID, chainID, "", taskID, "ASSIGN", "", setHash, builders)
		if err != nil {
			t.Fatal(err)
		}
		selected := false
		for _, address := range selection.SelectedBuilders {
			selected = selected || address == self
		}
		if !selected {
			return taskID
		}
	}
	t.Fatal("could not find task outside selection")
	return ""
}

func appBuilderRefs(addresses ...string) []types.BuilderRef {
	refs := make([]types.BuilderRef, 0, len(addresses))
	for index, address := range addresses {
		refs = append(refs, types.BuilderRef{Address: address, Rank: index + 1})
	}
	return refs
}

type stage1Registry struct {
	address       string
	queriedHeight uint64
	height        uint64
	builder       chaincli.BuilderState
	set           chaincli.BuilderSet
}

func (r *stage1Registry) QueryBuilder(_ context.Context, address string) (chaincli.BuilderState, error) {
	r.address = address
	return r.builder, nil
}

func (r *stage1Registry) LatestHeight(context.Context) (uint64, error) { return r.height, nil }

func (r *stage1Registry) QueryBuilderSetAtHeight(_ context.Context, height uint64) (chaincli.BuilderSet, error) {
	r.queriedHeight = height
	return r.set, nil
}

func appTestSigner(t *testing.T) signer.Signer {
	t.Helper()
	sg, err := signer.NewFromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return sg
}

type registrationChain struct {
	chaincli.Client
	acc        chaincli.AccountInfo
	broadcasts [][]byte
	result     chaincli.TxResult
	results    []chaincli.TxResult
	err        error
	errs       []error
	registered bool
}

func (c *registrationChain) LatestHeight(context.Context) (uint64, error) { return 1000, nil }

func (c *registrationChain) QueryBuilder(context.Context, string) (chaincli.BuilderState, error) {
	if !c.registered {
		return chaincli.BuilderState{}, chaincli.ErrNotFound
	}
	return chaincli.BuilderState{ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1}, nil
}

func (c *registrationChain) QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error) {
	return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
}

func (c *registrationChain) QueryServiceDescriptor(context.Context, string, string, uint64) (chaincli.ServiceDescriptorState, error) {
	return chaincli.ServiceDescriptorState{}, chaincli.ErrNotFound
}

func (c *registrationChain) AccountInfo(context.Context, string) (chaincli.AccountInfo, error) {
	return c.acc, nil
}

func (c *registrationChain) BroadcastTx(_ context.Context, tx []byte) (chaincli.TxResult, error) {
	c.broadcasts = append(c.broadcasts, tx)
	idx := len(c.broadcasts) - 1
	result, resultErr := c.broadcastResult(idx)
	if resultErr == nil && result.Code == 0 {
		var raw txv1beta1.TxRaw
		var body txv1beta1.TxBody
		if proto.Unmarshal(tx, &raw) == nil && proto.Unmarshal(raw.BodyBytes, &body) == nil && len(body.Messages) == 1 {
			if body.Messages[0].TypeUrl == chaincli.TypeURLMsgRegisterBuilder {
				c.registered = true
			}
		}
	}
	return result, resultErr
}

func (c *registrationChain) broadcastResult(idx int) (chaincli.TxResult, error) {
	if idx < len(c.errs) && c.errs[idx] != nil {
		if idx < len(c.results) {
			return c.results[idx], c.errs[idx]
		}
		return c.result, c.errs[idx]
	}
	if idx < len(c.results) {
		res := c.results[idx]
		if res.TxHash == nil {
			res.TxHash = []byte("txhash")
		}
		return res, nil
	}
	if c.err != nil {
		return c.result, c.err
	}
	if c.result.TxHash == nil {
		c.result.TxHash = []byte("txhash")
	}
	return c.result, nil
}
