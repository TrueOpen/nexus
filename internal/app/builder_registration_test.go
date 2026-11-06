package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

// End-to-end run of the builder-registration module: MsgRegisterBuilder really is broadcast carrying the three
// ServiceEndpointV1 entries derived from public_endpoint (in Phase 0 BuilderBond is fixed at zero, so there is no bond step).
// `nexus start` only checks and never submits: if the Builder is not registered, startup fails with zero broadcasts and no observation left behind;
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
