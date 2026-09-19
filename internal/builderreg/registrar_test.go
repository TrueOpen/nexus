package builderreg

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// Registration = one MsgRegisterBuilder; the Phase 0 BuilderBond is fixed at zero (wire v0.4.1 has no
// Builder bond message), so nothing beyond the registration may be written and a repeated Ensure is idempotent.
func TestRegistrarRegistersFromChainState(t *testing.T) {
	sg := testSigner(t)
	state := newBuilderState()
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))

	if err := reg.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.registers) != 1 || len(sub.updates) != 0 {
		t.Fatalf("writes register=%d update=%d", len(sub.registers), len(sub.updates))
	}
	register := sub.registers[0]
	if register.Builder != sg.Address() || register.AuthorizationNonce != 1 ||
		len(register.ServicePubKey) != 66 || len(register.ServiceKeyProof) != 128 {
		t.Fatalf("register = %+v", register)
	}
	assertDerivedEndpoints(t, register.Endpoints, "https://builder.example")

	if err := reg.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.registers) != 1 || len(sub.updates) != 0 {
		t.Fatalf("idempotent writes register=%d update=%d", len(sub.registers), len(sub.updates))
	}
}

// An update happens only when the endpoints changed, and expected_descriptor_version must be the
// **current** on-chain version (the keeper asserts equality and then writes current+1), not the target version.
func TestRegistrarUpdatesChangedDescriptorWithExpectedVersion(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://old.example")
	state.builder.CurrentDescriptorVersion = 3
	state.descriptor.DescriptorVersion = 3
	sub := &captureSubmitter{state: state}

	if err := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example")).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %+v", sub.updates)
	}
	update := sub.updates[0]
	if update.ExpectedDescriptorVersion != 3 || update.OperatorAddress != sg.Address() ||
		update.ParticipantType != "BUILDER" {
		t.Fatalf("update = %+v", update)
	}
	assertDerivedEndpoints(t, update.Endpoints, "https://builder.example")
}

// Unchanged descriptor content must not be resubmitted: the frozen-contract on-chain descriptor has no
// validity period, so N restarts still mean 0 MsgUpdateServiceDescriptor transactions.
func TestRegistrarDoesNotResubmitUnchangedDescriptor(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example")
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))

	for i := 0; i < 3; i++ {
		if err := reg.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(sub.updates) != 0 {
			t.Fatalf("restart %d produced %d descriptor updates", i, len(sub.updates))
		}
	}
}

// A change to protocol_version or tls_pubkey_hash alone still counts as a content change and must be resubmitted.
func TestRegistrarUpdatesOnEndpointFieldChange(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example")
	state.descriptor.Endpoints[1].ProtocolVersion = "v2"
	sub := &captureSubmitter{state: state}

	if err := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example")).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(sub.updates))
	}
}

// Explicitly configured endpoints take precedence over the public_endpoint derivation and are submitted ascending by kind.
func TestRegistrarSubmitsExplicitlyConfiguredEndpoints(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example")
	sub := &captureSubmitter{state: state}
	identity := identityConfig("https://builder.example")
	identity.ServiceEndpoints = []config.ServiceEndpointConfig{
		{Kind: "HEALTH_HTTPS", URI: "https://health.example/healthz"},
		{Kind: "NEXUS_GRPC", URI: "grpcs://rpc.example:9090", ProtocolVersion: "v2"},
	}

	if err := newTestRegistrar(state, sub, sg, identity).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(sub.updates))
	}
	got := sub.updates[0].Endpoints
	if len(got) != 2 {
		t.Fatalf("endpoints = %+v", got)
	}
	if got[0].Kind != hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC ||
		got[0].URI != "grpcs://rpc.example:9090" || got[0].ProtocolVersion != "v2" {
		t.Fatalf("endpoint 0 = %+v", got[0])
	}
	if got[1].Kind != hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS ||
		got[1].URI != "https://health.example/healthz" || got[1].ProtocolVersion != "v1" {
		t.Fatalf("endpoint 1 = %+v", got[1])
	}
}

// The wire v0.4.1 BuilderState carries only the service key status: a Builder that is REVOKED (or missing)
// can send nothing carrying a service signature, so Ensure must fail closed and must not submit a descriptor update.
func TestRegistrarRejectsNonOperationalBuilderState(t *testing.T) {
	sg := testSigner(t)
	for _, status := range []string{"REVOKED", ""} {
		t.Run("service key "+status, func(t *testing.T) {
			state := registeredBuilderState(sg, "https://old.example")
			state.builder.ServiceKeyStatus = status
			sub := &captureSubmitter{state: state}
			err := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example")).Ensure(context.Background())
			if err == nil || !strings.Contains(err.Error(), "service key status") {
				t.Fatalf("error = %v", err)
			}
			if len(sub.updates) != 0 || len(sub.registers) != 0 {
				t.Fatalf("nothing may be submitted: register=%d update=%d", len(sub.registers), len(sub.updates))
			}
		})
	}
}

func TestRegistrarReconcilesUnknownRegisterOutcomeByQuery(t *testing.T) {
	sg := testSigner(t)
	state := newBuilderState()
	sub := &captureSubmitter{
		state: state,
		registerErr: &coordinator.SubmissionError{
			Phase: coordinator.SubmissionBroadcast,
			Err:   errors.New("connection reset"),
		},
	}
	sub.applyRegisterBeforeError = true

	if err := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example")).Ensure(context.Background()); err != nil {
		t.Fatalf("reconciled outcome: %v", err)
	}
	if len(sub.registers) != 1 {
		t.Fatalf("writes register=%d", len(sub.registers))
	}
}

// A missing or invalid endpoint configuration must fail at startup with a readable error and must not submit an empty or half-filled list.
func TestRegistrarFailsFastOnMissingOrInvalidEndpointConfig(t *testing.T) {
	sg := testSigner(t)
	missing := identityConfig("")
	badEndpoint := identityConfig("builder.example")
	badKind := identityConfig("https://builder.example")
	badKind.ServiceEndpoints = []config.ServiceEndpointConfig{{Kind: "NEXUS_HTTP", URI: "https://a"}}
	badScheme := identityConfig("https://builder.example")
	badScheme.ServiceEndpoints = []config.ServiceEndpointConfig{{Kind: "NEXUS_GRPC", URI: "ftp://a"}}

	for name, cfg := range map[string]config.IdentityConfig{
		"no endpoints at all": missing,
		"relative endpoint":   badEndpoint,
		"unknown kind":        badKind,
		"scheme outside set":  badScheme,
	} {
		t.Run(name, func(t *testing.T) {
			state := newBuilderState()
			sub := &captureSubmitter{}
			err := newTestRegistrar(state, sub, sg, cfg).Ensure(context.Background())
			if err == nil {
				t.Fatal("expected a fail-fast validation error")
			}
			if len(sub.registers) != 0 || len(sub.updates) != 0 {
				t.Fatalf("nothing may be submitted: register=%d update=%d", len(sub.registers), len(sub.updates))
			}
		})
	}
}

// The three derived endpoints are NEXUS_GRPC / OBJECT_GATEWAY_HTTPS pointing at public_endpoint and
// HEALTH_HTTPS appending /healthz, already sorted ascending by kind.
func assertDerivedEndpoints(t *testing.T, endpoints []chaincli.ServiceEndpoint, base string) {
	t.Helper()
	want := []chaincli.ServiceEndpoint{
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: base, ProtocolVersion: "v1"},
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS, URI: base, ProtocolVersion: "v1"},
		{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS, URI: base + "/healthz", ProtocolVersion: "v1"},
	}
	if len(endpoints) != len(want) {
		t.Fatalf("endpoints = %+v", endpoints)
	}
	for i := range want {
		if endpoints[i] != want[i] {
			t.Fatalf("endpoint %d = %+v, want %+v", i, endpoints[i], want[i])
		}
	}
}

func newTestRegistrar(state *fakeBuilderState, sub *captureSubmitter, accountSigner signer.Signer, identity config.IdentityConfig) *Registrar {
	return New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kv.NewMemStore(),
		state,
		sub,
		accountSigner,
		accountSigner,
		identity,
		hubAuthority("trueopen-hub"),
	)
}

func identityConfig(endpoint string) config.IdentityConfig {
	return config.IdentityConfig{
		PublicEndpoint: endpoint,
		Moniker:        "builder-a",
		P2PHint:        "nats://builder.example:4222",
	}
}

func hubAuthority(chainID string) config.BuilderAuthority {
	return config.BuilderAuthority{
		Mode:          config.AuthorityHub,
		Chain:         config.ChainConfig{ChainID: chainID},
		LegacyChainID: "trueopen-localnet",
	}
}

func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

type fakeBuilderState struct {
	height     uint64
	builder    chaincli.BuilderState
	key        chaincli.ServiceKeyState
	descriptor chaincli.ServiceDescriptorState
	hasBuilder bool
	hasKey     bool
	hasDesc    bool
	// queries counts QueryBuilder calls; onQueryBuilder fires before each query and is used to simulate
	// "the commit only becomes visible on the Nth query after the broadcast".
	queries        int
	onQueryBuilder func(queries int)
}

func newBuilderState() *fakeBuilderState { return &fakeBuilderState{height: 1000} }

func registeredBuilderState(sg signer.Signer, endpoint string) *fakeBuilderState {
	state := newBuilderState()
	state.hasBuilder, state.hasKey, state.hasDesc = true, true, true
	state.builder = chaincli.BuilderState{Address: sg.Address(), ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1}
	state.key = chaincli.ServiceKeyState{ParticipantType: "BUILDER", OperatorAddress: sg.Address(), AuthorizationNonce: 1, Status: "ACTIVE"}
	endpoints, err := derivedServiceEndpoints(endpoint, "")
	if err != nil {
		panic(err)
	}
	hash, err := nodecontract.ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, sg.Address(), 1,
		endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		panic(err)
	}
	state.descriptor = chaincli.ServiceDescriptorState{
		ParticipantType: "BUILDER", OperatorAddress: sg.Address(), DescriptorVersion: 1,
		Endpoints: endpoints, DescriptorHash: hash, UpdatedHeight: 900,
	}
	return state
}

func (s *fakeBuilderState) LatestHeight(context.Context) (uint64, error) { return s.height, nil }
func (s *fakeBuilderState) QueryBuilder(context.Context, string) (chaincli.BuilderState, error) {
	s.queries++
	if s.onQueryBuilder != nil {
		s.onQueryBuilder(s.queries)
	}
	if !s.hasBuilder {
		return chaincli.BuilderState{}, chaincli.ErrNotFound
	}
	return s.builder, nil
}
func (s *fakeBuilderState) QueryServiceDescriptor(context.Context, string, string, uint64) (chaincli.ServiceDescriptorState, error) {
	if !s.hasDesc {
		return chaincli.ServiceDescriptorState{}, chaincli.ErrNotFound
	}
	return s.descriptor, nil
}

type captureSubmitter struct {
	state                    *fakeBuilderState
	registers                []chaincli.RegisterBuilderTx
	updates                  []chaincli.UpdateServiceDescriptorTx
	registerErr              error
	applyRegisterBeforeError bool
	// deferUpdates: a broadcast descriptor update is not committed immediately and only takes effect on applyPendingUpdate.
	deferUpdates  bool
	pendingUpdate *chaincli.UpdateServiceDescriptorTx
}

// applyPendingUpdate makes the most recently broadcast descriptor update take effect on chain (version+1).
func (s *captureSubmitter) applyPendingUpdate() {
	if s.pendingUpdate == nil || s.state == nil {
		return
	}
	tx := *s.pendingUpdate
	s.pendingUpdate = nil
	s.state.builder.CurrentDescriptorVersion = tx.ExpectedDescriptorVersion + 1
	s.state.hasDesc = true
	s.state.descriptor = chaincli.ServiceDescriptorState{
		ParticipantType: "BUILDER", OperatorAddress: tx.OperatorAddress,
		DescriptorVersion: tx.ExpectedDescriptorVersion + 1, Endpoints: tx.Endpoints, UpdatedHeight: s.state.height,
	}
}

func (s *captureSubmitter) SubmitRegisterBuilder(_ context.Context, tx chaincli.RegisterBuilderTx) (chaincli.TxResult, error) {
	s.registers = append(s.registers, tx)
	if s.state != nil && (s.registerErr == nil || s.applyRegisterBeforeError) {
		s.state.hasBuilder, s.state.hasKey, s.state.hasDesc = true, true, true
		s.state.builder = chaincli.BuilderState{Address: tx.Builder, ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1}
		s.state.key = chaincli.ServiceKeyState{ParticipantType: "BUILDER", OperatorAddress: tx.Builder, AuthorizationNonce: tx.AuthorizationNonce, Status: "ACTIVE"}
		s.state.descriptor = chaincli.ServiceDescriptorState{
			ParticipantType: "BUILDER", OperatorAddress: tx.Builder, DescriptorVersion: 1,
			Endpoints: tx.Endpoints, UpdatedHeight: 1000,
		}
	}
	return chaincli.TxResult{TxHash: []byte("register")}, s.registerErr
}

func (s *captureSubmitter) SubmitUpdateServiceDescriptor(_ context.Context, tx chaincli.UpdateServiceDescriptorTx) (chaincli.TxResult, error) {
	s.updates = append(s.updates, tx)
	s.pendingUpdate = &tx
	if !s.deferUpdates {
		s.applyPendingUpdate() // commit synchronously by default, equivalent to the real chain taking effect in the block after the broadcast
	}
	return chaincli.TxResult{TxHash: []byte("update")}, nil
}
