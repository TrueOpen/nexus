package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	authv1beta1 "cosmossdk.io/api/cosmos/auth/v1beta1"
	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	tmtypes "cosmossdk.io/api/tendermint/types"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

func TestStartCommandStartsAndStopsWithCommandContext(t *testing.T) {
	t.Setenv("NEXUS_DATA_DIR", t.TempDir())
	t.Setenv("NEXUS_INGRESS_ADDR", "localhost:0")
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_KEYSTORE_FILE", "")
	t.Setenv("NEXUS_KEYSTORE_PASSWORD_FILE", "")
	t.Setenv("NEXUS_KEYSTORE_PASSWORD", "")
	t.Setenv("NEXUS_PRIVATE_KEY", "")
	t.Setenv("NEXUS_PRIVATE_KEY_HEX", "")
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newRootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"start"})

	done := make(chan error, 1)
	go func() {
		done <- cmd.Execute()
	}()

	select {
	case err := <-done:
		t.Fatalf("start returned before cancellation: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("start did not stop after command context cancellation")
	}
}

// `nexus start` only checks and never submits (ADR-0015): when the Builder is not registered it refuses to start,
// broadcasts nothing and points at `nexus builder register`.
func TestStartCommandRefusesUnregisteredBuilderWithoutBroadcasting(t *testing.T) {
	fake := &fakeStartNode{chainID: "trueopen-localnet"}
	grpcAddr, stopNode := startFakeStartNode(t, fake)
	defer stopNode()

	t.Setenv("NEXUS_DATA_DIR", t.TempDir())
	t.Setenv("NEXUS_INGRESS_ADDR", "localhost:0")
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_CHAIN_GRPC", grpcAddr)
	t.Setenv("NEXUS_CHAIN_ID", "trueopen-localnet")
	t.Setenv("NEXUS_PRIVATE_KEY_HEX", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	t.Setenv("NEXUS_PUBLIC_ENDPOINT", "https://builder.example:8080")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newRootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"start"})

	done := make(chan error, 1)
	go func() {
		done <- cmd.Execute()
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "nexus builder register") {
			t.Fatalf("start on an unregistered Builder = %v, want a refusal naming `nexus builder register`", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("start did not refuse an unregistered Builder")
	}
	if fake.broadcasts.Load() != 0 {
		t.Fatalf("broadcasts = %d, want 0: start must not register on the operator's behalf", fake.broadcasts.Load())
	}
}

// In Hub mode Builder registration goes to the Hub only and never falls back to the Task Chain. Here the Hub accepts the
// registration transaction and the test asserts it landed on the Hub with nothing at all on the Task Chain (in Phase 0
// BuilderBond is fixed at zero, so there is no staking transaction).
//
// Flipping the assertion from "startup must fail" to "startup must succeed" is the core behavior change of this work item: the
// fake Hub's BuilderState carries neither active_term nor an admission status (wire v0.4.1), so the old code classified the on-chain
// Builder to have "no active term" and kept the coordinator from starting. Now builder_set_version comes from the height
// selector query, and the very same fake data must be able to bring the coordinator up.
func TestStartCommandRoutesBuilderRegistrationToHubOnly(t *testing.T) {
	taskNode := &fakeStartNode{accept: true, chainID: "trueopen-task-localnet"}
	taskGRPC, stopTask := startFakeStartNode(t, taskNode)
	defer stopTask()
	hubNode := &fakeStartNode{accept: true, chainID: "trueopen-hub-localnet"}
	hubGRPC, stopHub := startFakeStartNode(t, hubNode)
	defer stopHub()

	t.Setenv("NEXUS_DATA_DIR", t.TempDir())
	t.Setenv("NEXUS_INGRESS_ADDR", "localhost:0")
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_CHAIN_GRPC", taskGRPC)
	t.Setenv("NEXUS_CHAIN_ID", "trueopen-task-localnet")
	t.Setenv("NEXUS_HUB_ENABLED", "true")
	t.Setenv("NEXUS_HUB_GRPC", hubGRPC)
	t.Setenv("NEXUS_HUB_CHAIN_ID", "trueopen-hub-localnet")
	t.Setenv("NEXUS_PRIVATE_KEY_HEX", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	t.Setenv("NEXUS_PUBLIC_ENDPOINT", "https://builder.example:8080")

	// Registration is an explicit operator action: `builder register` first (one Hub transaction), then start.
	if _, err := executeBuilderCommand("builder", "register"); err != nil {
		t.Fatalf("builder register: %v", err)
	}
	if got := hubNode.broadcastTypeURLs(); len(got) != 1 {
		t.Fatalf("Hub broadcasts after register = %v, want register only", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newRootCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"start"})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	// start only checks and no longer broadcasts; wait until the coordinator has really queried the BuilderSet. start is a
	// resident process, so this does not wait for Execute to return but for it to reach the "all modules started" state;
	// builderSetQueries is the evidence that the coordinator has got as far as the seed step.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hubNode.builderSetQueries.Load() > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("start exited before the Hub finished Builder registration and BuilderSet seeding: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Seeding succeeded -> the process must still be alive. Give the remaining modules a moment to finish starting before
	// asserting, otherwise the cancel here interrupts modules that are still coming up and misreads "started" as "failed to start".
	select {
	case err := <-done:
		t.Fatalf("start exited while the Hub Builder was ACTIVE and in the BuilderSet: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("start did not stop after command context cancellation")
	}
	if got := taskNode.broadcasts.Load(); got != 0 {
		t.Fatalf("Task Chain received %d Builder broadcasts, want 0 (no fallback)", got)
	}
	want := []string{chaincli.TypeURLMsgRegisterBuilder}
	got := hubNode.broadcastTypeURLs()
	if len(got) != len(want) {
		t.Fatalf("Hub broadcasts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Hub broadcasts = %v, want %v", got, want)
		}
	}
}

type fakeStartNode struct {
	hubv1connect.UnimplementedQueryHandler
	broadcasts        atomic.Int32
	builderSetQueries atomic.Int32
	failAt            atomic.Int32
	registered        atomic.Bool
	accept            bool
	chainID           string
	mu                sync.Mutex
	typeURLs          []string
	builder           string
	// descriptor is the descriptor delivered by MsgRegisterBuilder / MsgUpdateServiceDescriptor;
	// `nexus start` only checks and never submits, so the query must read back what registration wrote.
	descriptor        *hubv1.ServiceDescriptorV1
	descriptorVersion uint64
}

func (n *fakeStartNode) GetLatestBlock(context.Context, *connect.Request[cmtv1beta1.GetLatestBlockRequest]) (*connect.Response[cmtv1beta1.GetLatestBlockResponse], error) {
	chainID := n.chainID
	if chainID == "" {
		chainID = "trueopen-localnet"
	}
	return connect.NewResponse(&cmtv1beta1.GetLatestBlockResponse{
		Block: &tmtypes.Block{Header: &tmtypes.Header{ChainId: chainID, Height: 1000}},
	}), nil
}

// Params lets app.New read phase0.evm_chain_id: the EIP-712 chainId comes from Hub params only,
// and nexus does not start if it cannot be read.
func (n *fakeStartNode) Params(context.Context, *connect.Request[hubv1.QueryHubParamsRequest]) (*connect.Response[hubv1.QueryHubParamsResponse], error) {
	return connect.NewResponse(&hubv1.QueryHubParamsResponse{
		Params: &hubv1.HubParamsV2{Phase0: &hubv1.Phase0ParamsV1{EvmChainId: 31337}},
	}), nil
}

func (n *fakeStartNode) Builder(_ context.Context, req *connect.Request[hubv1.QueryBuilderRequest]) (*connect.Response[hubv1.QueryBuilderResponse], error) {
	if !n.registered.Load() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("builder not found"))
	}
	n.mu.Lock()
	n.builder = req.Msg.GetBuilderAddress()
	n.mu.Unlock()
	return connect.NewResponse(&hubv1.QueryBuilderResponse{Builder: &hubv1.BuilderState{
		BuilderAddress:           req.Msg.GetBuilderAddress(),
		CurrentServiceKeyStatus:  hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
		CurrentDescriptorVersion: 1,
	}}), nil
}

func (n *fakeStartNode) BuilderSet(_ context.Context, req *connect.Request[hubv1.QueryBuilderSetRequest]) (*connect.Response[hubv1.QueryBuilderSetResponse], error) {
	n.builderSetQueries.Add(1)
	// Accept the height selector only: builder_set_version is a query result and Nexus holds no term it could send
	// (the wire v0.4.1 selector is height | builder_set_id only). Sending any other selector is a regression.
	if req.Msg.GetHeight() == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one builder set selector is required"))
	}
	n.mu.Lock()
	builder := n.builder
	n.mu.Unlock()
	if builder == "" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("builder not found"))
	}
	return connect.NewResponse(&hubv1.QueryBuilderSetResponse{Set: &hubv1.BuilderSetViewV1{
		BuilderSetVersion: 7, BuilderSetId: "7", BuilderSetHash: bytes.Repeat([]byte{0x5a}, 32),
		ActiveBuilders: []string{builder, "trueopen1builder2", "trueopen1builder3"}, ActiveBuilderCount: 3,
		EffectiveHeight: 899,
		BodyStatus:      sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
	}}), nil
}

func (n *fakeStartNode) CurrentServiceKey(context.Context, *connect.Request[hubv1.QueryCurrentServiceKeyRequest]) (*connect.Response[hubv1.QueryCurrentServiceKeyResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("service key not found"))
}

func (n *fakeStartNode) ServiceDescriptor(_ context.Context, req *connect.Request[hubv1.QueryServiceDescriptorRequest]) (*connect.Response[hubv1.QueryServiceDescriptorResponse], error) {
	n.mu.Lock()
	descriptor, version := n.descriptor, n.descriptorVersion
	n.mu.Unlock()
	if !n.registered.Load() || descriptor == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("service descriptor not found"))
	}
	return connect.NewResponse(&hubv1.QueryServiceDescriptorResponse{Descriptor_: &hubv1.ServiceDescriptorState{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, OperatorAddress: req.Msg.GetOperatorAddress(),
		DescriptorVersion: version, EndpointCount: uint32(len(descriptor.GetEndpoints())),
		Endpoints: descriptor.GetEndpoints(), UpdatedHeight: 1000,
	}}), nil
}

func (n *fakeStartNode) Account(context.Context, *connect.Request[authv1beta1.QueryAccountRequest]) (*connect.Response[authv1beta1.QueryAccountResponse], error) {
	acc, err := anypb.New(&authv1beta1.BaseAccount{AccountNumber: 7, Sequence: 42})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&authv1beta1.QueryAccountResponse{Account: acc}), nil
}

func (n *fakeStartNode) GetTx(context.Context, *connect.Request[txv1beta1.GetTxRequest]) (*connect.Response[txv1beta1.GetTxResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("tx not found"))
}

func (n *fakeStartNode) BroadcastTx(_ context.Context, req *connect.Request[txv1beta1.BroadcastTxRequest]) (*connect.Response[txv1beta1.BroadcastTxResponse], error) {
	count := n.broadcasts.Add(1)
	typeURL := ""
	var raw txv1beta1.TxRaw
	var body txv1beta1.TxBody
	if err := proto.Unmarshal(req.Msg.GetTxBytes(), &raw); err == nil {
		if proto.Unmarshal(raw.GetBodyBytes(), &body) == nil && len(body.GetMessages()) > 0 {
			typeURL = body.GetMessages()[0].GetTypeUrl()
			n.mu.Lock()
			n.typeURLs = append(n.typeURLs, typeURL)
			n.mu.Unlock()
		}
	}
	if failAt := n.failAt.Load(); failAt > 0 && count == failAt {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("broadcast response lost"))
	}
	if n.accept {
		switch typeURL {
		case chaincli.TypeURLMsgRegisterBuilder:
			var msg hubv1.MsgRegisterBuilder
			if proto.Unmarshal(body.GetMessages()[0].GetValue(), &msg) == nil {
				n.mu.Lock()
				n.descriptor, n.descriptorVersion = msg.GetDescriptor_(), 1
				n.mu.Unlock()
			}
			n.registered.Store(true)
		case chaincli.TypeURLMsgUpdateServiceDescriptor:
			var msg hubv1.MsgUpdateServiceDescriptor
			if proto.Unmarshal(body.GetMessages()[0].GetValue(), &msg) == nil {
				n.mu.Lock()
				n.descriptor, n.descriptorVersion = msg.GetDescriptor_(), n.descriptorVersion+1
				n.mu.Unlock()
			}
		}
		return connect.NewResponse(&txv1beta1.BroadcastTxResponse{TxResponse: &abciv1beta1.TxResponse{}}), nil
	}
	return connect.NewResponse(&txv1beta1.BroadcastTxResponse{
		TxResponse: &abciv1beta1.TxResponse{
			Code:   2,
			RawLog: "unable to resolve type URL /unsupported.MsgRegisterBuilder: tx parse error: tx parse error",
		},
	}), nil
}

func (n *fakeStartNode) broadcastTypeURLs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.typeURLs...)
}

func startFakeStartNode(t *testing.T, node *fakeStartNode) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/cosmos.auth.v1beta1.Query/Account", connect.NewUnaryHandler(
		"/cosmos.auth.v1beta1.Query/Account", node.Account,
	))
	mux.Handle("/cosmos.tx.v1beta1.Service/GetTx", connect.NewUnaryHandler(
		"/cosmos.tx.v1beta1.Service/GetTx", node.GetTx,
	))
	mux.Handle("/cosmos.tx.v1beta1.Service/BroadcastTx", connect.NewUnaryHandler(
		"/cosmos.tx.v1beta1.Service/BroadcastTx", node.BroadcastTx,
	))
	hubPath, hubHandler := hubv1connect.NewQueryHandler(node)
	mux.Handle(hubPath, hubHandler)
	mux.Handle("/cosmos.base.tendermint.v1beta1.Service/GetLatestBlock", connect.NewUnaryHandler(
		"/cosmos.base.tendermint.v1beta1.Service/GetLatestBlock", node.GetLatestBlock,
	))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake node: %v", err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
