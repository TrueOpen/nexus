package chaincli

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"connectrpc.com/connect"

	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	tmtypes "cosmossdk.io/api/tendermint/types"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
)

// The endpoint now comes directly from the on-chain ServiceDescriptorV1.endpoints; no
// descriptor document is fetched: the NEXUS_GRPC entry is the peer Builder's public address.
func TestResolveBuilderEndpointReadsNexusGRPCFromChain(t *testing.T) {
	hub := &descriptorHubQuery{
		builders: map[string]*hubv1.BuilderState{
			"builder-1": {BuilderAddress: "builder-1", CurrentDescriptorVersion: 3},
		},
		descriptors: map[string]*hubv1.ServiceDescriptorState{
			"builder-1": testServiceDescriptorState("builder-1", 3),
		},
	}
	c := testDescriptorClient(hub)

	endpoint, version, err := c.resolveBuilderEndpoint(context.Background(), "builder-1")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://rpc.builder.example" {
		t.Fatalf("endpoint = %q, want the on-chain NEXUS_GRPC uri", endpoint)
	}
	if version != 3 {
		t.Fatalf("version = %d, want the on-chain current version 3", version)
	}
}

// When only non-NEXUS_GRPC endpoints are published it must fail closed; an
// OBJECT_GATEWAY / HEALTH URI must not stand in for the gRPC address.
func TestResolveBuilderEndpointFailsClosedWithoutNexusGRPCKind(t *testing.T) {
	state := testServiceDescriptorState("builder-1", 3)
	state.Endpoints = []*hubv1.ServiceEndpointV1{{
		EndpointKind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
		Uri:          "https://rpc.builder.example/healthz", ProtocolVersion: "v1",
	}}
	hub := &descriptorHubQuery{
		builders: map[string]*hubv1.BuilderState{
			"builder-1": {BuilderAddress: "builder-1", CurrentDescriptorVersion: 3},
		},
		descriptors: map[string]*hubv1.ServiceDescriptorState{"builder-1": state},
	}
	c := testDescriptorClient(hub)

	if endpoint, _, err := c.resolveBuilderEndpoint(context.Background(), "builder-1"); err == nil {
		t.Fatalf("endpoint = %q, want a fail-closed error when no NEXUS_GRPC endpoint is published", endpoint)
	}
}

// When the descriptor row itself is invalid (here an empty endpoints list) it also fails closed.
func TestResolveBuilderEndpointRejectsInvalidDescriptorRow(t *testing.T) {
	state := testServiceDescriptorState("builder-1", 3)
	state.Endpoints = nil
	state.EndpointCount = 0
	hub := &descriptorHubQuery{
		builders: map[string]*hubv1.BuilderState{
			"builder-1": {BuilderAddress: "builder-1", CurrentDescriptorVersion: 3},
		},
		descriptors: map[string]*hubv1.ServiceDescriptorState{"builder-1": state},
	}
	c := testDescriptorClient(hub)

	if _, _, err := c.resolveBuilderEndpoint(context.Background(), "builder-1"); err == nil {
		t.Fatal("an empty endpoints list must be rejected")
	}
}

// BuilderSet member endpoints are resolved from on-chain descriptors: BuilderSetViewV1's
// active_builders carries only Address, so the endpoint must be looked up per member via
// QueryServiceDescriptor.
func TestQueryBuilderSetResolvesMemberEndpoints(t *testing.T) {
	hub := &descriptorHubQuery{
		builderSet: &hubv1.QueryBuilderSetResponse{Set: &hubv1.BuilderSetViewV1{
			BuilderSetVersion: 7, BuilderSetId: "7", BuilderSetHash: bytes.Repeat([]byte{0x5a}, 32),
			ActiveBuilders:     []string{"builder-1", "builder-2"},
			ActiveBuilderCount: 2, EffectiveHeight: 99,
			BodyStatus: sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
		}},
		builders: map[string]*hubv1.BuilderState{
			"builder-1": {BuilderAddress: "builder-1", CurrentDescriptorVersion: 3},
			"builder-2": {BuilderAddress: "builder-2", CurrentDescriptorVersion: 3},
		},
		descriptors: map[string]*hubv1.ServiceDescriptorState{
			"builder-1": testServiceDescriptorState("builder-1", 3),
			"builder-2": testServiceDescriptorState("builder-2", 3),
		},
	}
	c := testDescriptorClient(hub)

	got, err := c.QueryBuilderSetAtHeight(context.Background(), 4242)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 2 {
		t.Fatalf("members = %+v", got.Members)
	}
	for i, want := range []string{"builder-1", "builder-2"} {
		if got.Members[i].Address != want || got.Members[i].Rank != i+1 ||
			got.Members[i].Endpoint != "https://rpc.builder.example" {
			t.Fatalf("member %d = %+v", i, got.Members[i])
		}
	}
}

// Endpoint resolution failure must not affect BuilderSet membership and rank; this degradation path must be kept.
func TestQueryBuilderSetPreservesMembershipWhenEndpointUnavailable(t *testing.T) {
	hub := &descriptorHubQuery{
		builderSet: &hubv1.QueryBuilderSetResponse{Set: &hubv1.BuilderSetViewV1{
			BuilderSetVersion: 7, BuilderSetId: "7", BuilderSetHash: bytes.Repeat([]byte{0x5a}, 32),
			ActiveBuilders:     []string{"builder-1", "builder-2"},
			ActiveBuilderCount: 2, EffectiveHeight: 99,
			BodyStatus: sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE,
		}},
		builders:    map[string]*hubv1.BuilderState{},
		descriptors: map[string]*hubv1.ServiceDescriptorState{},
	}
	c := testDescriptorClient(hub)

	got, err := c.QueryBuilderSetAtHeight(context.Background(), 4242)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 2 {
		t.Fatalf("members = %+v", got.Members)
	}
	for i, want := range []string{"builder-1", "builder-2"} {
		if got.Members[i].Address != want || got.Members[i].Rank != i+1 || got.Members[i].Endpoint != "" {
			t.Fatalf("member %d = %+v", i, got.Members[i])
		}
	}
}

// QueryBuilder maps by the wire v0.4.1 field names/enums: builder_address,
// current_service_address, ServiceKeyStatus short name, service_authorization_nonce,
// registered_height, current_descriptor_version. BuilderState no longer carries an
// admission status (BuilderStatus lives in the governance-side BuilderAdmissionState and
// is not published separately by the public Query).
func TestQueryBuilderMapsFrozenBuilderState(t *testing.T) {
	hub := &descriptorHubQuery{
		builders: map[string]*hubv1.BuilderState{
			"builder-1": {
				BuilderAddress: "builder-1", CurrentServiceAddress: "service-1",
				CurrentServiceKeyStatus:   hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
				ServiceAuthorizationNonce: 5,
				RegisteredHeight:          88, CurrentDescriptorVersion: 3,
			},
		},
	}
	c := testDescriptorClient(hub)

	got, err := c.QueryBuilder(context.Background(), "builder-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "builder-1" || got.CurrentServiceAddress != "service-1" || got.ServiceKeyStatus != "ACTIVE" ||
		got.ServiceAuthorizationNonce != 5 || got.RegisteredHeight != 88 || got.CurrentDescriptorVersion != 3 {
		t.Fatalf("builder = %+v", got)
	}
}

// participant_type is now the hub.v1.ParticipantType enum: an unrecognized name must
// error rather than silently being sent as UNSPECIFIED.
func TestQueryServiceDescriptorRejectsUnknownParticipantType(t *testing.T) {
	hub := &descriptorHubQuery{descriptors: map[string]*hubv1.ServiceDescriptorState{}}
	c := testDescriptorClient(hub)

	if _, err := c.QueryServiceDescriptor(context.Background(), "WORKER", "builder-1", 3); err == nil {
		t.Fatal("WORKER is not a ParticipantType value and must be rejected")
	}
	if _, err := c.QueryCurrentServiceKey(context.Background(), "WORKER", "builder-1"); err == nil {
		t.Fatal("WORKER is not a ParticipantType value and must be rejected")
	}
}

func TestQueryServiceDescriptorMapsFrozenState(t *testing.T) {
	state := testServiceDescriptorState("builder-1", 3)
	hub := &descriptorHubQuery{descriptors: map[string]*hubv1.ServiceDescriptorState{"builder-1": state}}
	c := testDescriptorClient(hub)

	got, err := c.QueryServiceDescriptor(context.Background(), "BUILDER", "builder-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.ParticipantType != "BUILDER" || got.OperatorAddress != "builder-1" || got.DescriptorVersion != 3 {
		t.Fatalf("descriptor = %+v", got)
	}
	if got.DescriptorHash != hex.EncodeToString(state.GetDescriptorHash()) || got.UpdatedHeight != 120 {
		t.Fatalf("descriptor hash/height = %+v", got)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].URI != "https://rpc.builder.example" ||
		got.Endpoints[0].Kind != hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC ||
		got.Endpoints[0].ProtocolVersion != "v1" || got.Endpoints[0].TLSPubKeyHash != "" {
		t.Fatalf("endpoints = %+v", got.Endpoints)
	}
	// The version in the request is only used for the consistency assertion; it is no longer a query key.
	if _, err := c.QueryServiceDescriptor(context.Background(), "BUILDER", "builder-1", 4); err == nil {
		t.Fatal("a version mismatch must not be reported as a hit")
	}
}

func testServiceDescriptorState(address string, version uint64) *hubv1.ServiceDescriptorState {
	return &hubv1.ServiceDescriptorState{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
		OperatorAddress: address, DescriptorVersion: version, EndpointCount: 1,
		Endpoints: []*hubv1.ServiceEndpointV1{{
			EndpointKind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
			Uri:          "https://rpc.builder.example", ProtocolVersion: "v1",
		}},
		DescriptorHash: mustHash32("44"), UpdatedHeight: 120,
	}
}

func testDescriptorClient(hub *descriptorHubQuery) *client {
	return &client{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), hubQuery: hub,
		latestBlock: &recordLatestBlock{response: latestBlockResponse(105)},
	}
}

type descriptorHubQuery struct {
	hubv1connect.QueryClient
	builderSet      *hubv1.QueryBuilderSetResponse
	builders        map[string]*hubv1.BuilderState
	descriptors     map[string]*hubv1.ServiceDescriptorState
	builderCalls    map[string]int
	descriptorCalls map[string]int
}

func (q *descriptorHubQuery) BuilderSet(_ context.Context, _ *connect.Request[hubv1.QueryBuilderSetRequest]) (*connect.Response[hubv1.QueryBuilderSetResponse], error) {
	return connect.NewResponse(q.builderSet), nil
}

func (q *descriptorHubQuery) Builder(_ context.Context, req *connect.Request[hubv1.QueryBuilderRequest]) (*connect.Response[hubv1.QueryBuilderResponse], error) {
	if q.builderCalls == nil {
		q.builderCalls = make(map[string]int)
	}
	address := req.Msg.GetBuilderAddress()
	q.builderCalls[address]++
	return connect.NewResponse(&hubv1.QueryBuilderResponse{Builder: q.builders[address]}), nil
}

func (q *descriptorHubQuery) ServiceDescriptor(_ context.Context, req *connect.Request[hubv1.QueryServiceDescriptorRequest]) (*connect.Response[hubv1.QueryServiceDescriptorResponse], error) {
	if q.descriptorCalls == nil {
		q.descriptorCalls = make(map[string]int)
	}
	address := req.Msg.GetOperatorAddress()
	q.descriptorCalls[address]++
	return connect.NewResponse(&hubv1.QueryServiceDescriptorResponse{Descriptor_: q.descriptors[address]}), nil
}

func latestBlockResponse(height uint64) *cmtv1beta1.GetLatestBlockResponse {
	return &cmtv1beta1.GetLatestBlockResponse{Block: &tmtypes.Block{Header: &tmtypes.Header{Height: int64(height)}}}
}
