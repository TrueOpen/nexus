// Real node-transport implementation of Client. Three transports:
//
//   - QueryTask     : task.v1.Query/Task over connectrpc gRPC (h2c).
//   - BroadcastTx   : cosmos.tx.v1beta1.Service/BroadcastTx over the same
//     gRPC endpoint (cfg.Chain.GRPCAddr).
//   - Events        : task.v1.TaskEventService streams plus height polling.
//
// BroadcastTx sends already-signed bytes through the node gRPC tx service.
// Offline tolerance: New() never dials; Start() launches the event loop in a
// goroutine that retries with backoff. A down node must NOT block or fail Start.
package chaincli

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	authv1beta1 "cosmossdk.io/api/cosmos/auth/v1beta1"
	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
)

type client struct {
	log *slog.Logger
	cfg config.ChainConfig

	// gRPC query/broadcast path (connectrpc over h2c).
	taskQuery   taskv1connect.QueryClient
	hubQuery    hubv1connect.QueryClient
	auth        authQueryClient // cosmos.auth.v1beta1.Query (account_number/sequence)
	tx          txServiceClient // cosmos.tx.v1beta1.Service (BroadcastTx)
	latestBlock latestBlockClient

	taskEvents  taskv1connect.TaskEventServiceClient
	hubEvents   hubv1connect.HubEventServiceClient
	cursorStore eventCursorStore

	events chan ChainEvent

	sessionMu            sync.Mutex
	sessions             map[string]*sessionSubscription
	started              bool
	heightEventsInterval time.Duration
	heightCancel         context.CancelFunc
	protocolEvents       bool
	protocolCancel       context.CancelFunc

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New returns the REAL chain client. It does NOT dial the node — construction
// always succeeds so the service can boot offline. The node is contacted lazily
// (per QueryTask/BroadcastTx call) and by the background event loop started in
// Start(), which retries with capped backoff when the node is unreachable.
func New(log *slog.Logger, cfg config.ChainConfig, options ...Option) Client {
	grpcBase := grpcBaseURL(cfg.GRPCAddr)
	// http:// uses h2c (plaintext HTTP/2 prior-knowledge, node's default plaintext gRPC port);
	// https:// uses TLS verified against the system CA roots (Deployment Security Baseline:
	// write https once the node port has TLS enabled).
	h2cTransport := newGRPCTransport(grpcBase)
	grpcHTTP := &http.Client{Transport: h2cTransport, Timeout: 15 * time.Second}

	tq := taskv1connect.NewQueryClient(grpcHTTP, grpcBase, connect.WithGRPC())
	hq := hubv1connect.NewQueryClient(grpcHTTP, grpcBase, connect.WithGRPC())
	a := newCosmosAuthClient(grpcHTTP, grpcBase, connect.WithGRPC())
	tx := newCosmosTxClient(grpcHTTP, grpcBase, connect.WithGRPC())
	latestBlock := newCosmosLatestBlockClient(grpcHTTP, grpcBase, connect.WithGRPC())

	// Event streams are long-lived connections: no client Timeout; the lifetime is controlled by ctx.
	streamHTTP := &http.Client{Transport: h2cTransport}
	taskEvents := taskv1connect.NewTaskEventServiceClient(streamHTTP, grpcBase, connect.WithGRPC())
	// wire v0.4.1: non-Task protocol events (BuilderSet rotation etc.) go through hub.v1.HubEventService.
	hubEvents := hubv1connect.NewHubEventServiceClient(streamHTTP, grpcBase, connect.WithGRPC())

	c := &client{
		log:         log,
		cfg:         cfg,
		taskQuery:   tq,
		hubQuery:    hq,
		auth:        a,
		tx:          tx,
		latestBlock: latestBlock,
		taskEvents:  taskEvents,
		hubEvents:   hubEvents,
		events:      make(chan ChainEvent, 256),
		sessions:    make(map[string]*sessionSubscription),
		stopCh:      make(chan struct{}),
	}
	for _, option := range options {
		if option != nil {
			option(c)
		}
	}
	return c
}

func (c *client) Start(_ context.Context) error {
	c.log.Info("chaincli started (real transport)",
		"grpc", configuredLabel(c.cfg.GRPCAddr),
		"chain_id", configuredLabel(c.cfg.ChainID))
	c.sessionMu.Lock()
	if !c.started {
		c.started = true
		for sessionID, session := range c.sessions {
			c.startTaskSessionLocked(sessionID, session)
		}
		c.startHeightEventsLocked()
		c.startProtocolEventsLocked()
	}
	c.sessionMu.Unlock()
	return nil
}

func (c *client) Stop(_ context.Context) error {
	stopped := false
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.sessionMu.Lock()
		c.started = false
		for _, session := range c.sessions {
			if session.cancel != nil {
				session.cancel()
				session.cancel = nil
			}
		}
		if c.heightCancel != nil {
			c.heightCancel()
			c.heightCancel = nil
		}
		if c.protocolCancel != nil {
			c.protocolCancel()
			c.protocolCancel = nil
		}
		c.sessionMu.Unlock()
		stopped = true
	})
	if stopped {
		c.wg.Wait()
		close(c.events)
	}
	return nil
}

func (c *client) Events() <-chan ChainEvent { return c.events }

// QueryBuilderSetAtHeight fetches the authoritative BuilderSet at the given height
// via the height selector (Interface Contract §16.3: exactly one oneof selector).
//
// Why only the height branch is exposed: term is the *result* of the query, not an
// input. The current Node BuilderState no longer publishes active_term, so the caller
// has no trusted term to fill in; the only correct way to ask "which term is it now"
// is "which one is at this height". The term and builder_set_id branches belong to
// historical replay and are not exposed on the startup/admission path.
func (c *client) QueryBuilderSetAtHeight(ctx context.Context, height uint64) (BuilderSet, error) {
	if height == 0 {
		return BuilderSet{}, fmt.Errorf("query builder set: height must be greater than zero")
	}
	resp, err := c.hubQuery.BuilderSet(ctx, connect.NewRequest(&hubv1.QueryBuilderSetRequest{
		Selector: &hubv1.QueryBuilderSetRequest_Height{Height: height},
	}))
	if err != nil {
		return BuilderSet{}, applicationQueryError("builder set", err)
	}
	set := resp.Msg.GetSet()
	if set == nil || set.GetBuilderSetVersion() == 0 {
		return BuilderSet{}, ErrNotFound
	}
	// body_status must be checked first: §16.5 requires that when PRUNED, active_builders
	// is empty but active_builder_count is retained, and "an empty array must not be
	// interpreted as an empty BuilderSet". Parsing members before checking the status
	// would already have read a pruned body as an empty set.
	switch set.GetBodyStatus() {
	case sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE:
	case sharedv1.StoredBodyStatus_STORED_BODY_STATUS_PRUNED:
		return BuilderSet{}, fmt.Errorf(
			"query builder set: version %d member body is PRUNED at height %d (active_builder_count %d retained); the authoritative membership is unavailable",
			set.GetBuilderSetVersion(), height, set.GetActiveBuilderCount())
	default:
		return BuilderSet{}, fmt.Errorf("query builder set: version %d has invalid body_status %s",
			set.GetBuilderSetVersion(), set.GetBodyStatus())
	}
	// The commitment is a raw Hash32: a wrong length is not a commitment, do not hex it
	// and treat it as real. The set hash is not recomputed here: the view does not
	// publish builder_set_members_hash, so any local recomputation would just be a
	// different formula and the comparison would fail deterministically. The
	// shape-checked on-chain hash is authoritative.
	rawSetHash := set.GetBuilderSetHash()
	if len(rawSetHash) != 32 {
		return BuilderSet{}, fmt.Errorf("query builder set: version %d builder_set_hash is %d bytes, want 32",
			set.GetBuilderSetVersion(), len(rawSetHash))
	}
	addresses, err := parseCanonicalMemberList("builder set", set.GetActiveBuilders())
	if err != nil {
		return BuilderSet{}, err
	}
	if len(addresses) == 0 {
		return BuilderSet{}, fmt.Errorf("query builder set: version %d has no members", set.GetBuilderSetVersion())
	}
	if uint64(len(addresses)) != uint64(set.GetActiveBuilderCount()) {
		return BuilderSet{}, fmt.Errorf("query builder set: version %d returned %d members but active_builder_count is %d",
			set.GetBuilderSetVersion(), len(addresses), set.GetActiveBuilderCount())
	}
	members := make([]types.BuilderRef, len(addresses))
	for i, address := range addresses {
		members[i] = types.BuilderRef{Address: address, Rank: i + 1}
	}
	// The endpoint is not on BuilderSetViewV1 (field 6 carries only Address), so the
	// on-chain descriptor must be queried per member (§9.6b). A single member's resolve
	// failure only degrades its endpoint; membership and rank stay intact. Rank is a
	// consensus fact and must not be reordered because one peer's descriptor is missing.
	for i := range members {
		endpoint, version, resolveErr := c.resolveBuilderEndpoint(ctx, members[i].Address)
		if resolveErr != nil {
			if c.log != nil {
				c.log.Warn("chaincli: builder endpoint resolution failed",
					"builder", members[i].Address, "descriptor_version", version,
					"err", redactSensitiveText(resolveErr.Error()))
			}
			continue
		}
		members[i].Endpoint = endpoint
	}
	updatedHeight, err := uint64ToInt64("builder set effective height", set.GetEffectiveHeight())
	if err != nil {
		return BuilderSet{}, err
	}
	return BuilderSet{
		Epoch: set.GetBuilderSetVersion(), BuilderSetID: set.GetBuilderSetId(),
		Members: members, SetHash: hex.EncodeToString(rawSetHash),
		ActiveBuilderCount: set.GetActiveBuilderCount(),
		BodyStatus:         enumShortName("STORED_BODY_STATUS_", set.GetBodyStatus()),
		UpdatedHeight:      updatedHeight,
	}, nil
}

// QueryTaskBuilders reads the task's frozen Task Builder selection (wire v0.1.2
// task.v1.Query/TaskBuilders). The old hub.v1.Query/StageBuilderSelection does
// not exist on chain; settlement submission rights rotate in
// selected_task_builders order (§10.10a), and this is the only read path.
func (c *client) QueryTaskBuilders(ctx context.Context, key TaskKey) (TaskBuilderSelectionState, error) {
	if err := key.Validate(); err != nil {
		return TaskBuilderSelectionState{}, err
	}
	taskID, err := nodecontract.Hash32Bytes("task_id", key.TaskID)
	if err != nil {
		return TaskBuilderSelectionState{}, fmt.Errorf("query task builders task=%q: %w", key.TaskID, err)
	}
	resp, err := c.taskQuery.TaskBuilders(ctx, connect.NewRequest(&taskv1.QueryTaskBuildersRequest{TaskId: taskID}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return TaskBuilderSelectionState{}, ErrNotFound
		}
		return TaskBuilderSelectionState{}, applicationQueryError("task builders", err)
	}
	selection := resp.Msg.GetSelection()
	if selection == nil || len(selection.GetTaskId()) == 0 {
		return TaskBuilderSelectionState{}, ErrNotFound
	}
	if hex.EncodeToString(selection.GetTaskId()) != key.TaskID {
		return TaskBuilderSelectionState{}, fmt.Errorf("query task builders: response task_id does not match request")
	}
	builders := make([]string, 0, len(selection.GetSelectedTaskBuilders()))
	seen := make(map[string]struct{}, len(selection.GetSelectedTaskBuilders()))
	for _, builder := range selection.GetSelectedTaskBuilders() {
		if builder == "" || strings.TrimSpace(builder) != builder {
			return TaskBuilderSelectionState{}, fmt.Errorf("query task builders: selected_task_builders contains an invalid address")
		}
		if _, dup := seen[builder]; dup {
			return TaskBuilderSelectionState{}, fmt.Errorf("query task builders: selected_task_builders contains duplicate %q", builder)
		}
		seen[builder] = struct{}{}
		builders = append(builders, builder)
	}
	return TaskBuilderSelectionState{
		TaskID:           key.TaskID,
		SelectedBuilders: builders,
		SelectedCount:    selection.GetSelectedTaskBuilderCount(),
		CreatedHeight:    selection.GetCreatedHeight(),
		BodyStatus:       enumShortName("STORED_BODY_STATUS_", selection.GetBodyStatus()),
	}, nil
}

// QuerySettlementBuilderGraceBlocks reads the Hub parameter builder.settlement_builder_grace_blocks:
// after the reveal deadline, rank i has exclusive rights in (reveal+(i-1)·g, reveal+i·g];
// only after all windows pass may anyone submit (§10.10a).
func (c *client) QuerySettlementBuilderGraceBlocks(ctx context.Context) (uint64, error) {
	resp, err := c.hubQuery.Params(ctx, connect.NewRequest(&hubv1.QueryHubParamsRequest{}))
	if err != nil {
		return 0, applicationQueryError("hub params", err)
	}
	grace := resp.Msg.GetParams().GetBuilder().GetSettlementBuilderGraceBlocks()
	if grace == 0 {
		return 0, fmt.Errorf("query hub params: settlement_builder_grace_blocks is zero")
	}
	return grace, nil
}

// QueryEVMChainID reads the Hub parameter phase0.evm_chain_id. 0 is treated as
// unconfigured: chainId 0 in the EIP-712 domain would make every user signature fail
// verification, so it is better to error here.
func (c *client) QueryEVMChainID(ctx context.Context) (uint64, error) {
	resp, err := c.hubQuery.Params(ctx, connect.NewRequest(&hubv1.QueryHubParamsRequest{}))
	if err != nil {
		return 0, applicationQueryError("hub params", err)
	}
	evmChainID := resp.Msg.GetParams().GetPhase0().GetEvmChainId()
	if evmChainID == 0 {
		return 0, fmt.Errorf("query hub params: phase0.evm_chain_id is zero")
	}
	return evmChainID, nil
}

func (c *client) QueryProfile(ctx context.Context, modelID string, profileVersion uint32) (ProfileState, error) {
	if strings.TrimSpace(modelID) == "" || strings.TrimSpace(modelID) != modelID || profileVersion == 0 {
		return ProfileState{}, fmt.Errorf("query profile: model_id and profile_version are required and canonical")
	}
	resp, err := c.hubQuery.Profile(ctx, connect.NewRequest(&hubv1.QueryProfileRequest{
		ModelId: modelID, ProfileVersion: profileVersion,
	}))
	if err != nil {
		return ProfileState{}, applicationQueryError("profile", err)
	}
	profile := resp.Msg.GetProfile()
	if profile == nil || profile.GetModelId() == "" {
		return ProfileState{}, ErrNotFound
	}
	if profile.GetModelId() != modelID || profile.GetProfileVersion() != profileVersion {
		return ProfileState{}, fmt.Errorf("query profile: response key does not match request")
	}
	return ProfileState{
		ModelID: profile.GetModelId(), ProfileVersion: profile.GetProfileVersion(), Status: profile.GetStatus().String(),
		ChallengeOpenWindowBlocks: profile.GetChallengeOpenWindowBlocks(),
		EvidenceSchemaHash:        hex.EncodeToString(profile.GetVerificationProfile().GetEvidenceSchemaHash()),
	}, nil
}

func (c *client) QueryBuilder(ctx context.Context, address string) (BuilderState, error) {
	resp, err := c.hubQuery.Builder(ctx, connect.NewRequest(&hubv1.QueryBuilderRequest{BuilderAddress: address}))
	if err != nil {
		return BuilderState{}, applicationQueryError("builder", err)
	}
	b := resp.Msg.GetBuilder()
	if b == nil || b.GetBuilderAddress() == "" {
		return BuilderState{}, ErrNotFound
	}
	return BuilderState{
		Address: b.GetBuilderAddress(), CurrentServiceAddress: b.GetCurrentServiceAddress(),
		ServiceKeyStatus:          enumShortName("SERVICE_KEY_STATUS_", b.GetCurrentServiceKeyStatus()),
		ServiceAuthorizationNonce: b.GetServiceAuthorizationNonce(),
		RegisteredHeight:          b.GetRegisteredHeight(), CurrentDescriptorVersion: b.GetCurrentDescriptorVersion(),
	}, nil
}

func (c *client) QueryCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (ServiceKeyState, error) {
	domain, err := parseParticipantType(participantType)
	if err != nil {
		return ServiceKeyState{}, fmt.Errorf("query current service key: %w", err)
	}
	resp, err := c.hubQuery.CurrentServiceKey(ctx, connect.NewRequest(&hubv1.QueryCurrentServiceKeyRequest{
		ParticipantType: domain, OperatorAddress: operatorAddress,
	}))
	if err != nil {
		return ServiceKeyState{}, applicationQueryError("current service key", err)
	}
	b := resp.Msg.GetBinding()
	if b == nil || b.GetOperatorAddress() == "" {
		return ServiceKeyState{}, ErrNotFound
	}
	// The frozen contract replaced the binding with CurrentServiceKeyViewV1: service_pubkey
	// is bytes, authorization_nonce was renamed service_authorization_nonce, the status
	// became a oneof selected by participant_type, and updated_height was removed from the wire.
	state := ServiceKeyState{
		ParticipantType: enumShortName("PARTICIPANT_TYPE_", b.GetParticipantType()),
		OperatorAddress: b.GetOperatorAddress(), ServiceAddress: b.GetServiceAddress(),
		ServicePubKey:      hex.EncodeToString(b.GetServicePubkey()),
		AuthorizationNonce: b.GetServiceAuthorizationNonce(),
		Status:             currentServiceKeyStatus(b),
	}
	return state, nil
}

// currentServiceKeyStatus reads the status only from the oneof branch matching
// binding.participant_type.
//
// The contract (query_registry.proto:301) requires "Exactly one status matching
// participant_type is set". Since wire v0.4.1 both branches are ServiceKeyStatus, but the
// branch is still selected by participant_type: reading across domains would admit on the
// wrong domain's status. Returns an empty string when the branch is missing or
// mismatched, so the ACTIVE assertion in servicekey fails closed.
func currentServiceKeyStatus(b *hubv1.CurrentServiceKeyViewV1) string {
	switch b.GetParticipantType() {
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX:
		if status, ok := b.GetParticipantStatus().(*hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus); ok {
			return enumShortName("SERVICE_KEY_STATUS_", status.CortexServiceKeyStatus)
		}
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		if status, ok := b.GetParticipantStatus().(*hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus); ok {
			return enumShortName("SERVICE_KEY_STATUS_", status.BuilderServiceKeyStatus)
		}
	}
	return ""
}

// QueryCortexNode reads the Cortex stable identity row (hub.v1.Query/CortexNode).
// This row comes from the same table as the CORTEX branch of QueryCurrentServiceKey; the
// auth callback service only uses it to confirm "this operator is registered as a
// Cortex". A missing row (including an empty row with empty operator_address) is always
// ErrNotFound; zero values must not admit.
func (c *client) QueryCortexNode(ctx context.Context, operatorAddress string) (CortexNodeState, error) {
	resp, err := c.hubQuery.CortexNode(ctx, connect.NewRequest(&hubv1.QueryCortexNodeRequest{OperatorAddress: operatorAddress}))
	if err != nil {
		return CortexNodeState{}, applicationQueryError("cortex node", err)
	}
	node := resp.Msg.GetNode()
	if node == nil || node.GetOperatorAddress() == "" {
		return CortexNodeState{}, ErrNotFound
	}
	if node.GetOperatorAddress() != operatorAddress {
		return CortexNodeState{}, fmt.Errorf("query cortex node: response key does not match request")
	}
	return CortexNodeState{
		OperatorAddress:           node.GetOperatorAddress(),
		CurrentServiceAddress:     node.GetCurrentServiceAddress(),
		CurrentServicePubKey:      hex.EncodeToString(node.GetCurrentServicePubkey()),
		ServiceAuthorizationNonce: node.GetServiceAuthorizationNonce(),
		ServiceKeyStatus:          enumShortName("SERVICE_KEY_STATUS_", node.GetServiceKeyStatus()),
		RegisteredHeight:          node.GetRegisteredHeight(),
		UpdatedHeight:             node.GetUpdatedHeight(),
	}, nil
}

func (c *client) QueryServiceDescriptor(ctx context.Context, participantType, operatorAddress string, descriptorVersion uint64) (ServiceDescriptorState, error) {
	domain, err := parseParticipantType(participantType)
	if err != nil {
		return ServiceDescriptorState{}, fmt.Errorf("query service descriptor: %w", err)
	}
	// The frozen contract's QueryServiceDescriptorRequest has only (participant_type,
	// operator_address): descriptor_version is no longer a query key, so we can only
	// assert consistency against the returned current version.
	resp, err := c.hubQuery.ServiceDescriptor(ctx, connect.NewRequest(&hubv1.QueryServiceDescriptorRequest{
		ParticipantType: domain, OperatorAddress: operatorAddress,
	}))
	if err != nil {
		return ServiceDescriptorState{}, applicationQueryError("service descriptor", err)
	}
	d := resp.Msg.GetDescriptor_()
	if d == nil || d.GetOperatorAddress() == "" {
		return ServiceDescriptorState{}, ErrNotFound
	}
	if descriptorVersion != 0 && d.GetDescriptorVersion() != descriptorVersion {
		return ServiceDescriptorState{}, ErrNotFound
	}
	// descriptor_uri / descriptor_schema_version / effective_height /
	// expires_height were replaced by repeated ServiceEndpointV1 endpoints: the descriptor
	// content now lives entirely on chain and maps over directly.
	return ServiceDescriptorState{
		ParticipantType: enumShortName("PARTICIPANT_TYPE_", d.GetParticipantType()),
		OperatorAddress: d.GetOperatorAddress(), DescriptorVersion: d.GetDescriptorVersion(),
		Endpoints:      mapServiceEndpoints(d.GetEndpoints()),
		DescriptorHash: hex.EncodeToString(d.GetDescriptorHash()), UpdatedHeight: d.GetUpdatedHeight(),
	}, nil
}

// mapServiceEndpoints copies the wire endpoints into value types. An absent optional
// tls_pubkey_hash is left as an empty string. Empty and present-empty are distinct in
// the §1.2 canonical encoding, but "absent" on the wire is nil, and we do not fabricate
// a present value here.
func mapServiceEndpoints(wire []*hubv1.ServiceEndpointV1) []ServiceEndpoint {
	if len(wire) == 0 {
		return nil
	}
	endpoints := make([]ServiceEndpoint, 0, len(wire))
	for _, endpoint := range wire {
		if endpoint == nil {
			continue
		}
		endpoints = append(endpoints, ServiceEndpoint{
			Kind:            endpoint.GetEndpointKind(),
			URI:             endpoint.GetUri(),
			ProtocolVersion: endpoint.GetProtocolVersion(),
			TLSPubKeyHash:   hex.EncodeToString(endpoint.GetTlsPubkeyHash()),
		})
	}
	return endpoints
}

func (c *client) LatestHeight(ctx context.Context) (uint64, error) {
	if c.latestBlock == nil {
		return 0, fmt.Errorf("query latest height: latest-block gRPC client is not configured")
	}
	resp, err := c.latestBlock.GetLatestBlock(ctx, connect.NewRequest(&cmtv1beta1.GetLatestBlockRequest{}))
	if err != nil {
		return 0, fmt.Errorf("query latest height: %s", redactSensitiveText(err.Error()))
	}
	header := resp.Msg.GetBlock().GetHeader()
	if header == nil || header.GetHeight() <= 0 {
		return 0, fmt.Errorf("query latest height: GetLatestBlock returned an invalid header")
	}
	if configured := strings.TrimSpace(c.cfg.ChainID); configured != "" && header.GetChainId() != "" && header.GetChainId() != configured {
		return 0, fmt.Errorf("query latest height: chain id %q does not match configured %q", header.GetChainId(), configured)
	}
	return uint64(header.GetHeight()), nil
}

func applicationQueryError(kind string, err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return fmt.Errorf("query %s: %w", kind, ErrNotFound)
	}
	return fmt.Errorf("query %s: endpoint unavailable: %s", kind, redactSensitiveText(err.Error()))
}

// Simulate is deferred this round (tx assembly/signing is out of scope, so there
// is nothing to simulate yet). Returns ErrNotSupportedOnChain.
func (c *client) Simulate(_ context.Context, _ []byte) (SimResult, error) {
	return SimResult{}, fmt.Errorf("simulate tx: %w", ErrNotSupportedOnChain)
}

// AccountInfo queries cosmos.auth.v1beta1.Query/Account for the signer's
// account_number / sequence (used to assemble the SignDoc). The Any is decoded as BaseAccount.
func (c *client) AccountInfo(ctx context.Context, address string) (AccountInfo, error) {
	resp, err := c.auth.Account(ctx, connect.NewRequest(&authv1beta1.QueryAccountRequest{Address: address}))
	if err != nil {
		return AccountInfo{}, fmt.Errorf("query account %q: endpoint unavailable: %s", address, redactSensitiveText(err.Error()))
	}
	anyAcc := resp.Msg.GetAccount()
	if anyAcc == nil {
		return AccountInfo{}, fmt.Errorf("query account %q: empty response", address)
	}
	var base authv1beta1.BaseAccount
	if err := proto.Unmarshal(anyAcc.GetValue(), &base); err != nil {
		return AccountInfo{}, fmt.Errorf("query account %q: decode %s: %w", address, anyAcc.GetTypeUrl(), err)
	}
	return AccountInfo{AccountNumber: base.GetAccountNumber(), Sequence: base.GetSequence()}, nil
}

func (c *client) QueryTask(ctx context.Context, key TaskKey) (OnChainTask, error) {
	if err := key.Validate(); err != nil {
		return OnChainTask{}, err
	}
	// The frozen contract's QueryTaskRequest has only `1=task_id:Hash32`: session is no
	// longer a query key, so we can only assert consistency against the returned core.session_id.
	taskID, err := nodecontract.Hash32Bytes("task_id", key.TaskID)
	if err != nil {
		return OnChainTask{}, fmt.Errorf("query task session=%q task=%q: %w", key.SessionID, key.TaskID, err)
	}
	resp, err := c.taskQuery.Task(ctx, connect.NewRequest(&taskv1.QueryTaskRequest{TaskId: taskID}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return OnChainTask{}, fmt.Errorf("query task session=%q task=%q: %w", key.SessionID, key.TaskID, ErrNotFound)
		}
		return OnChainTask{}, fmt.Errorf("query task session=%q task=%q: endpoint unavailable: %s", key.SessionID, key.TaskID, redactSensitiveText(err.Error()))
	}
	if resp.Msg == nil {
		return OnChainTask{}, fmt.Errorf("query task session=%q task=%q: empty response", key.SessionID, key.TaskID)
	}
	return c.mapTask(key, resp.Msg)
}

// QuerySettlementBuildFacts has no corresponding RPC in the frozen contract: §16 no
// longer registers any settlement-build/preview interface, §10.10a explicitly forbids
// exposing SettlementFactsV1 as a submitted settlement, and QuerySettlement /
// QuerySettlementFinality may only be registered once the open settlement and
// finality blockers are resolved. This fails closed rather than assembling approximate facts
// from other Queries.
func (c *client) QuerySettlementBuildFacts(_ context.Context, key TaskKey) (SettlementBuildFacts, error) {
	if err := key.Validate(); err != nil {
		return SettlementBuildFacts{}, err
	}
	return SettlementBuildFacts{}, fmt.Errorf("query settlement build facts session=%q task=%q: %w",
		key.SessionID, key.TaskID, ErrNotSupportedOnChain)
}

func (c *client) QueryTimeoutBucket(ctx context.Context, bucketKey string, version, _ uint64) (TimeoutBucketState, error) {
	if strings.TrimSpace(bucketKey) == "" || strings.TrimSpace(bucketKey) != bucketKey {
		return TimeoutBucketState{}, fmt.Errorf("query timeout bucket: bucket_key is required and canonical")
	}
	// The frozen contract moved the timeout bucket query to hub.v1.Query; the request
	// has only (bucket_key, optional version) and height is no longer a query key. The
	// response became the generic ParameterBucketVersionViewV1 (BucketKind + entry table)
	// with no per-stage infer/verify/reveal/challenge timeout fields.
	request := &hubv1.QueryTimeoutBucketRequest{BucketKey: bucketKey}
	if version != 0 {
		request.Version = &version
	}
	resp, err := c.hubQuery.TimeoutBucket(ctx, connect.NewRequest(request))
	if err != nil {
		return TimeoutBucketState{}, applicationQueryError("timeout bucket", err)
	}
	bucket := resp.Msg.GetBucket()
	if bucket == nil || bucket.GetBucketKey() == "" {
		return TimeoutBucketState{}, ErrNotFound
	}
	if bucket.GetBucketKey() != bucketKey || (version != 0 && bucket.GetVersion() != version) {
		return TimeoutBucketState{}, fmt.Errorf("query timeout bucket: response key does not match request")
	}
	if bucket.GetBucketKind() != sharedv1.BucketKind_BUCKET_KIND_TIMEOUT {
		return TimeoutBucketState{}, fmt.Errorf("query timeout bucket: response bucket kind is %s",
			enumShortName("BUCKET_KIND_", bucket.GetBucketKind()))
	}
	// Infer/Verify/Reveal/ChallengeTimeoutBlocks, Source, CreatedHeight,
	// SupersededByVersion have no corresponding fields on the new wire (the entry table
	// gives timeout_blocks per work-unit upper bound); left zero until a follow-up rewires them.
	return TimeoutBucketState{
		BucketKey: bucket.GetBucketKey(), Version: bucket.GetVersion(), EffectiveHeight: bucket.GetEffectiveHeight(),
	}, nil
}

// mapTask projects the frozen contract's TaskViewV1 back onto nexus's OnChainTask.
//
// The new wire differs from the old one by splitting rather than renaming: QueryTask
// returns only `TaskActiveBundleV1{core, assignment, verifier_assignment}`, while the
// infer receipt, settlement and failure class are carried by separate RPCs such as
// QueryInferReceipt / QueryTaskFailureClass (§16.2/§16.5). All status fields changed from
// free-form strings to closed enums and all IDs/hashes to bytes. Hence the InferReceipt /
// Settlement / TaskVerdict / FailureClass / SampleSeed / AssignedSet sections of
// OnChainTask stay zero after this change: they are not in the QueryTask response, and
// filling them needs separate wiring in a follow-up.
func (c *client) mapTask(key TaskKey, response *taskv1.QueryTaskResponse) (OnChainTask, error) {
	bundle := response.GetTask().GetActive()
	if bundle == nil {
		return OnChainTask{}, fmt.Errorf("query task: active bundle is missing")
	}
	core := bundle.GetCore()
	if core == nil || len(core.GetTaskId()) == 0 {
		return OnChainTask{}, fmt.Errorf("query task: core state is missing")
	}
	if hex.EncodeToString(core.GetTaskId()) != key.TaskID {
		return OnChainTask{}, fmt.Errorf("query task: core key does not match request")
	}
	if len(core.GetSessionId()) != 0 && hex.EncodeToString(core.GetSessionId()) != key.SessionID {
		return OnChainTask{}, fmt.Errorf("query task: core session does not match request")
	}
	state, err := mapTaskPhase(core.GetTaskPhase())
	if err != nil {
		return OnChainTask{}, err
	}
	result := OnChainTask{
		SessionID: key.SessionID, TaskID: key.TaskID,
		Status: enumShortName("TASK_PHASE_", core.GetTaskPhase()), State: state,
		ReceiptAccepted: core.GetReceiptStatus() == taskv1.ReceiptStatus_RECEIPT_STATUS_RECEIPT_ACCEPTED,
		Assignment: TaskAssignmentState{
			UserAddress: core.GetUserAddress(), OrderSequence: core.GetOrderSequence(),
			ModelID: core.GetModelId(), ProfileVersion: core.GetProfileVersion(),
			AcceptedTaskHash: hex.EncodeToString(core.GetAcceptedTaskHash()),
		},
	}

	if assignment := bundle.GetAssignment(); assignment != nil {
		if hex.EncodeToString(assignment.GetTaskId()) != key.TaskID {
			return OnChainTask{}, fmt.Errorf("query task: assignment key does not match request")
		}
		result.Winner = assignment.GetWinnerWorker()
		result.InferDeadline, err = uint64ToInt64("infer deadline height", assignment.GetInferDeadlineHeight())
		if err != nil {
			return OnChainTask{}, err
		}
		// BuilderRank / BuilderSelectionProof / WorkerHandraiseSet / fee fields and order
		// envelope fields were removed from the assignment wire (Keeper-derived or carried
		// by other Queries); only facts that actually exist on the new wire are filled here.
		result.Assignment.CandidateSnapshotID = hex.EncodeToString(assignment.GetCandidatePoolSnapshotId())
		result.Assignment.CandidateSetHash = hex.EncodeToString(assignment.GetAssignmentCandidateSetHash())
		result.Assignment.SelectedWorkerOperatorAddress = assignment.GetWinnerWorker()
		result.Assignment.InferDeadlineHeight = assignment.GetInferDeadlineHeight()
		result.Assignment.AssignAcceptHeight = assignment.GetAssignAcceptHeight()
		result.Assignment.AssignmentRandomnessHeight = assignment.GetAssignmentRandomnessHeight()
		result.Assignment.WinnerConfirmHeight = assignment.GetWinnerConfirmHeight()
	}

	// Since wire v0.4.1 the bundle is published per round (round1 / round2); Phase 0 has
	// only the normal verification round 1, challenge round 2 is not active, so only round1 is read.
	if verification := bundle.GetRound1VerifierAssignment(); verification != nil {
		if hex.EncodeToString(verification.GetTaskId()) != key.TaskID {
			return OnChainTask{}, fmt.Errorf("query task: verifier assignment key does not match request")
		}
		for _, verifier := range verification.GetSelectedVerifiers() {
			if address := verifier.GetOperatorAddress(); address != "" {
				result.Verifiers = append(result.Verifiers, address)
			}
		}
		// VerificationSampleSeed / WorkerRevealDeadlineHeight /
		// SampleSeedReadyHeight / Stage3BuilderGraceBlocks / BuilderOperatorAddress
		// no longer exist on VerifierAssignmentState; left zero.
		result.VerifierAssignment = VerifierAssignmentState{
			CommitDeadlineHeight: verification.GetCommitDeadlineHeight(),
			RevealDeadlineHeight: verification.GetRevealDeadlineHeight(),
			VerifyDeadlineHeight: verification.GetVerifyDeadlineHeight(),
			OpenVerifyHeight:     verification.GetOpenVerifyHeight(),
		}
		result.Deadlines.Commit, err = uint64ToInt64("commit deadline height", verification.GetCommitDeadlineHeight())
		if err != nil {
			return OnChainTask{}, err
		}
		result.Deadlines.Reveal, err = uint64ToInt64("reveal deadline height", verification.GetRevealDeadlineHeight())
		if err != nil {
			return OnChainTask{}, err
		}
		result.Deadlines.Verify, err = uint64ToInt64("verify deadline height", verification.GetVerifyDeadlineHeight())
		if err != nil {
			return OnChainTask{}, err
		}
	}
	return result, nil
}

// mapTaskPhase maps the frozen contract's TaskPhase enum to the local FSM state. The old
// ASSIGN_RANDOMNESS_PENDING / RECEIPT_ONLY_ACCEPTED / VERIFYING /
// VERIFY_FAILED string states were replaced by this enum.
func mapTaskPhase(phase taskv1.TaskPhase) (types.TaskState, error) {
	switch phase {
	case taskv1.TaskPhase_TASK_PHASE_WORKER_ASSIGNMENT_PENDING:
		return types.Pending, nil
	case taskv1.TaskPhase_TASK_PHASE_WORKER_ASSIGNED:
		return types.Assigned, nil
	case taskv1.TaskPhase_TASK_PHASE_RECEIPT_COMMITTED,
		taskv1.TaskPhase_TASK_PHASE_VERIFIER_ASSIGNED,
		taskv1.TaskPhase_TASK_PHASE_COMMITTING,
		taskv1.TaskPhase_TASK_PHASE_REVEALING,
		taskv1.TaskPhase_TASK_PHASE_SETTLING:
		return types.Verifying, nil
	case taskv1.TaskPhase_TASK_PHASE_SETTLED:
		return types.Settled, nil
	case taskv1.TaskPhase_TASK_PHASE_FAILED:
		return types.Failed, nil
	default:
		return types.Pending, fmt.Errorf("query task: unknown task phase %s", phase)
	}
}

// enumShortName strips the type prefix from a protobuf enum value, yielding the short
// name nexus uses internally (SERVICE_KEY_STATUS_ACTIVE → ACTIVE). The frozen contract
// replaced all free-form string status fields with closed enums, while nexus's Go structs
// and downstream modules still compare short-name strings, so the conversion happens
// once at the chaincli layer and enum types are not propagated upward.
func enumShortName[E interface {
	~int32
	String() string
}](prefix string, value E) string {
	return strings.TrimPrefix(value.String(), prefix)
}

// parseParticipantType converts the participant type short name used inside nexus to the
// frozen contract's hub.v1.ParticipantType. enum and string are different protobuf
// wire types, so an unrecognized value must error rather than silently sending UNSPECIFIED.
func parseParticipantType(participantType string) (sharedv1.ParticipantType, error) {
	value, ok := sharedv1.ParticipantType_value["PARTICIPANT_TYPE_"+participantType]
	if !ok || sharedv1.ParticipantType(value) == sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED {
		return sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED,
			fmt.Errorf("participant type %q is not a hub.v1.ParticipantType value", participantType)
	}
	return sharedv1.ParticipantType(value), nil
}

// mapTaskVerdict / mapTaskStatus were removed together with the string task status /
// task_verdict wire: the frozen contract replaced them with the TaskPhase / TaskVerdict
// enums, and the verdict no longer appears in the QueryTask response (see mapTask).

// queryWorkerHandraise / parseWorkerHandraiseBuilders were removed together with the
// TaskAssignment worker_handraise_set string field: the frozen contract no longer puts
// the hand-raise set into Task state as a JSON string (raw hand-raises are never persisted).

func parseCanonicalList(field, value string, expected int) ([]string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("query %s: canonical comma-separated list is empty or padded", field)
	}
	parts := strings.Split(value, ",")
	if expected > 0 && len(parts) != expected {
		return nil, fmt.Errorf("query %s: expected %d entries, got %d", field, expected, len(parts))
	}
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return nil, fmt.Errorf("query %s: list entry is empty or padded", field)
		}
		if _, ok := seen[part]; ok {
			return nil, fmt.Errorf("query %s: duplicate list entry %q", field, part)
		}
		seen[part] = struct{}{}
	}
	return parts, nil
}

// parseCanonicalMemberList validates a typed `repeated Address` member list.
//
// The difference from parseCanonicalList is not just "no split": in the delimited-string
// shape the member count is a parse result, in the typed list it is a wire fact, so the
// number of returned members can be reconciled directly against active_builder_count.
// Order is preserved as is: rank is decided by on-chain order, no local sorting.
func parseCanonicalMemberList(field string, values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	members := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("query %s: member entry is empty or padded", field)
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("query %s: duplicate member entry %q", field, value)
		}
		seen[value] = struct{}{}
		members = append(members, value)
	}
	return members, nil
}

// uint64ToInt64 narrows an on-chain uint64 height into the local int64.
//
// Overflow is not "impossible": the chain stores heights as uint64, locally they are
// int64, and the upper bounds differ by a factor of two (9.22e18 vs 1.84e19). The
// keeper's overflow guard when computing deadlines only catches full uint64 overflow
// (checkedAddUint64 at node assignment_randomness.go:215), so a value between the two
// bounds is valid on chain and persisted normally, and only becomes unreadable here.
// A misconfigured governance parameter produces exactly such values (e.g. a timeout
// bucket entry's timeout_blocks set to MaxUint64).
//
// The error must therefore carry the *actual value*: without it, operators only know
// "some height exceeded int64", neither by how much nor which governance parameter is
// wrong, and would have to reverse-engineer it from node source.
func uint64ToInt64(field string, value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("query task: %s = %d exceeds int64 max %d "+
			"(chain stores heights as uint64; a value this large means an on-chain "+
			"parameter is misconfigured, not a nexus decoding bug)",
			field, value, uint64(math.MaxInt64))
	}
	return int64(value), nil
}

// --- URL helpers -----------------------------------------------------------

// grpcBaseURL turns the configured gRPC address into a connectrpc base URL:
// "host:port" / "tcp://" / "http://" / "grpc://" → http:// (h2c),
// "https://" / "grpcs://" → https:// (TLS).
func grpcBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	lower := strings.ToLower(addr)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return "https://" + addr[len("https://"):]
	case strings.HasPrefix(lower, "grpcs://"):
		return "https://" + addr[len("grpcs://"):]
	}
	for _, prefix := range []string{"tcp://", "http://", "grpc://"} {
		if strings.HasPrefix(lower, prefix) {
			addr = addr[len(prefix):]
			break
		}
	}
	return "http://" + addr
}

// newGRPCTransport picks the transport by the base URL scheme: h2c for http, TLS with CA root verification for https.
func newGRPCTransport(base string) *http2.Transport {
	if strings.HasPrefix(strings.ToLower(base), "https://") {
		return &http2.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	}
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}
