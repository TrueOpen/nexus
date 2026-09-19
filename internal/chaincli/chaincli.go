// Package chaincli is the only module that talks to the local node (Implementation Design §4.5).
// gRPC :9090 query/simulate/broadcast + TaskEventService subscription (single endpoint).
// The real client lives in client.go / events.go; NewStub remains for offline runs: it does
// not connect to node and returns placeholder results.
package chaincli

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/TrueOpen/nexus/internal/config"
)

// ErrNotSupportedOnChain is retained for operations, such as simulation, that
// Nexus has not wired to the current Node API.
var ErrNotSupportedOnChain = errors.New("chaincli: operation is not wired to the current node api")

// ErrInvalidTaskKey means a task-scoped node request is missing the compound
// identity required by the target contract: (session_id, task_id).
var ErrInvalidTaskKey = errors.New("chaincli: invalid task key")

// ErrNotFound is returned when an application Query has no state for its key.
var ErrNotFound = errors.New("chaincli: state not found")

// ChainEvent combines TaskEventService notifications and monotonic height polls.
type ChainEvent struct {
	Type             string
	EventCode        string
	SessionID        string
	TaskID           string
	Height           int64
	Attrs            map[string]string
	TaskNotification bool
}

// TxResult is the broadcast result.
type TxResult struct {
	TxHash []byte
	Code   uint32
	Height int64
	RawLog string
}

// AccountInfo is the account information needed for signing (auth Query/Account).
type AccountInfo struct {
	AccountNumber uint64
	Sequence      uint64
}

// Client abstracts chain interaction (query / broadcast / subscribe, see Interface & Topic Catalogue §2, §4.3).
type Client interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	// --- Queries (gRPC :9090, §2.1) ---
	// QueryBuilderSetAtHeight fetches the authoritative BuilderSet at the height via the
	// height selector; term is a result, not an input (the current Node BuilderState has no active_term).
	QueryBuilderSetAtHeight(ctx context.Context, height uint64) (BuilderSet, error)
	// QueryTaskBuilders reads the task's frozen Task Builder selection (task.v1.Query/TaskBuilders).
	QueryTaskBuilders(ctx context.Context, key TaskKey) (TaskBuilderSelectionState, error)
	// QuerySettlementBuilderGraceBlocks reads the Hub parameter settlement_builder_grace_blocks (§10.10a).
	QuerySettlementBuilderGraceBlocks(ctx context.Context) (uint64, error)
	// QueryEVMChainID reads the Hub parameter phase0.evm_chain_id: the numeric chainId of
	// the EIP-712 domain, unrelated to the Cosmos chain-id string. The Keeper ante uses it
	// to verify user signatures, and nexus must use the same value when verifying USER Task
	// data requests, so it is read from chain instead of configured separately.
	QueryEVMChainID(ctx context.Context) (uint64, error)
	QueryBuilder(ctx context.Context, address string) (BuilderState, error)
	QueryCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (ServiceKeyState, error)
	// QueryCortexNode reads the Cortex stable identity row (hub.v1.Query/CortexNode); returns ErrNotFound when absent.
	QueryCortexNode(ctx context.Context, operatorAddress string) (CortexNodeState, error)
	QueryServiceDescriptor(ctx context.Context, participantType, operatorAddress string, descriptorVersion uint64) (ServiceDescriptorState, error)
	QueryProfile(ctx context.Context, modelID string, profileVersion uint32) (ProfileState, error)
	LatestHeight(ctx context.Context) (uint64, error)
	QueryTask(ctx context.Context, key TaskKey) (OnChainTask, error)
	QuerySettlementBuildFacts(ctx context.Context, key TaskKey) (SettlementBuildFacts, error)
	QueryTimeoutBucket(ctx context.Context, bucketKey string, version, height uint64) (TimeoutBucketState, error)
	Simulate(ctx context.Context, unsignedTx []byte) (SimResult, error)
	// AccountInfo queries the signer account's account_number / sequence (cosmos auth, used to assemble the SignDoc).
	AccountInfo(ctx context.Context, address string) (AccountInfo, error)

	// --- Broadcast signed Tx (Assign / OpenVerify / WorkerReveal / Settle / Register / Unbond) ---
	BroadcastTx(ctx context.Context, tx []byte) (TxResult, error)

	// --- Subscribe to chain events (AssignAccepted / OpenVerifyAccepted / WorkerRevealReceiptAccepted /
	// SettleAccepted (with task_verdict) / BuilderSetUpdated ...) ---
	Events() <-chan ChainEvent
}

// TaskEventTracker lets the Coordinator declare which compound task keys need
// a resumable Node event stream without coupling the base Client interface to
// the real transport implementation.
type TaskEventTracker interface {
	TrackTaskEvents(TaskKey) error
	UntrackTaskEvents(TaskKey)
}

type stubClient struct {
	log      *slog.Logger
	cfg      config.ChainConfig
	events   chan ChainEvent
	stopOnce sync.Once
}

// NewStub returns the stub chain client.
func NewStub(log *slog.Logger, cfg config.ChainConfig) Client {
	return &stubClient{log: log, cfg: cfg, events: make(chan ChainEvent)}
}

func (c *stubClient) Start(_ context.Context) error {
	c.log.Warn("chaincli STUB mode: node client not implemented yet",
		"grpc", configuredLabel(c.cfg.GRPCAddr),
		"chain_id", configuredLabel(c.cfg.ChainID))
	return nil
}

func (c *stubClient) Stop(_ context.Context) error {
	c.stopOnce.Do(func() {
		close(c.events)
	})
	return nil
}

// QueryBuilderSetAtHeight has no source of truth to query in stub mode: it returns ErrNotFound
// rather than a fake set with "term equals height". The old stub returned
// BuilderSet{Epoch: epoch} because the input was the term itself; now the input is a
// height, and copying that would invent a nonexistent term.
func (c *stubClient) QueryBuilderSetAtHeight(_ context.Context, height uint64) (BuilderSet, error) {
	c.log.Debug("query builder set at height (stub)", "height", height)
	return BuilderSet{}, ErrNotFound
}

func (c *stubClient) QueryTaskBuilders(_ context.Context, key TaskKey) (TaskBuilderSelectionState, error) {
	if err := key.Validate(); err != nil {
		return TaskBuilderSelectionState{}, err
	}
	return TaskBuilderSelectionState{TaskID: key.TaskID}, ErrNotFound
}

func (c *stubClient) QuerySettlementBuilderGraceBlocks(context.Context) (uint64, error) {
	return 0, ErrNotFound
}

func (c *stubClient) QueryEVMChainID(context.Context) (uint64, error) {
	return 0, ErrNotFound
}

func (c *stubClient) QueryBuilder(_ context.Context, address string) (BuilderState, error) {
	return BuilderState{Address: address}, ErrNotFound
}

func (c *stubClient) QueryCurrentServiceKey(_ context.Context, participantType, operatorAddress string) (ServiceKeyState, error) {
	return ServiceKeyState{ParticipantType: participantType, OperatorAddress: operatorAddress}, ErrNotFound
}

func (c *stubClient) QueryCortexNode(_ context.Context, operatorAddress string) (CortexNodeState, error) {
	return CortexNodeState{OperatorAddress: operatorAddress}, ErrNotFound
}

func (c *stubClient) QueryServiceDescriptor(_ context.Context, participantType, operatorAddress string, descriptorVersion uint64) (ServiceDescriptorState, error) {
	return ServiceDescriptorState{ParticipantType: participantType, OperatorAddress: operatorAddress, DescriptorVersion: descriptorVersion}, ErrNotFound
}

func (c *stubClient) QueryProfile(_ context.Context, modelID string, profileVersion uint32) (ProfileState, error) {
	return ProfileState{ModelID: modelID, ProfileVersion: profileVersion}, ErrNotFound
}

func (c *stubClient) LatestHeight(context.Context) (uint64, error) { return 0, ErrNotSupportedOnChain }

func (c *stubClient) QueryTask(_ context.Context, key TaskKey) (OnChainTask, error) {
	if err := key.Validate(); err != nil {
		return OnChainTask{}, err
	}
	c.log.Debug("query task (stub)", "session_id", key.SessionID, "task_id", key.TaskID)
	return OnChainTask{SessionID: key.SessionID, TaskID: key.TaskID}, nil
}

func (c *stubClient) QuerySettlementBuildFacts(_ context.Context, key TaskKey) (SettlementBuildFacts, error) {
	if err := key.Validate(); err != nil {
		return SettlementBuildFacts{}, err
	}
	return SettlementBuildFacts{}, ErrNotFound
}

func (c *stubClient) QueryTimeoutBucket(_ context.Context, bucketKey string, version, _ uint64) (TimeoutBucketState, error) {
	return TimeoutBucketState{BucketKey: bucketKey, Version: version}, ErrNotFound
}

func (c *stubClient) Simulate(_ context.Context, tx []byte) (SimResult, error) {
	c.log.Debug("simulate tx (stub)", "bytes", len(tx))
	return SimResult{OK: true}, nil
}

func (c *stubClient) AccountInfo(_ context.Context, address string) (AccountInfo, error) {
	c.log.Debug("account info (stub)", "address", address)
	return AccountInfo{}, nil
}

func (c *stubClient) BroadcastTx(_ context.Context, tx []byte) (TxResult, error) {
	c.log.Debug("broadcast tx (stub)", "bytes", len(tx))
	return TxResult{Code: 0, RawLog: "stub: not broadcast"}, nil
}

func (c *stubClient) Events() <-chan ChainEvent { return c.events }
