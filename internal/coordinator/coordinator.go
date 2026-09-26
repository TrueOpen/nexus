// Package coordinator is the orchestration core of nexus (Implementation Design §4.2 / Detailed Design §3).
// One state machine per order (taskFSM) drives the three on-chain stages (Assign / OpenVerify / Settle) + commit-reveal.
// Covers: happy path, SETTLE rank timing and failover (§4), snapshot persistence and restart recovery reconciliation (§6.2).
package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/credential"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// ErrTaskNotFound / ErrUnauthorized reuse the types package sentinels (ingress maps them to error codes).
var (
	ErrTaskNotFound = types.ErrTaskNotFound
	ErrUnauthorized = types.ErrUnauthorized
)

const terminalTaskVersion = 1

const payloadCleanupVersion = 1

type terminalTaskRecord struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"`
}

type payloadCleanupRecord struct {
	Version   int    `json:"version"`
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
}

// taskKey is the composite task key = session_id|task_id.
func taskKey(sessionID, taskID string) string { return sessionID + "|" + taskID }

type Coordinator struct {
	log             *slog.Logger
	bus             msgbus.Bus
	chain           chaincli.Client
	protocolEvents  <-chan chaincli.ChainEvent
	chainID         string
	query           TaskQuerier
	settlementFacts SettlementFactsQuerier
	challenge       ChallengeQuerier
	inferReceipts   InferReceiptQuerier
	taskEvents      chaincli.TaskEventTracker
	txQuery         TxQuerier
	height          HeightQuerier
	selection       BuilderSelectionQuerier
	epochLength     atomic.Uint64
	relay           relay.Custodian
	kv              kv.Store
	submit          Submitter
	outputs         outputdelivery.Manager
	payloads        payloadstore.Store
	resultReadiness ResultReadiness

	mu           sync.RWMutex
	tasks        map[string]*taskFSM // key = session_id|task_id
	trackedTasks map[string]chaincli.TaskKey
	// Terminal task state has three layers. The NSTerminalTask KV marker is the durable fact that a
	// task is terminal and who receives its output; it is never deleted (taskdata retention relies
	// on it). terminalTasks, acceptedOutputs, outputFinalized and the task's journal are in-memory
	// caches kept only while outputdelivery holds the task's tombstone, and are dropped when that
	// tombstone expires (releaseTerminalTask). terminalTasks is not preloaded at startup: a miss
	// falls back to the KV marker (terminalRecipient).
	acceptedOutputs map[string][]byte
	terminalTasks   map[string]string
	// Terminal snapshots remain durable until outputdelivery has reconciled
	// PREPARED records and queued terminal notifications.
	outputRecoveryPending bool
	recoveryCleanup       map[string]struct{}
	outputFinalized       map[string]struct{}

	jmu      sync.Mutex
	journals map[string]*journal // per-task event journal; kept after task close until its tombstone expires

	identity  signer.Signer // for credential issuance (nil = dev mode, unsigned credentials)
	registry  BuilderRegistry
	admission OrderAdmission

	// serviceSigner is the current service key private key; serviceKeys is its on-chain query port.
	// Without either, BusEnvelopeV1 cannot be signed and the coordinator sends no task-control frame at all
	// (none of the 20 fields in contract §5.2 is optional; there is no "send unsigned for now" degradation).
	serviceSigner signer.Signer
	serviceKeys   servicekey.Resolver
	addressPrefix string
	busPublisher  *busadapter.Publisher
	busReceiver   *busadapter.Receiver
	busReplay     *busadapter.KVReplayStore
	prepares      *prepareCodec

	active *activeSet // active BuilderSet roster + this node's identity (currently stub-fed, see activeset.go)

	// deadlineSweep decides whether this Builder actively acts as public deadline runner (off by default).
	deadlineSweep DeadlineSweepPolicy

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup

	callbackMu      sync.Mutex
	callbacksClosed bool
	callbackWG      sync.WaitGroup

	chainStateMu        sync.RWMutex
	chainState          chainStateRecord
	heightAuthoritative bool
	reconcileRequests   chan reconcileRequest
	reconcilePendingMu  sync.Mutex
	reconcilePending    map[string]reconcileRequest
	reconcileStop       chan struct{}
	reconcileDone       chan struct{}
	reconcileStarted    chan struct{}
	reconcileStartOnce  sync.Once
	reconcileStopOnce   sync.Once
	// settlementFactsGone logs once that the chain has no settlement build facts query.
	settlementFactsGone sync.Once

	// chainReset is told when the latest height falls far below an observed one, and is asked
	// whether the chain is unchanged before a task missing from it is closed. Nil means the chain
	// identity check is off.
	chainReset ChainResetWatch
	// taskGoneWarned rate-limits the WARN for a task the chain no longer knows.
	taskGoneMu         sync.Mutex
	taskGoneWarned     map[string]time.Time
	reconcileRetryBase time.Duration
	reconcileRetryMax  time.Duration
}

// Option is optional wiring-time configuration.
type Option func(*Coordinator)

// BuilderRegistry is the authoritative Hub-side read port for Builder identity and BuilderSet.
//
// LatestHeight must come from the **same** Hub client: the BuilderSet lives on the Hub; querying
// the Hub's BuilderSet with a Task Chain height reads the same number across chains and silently
// returns the wrong term when the two chains' heights are not in sync.
type BuilderRegistry interface {
	QueryBuilder(context.Context, string) (chaincli.BuilderState, error)
	LatestHeight(context.Context) (uint64, error)
	QueryBuilderSetAtHeight(context.Context, uint64) (chaincli.BuilderSet, error)
}

// ResultReadiness answers this Builder's local data-ready for one Worker result (04 §326); the
// task data plane (taskdata.Service) implements it.
type ResultReadiness interface {
	ResultReady(context.Context, taskdata.ResultReadyQuery) (bool, error)
}

// SetResultReadiness wires in the task data plane; call it before Start. Without it no task is
// ever data-ready, so no OPEN_VERIFY or Verifier hand-raise proposal is sent, as there is no data
// to serve.
func (c *Coordinator) SetResultReadiness(readiness ResultReadiness) {
	c.resultReadiness = readiness
}

// OnResultFinalized is the task data plane's result-finalized observer: the Worker's
// FinalizeTaskResult succeeded here, so the task may now be data-ready.
func (c *Coordinator) OnResultFinalized(sessionID, taskID string) {
	if fsm, ok := c.getFSM(sessionID, taskID); ok {
		fsm.onResultFinalized()
	}
}

type TaskQuerier interface {
	QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error)
}

type SettlementFactsQuerier interface {
	QuerySettlementBuildFacts(context.Context, chaincli.TaskKey) (chaincli.SettlementBuildFacts, error)
}

// InferReceiptQuerier reads the hashes of a task's accepted InferReceipt.
type InferReceiptQuerier interface {
	QueryInferReceipt(context.Context, string) (chaincli.AcceptedInferReceipt, error)
}

// ChallengeQuerier reads the chain's verification round limit and a task's challenge window
// (06 §5, §9).
type ChallengeQuerier interface {
	QueryMaxVerifyRound(context.Context) (uint32, error)
	QueryTaskStage(context.Context, string) (chaincli.TaskStage, error)
}

type TxQuerier interface {
	QueryTx(context.Context, []byte) (chaincli.TxResult, error)
}

type HeightQuerier interface {
	LatestHeight(context.Context) (uint64, error)
}

// BuilderSelectionQuerier provides on-chain facts for settlement ordering: the frozen Task Builder
// order and the grace blocks per rank (§10.10a).
type BuilderSelectionQuerier interface {
	QueryTaskBuilders(context.Context, chaincli.TaskKey) (chaincli.TaskBuilderSelectionState, error)
	QuerySettlementBuilderGraceBlocks(context.Context) (uint64, error)
}

// epochLengthQuerier is the Hub epoch length read; the selection querier may offer it.
type epochLengthQuerier interface {
	QueryEpochLengthBlocks(context.Context) (uint64, error)
}

// currentEpoch returns the epoch of the last observed chain height. The epoch length is read
// from the Hub once and cached; false means it is not known.
func (c *Coordinator) currentEpoch() (uint64, bool) {
	length := c.epochLength.Load()
	if length == 0 {
		query, ok := c.selection.(epochLengthQuerier)
		if !ok {
			return 0, false
		}
		ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
		read, err := query.QueryEpochLengthBlocks(ctx)
		cancel()
		if err != nil || read == 0 {
			return 0, false
		}
		c.epochLength.Store(read)
		length = read
	}
	height, authoritative := c.currentChainHeight()
	if !authoritative || height == 0 {
		return 0, false
	}
	return height / length, true
}

// WithSubmitter injects a custom Tx submitter (e.g. NewSignedSubmitter with real signing).
func WithSubmitter(s Submitter) Option {
	return func(c *Coordinator) { c.submit = s }
}

// WithIdentitySigner injects the Builder identity signer: issues/verifies retrieval credentials (CredentialV1).
// Not injected = dev mode (unsigned credentials).
func WithIdentitySigner(sg signer.Signer) Option {
	return func(c *Coordinator) { c.identity = sg }
}

func WithBuilderRegistry(registry BuilderRegistry) Option {
	return func(c *Coordinator) { c.registry = registry }
}

// WithServiceKey injects the current service key private key and its on-chain query port.
// Not injected = this node can neither send nor accept BusEnvelopeV1 (contract §5.2).
func WithServiceKey(serviceSigner signer.Signer, resolver servicekey.Resolver, addressPrefix string) Option {
	return func(c *Coordinator) {
		c.serviceSigner = serviceSigner
		c.serviceKeys = resolver
		c.addressPrefix = addressPrefix
	}
}

func WithOrderAdmission(admission OrderAdmission) Option {
	return func(c *Coordinator) { c.admission = admission }
}

func WithTaskQuerier(query TaskQuerier) Option {
	return func(c *Coordinator) {
		c.query = query
		c.settlementFacts, _ = query.(SettlementFactsQuerier)
		c.challenge, _ = query.(ChallengeQuerier)
		c.inferReceipts, _ = query.(InferReceiptQuerier)
	}
}

func WithTxQuerier(query TxQuerier) Option {
	return func(c *Coordinator) { c.txQuery = query }
}

func WithHeightQuerier(query HeightQuerier) Option {
	return func(c *Coordinator) { c.height = query }
}

func WithBuilderSelectionQuerier(query BuilderSelectionQuerier) Option {
	return func(c *Coordinator) { c.selection = query }
}

func WithProtocolEventSource(events <-chan chaincli.ChainEvent) Option {
	return func(c *Coordinator) { c.protocolEvents = events }
}

// WithOutputDelivery wires bounded plaintext output delivery into the task lifecycle.
func WithOutputDelivery(outputs outputdelivery.Manager) Option {
	return func(c *Coordinator) { c.outputs = outputs }
}

// WithPayloadStore wires encrypted input persistence into order admission and task lifecycle cleanup.
func WithPayloadStore(payloads payloadstore.Store) Option {
	return func(c *Coordinator) { c.payloads = payloads }
}

// WithSettleRankDelay is a no-op: fallback settlement submission timing is decided by chain height and the Hub
// parameter settlement_builder_grace_blocks (§10.10a), no longer by the local clock. Signature kept for callers.
func WithSettleRankDelay(time.Duration) Option {
	return func(*Coordinator) {}
}

// WithDeadlineSweep enables the Builder to actively sweep expired deadlines (off by default).
// See DeadlineSweepPolicy for semantics and why it is off by default.
func WithDeadlineSweep(policy DeadlineSweepPolicy) Option {
	return func(c *Coordinator) { c.deadlineSweep = policy }
}

// ChainResetWatch is the chain identity check (chainreset.Monitor).
type ChainResetWatch interface {
	// Suspect reports a sign of a chain reset; a confirmed reset stops the process.
	Suspect(reason string)
	// SameChain reports whether the chain still has the recorded identity.
	SameChain(ctx context.Context) (bool, error)
}

// WithChainResetWatch enables the chain identity check.
func WithChainResetWatch(watch ChainResetWatch) Option {
	return func(c *Coordinator) { c.chainReset = watch }
}

// New assembles the Coordinator. selfAddr is this node's on-chain builder address (from config.Identity.BuilderAddress);
// empty means no identity configured, so self-check / MyRank always report "not in set". chainID is the Task Chain ID.
func New(log *slog.Logger, bus msgbus.Bus, chain chaincli.Client, rl relay.Custodian, store kv.Store, selfAddr, chainID string, opts ...Option) *Coordinator {
	c := &Coordinator{
		log:                log,
		bus:                bus,
		chain:              chain,
		chainID:            chainID,
		query:              chain,
		settlementFacts:    chain,
		challenge:          chain,
		inferReceipts:      chain,
		height:             chain,
		relay:              rl,
		kv:                 store,
		submit:             newDefaultSubmitter(log, chain),
		tasks:              make(map[string]*taskFSM),
		trackedTasks:       make(map[string]chaincli.TaskKey),
		acceptedOutputs:    make(map[string][]byte),
		terminalTasks:      make(map[string]string),
		recoveryCleanup:    make(map[string]struct{}),
		outputFinalized:    make(map[string]struct{}),
		journals:           make(map[string]*journal),
		active:             newActiveSet(selfAddr),
		stop:               make(chan struct{}),
		reconcileRequests:  make(chan reconcileRequest, 512),
		reconcilePending:   make(map[string]reconcileRequest),
		reconcileStop:      make(chan struct{}),
		reconcileDone:      make(chan struct{}),
		reconcileStarted:   make(chan struct{}),
		reconcileRetryBase: time.Second,
		reconcileRetryMax:  30 * time.Second,
	}
	if query, ok := chain.(TxQuerier); ok {
		c.txQuery = query
	}
	if tracker, ok := chain.(chaincli.TaskEventTracker); ok {
		c.taskEvents = tracker
	}
	for _, o := range opts {
		o(c)
	}
	c.busPublisher, c.busReceiver = c.buildBusAdapters()
	c.prepares = &prepareCodec{
		log: log, chainID: chainID, addressPrefix: c.addressPrefix,
		self: selfAddr, signer: c.serviceSigner, authority: c.serviceKeys,
	}
	c.outputRecoveryPending = c.outputs != nil
	if c.outputs != nil {
		c.outputs.SetTerminationObserver(c.onOutputFinalized)
		c.outputs.SetTombstoneObserver(c.releaseTerminalTask)
	}
	return c
}

func (c *Coordinator) Start(ctx context.Context) error {
	self := c.active.self
	c.log.Info("builder identity", "address", self, "configured", self != "")

	if err := c.seedBuilderSet(ctx); err != nil {
		if c.identity != nil {
			return err
		}
		c.log.Warn("Hub BuilderSet unavailable; running without an active roster", "err", err)
	}
	c.log.Info("builder active status", "active", c.active.IsActive(), "roster_size", len(c.active.Members()))
	if err := c.loadChainState(); err != nil {
		return err
	}
	if _, err := c.refreshChainHeight(ctx); err != nil {
		c.log.Warn("initial chain height refresh failed; recovery remains non-authoritative", "err", err)
	}

	// Restart recovery (§6.2): load snapshots -> reconcile on-chain -> resume subscriptions; done before the event loop
	// so recovery does not race with live events over the same state machine's initialization.
	if err := c.recoverTasks(ctx); err != nil {
		return err
	}
	// outbox republish: envelopes signed and persisted before the last process exit but possibly never sent are
	// resent verbatim (bytes and message_id unchanged; receivers admit them as legitimate retries); then the periodic
	// maintenance loop starts: it retries runtime publish failures within TTL and prunes the replay store at low frequency.
	c.republishOutbox(ctx)
	c.startBusMaintenance()
	c.startReconcileWorker()
	c.requestReconcile("coordinator startup")

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.eventLoop()
	}()
	c.log.Info("coordinator started")
	return nil
}

func (c *Coordinator) seedBuilderSet(ctx context.Context) error {
	if c.active.self == "" {
		if c.identity != nil {
			return fmt.Errorf("signed coordinator identity has no Builder address")
		}
		return nil
	}
	if c.registry == nil {
		return fmt.Errorf("Hub builder registry is required for configured Builder identity")
	}
	builder, err := c.registry.QueryBuilder(ctx, c.active.self)
	if err != nil {
		return fmt.Errorf("Hub builder registry: query Builder: %w", err)
	}
	if builder.Address != c.active.self {
		return fmt.Errorf("Hub Builder row address %q does not match local Builder %q", builder.Address, c.active.self)
	}
	// wire v0.4.1 BuilderState carries no admission status; the Builder row only tells the service key status.
	// "Admitted or not" is answered by the next step: BuilderSet membership at a fixed height.
	if builder.ServiceKeyStatus != serviceKeyStatusActive {
		return fmt.Errorf("Hub Builder %q service key status is %q, want %s", c.active.self, builder.ServiceKeyStatus, serviceKeyStatusActive)
	}
	height, err := c.registry.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("Hub builder registry: query latest height: %w", err)
	}
	if height == 0 {
		return fmt.Errorf("Hub builder registry: latest height is zero")
	}
	set, err := c.registry.QueryBuilderSetAtHeight(ctx, height)
	if err != nil {
		return fmt.Errorf("Hub builder registry: query BuilderSet at height %d: %w", height, err)
	}
	if set.Epoch == 0 {
		return fmt.Errorf("Hub BuilderSet at height %d returned no term", height)
	}
	if len(set.Members) == 0 {
		return fmt.Errorf("Hub BuilderSet version %d is empty", set.Epoch)
	}
	seen := make(map[string]struct{}, len(set.Members))
	selfFound := false
	for _, member := range set.Members {
		if member.Address == "" || strings.TrimSpace(member.Address) != member.Address {
			return fmt.Errorf("Hub BuilderSet version %d contains an invalid address", set.Epoch)
		}
		if _, exists := seen[member.Address]; exists {
			return fmt.Errorf("Hub BuilderSet version %d contains duplicate address %q", set.Epoch, member.Address)
		}
		seen[member.Address] = struct{}{}
		selfFound = selfFound || member.Address == c.active.self
	}
	if !selfFound {
		return fmt.Errorf("Hub BuilderSet version %d does not contain Builder %q", set.Epoch, c.active.self)
	}
	setHash, err := hex.DecodeString(set.SetHash)
	if err != nil || len(setHash) != sha256.Size {
		return fmt.Errorf("Hub BuilderSet version %d has a malformed set hash", set.Epoch)
	}
	if set.BuilderSetID == "" {
		return fmt.Errorf("Hub BuilderSet version %d has no builder_set_id", set.Epoch)
	}
	c.log.Info("active-set seeded from Hub BuilderSet",
		"height", height, "builder_set_version", set.Epoch, "builder_set_id", set.BuilderSetID,
		"members", len(set.Members), "set_hash", set.SetHash)
	// id and hash must come from this same read: fetching BusEnvelopeV1 fields 11/12 in two queries
	// can assemble a set that never existed on-chain at a term boundary.
	c.active.Update(set.Epoch, set.Members, builderSetRef{
		ID: set.BuilderSetID, Hash: "0x" + hex.EncodeToString(setHash),
	})
	return nil
}

func (c *Coordinator) Stop(_ context.Context) error {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.wg.Wait()
		c.stopReconcileWorker()
		c.callbackMu.Lock()
		c.callbacksClosed = true
		c.callbackMu.Unlock()
		c.callbackWG.Wait()
		c.mu.RLock()
		tasks := make([]*taskFSM, 0, len(c.tasks))
		for _, fsm := range c.tasks {
			tasks = append(tasks, fsm)
		}
		c.mu.RUnlock()
		for _, fsm := range tasks {
			fsm.shutdown()
		}
	})
	return nil
}

// journalFor gets (or creates) a task's event journal.
func (c *Coordinator) journalFor(key string) *journal {
	c.jmu.Lock()
	defer c.jmu.Unlock()
	j, ok := c.journals[key]
	if !ok {
		j = newJournal()
		c.journals[key] = j
	}
	return j
}

// newFSM assembles an order state machine instance.
func (c *Coordinator) newFSM(o types.Order) *taskFSM {
	key := taskKey(o.SessionID, o.TaskID)
	fsm := &taskFSM{
		log:                   c.log,
		bus:                   c.bus,
		publisher:             c.busPublisher,
		receiver:              c.busReceiver,
		prepares:              c.prepares,
		submit:                c.submit,
		relay:                 c.relay,
		self:                  c.active.self,
		chainID:               c.chainID,
		sessionID:             o.SessionID,
		taskID:                o.TaskID,
		modelID:               o.ModelID,
		profileVersion:        o.ProfileVersion,
		payloadCID:            o.PayloadCID,
		user:                  o.User,
		deadline:              o.Deadline,
		priceHint:             o.PriceHint,
		order:                 o,
		events:                c.journalFor(key),
		builderSet:            c.active.Members(),
		state:                 types.Pending,
		workerHR:              make(map[string]*taskv1.WorkerHandraiseV1),
		verifierHR:            make(map[string]*taskv1.VerifierHandraiseV1),
		verifierHRProposed:    make(map[string]bool),
		verifierHRExcluded:    make(map[string]uint64),
		currentEpoch:          c.currentEpoch,
		verifierProposalDelay: verifierProposalBatchDelay,
		resultReadiness:       c.resultReadiness,
		verifyResults:         make(map[string]*taskv1.ResultReceiptV2),
		verifyCommits:         make(map[string]*taskv1.VerifyCommitV1),
		fullReveals:           make(map[string]bool),
		prepareSeen:           make(map[string]int64),
		requestReconcile:      c.requestReconcile,
		beginExternalHandler:  c.beginCallback,
		endExternalHandler:    c.callbackWG.Done,
		onClose: func() {
			c.deletePayload(o.SessionID, o.TaskID)
			// The terminal marker goes first, as in recovery: Terminate may report the output
			// finalized synchronously, and that deletes the snapshot only once the marker is durable.
			recipient := c.removeTask(key)
			if c.outputs != nil {
				if err := c.outputs.Terminate(o.SessionID, o.TaskID, recipient); err != nil {
					c.log.Error("output delivery terminate failed",
						"session_id", o.SessionID,
						"task_id", o.TaskID,
						"err", err,
					)
				}
			}
		},
		persist: func(sn taskSnapshot) error {
			b, err := json.Marshal(sn)
			if err != nil {
				c.log.Warn("task snapshot encode failed", "task_id", sn.TaskID, "err", err)
				return err
			}
			if err := c.kv.Set(kv.NSTask, key, b); err != nil {
				c.log.Warn("task snapshot persist failed (recovery will rebuild from chain)", "task_id", sn.TaskID, "err", err)
				return err
			}
			// Index and snapshot share one source: written only after the snapshot write succeeds; recovery rebuilds it from the snapshot too.
			if err := c.kv.Set(kv.NSTaskSession, sn.TaskID, []byte(sn.SessionID)); err != nil {
				c.log.Warn("task session index persist failed", "task_id", sn.TaskID, "err", err)
				return err
			}
			return nil
		},
		unpersist: func() {
			c.deleteTaskSnapshot(key)
		},
	}
	fsm.onAbandon = func() {
		c.deletePayload(o.SessionID, o.TaskID)
		c.abandonTask(key, fsm)
	}
	return fsm
}

func (c *Coordinator) beginCallback() bool {
	c.callbackMu.Lock()
	defer c.callbackMu.Unlock()
	if c.callbacksClosed {
		return false
	}
	c.callbackWG.Add(1)
	return true
}

// OnOrder implements the ingress order entry (called by IngressAPI after signature verification): build FSM -> Pending.
func (c *Coordinator) OnOrder(ctx context.Context, o types.Order) error {
	key := taskKey(o.SessionID, o.TaskID)
	hadInlinePayload := len(o.Payload) > 0
	_, alreadyTerminal, err := c.terminalRecipient(o.SessionID, o.TaskID)
	if err != nil {
		return fmt.Errorf("read terminal task marker: %w", err)
	}
	if alreadyTerminal {
		c.log.Info("terminal order replay ignored", "session_id", o.SessionID, "task_id", o.TaskID)
		return nil
	}
	if c.admission != nil {
		result, err := c.admission.AdmitOrder(ctx, o)
		if err != nil {
			code := "NEXUS_INGRESS_STAGE1_VALIDATION_FAILED"
			switch {
			case errors.Is(err, ErrNotSelectedBuilder):
				code = ErrNotSelectedBuilder.Error()
			case errors.Is(err, ErrAdmissionUnavailable):
				code = ErrAdmissionUnavailable.Error()
			}
			c.log.Warn("stage1 order admission failed; continuing in observe-only mode",
				"session_id", o.SessionID, "task_id", o.TaskID, "code", code, "err", err)
		} else {
			o.Stage1BuilderRank = result.Rank
			o.Stage1SelectionProof = result.Proof
			c.log.Debug("stage1 order admission accepted", "task_id", o.TaskID, "term", result.TermID, "rank", result.Rank)
		}
	}
	if len(o.Payload) > 0 {
		if c.payloads == nil {
			return fmt.Errorf("%w: payload store is not configured", payloadstore.ErrStore)
		}
		if err := c.payloads.Put(ctx, payloadstore.Submission{
			SessionID: o.SessionID, TaskID: o.TaskID, TaskHash: o.TaskHash, Ref: o.PayloadCID,
			Hash: o.PayloadHash, Payload: o.Payload, DeadlineHeight: o.DeadlineHeight,
		}); err != nil {
			return err
		}
		o.Payload = nil // payload bytes live only in payloadstore, never in FSM snapshots.
	}
	c.mu.Lock()
	if _, terminal := c.terminalTasks[key]; terminal {
		c.mu.Unlock()
		c.deletePayload(o.SessionID, o.TaskID)
		c.log.Info("terminal order replay ignored", "session_id", o.SessionID, "task_id", o.TaskID)
		return nil
	}
	fsm, exists := c.tasks[key]
	if !exists {
		fsm = c.newFSM(o)
		c.tasks[key] = fsm
	}
	n := len(c.tasks)
	c.mu.Unlock()

	c.log.Info("order received",
		"session_id", o.SessionID,
		"task_id", o.TaskID,
		"task_hash", o.TaskHash,
		"model_id", o.ModelID,
		"has_inline_payload", hadInlinePayload,
		"tasks_inflight", n,
	)
	if !exists {
		if err := c.trackTaskEvents(key, fsm); err != nil {
			c.log.Error("order initialization failed",
				"phase", "track_task_events", "session_id", o.SessionID, "task_id", o.TaskID, "err", err)
			c.deletePayload(o.SessionID, o.TaskID)
			c.abandonTask(key, fsm)
			return fmt.Errorf("track task events: %w", err)
		}
		if err := fsm.onOrder(); err != nil {
			c.log.Error("order initialization failed",
				"phase", "initialize_task", "session_id", o.SessionID, "task_id", o.TaskID, "err", err)
			c.deletePayload(o.SessionID, o.TaskID)
			c.abandonTask(key, fsm)
			return fmt.Errorf("initialize task FSM: %w", err)
		}
	}
	if accepted, ok := c.payloads.(payloadstore.AcceptanceStore); ok && hadInlinePayload {
		if err := accepted.MarkAccepted(ctx, o.SessionID, o.TaskID); err != nil {
			c.log.Error("order initialization failed",
				"phase", "mark_payload_accepted", "session_id", o.SessionID, "task_id", o.TaskID, "err", err)
			return fmt.Errorf("mark task input accepted: %w", err)
		}
	}
	c.log.Info("order accepted locally",
		"session_id", o.SessionID, "task_id", o.TaskID, "task_hash", o.TaskHash, "tasks_inflight", n)
	return nil
}

// HasAcceptedOrder reports durable local acceptance for taskdata recovery.
func (c *Coordinator) HasAcceptedOrder(_ context.Context, key taskdata.ObjectKey) (bool, error) {
	if key.Kind != taskdata.ObjectKindInput || key.SessionID == "" || key.TaskID == "" {
		return false, taskdata.ErrMalformed
	}
	encoded := taskKey(key.SessionID, key.TaskID)
	if _, found, err := c.kv.GetWithError(kv.NSTask, encoded); err != nil {
		return false, err
	} else if found {
		return true, nil
	}
	_, found, err := c.kv.GetWithError(kv.NSTerminalTask, encoded)
	return found, err
}

// HasTerminatedOrder requires a durable terminal marker; absence from the
// in-memory task map alone is not enough evidence to delete task input.
func (c *Coordinator) HasTerminatedOrder(_ context.Context, key taskdata.ObjectKey) (bool, error) {
	if key.Kind != taskdata.ObjectKindInput || key.SessionID == "" || key.TaskID == "" {
		return false, taskdata.ErrMalformed
	}
	_, found, err := c.kv.GetWithError(kv.NSTerminalTask, taskKey(key.SessionID, key.TaskID))
	return found, err
}

// FetchPayload returns the encrypted task input to an authenticated task participant.
func (c *Coordinator) FetchPayload(ctx context.Context, sessionID, taskID, requester, usage string) (types.TaskPayload, types.Credential, error) {
	if c.payloads == nil {
		return types.TaskPayload{}, types.Credential{}, fmt.Errorf("%w: payload store is not configured", payloadstore.ErrStore)
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.TaskPayload{}, types.Credential{}, ErrTaskNotFound
	}
	if !fsm.authorizedForPayload(requester, usage) {
		c.log.Warn("payload fetch denied", "session_id", sessionID, "task_id", taskID, "requester", requester, "usage", usage)
		return types.TaskPayload{}, types.Credential{}, ErrUnauthorized
	}
	height, _ := c.currentChainHeight()
	stored, err := c.payloads.Fetch(ctx, sessionID, taskID, height)
	if err != nil {
		return types.TaskPayload{}, types.Credential{}, err
	}
	cred, err := c.issueCredential(sessionID, taskID, requester, usage, types.AccessPackage, nowMS()+credentialTTL.Milliseconds())
	if err != nil {
		return types.TaskPayload{}, types.Credential{}, err
	}
	c.log.Debug("payload served", "session_id", sessionID, "task_id", taskID, "requester", requester, "usage", usage)
	return types.TaskPayload{
		SessionID: stored.SessionID, TaskID: stored.TaskID, Ref: stored.Ref, Hash: stored.Hash,
		Payload: stored.Payload, DeadlineHeight: stored.DeadlineHeight,
	}, cred, nil
}

func (c *Coordinator) deletePayload(sessionID, taskID string) {
	if c.payloads == nil {
		return
	}
	key := taskKey(sessionID, taskID)
	if err := c.payloads.Delete(context.Background(), sessionID, taskID); err != nil {
		record, marshalErr := json.Marshal(payloadCleanupRecord{
			Version: payloadCleanupVersion, SessionID: sessionID, TaskID: taskID,
		})
		if marshalErr != nil {
			c.log.Error("payload cleanup intent encode failed", "session_id", sessionID, "task_id", taskID, "err", marshalErr)
		} else if persistErr := c.kv.Set(kv.NSPayloadCleanup, key, record); persistErr != nil {
			c.log.Error("payload cleanup intent persist failed", "session_id", sessionID, "task_id", taskID, "err", persistErr)
		}
		c.log.Error("payload cleanup failed; queued for retry", "session_id", sessionID, "task_id", taskID, "err", err)
		c.requestReconcile("payload cleanup pending")
		return
	}
	if err := c.kv.Delete(kv.NSPayloadCleanup, key); err != nil {
		c.log.Warn("payload cleanup intent delete failed", "session_id", sessionID, "task_id", taskID, "err", err)
	}
}

func (c *Coordinator) retryPayloadCleanup(ctx context.Context) error {
	if c.payloads == nil {
		return nil
	}
	var pending []payloadCleanupRecord
	var decodeErr error
	if err := c.kv.Scan(kv.NSPayloadCleanup, func(key string, raw []byte) bool {
		var record payloadCleanupRecord
		if err := json.Unmarshal(raw, &record); err != nil || record.Version != payloadCleanupVersion ||
			record.SessionID == "" || record.TaskID == "" || key != taskKey(record.SessionID, record.TaskID) {
			decodeErr = fmt.Errorf("invalid payload cleanup intent %q", key)
			return false
		}
		pending = append(pending, record)
		return true
	}); err != nil {
		return fmt.Errorf("scan payload cleanup intents: %w", err)
	}
	if decodeErr != nil {
		return decodeErr
	}
	for _, record := range pending {
		if err := c.payloads.Delete(ctx, record.SessionID, record.TaskID); err != nil {
			return fmt.Errorf("retry payload cleanup %s: %w", taskKey(record.SessionID, record.TaskID), err)
		}
		if err := c.kv.Delete(kv.NSPayloadCleanup, taskKey(record.SessionID, record.TaskID)); err != nil {
			return fmt.Errorf("delete payload cleanup intent %s: %w", taskKey(record.SessionID, record.TaskID), err)
		}
	}
	return nil
}

// OnInferReceipt receives the signed InferReceipt submitted by the selected Worker (Nexus<->Cortex
// contract §2.4): feeds the state machine + hands it to the relay credential store (called by IngressAPI SubmitInferReceipt).
//
// The contract "target-state baseline" removed SubmitOutputRef / the OutputRef object, so this no longer
// receives output_cid, sealed keys or inline plaintext: actual output/evidence content is persisted via
// UploadTaskResultData and fetched via FetchTaskData.
// Accepting the receipt neither waits for output/evidence upload to finish (§2.4) nor implies on-chain acceptance.
func (c *Coordinator) OnInferReceipt(_ context.Context, receipt types.InferReceiptSubmission) error {
	c.log.Info("infer receipt received", "session_id", receipt.SessionID, "task_id", receipt.TaskID,
		"worker", receipt.WorkerAddress)
	if err := validateInferReceiptShape(receipt); err != nil {
		return err
	}
	fsm, ok := c.getFSM(receipt.SessionID, receipt.TaskID)
	if !ok {
		return ErrTaskNotFound
	}
	if err := fsm.validateInferReceipt(receipt); err != nil {
		return err
	}
	if err := c.relay.Hold(receipt, 0); err != nil {
		if errors.Is(err, relay.ErrConflict) {
			return fmt.Errorf("%w: conflicting relay infer receipt", types.ErrInvalidArgument)
		}
		return err
	}
	if _, err := fsm.acceptInferReceipt(receipt); err != nil {
		return err
	}
	return nil
}

// OnVerifyCommit relays a verify commit signed by a selected Verifier (Cortex contract §2.5).
// The initial relay implementation trusts the Builder: after validation it is submitted on-chain as MsgBatchSubmitVerifyCommit; return means broadcast only.
func (c *Coordinator) OnVerifyCommit(_ context.Context, sessionID, taskID string, commit *taskv1.VerifyCommitV1) (types.VerifyRelayAck, error) {
	if commit == nil {
		return types.VerifyRelayAck{}, fmt.Errorf("%w: commit is required", types.ErrInvalidArgument)
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.VerifyRelayAck{}, ErrTaskNotFound
	}
	return fsm.relayVerifyCommit(commit)
}

// OnVerifyResult relays a result receipt signed by a selected Verifier (Cortex contract §2.6):
// carries the same ResultReceiptV2 as the VERIFY_RESULT JetStream path and shares the same relay logic.
func (c *Coordinator) OnVerifyResult(_ context.Context, sessionID, taskID string, receipt *taskv1.ResultReceiptV2) (types.VerifyRelayAck, error) {
	if receipt == nil {
		return types.VerifyRelayAck{}, fmt.Errorf("%w: receipt is required", types.ErrInvalidArgument)
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.VerifyRelayAck{}, ErrTaskNotFound
	}
	return fsm.relayVerifyResult(receipt)
}

// validateInferReceiptShape checks the minimal semantic fields of contract §2.4.
// The field set is the InferReceiptV2 frozen in §5.14: commit hash / trace / checkpoint / batch /
// token_count / work_unit were removed from wire and are now carried by typed required_evidence_commitments.
// The kind set and count limit are Keeper admission checks (contract §8.5; a known contract gap);
// locally we only require a non-empty list -- the §9.7 V1 text path always has WORKER_VALUE_OPENING.
func validateInferReceiptShape(receipt types.InferReceiptSubmission) error {
	switch {
	case receipt.SessionID == "":
		return fmt.Errorf("%w: empty session_id", types.ErrInvalidArgument)
	case receipt.TaskID == "":
		return fmt.Errorf("%w: empty task_id", types.ErrInvalidArgument)
	case receipt.TaskHash == "":
		return fmt.Errorf("%w: empty task_hash", types.ErrInvalidArgument)
	case receipt.SchemaVersion == 0:
		return fmt.Errorf("%w: empty schema_version", types.ErrInvalidArgument)
	case receipt.ChainID == "":
		return fmt.Errorf("%w: empty chain_id", types.ErrInvalidArgument)
	case len(receipt.OutputHash) == 0:
		return fmt.Errorf("%w: empty output_hash", types.ErrInvalidArgument)
	case receipt.OutputSizeBytes == 0:
		return fmt.Errorf("%w: output_size_bytes must be positive", types.ErrInvalidArgument)
	case receipt.WorkerAddress == "":
		return fmt.Errorf("%w: empty worker_address", types.ErrInvalidArgument)
	case receipt.ServiceAuthorizationNonce == 0:
		return fmt.Errorf("%w: service_authorization_nonce must be positive", types.ErrInvalidArgument)
	case len(receipt.GenerationParamsDigest) == 0:
		return fmt.Errorf("%w: empty generation_params_digest", types.ErrInvalidArgument)
	case len(receipt.EvidenceCommitments) == 0:
		return fmt.Errorf("%w: empty required_evidence_commitments", types.ErrInvalidArgument)
	case receipt.ExpiryHeight == 0:
		return fmt.Errorf("%w: expiry_height must be positive", types.ErrInvalidArgument)
	case len(receipt.InferReceiptHash) == 0:
		return fmt.Errorf("%w: empty infer_receipt_hash", types.ErrInvalidArgument)
	case len(receipt.WorkerServiceSignature) == 0:
		return fmt.Errorf("%w: empty worker_service_signature", types.ErrInvalidArgument)
	default:
		return nil
	}
}

// SubscribeOutput replays the prepared plaintext output or waits for its submission to complete.
//
// It only waits when the delivery has been Prepared (a record exists). This is the legacy plaintext
// path, used only when task_data.output_stream is disabled; no production entry point
// calls Prepare, so without a record the wait would never end; return OUTPUT_UNAVAILABLE right away
// so the SDK fails fast instead of hanging. Users pick up output via FetchOutputRef +
// FetchTaskData(OUTPUT).
func (c *Coordinator) SubscribeOutput(ctx context.Context, sessionID, taskID, requester string) (types.PlaintextOutput, error) {
	if c.outputs == nil {
		return types.PlaintextOutput{}, outputdelivery.ErrUnavailable
	}
	owner := ""
	if fsm, ok := c.getFSM(sessionID, taskID); ok {
		fsm.mu.Lock()
		owner = fsm.user
		fsm.mu.Unlock()
	} else if !c.outputs.Known(sessionID, taskID) {
		recipient, known, err := c.terminalRecipient(sessionID, taskID)
		if err != nil {
			return types.PlaintextOutput{}, err
		}
		if !known {
			return types.PlaintextOutput{}, types.ErrTaskNotFound
		}
		if recipient == "" || recipient != requester {
			return types.PlaintextOutput{}, outputdelivery.ErrUnauthorized
		}
	}
	if !c.outputs.Known(sessionID, taskID) {
		if owner != "" && owner != requester {
			return types.PlaintextOutput{}, outputdelivery.ErrUnauthorized
		}
		return types.PlaintextOutput{}, outputdelivery.ErrUnavailable
	}
	return c.outputs.Subscribe(ctx, outputdelivery.SubscribeRequest{
		SessionID: sessionID, TaskID: taskID, Requester: requester, ActiveTaskOwner: owner,
	})
}

// AckOutput acknowledges durable SDK receipt and makes plaintext immediately unreadable.
func (c *Coordinator) AckOutput(_ context.Context, sessionID, taskID, outputID, requester string) (types.OutputAck, error) {
	if c.outputs == nil {
		return types.OutputAck{}, outputdelivery.ErrUnavailable
	}
	if fsm, ok := c.getFSM(sessionID, taskID); ok {
		fsm.mu.Lock()
		owner := fsm.user
		fsm.mu.Unlock()
		if owner == "" || owner != requester {
			return types.OutputAck{}, outputdelivery.ErrUnauthorized
		}
	} else if !c.outputs.Known(sessionID, taskID) {
		recipient, known, err := c.terminalRecipient(sessionID, taskID)
		if err != nil {
			return types.OutputAck{}, err
		}
		if !known {
			return types.OutputAck{}, types.ErrTaskNotFound
		}
		if recipient == "" || recipient != requester {
			return types.OutputAck{}, outputdelivery.ErrUnauthorized
		}
	}
	return c.outputs.Ack(outputdelivery.AckRequest{
		SessionID: sessionID, TaskID: taskID, OutputID: outputID, Requester: requester,
	})
}

// TaskOwner returns the ordering user's address: streaming SubscribeOutput / AckOutput may only be subscribed by it.
// In-flight tasks read the FSM, terminal tasks read the terminal record; neither means the task is unknown.
func (c *Coordinator) TaskOwner(_ context.Context, sessionID, taskID string) (string, error) {
	if fsm, ok := c.getFSM(sessionID, taskID); ok {
		fsm.mu.Lock()
		owner := fsm.user
		fsm.mu.Unlock()
		return owner, nil
	}
	if recipient, known, err := c.terminalRecipient(sessionID, taskID); err != nil {
		return "", err
	} else if known {
		return recipient, nil
	}
	return "", types.ErrTaskNotFound
}

// HasAcceptedOutput is used during output-delivery restart reconciliation.
func (c *Coordinator) HasAcceptedOutput(sessionID, taskID string, outputHash []byte) bool {
	fsm, ok := c.getFSM(sessionID, taskID)
	if ok {
		fsm.mu.Lock()
		defer fsm.mu.Unlock()
		return len(fsm.outputHash) > 0 && bytes.Equal(fsm.outputHash, outputHash)
	}
	c.mu.RLock()
	accepted := c.acceptedOutputs[taskKey(sessionID, taskID)]
	c.mu.RUnlock()
	return len(accepted) > 0 && bytes.Equal(accepted, outputHash)
}

// IsTaskTerminal gates tombstone deletion after its minimum retention period.
func (c *Coordinator) IsTaskTerminal(sessionID, taskID string) bool {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return true
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.state == types.Closed || fsm.state == types.Failed
}

// terminalRecipient reports whether the task has a terminal marker and who receives its output.
// The in-memory map is only a cache; a miss reads the durable KV marker without re-caching it, so
// a released task does not grow the map again.
func (c *Coordinator) terminalRecipient(sessionID, taskID string) (string, bool, error) {
	return c.terminalMarker(taskKey(sessionID, taskID))
}

func (c *Coordinator) terminalMarker(key string) (string, bool, error) {
	c.mu.RLock()
	recipient, ok := c.terminalTasks[key]
	c.mu.RUnlock()
	if ok {
		return recipient, true, nil
	}
	raw, found, err := c.kv.GetWithError(kv.NSTerminalTask, key)
	if err != nil || !found {
		return "", false, err
	}
	var record terminalTaskRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != terminalTaskVersion {
		return "", false, fmt.Errorf("invalid terminal task marker %q", key)
	}
	return record.Recipient, true, nil
}

// releaseTerminalTask drops the in-memory state kept for a terminal task once outputdelivery has
// deleted its tombstone. The KV terminal marker stays.
func (c *Coordinator) releaseTerminalTask(sessionID, taskID string) {
	key := taskKey(sessionID, taskID)
	c.mu.Lock()
	if _, active := c.tasks[key]; active {
		c.mu.Unlock()
		return
	}
	delete(c.terminalTasks, key)
	delete(c.acceptedOutputs, key)
	delete(c.outputFinalized, key)
	c.mu.Unlock()
	c.jmu.Lock()
	delete(c.journals, key)
	c.jmu.Unlock()
}

// CompleteOutputRecovery releases terminal snapshots only after outputdelivery
// has durably promoted or rejected every recovered PREPARED record.
func (c *Coordinator) CompleteOutputRecovery() error {
	c.mu.Lock()
	c.outputRecoveryPending = false
	keys := make([]string, 0, len(c.recoveryCleanup))
	for key := range c.recoveryCleanup {
		keys = append(keys, key)
	}
	c.mu.Unlock()

	var firstErr error
	for _, key := range keys {
		if !c.isOutputFinalized(key) {
			err := fmt.Errorf("terminal output %q is not durably finalized", key)
			c.log.Warn("retaining terminal task snapshot", "key", key, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !c.terminalMarkerDurable(key) {
			err := fmt.Errorf("terminal task marker %q is not durable", key)
			c.log.Warn("retaining terminal task snapshot", "key", key, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		c.deleteTaskSessionIndex(key)
		if err := c.kv.Delete(kv.NSTask, key); err != nil {
			c.log.Warn("task snapshot delete failed after output recovery", "key", key, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		c.mu.Lock()
		delete(c.recoveryCleanup, key)
		c.mu.Unlock()
	}
	return firstErr
}

// FetchOutputRef only issues a bound credential (called by IngressAPI, deprecated).
// The Nexus<->Cortex contract "target-state baseline" removed the OutputRef object, so there is no ref to return;
// it is kept only because the fate of this RPC is still undecided. access_level still decides the authorization surface:
//   - SEALED_KEY: only the order user or a selected Verifier (within the verify-select set).
//   - PACKAGE: task existence suffices.
func (c *Coordinator) FetchOutputRef(_ context.Context, sessionID, taskID, requester string, level types.AccessLevel, usage string) (types.Credential, error) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.Credential{}, ErrTaskNotFound
	}
	if level == types.AccessSealedKey && !fsm.authorizedForSealedKey(requester) {
		c.log.Warn("sealed-key fetch denied", "session_id", sessionID, "task_id", taskID, "requester", requester)
		return types.Credential{}, ErrUnauthorized
	}
	if _, err := c.relay.Serve(sessionID, taskID, level); err != nil {
		return types.Credential{}, err
	}
	cred, err := c.issueCredential(sessionID, taskID, requester, usage, level, nowMS()+credentialTTL.Milliseconds())
	if err != nil {
		return types.Credential{}, err
	}
	c.log.Debug("fetch output ref served", "session_id", sessionID, "task_id", taskID,
		"requester", requester, "access_level", level.String(), "usage", usage)
	return cred, nil
}

// issueCredential issues a retrieval credential bound to task/recipient/usage/expiry.
func (c *Coordinator) issueCredential(sessionID, taskID, recipient, usage string, level types.AccessLevel, validUntil int64) (types.Credential, error) {
	return credential.Issue(c.identity, types.Credential{
		SessionID:   sessionID,
		TaskID:      taskID,
		Recipient:   recipient,
		Usage:       usage,
		AccessLevel: level,
		ValidUntil:  validUntil,
	})
}

// RefreshCredential exchanges an old credential for a new one (v1.5 §3.5, deprecated): stateless check of the old one
// (signature/ID/not expired) + matching recipient/usage + credential still held, then renew.
// The Nexus<->Cortex contract "target-state baseline" states V1 does not refresh standalone download credentials; this method's fate is pending;
// the OutputRef object was removed, so only the new credential is returned.
func (c *Coordinator) RefreshCredential(_ context.Context, old types.Credential, recipient, usage string, requestedValidUntil int64) (types.Credential, error) {
	if recipient != old.Recipient {
		return types.Credential{}, credential.ErrWrongRecipient
	}
	if usage != old.Usage {
		return types.Credential{}, credential.ErrWrongUsage
	}
	var issuerPub []byte
	if c.identity != nil {
		issuerPub = c.identity.PubKeyCompressed()
	}
	if err := credential.Verify(old, issuerPub, nowMS()); err != nil {
		return types.Credential{}, err
	}
	if _, err := c.relay.Serve(old.SessionID, old.TaskID, old.AccessLevel); err != nil {
		return types.Credential{}, err // held credential released/expired -> no renewal
	}
	validUntil := nowMS() + credentialTTL.Milliseconds()
	if requestedValidUntil > 0 && requestedValidUntil < validUntil {
		validUntil = requestedValidUntil // may only shorten; capped by credentialTTL
	}
	cred, err := c.issueCredential(old.SessionID, old.TaskID, old.Recipient, old.Usage, old.AccessLevel, validUntil)
	if err != nil {
		return types.Credential{}, err
	}
	c.log.Debug("credential refreshed", "session_id", old.SessionID, "task_id", old.TaskID,
		"recipient", old.Recipient, "valid_until", validUntil)
	return cred, nil
}

// TaskEvents subscribes to the task event stream (v1.5 §3.4): history replay after cursor + live channel.
// The journal is kept after task close, so history remains queryable.
func (c *Coordinator) TaskEvents(_ context.Context, sessionID, taskID string, fromCursor uint64) ([]types.TaskEvent, <-chan types.TaskEvent, func(), error) {
	key := taskKey(sessionID, taskID)
	c.jmu.Lock()
	j, ok := c.journals[key]
	c.jmu.Unlock()
	if !ok {
		return nil, nil, nil, ErrTaskNotFound
	}
	replay, live, cancel := j.subscribe(fromCursor)
	return replay, live, cancel, nil
}

// PrepareChallenge assembles challenge inputs (v1.5 §3.6): challenge window facts + estimate.
// It submits no verdict; the challenge itself is MsgOpenChallengeRound, which anyone may submit on
// chain. The opener holds no evidence (06 §5): the round's Verifiers fetch the task data
// themselves, so the plan lists no required evidence and the challenge kind does not change it.
//
// A round can open while the task is not final, the round limit allows a second round, and the
// challenge window is the task's next deadline without the chain height having passed it. The
// Keeper reports that window through TaskStage only after round 1 has closed and while no round
// is open (06 §5, §9).
func (c *Coordinator) PrepareChallenge(ctx context.Context, sessionID, taskID, _ string) (types.ChallengePlan, error) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.ChallengePlan{}, ErrTaskNotFound
	}
	height, err := c.refreshChainHeight(ctx)
	if err != nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: latest height: %v", types.ErrChainStateUnavailable, err)
	}
	if c.query == nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: task query is not configured", types.ErrChainStateUnavailable)
	}
	queryCtx, cancel := context.WithTimeout(ctx, reconcileQueryTimeout)
	task, err := c.query.QueryTask(queryCtx, chaincli.TaskKey{SessionID: sessionID, TaskID: taskID})
	cancel()
	if err != nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: query task: %v", types.ErrChainStateUnavailable, err)
	}
	if task.SessionID != sessionID || task.TaskID != taskID {
		return types.ChallengePlan{}, fmt.Errorf("%w: task scope mismatch", types.ErrChainStateUnavailable)
	}
	status := task.Settlement.FinalityStatus
	switch status {
	case "PENDING", "FINAL":
	default:
		return types.ChallengePlan{}, fmt.Errorf("%w: unknown finality status %q", types.ErrChainStateUnavailable, status)
	}
	if c.challenge == nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: challenge query is not configured", types.ErrChainStateUnavailable)
	}
	paramsCtx, cancelParams := context.WithTimeout(ctx, reconcileQueryTimeout)
	maxVerifyRound, err := c.challenge.QueryMaxVerifyRound(paramsCtx)
	cancelParams()
	if err != nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: query challenge params: %v", types.ErrChainStateUnavailable, err)
	}
	stageCtx, cancelStage := context.WithTimeout(ctx, reconcileQueryTimeout)
	stage, err := c.challenge.QueryTaskStage(stageCtx, taskID)
	cancelStage()
	if err != nil {
		return types.ChallengePlan{}, fmt.Errorf("%w: query task stage: %v", types.ErrChainStateUnavailable, err)
	}
	fsm.mu.Lock()
	fsm.reconcile(task)
	if err := fsm.save(); err != nil {
		fsm.mu.Unlock()
		return types.ChallengePlan{}, fmt.Errorf("%w: persist task facts: %v", types.ErrChainStateUnavailable, err)
	}
	fsm.mu.Unlock()
	closeHeight := stage.ChallengeCloseHeight()
	open := status == "PENDING" &&
		maxVerifyRound > 1 &&
		closeHeight != 0 &&
		height <= closeHeight
	return types.ChallengePlan{
		ChallengeOpen:        open,
		ChallengeCloseHeight: closeHeight,
		EstimatedBond:        types.Coin{},
		EstimatedGas:         challengeGasEstimate,
	}, nil
}

// TaskStatus returns a task status snapshot (called by IngressAPI): coarse state + fine-grained phase (v1.5 §3.3).
func (c *Coordinator) TaskStatus(_ context.Context, sessionID, taskID string) (types.TaskStatus, error) {
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return types.TaskStatus{}, ErrTaskNotFound
	}
	fsm.mu.Lock()
	st := fsm.state.String()
	ph := fsm.phase.String()
	fsm.mu.Unlock()
	return types.TaskStatus{State: st, TaskPhase: ph}, nil
}

// ---- Typed chain-event entry points (callable directly; in production eventLoop adapts chain.Events() and forwards) ----

// OnAssignAccepted: AssignTx included in a block (step 1 of two): winner undecided, randomness pending.
func (c *Coordinator) OnAssignAccepted(ev chaincli.AssignAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onAssignAccepted(ev)
	}
}

// OnAssignmentFinalized: randomness settled (step 2 of two): PENDING -> ASSIGNED, notify start of work.
func (c *Coordinator) OnAssignmentFinalized(ev chaincli.AssignmentFinalized) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onAssignmentFinalized(ev)
	}
}

// OnOpenVerifyAccepted: open-verify included in a block (no seed): ASSIGNED -> VERIFYING.
func (c *Coordinator) OnOpenVerifyAccepted(ev chaincli.OpenVerifyAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onOpenVerifyAccepted(ev)
	}
}

// OnSampleReady: sampling seed ready: deliver the seed via trueopen.sample-ready.
func (c *Coordinator) OnSampleReady(ev chaincli.SampleReady) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onSampleReady(ev)
	}
}

// OnFullResultRevealAccepted: Verifier full-result reveal self-rescue included on-chain.
func (c *Coordinator) OnFullResultRevealAccepted(ev chaincli.FullResultRevealAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onFullResultRevealAccepted(ev)
	}
}

// OnSweepDeadlineAccepted: deadline sweep advanced: task converges to a terminal state.
func (c *Coordinator) OnSweepDeadlineAccepted(ev chaincli.SweepDeadlineAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onSweepDeadlineAccepted(ev)
	}
}

// OnWorkerRevealAccepted: Worker reveal receipt submitted on-chain (or reveal timed out).
func (c *Coordinator) OnWorkerRevealAccepted(ev chaincli.WorkerRevealAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onWorkerRevealAccepted(ev)
	}
}

// OnSettleAccepted: settlement included in a block: VERIFYING -> SETTLED, challenge window opens.
func (c *Coordinator) OnSettleAccepted(ev chaincli.SettleAccepted) {
	if fsm, ok := c.getFSM(ev.SessionID, ev.TaskID); ok {
		fsm.onSettleAccepted(ev)
	}
}

// ---- Internal ----

// SessionForTask looks up session_id by task_id. The three relay requests of wire v0.4.1 carry only the
// on-chain message body, the on-chain task_id has no session, and the FSM is keyed by (session, task); this
// index is written together with the task snapshot and deleted with it, and creates no new fact itself.
func (c *Coordinator) SessionForTask(_ context.Context, taskID string) (string, error) {
	if taskID == "" {
		return "", types.ErrInvalidArgument
	}
	value, found, err := c.kv.GetWithError(kv.NSTaskSession, taskID)
	if err != nil {
		return "", err
	}
	if !found || len(value) == 0 {
		return "", types.ErrTaskNotFound
	}
	return string(value), nil
}

// deleteTaskSessionIndex extracts task_id from the "session|task" key and deletes the index entry.
func (c *Coordinator) deleteTaskSessionIndex(key string) {
	_, taskID, found := strings.Cut(key, "|")
	if !found || taskID == "" {
		return
	}
	if err := c.kv.Delete(kv.NSTaskSession, taskID); err != nil {
		c.log.Warn("task session index delete failed", "task_id", taskID, "err", err)
	}
}

func (c *Coordinator) getFSM(sessionID, taskID string) (*taskFSM, bool) {
	c.mu.RLock()
	fsm, ok := c.tasks[taskKey(sessionID, taskID)]
	c.mu.RUnlock()
	return fsm, ok
}

func (c *Coordinator) trackTaskEvents(key string, fsm *taskFSM) error {
	if c.taskEvents == nil {
		return nil
	}
	eventKey := chaincli.TaskKey{SessionID: fsm.sessionID, TaskID: fsm.taskID}
	if err := c.taskEvents.TrackTaskEvents(eventKey); err != nil {
		return err
	}
	c.mu.Lock()
	if c.tasks[key] != fsm {
		c.mu.Unlock()
		c.taskEvents.UntrackTaskEvents(eventKey)
		return nil
	}
	if c.trackedTasks == nil {
		c.trackedTasks = make(map[string]chaincli.TaskKey)
	}
	c.trackedTasks[key] = eventKey
	c.mu.Unlock()
	return nil
}

func (c *Coordinator) removeTask(key string) string {
	c.mu.RLock()
	fsm := c.tasks[key]
	c.mu.RUnlock()
	existingRecipient, alreadyTerminal, err := c.terminalMarker(key)
	if err != nil {
		c.log.Warn("terminal task marker unreadable; rewriting it", "key", key, "err", err)
	}
	var accepted []byte
	recipient := existingRecipient
	if fsm != nil {
		fsm.mu.Lock()
		accepted = append([]byte(nil), fsm.outputHash...)
		if !alreadyTerminal {
			recipient = fsm.user
		}
		fsm.mu.Unlock()
	}
	raw, err := json.Marshal(terminalTaskRecord{Version: terminalTaskVersion, Recipient: recipient})
	if err != nil {
		c.log.Error("terminal task marker encode failed; retaining snapshot for retry", "key", key, "err", err)
	} else if err := c.kv.Set(kv.NSTerminalTask, key, raw); err != nil {
		c.log.Error("terminal task marker persist failed; retaining snapshot for retry", "key", key, "err", err)
	}
	c.mu.Lock()
	if len(accepted) > 0 {
		c.acceptedOutputs[key] = accepted
	}
	c.terminalTasks[key] = recipient
	delete(c.tasks, key)
	eventKey, tracked := c.trackedTasks[key]
	delete(c.trackedTasks, key)
	c.mu.Unlock()
	if tracked {
		c.taskEvents.UntrackTaskEvents(eventKey)
	}
	return recipient
}

// abandonTask drops a task that never reached the chain. Its journal is kept so the user can see
// why it was rejected; with no output tombstone nothing releases it (a known, low-volume leak).
func (c *Coordinator) abandonTask(key string, expected *taskFSM) {
	removed := false
	var trackedKey chaincli.TaskKey
	c.mu.Lock()
	if c.tasks[key] == expected {
		delete(c.tasks, key)
		trackedKey = c.trackedTasks[key]
		delete(c.trackedTasks, key)
		removed = true
	}
	c.mu.Unlock()
	if trackedKey.SessionID != "" {
		c.taskEvents.UntrackTaskEvents(trackedKey)
	}
	if removed {
		if err := c.kv.Delete(kv.NSTask, key); err != nil {
			c.log.Warn("abandoned task snapshot delete failed", "key", key, "err", err)
		}
	}
}

func (c *Coordinator) deleteTaskSnapshot(key string) {
	c.mu.Lock()
	if c.outputRecoveryPending {
		c.recoveryCleanup[key] = struct{}{}
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	if c.outputs != nil && !c.isOutputFinalized(key) {
		c.log.Warn("terminal output not finalized; retaining task snapshot", "key", key)
		return
	}
	if !c.terminalMarkerDurable(key) {
		c.log.Warn("terminal task marker missing; retaining task snapshot", "key", key)
		return
	}
	c.deleteTaskSessionIndex(key)
	if err := c.kv.Delete(kv.NSTask, key); err != nil {
		c.log.Warn("task snapshot delete failed", "key", key, "err", err)
	}
}

func (c *Coordinator) onOutputFinalized(sessionID, taskID string) {
	key := taskKey(sessionID, taskID)
	c.mu.Lock()
	c.outputFinalized[key] = struct{}{}
	c.mu.Unlock()
	c.deleteTaskSnapshot(key)
}

func (c *Coordinator) isOutputFinalized(key string) bool {
	c.mu.RLock()
	_, ok := c.outputFinalized[key]
	c.mu.RUnlock()
	return ok
}

func (c *Coordinator) terminalMarkerDurable(key string) bool {
	raw, ok, err := c.kv.GetWithError(kv.NSTerminalTask, key)
	if err != nil || !ok {
		return false
	}
	var record terminalTaskRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Version != terminalTaskVersion {
		return false
	}
	c.mu.RLock()
	recipient, known := c.terminalTasks[key]
	c.mu.RUnlock()
	return !known || record.Recipient == recipient
}

func (c *Coordinator) OnChainEvent(ev chaincli.ChainEvent) {
	if ev.Type == chaincli.EventResyncRequired {
		if ev.SessionID != "" {
			c.requestSessionReconcile(ev.SessionID, "event stream subscribed")
		} else {
			c.requestReconcile("event stream subscribed")
		}
		return
	}
	if ev.Type == chaincli.EventNewBlock {
		c.onNewBlock(ev.Height)
		return
	}
	if ev.TaskNotification {
		if ev.SessionID == "" || ev.TaskID == "" {
			c.requestReconcile("task notification missing compound task key")
		} else {
			c.requestTaskEventReconcile(ev, "task event notification")
		}
		return
	}
	if isTaskStateEvent(ev.Type) && (ev.SessionID == "" || ev.TaskID == "") {
		c.requestReconcile("application event missing compound task key")
		return
	}
	if taskEventNeedsQuery(ev) {
		c.requestTaskReconcile(ev.SessionID, ev.TaskID, ev.Height, "incomplete application event")
		return
	}

	switch ev.Type {
	case chaincli.EventBuilderSetUpdated:
		c.requestBuilderSetReconcile(ev.Height, "Hub BuilderSet event")
	case chaincli.EventAssignAccepted:
		c.OnAssignAccepted(chaincli.AssignAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID, Height: ev.Height,
		})
	case chaincli.EventAssignmentFinalized:
		c.OnAssignmentFinalized(chaincli.AssignmentFinalized{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			Winner:              ev.Attrs["winner_worker"],
			Height:              ev.Height,
			InferDeadlineHeight: parseUint64Attr(ev.Attrs["infer_deadline_height"]),
		})
	case chaincli.EventOpenVerifyAccepted:
		c.OnOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			Verifiers: splitCSV(ev.Attrs["formal_verifier_set"]),
			Deadlines: types.Deadlines{
				Commit: parseInt64Attr(ev.Attrs["commit_deadline_height"]), WorkerReveal: parseInt64Attr(ev.Attrs["worker_reveal_deadline_height"]),
				Reveal: parseInt64Attr(ev.Attrs["reveal_deadline_height"]), Verify: parseInt64Attr(ev.Attrs["verify_deadline_height"]),
			}, Height: ev.Height,
		})
	case chaincli.EventSampleReady:
		c.OnSampleReady(chaincli.SampleReady{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			SampleSeed:  decodeSeedAttr(ev.Attrs["verification_sample_seed_hash"]),
			ReadyHeight: parseInt64Attr(ev.Attrs["sample_seed_ready_height"]),
			Height:      ev.Height,
		})
	case chaincli.EventFullResultRevealAccepted:
		c.OnFullResultRevealAccepted(chaincli.FullResultRevealAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			Verifier: ev.Attrs["verifier"], Height: ev.Height,
		})
	case chaincli.EventSweepDeadlineAccepted:
		c.OnSweepDeadlineAccepted(chaincli.SweepDeadlineAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			DeadlineKind:   parseDeadlineKindAttr(ev.Attrs["deadline_kind"]),
			TransitionCode: parseDeadlineTransitionAttr(ev.Attrs["transition_code"]),
			Height:         ev.Height,
		})
	case chaincli.EventWorkerRevealAccepted:
		c.OnWorkerRevealAccepted(chaincli.WorkerRevealAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID, Height: ev.Height,
		})
	case chaincli.EventSettleAccepted:
		c.OnSettleAccepted(chaincli.SettleAccepted{
			SessionID: ev.SessionID, TaskID: ev.TaskID,
			TaskVerdict: parseTaskVerdict(ev.Attrs["task_verdict"]),
			// EventTaskSettled carries only settlement_height / task_finality_height; finality_status
			// comes from QueryTask, and credential release looks only at the queried state.
			Settlement: chaincli.TaskSettlementState{
				SettlementHeight:   uint64(parseInt64Attr(ev.Attrs["settlement_height"])),
				TaskFinalityHeight: uint64(parseInt64Attr(ev.Attrs["task_finality_height"])),
			},
			Height: ev.Height,
		})
	default:
		c.log.Debug("unhandled chain event", "type", ev.Type, "task_id", ev.TaskID)
	}
}

func isTaskStateEvent(eventType string) bool {
	switch eventType {
	case chaincli.EventAssignAccepted, chaincli.EventAssignmentFinalized, chaincli.EventOpenVerifyAccepted,
		chaincli.EventSampleReady, chaincli.EventWorkerRevealAccepted, chaincli.EventFullResultRevealAccepted,
		chaincli.EventSettleAccepted, chaincli.EventSweepDeadlineAccepted:
		return true
	default:
		return false
	}
}

func taskEventNeedsQuery(ev chaincli.ChainEvent) bool {
	if !isTaskStateEvent(ev.Type) {
		return false
	}
	switch ev.Type {
	case chaincli.EventAssignAccepted, chaincli.EventAssignmentFinalized, chaincli.EventOpenVerifyAccepted, chaincli.EventSettleAccepted:
		return true
	case chaincli.EventSampleReady:
		return ev.Attrs["verification_sample_seed_hash"] == "" || ev.Attrs["sample_seed_ready_height"] == ""
	case chaincli.EventFullResultRevealAccepted:
		return ev.Attrs["verifier"] == ""
	case chaincli.EventSweepDeadlineAccepted:
		// transition_code is the only basis for deciding whether the task converged; if missing we must go back
		// to Query and reconcile, never guess the task's fate from deadline_kind alone.
		return ev.Attrs["transition_code"] == ""
	default:
		return false
	}
}

func (c *Coordinator) onNewBlock(rawHeight int64) {
	if rawHeight <= 0 {
		return
	}
	height := uint64(rawHeight)
	if c.payloads != nil {
		if err := c.payloads.Sweep(context.Background(), height); err != nil {
			c.log.Error("payload deadline sweep failed", "height", height, "err", err)
		}
	}
	c.chainStateMu.Lock()
	previous := c.chainState.LastObservedHeight
	wasAuthoritative := c.heightAuthoritative
	if wasAuthoritative && height <= previous {
		c.chainStateMu.Unlock()
		return
	}
	if !wasAuthoritative {
		previous = 0
	}
	next := c.chainState
	next.Version = chainStateVersion
	next.LastObservedHeight = height
	encoded, err := json.Marshal(next)
	if err == nil {
		err = c.kv.Set(kv.NSChainState, chainStateKey, encoded)
	}
	if err != nil {
		c.heightAuthoritative = false
		c.chainStateMu.Unlock()
		c.log.Warn("new block height persist failed", "height", height, "err", err)
		c.requestReconcile("new block height persistence failed")
		return
	}
	c.chainState = next
	c.heightAuthoritative = true
	c.chainStateMu.Unlock()
	if previous != 0 && height > previous+1 {
		c.requestReconcile(fmt.Sprintf("block height gap %d..%d", previous, height))
	}
	if height%reconcileEveryBlocks == 0 {
		c.requestReconcile("periodic block reconciliation")
	}
	c.requestDueLifecycleReconcile(height)
	c.sweepDueDeadlines(height)
	c.observeSettleHeight(height)
}

// observeSettleHeight feeds the chain height to every task: submission windows for settlement rank >= 2 open
// by chain height (§10.10a), not by local clock.
func (c *Coordinator) observeSettleHeight(height uint64) {
	c.mu.RLock()
	tasks := make([]*taskFSM, 0, len(c.tasks))
	for _, fsm := range c.tasks {
		tasks = append(tasks, fsm)
	}
	c.mu.RUnlock()
	for _, fsm := range tasks {
		fsm.onHeight(height)
	}
}

// sweepDueDeadlines performs a public deadline sweep on each new block for tasks this node is tracking.
// Off by default (see DeadlineSweepPolicy); when off, Nexus only observes DEADLINE_SWEPT events.
func (c *Coordinator) sweepDueDeadlines(height uint64) {
	if !c.deadlineSweep.Enabled {
		return
	}
	c.mu.RLock()
	tasks := make([]*taskFSM, 0, len(c.tasks))
	for _, fsm := range c.tasks {
		tasks = append(tasks, fsm)
	}
	c.mu.RUnlock()
	for _, fsm := range tasks {
		fsm.sweepDueDeadlines(c.deadlineSweep, height)
	}
}

func (c *Coordinator) reconcileTask(sessionID, taskID string, eventHeight int64, reason string, notifications []chaincli.ChainEvent) bool {
	if c.query == nil {
		c.log.Warn("task reconciliation skipped: Task Query is not configured", "task_id", taskID, "reason", reason)
		return false
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	snapshot, err := c.query.QueryTask(ctx, chaincli.TaskKey{SessionID: sessionID, TaskID: taskID})
	cancel()
	if err != nil {
		if errors.Is(err, chaincli.ErrNotFound) && c.reconcileMissingPendingTask(fsm, eventHeight, reason) {
			if eventHeight > 0 {
				if _, active := c.getFSM(sessionID, taskID); active {
					return false
				}
			}
			return true
		}
		if errors.Is(err, chaincli.ErrNotFound) {
			return c.reconcileTaskGone(fsm, reason, err)
		}
		// Include session_id: the composite key is session+task; task_id alone cannot locate the task
		// in a multi-session deployment. err now carries the actual out-of-range value (chaincli.uint64ToInt64).
		c.log.Warn("task reconciliation query failed",
			"session_id", sessionID, "task_id", taskID, "reason", reason, "err", err)
		return false
	}
	c.applyAuthoritativeTask(fsm, snapshot, eventHeight)
	var settlementFacts *chaincli.SettlementBuildFacts
	if snapshot.State == types.Verifying && snapshot.Status != "RECEIPT_ONLY_ACCEPTED" {
		if c.settlementFacts == nil {
			c.log.Warn("task reconciliation skipped: SettlementBuildFacts Query is not configured", "task_id", taskID, "reason", reason)
			return false
		}
		factsCtx, factsCancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
		facts, factsErr := c.settlementFacts.QuerySettlementBuildFacts(factsCtx, chaincli.TaskKey{SessionID: sessionID, TaskID: taskID})
		factsCancel()
		if factsErr != nil {
			if c.settlementFactsUnsupported(factsErr) {
				return taskNotificationsObserved(snapshot, nil, notifications)
			}
			c.log.Warn("settlement facts reconciliation query failed", "task_id", taskID, "reason", reason, "err", factsErr)
			return false
		}
		if err := fsm.reconcileSettlementFacts(facts, true); err != nil {
			c.log.Warn("settlement facts reconciliation failed", "task_id", taskID, "reason", reason, "err", err)
			return false
		}
		c.reconcileSettleSelection(fsm)
		settlementFacts = &facts
	}
	return taskNotificationsObserved(snapshot, settlementFacts, notifications)
}

// taskGoneWarnEvery is how often the WARN for one task missing from the chain repeats; it is
// reconciled every few blocks, and the rest go to DEBUG.
const taskGoneWarnEvery = 10 * time.Minute

// reconcileTaskGone handles a task this Builder saw on chain and the chain no longer returns. The
// chain removes tasks itself (task cleanup and failure pruning), so on the same chain the task is
// over and is closed locally. That needs the chain identity: without it a reset chain, or a node
// that answers for another chain, would close live tasks, so the task stays and is retried.
func (c *Coordinator) reconcileTaskGone(fsm *taskFSM, reason string, err error) bool {
	sessionID, taskID := fsm.sessionID, fsm.taskID
	if c.chainReset != nil {
		ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
		same, idErr := c.chainReset.SameChain(ctx)
		cancel()
		switch {
		case idErr != nil:
			c.log.Debug("chain identity check failed; keeping task missing from the chain",
				"session_id", sessionID, "task_id", taskID, "err", idErr)
		case same:
			height, _ := c.currentChainHeight()
			if fsm.closeGone(height) {
				c.forgetTaskGone(sessionID, taskID)
				c.log.Info("task no longer on chain; closed locally",
					"session_id", sessionID, "task_id", taskID, "height", height)
				return true
			}
		default:
			c.log.Debug("task missing from a chain whose identity changed; keeping it",
				"session_id", sessionID, "task_id", taskID)
		}
	}
	c.warnTaskGone(sessionID, taskID, reason, err)
	return false
}

func (c *Coordinator) warnTaskGone(sessionID, taskID, reason string, err error) {
	key := sessionID + "|" + taskID
	now := time.Now()
	c.taskGoneMu.Lock()
	last, seen := c.taskGoneWarned[key]
	warn := !seen || now.Sub(last) >= taskGoneWarnEvery
	if warn {
		if c.taskGoneWarned == nil {
			c.taskGoneWarned = make(map[string]time.Time)
		}
		c.taskGoneWarned[key] = now
	}
	c.taskGoneMu.Unlock()
	log := c.log.Debug
	if warn {
		log = c.log.Warn
	}
	log("task reconciliation query failed: task not found on chain",
		"session_id", sessionID, "task_id", taskID, "reason", reason, "err", err)
}

func (c *Coordinator) forgetTaskGone(sessionID, taskID string) {
	c.taskGoneMu.Lock()
	delete(c.taskGoneWarned, sessionID+"|"+taskID)
	c.taskGoneMu.Unlock()
}

func (c *Coordinator) suspectChainReset(reason string) {
	if c.chainReset != nil {
		c.chainReset.Suspect(reason)
	}
}

// settlementFactsUnsupported reports whether err says the chain has no settlement build facts
// query. That is a property of the node API, not a transient failure, so callers reconcile without
// the facts instead of retrying every block, and it is logged once.
func (c *Coordinator) settlementFactsUnsupported(err error) bool {
	if !errors.Is(err, chaincli.ErrNotSupportedOnChain) {
		return false
	}
	c.settlementFactsGone.Do(func() {
		c.log.Debug("settlement build facts are not available on this chain; reconciling without them", "err", err)
	})
	return true
}

func taskNotificationsObserved(snapshot chaincli.OnChainTask, settlementFacts *chaincli.SettlementBuildFacts, notifications []chaincli.ChainEvent) bool {
	for _, event := range notifications {
		if snapshot.State == types.Failed {
			continue
		}
		switch event.Type {
		case chaincli.EventAssignAccepted:
			if snapshot.Assignment.AssignAcceptHeight == 0 && len(snapshot.AssignedSet) == 0 && !taskStateAtLeastAssigned(snapshot.State) {
				return false
			}
		case chaincli.EventAssignmentFinalized:
			if !taskStateAtLeastAssigned(snapshot.State) {
				return false
			}
		case chaincli.EventOpenVerifyAccepted:
			if !taskStateAtLeastVerifying(snapshot.State) {
				return false
			}
		case chaincli.EventWorkerRevealAccepted:
			if settlementFacts == nil || !settlementFacts.HasWorkerRevealReceipt {
				return false
			}
		case chaincli.EventFullResultRevealAccepted:
			if settlementFacts == nil || !settlementFactsHasFullReveal(*settlementFacts, taskEventVerifier(event)) {
				return false
			}
		case chaincli.EventSampleReady:
			if len(snapshot.SampleSeed) == 0 && !taskStateAtLeastSettled(snapshot.State) {
				return false
			}
		case chaincli.EventSettleAccepted:
			if !taskStateAtLeastSettled(snapshot.State) {
				return false
			}
		case chaincli.EventSweepDeadlineAccepted:
			// Block-inclusion confirmation of MsgSweepDeadline: a terminal transition must be visible as a failed
			// task in the on-chain snapshot. The loop top already admitted a Failed snapshot as "observed"; reaching
			// here means the snapshot has not converged yet, so keep reconciling instead of accepting.
			// Non-terminal transitions (COMMIT_CLOSED / REVEAL_CLOSED and other window advances) are not expected
			// to be terminal anyway; leave them to the next event or periodic reconciliation.
			if sweepConvergesTask(event) {
				return false
			}
		case chaincli.EventTaskStateChanged:
			switch event.EventCode {
			case "ASSIGNMENT_FAILED", "WORKER_TIMEOUT":
				return false
			case "INFER_RECEIPT_ACCEPTED", "REVEAL_PHASE_STARTED":
				if !taskStateAtLeastVerifying(snapshot.State) {
					return false
				}
			case "TASK_FINALITY_ADVANCED", "CHALLENGE_OPENED", "CHALLENGE_CLOSED":
				if !taskStateAtLeastSettled(snapshot.State) {
					return false
				}
			}
		}
	}
	return true
}

func settlementFactsHasFullReveal(facts chaincli.SettlementBuildFacts, verifier string) bool {
	if verifier == "" {
		return len(facts.FullResultReveals) > 0
	}
	for _, reveal := range facts.FullResultReveals {
		if reveal.Verifier == verifier {
			return true
		}
	}
	return false
}

func (c *Coordinator) reconcileMissingPendingTask(fsm *taskFSM, eventHeight int64, reason string) bool {
	fsm.mu.Lock()
	if fsm.state != types.Pending {
		fsm.mu.Unlock()
		return false
	}
	taskID := fsm.taskID
	txHash := append([]byte(nil), fsm.assignTxHash...)
	deadline := fsm.order.DeadlineHeight
	fsm.mu.Unlock()
	height, authoritative := c.currentChainHeight()
	if eventHeight > 0 && uint64(eventHeight) > height {
		height, authoritative = uint64(eventHeight), true
	}
	expired := authoritative && deadline != 0 && height > deadline

	if len(txHash) == 0 {
		if expired {
			fsm.onAssignTimeout(height)
			return true
		}
		c.log.Debug("pending task not on chain yet", "task_id", taskID, "reason", reason)
		return true
	}
	if c.txQuery == nil {
		if expired {
			fsm.onAssignTimeout(height)
			return true
		}
		c.log.Warn("AssignTx confirmation skipped: Tx Query is not configured", "task_id", taskID)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	result, err := c.txQuery.QueryTx(ctx, txHash)
	cancel()
	if err != nil {
		if errors.Is(err, chaincli.ErrNotFound) {
			if expired {
				fsm.onAssignTimeout(height)
				return true
			}
			c.log.Debug("AssignTx awaiting DeliverTx", "task_id", taskID, "tx_hash", hex.EncodeToString(txHash))
			return true
		}
		c.log.Warn("AssignTx confirmation query failed", "task_id", taskID,
			"tx_hash", hex.EncodeToString(txHash), "err", err)
		if expired {
			fsm.onAssignTimeout(height)
		}
		return true
	}
	if result.Code != 0 {
		fsm.onAssignRejected(result)
		return true
	}
	c.log.Warn("AssignTx DeliverTx succeeded but task query is not available yet",
		"task_id", taskID, "tx_hash", hex.EncodeToString(txHash), "height", result.Height)
	return true
}

// fillAcceptedReceipt gives a Builder that did not receive the Worker's signed receipt the
// accepted output_hash and infer_receipt_hash from the chain. The Worker hands its receipt to
// one Builder only, and without these hashes the others drop every Verifier handraise. It
// does not make the output or evidence available on this Builder.
func (c *Coordinator) fillAcceptedReceipt(fsm *taskFSM) {
	if c.inferReceipts == nil || !fsm.needsAcceptedReceipt() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	receipt, err := c.inferReceipts.QueryInferReceipt(ctx, fsm.taskID)
	cancel()
	if err != nil {
		c.log.Warn("accepted infer receipt query failed", "task_id", fsm.taskID, "err", err)
		return
	}
	fsm.setAcceptedReceipt(receipt)
}

func (c *Coordinator) applyAuthoritativeTask(fsm *taskFSM, snapshot chaincli.OnChainTask, height int64) {
	// task_hash is a consensus fact and may only come from on-chain query/event. Once recorded, subsequent
	// Worker proposals for the same task can take the ExistingTaskRefV1 branch per §4.2.1.
	fsm.rememberAcceptedTaskHash(snapshot.Assignment.AcceptedTaskHash)
	if snapshot.State == types.Failed {
		fsm.onAuthoritativeFailure(snapshot, height)
		return
	}
	if snapshot.Compacted {
		closeHeight := uint64(0)
		if height > 0 {
			closeHeight = uint64(height)
		}
		if currentHeight, authoritative := c.currentChainHeight(); authoritative {
			closeHeight = currentHeight
		}
		fsm.closeCompacted(snapshot, closeHeight)
		return
	}
	fsm.mu.Lock()
	state, phase := fsm.state, fsm.phase
	fsm.mu.Unlock()

	if state == types.Pending && phase == types.PhaseUnspecified &&
		(snapshot.Assignment.AssignAcceptHeight != 0 || len(snapshot.AssignedSet) > 0 || taskStateAtLeastAssigned(snapshot.State)) {
		fsm.onAssignAccepted(chaincli.AssignAccepted{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, AssignedSet: snapshot.AssignedSet,
			Height: authoritativeEventHeight(snapshot.Assignment.AssignAcceptHeight, height),
		})
		phase = types.PhaseAssignRandomnessPending
	}
	if state == types.Pending && taskStateAtLeastAssigned(snapshot.State) {
		finalizedHeight := snapshot.Assignment.WinnerConfirmHeight
		if finalizedHeight == 0 {
			finalizedHeight = snapshot.Assignment.AssignmentRandomnessHeight
		}
		fsm.onAssignmentFinalized(chaincli.AssignmentFinalized{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, Winner: snapshot.Winner,
			Height:              authoritativeEventHeight(finalizedHeight, height),
			InferDeadlineHeight: snapshot.Assignment.InferDeadlineHeight,
		})
		state = types.Assigned
	}
	// Once the chain accepts the receipt (from RECEIPT_COMMITTED on) OPEN_VERIFY should be sent; it and
	// "verifiers decided" are two different facts, the former only opens the verify window.
	if (state == types.Assigned || state == types.Verifying) &&
		(snapshot.ReceiptAccepted || snapshot.InferReceipt.InferReceiptHash != "") {
		c.fillAcceptedReceipt(fsm)
		fsm.onInferReceiptAccepted()
	}
	// Assignment is settled only when the chain has actually fixed the verifier set; RECEIPT_COMMITTED also
	// maps to Verifying, but Verifiers is empty then, and treating it as assignment would notify 0 verifiers.
	if state == types.Assigned && taskStateAtLeastVerifying(snapshot.State) && len(snapshot.Verifiers) > 0 {
		fsm.onOpenVerifyAccepted(chaincli.OpenVerifyAccepted{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, Verifiers: snapshot.Verifiers, Deadlines: snapshot.Deadlines,
			Height: authoritativeEventHeight(snapshot.VerifierAssignment.OpenVerifyHeight, height),
		})
		state = types.Verifying
	}
	if state == types.Verifying && len(snapshot.SampleSeed) > 0 {
		fsm.onSampleReady(chaincli.SampleReady{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, SampleSeed: snapshot.SampleSeed,
			ReadyHeight: authoritativeEventHeight(snapshot.VerifierAssignment.SampleSeedReadyHeight, height),
			Height:      authoritativeEventHeight(snapshot.VerifierAssignment.SampleSeedReadyHeight, height),
		})
	}
	if state == types.Verifying && taskStateAtLeastSettled(snapshot.State) {
		fsm.onSettleAccepted(chaincli.SettleAccepted{
			SessionID: snapshot.SessionID, TaskID: snapshot.TaskID, TaskVerdict: snapshot.TaskVerdict,
			Settlement: snapshot.Settlement, Height: authoritativeEventHeight(snapshot.Settlement.SettlementHeight, height),
		})
	}

	fsm.mu.Lock()
	fsm.reconcile(snapshot)
	_ = fsm.save()
	fsm.mu.Unlock()
	c.reconcileSettleSelection(fsm)
	if currentHeight, authoritative := c.currentChainHeight(); authoritative {
		fsm.closeSettledAtHeight(currentHeight)
	}
}

func authoritativeEventHeight(authoritative uint64, fallback int64) int64 {
	if authoritative > 0 && authoritative <= math.MaxInt64 {
		return int64(authoritative)
	}
	return fallback
}

func taskStateAtLeastAssigned(state types.TaskState) bool {
	return state == types.Assigned || state == types.Verifying || state == types.Settled || state == types.Closed
}

func taskStateAtLeastVerifying(state types.TaskState) bool {
	return state == types.Verifying || state == types.Settled || state == types.Closed
}

func taskStateAtLeastSettled(state types.TaskState) bool {
	return state == types.Settled || state == types.Closed
}

func parseInt64Attr(value string) int64 {
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}

func parseUint64Attr(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}

// sweepConvergesTask reads the event attr directly to decide whether this sweep converged the task,
// reusing chaincli's transition-code semantics so the two places do not diverge.
func sweepConvergesTask(event chaincli.ChainEvent) bool {
	return chaincli.SweepDeadlineAccepted{
		TransitionCode: parseDeadlineTransitionAttr(event.Attrs["transition_code"]),
	}.ConvergesTask()
}

// parseDeadlineKindAttr / parseDeadlineTransitionAttr restore the event attr (prefix stripped by chaincli)
// into the mirror enums. Uses the proto-generated _value tables rather than a hand-written switch so
// that a new kind / transition in the contract is not silently missed here.
func parseDeadlineKindAttr(value string) taskv1.DeadlineKindV1 {
	if value == "" {
		return taskv1.DeadlineKindV1_DEADLINE_KIND_V1_UNSPECIFIED
	}
	return taskv1.DeadlineKindV1(taskv1.DeadlineKindV1_value["DEADLINE_KIND_V1_"+value])
}

func parseDeadlineTransitionAttr(value string) taskv1.DeadlineTransitionCode {
	if value == "" {
		return taskv1.DeadlineTransitionCode_DEADLINE_TRANSITION_CODE_UNSPECIFIED
	}
	return taskv1.DeadlineTransitionCode(taskv1.DeadlineTransitionCode_value["DEADLINE_TRANSITION_CODE_"+value])
}

func parseTaskVerdict(value string) types.TaskVerdict {
	switch value {
	case "PASS":
		return types.VerdictPass
	case "FAIL":
		return types.VerdictFail
	case "NO_CONSENSUS":
		return types.VerdictNoConsensus
	case "FAIL_REVEAL_TIMEOUT":
		return types.VerdictFailRevealTimeout
	case "WORKER_TIMEOUT":
		return types.VerdictWorkerTimeout
	case "VERIFY_UNAVAILABLE":
		return types.VerdictVerifyUnavailable
	case "ASSIGN_TIMEOUT":
		return types.VerdictAssignTimeout
	default:
		return types.VerdictUnspecified
	}
}

// decodeSeedAttr decodes the seed string in a chain event attr back to bytes: hex first, then base64;
// if neither, use the raw bytes (legacy encoding undefined, best-effort).
func decodeSeedAttr(s string) []byte {
	if s == "" {
		return nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	return []byte(s)
}

// splitCSV splits a comma-separated attr value into non-empty segments.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// eventLoop consumes chain events and forwards to OnChainEvent to drive the matching order state machine.
func (c *Coordinator) eventLoop() {
	events := c.chain.Events()
	protocolEvents := c.protocolEvents
	for events != nil || protocolEvents != nil {
		select {
		case <-c.stop:
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			c.log.Debug("chain event", "type", ev.Type, "session_id", ev.SessionID, "task_id", ev.TaskID, "height", ev.Height)
			c.OnChainEvent(ev)
		case ev, ok := <-protocolEvents:
			if !ok {
				protocolEvents = nil
				continue
			}
			c.log.Debug("protocol chain event", "type", ev.Type, "height", ev.Height)
			c.OnChainEvent(ev)
		}
	}
}
