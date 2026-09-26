// Package app is the composition root of nexus: it wires the modules in dependency order and provides a single Start/Stop (Implementation Design §2).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/identity"
	"github.com/TrueOpen/nexus/internal/ingress"
	"github.com/TrueOpen/nexus/internal/ingresstls"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// module is a named startable/stoppable unit.
type module struct {
	name  string
	start func(context.Context) error
	stop  func(context.Context) error
}

type lifecycle interface {
	Start(context.Context) error
	Stop(context.Context) error
}

type outputRecoveryLifecycle struct {
	lifecycle
	complete func() error
}

func (l outputRecoveryLifecycle) Start(ctx context.Context) error {
	if err := l.lifecycle.Start(ctx); err != nil {
		return err
	}
	if err := l.complete(); err != nil {
		_ = l.lifecycle.Stop(ctx)
		return fmt.Errorf("complete output recovery: %w", err)
	}
	return nil
}

func runtimeModules(taskData, rl, coord, outputs, ing lifecycle) []module {
	return []module{
		{"task-data", taskData.Start, taskData.Stop},
		{"relay", rl.Start, rl.Stop},
		{"coordinator", coord.Start, coord.Stop},
		{"output-delivery", outputs.Start, outputs.Stop},
		{"ingress", ing.Start, ing.Stop},
	}
}

type taskDataTaskAuthority interface {
	LatestHeight(context.Context) (uint64, error)
	QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error)
}

type taskDataKeyAuthority interface {
	QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error)
}

// taskDataProfileAuthority is the query path Finalize uses to decide whether a manifest belongs to the locked schema.
type taskDataProfileAuthority interface {
	QueryProfile(ctx context.Context, modelID string, profileVersion uint32) (chaincli.ProfileState, error)
}

type taskDataAuthority struct {
	tasks    taskDataTaskAuthority
	keys     taskDataKeyAuthority
	profiles taskDataProfileAuthority
}

func newTaskDataAuthority(tasks taskDataTaskAuthority, keys taskDataKeyAuthority, profiles taskDataProfileAuthority) taskDataAuthority {
	return taskDataAuthority{tasks: tasks, keys: keys, profiles: profiles}
}

func (a taskDataAuthority) LatestHeight(ctx context.Context) (uint64, error) {
	return a.tasks.LatestHeight(ctx)
}

func (a taskDataAuthority) QueryTask(ctx context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	return a.tasks.QueryTask(ctx, key)
}

func (a taskDataAuthority) QueryCurrentServiceKey(ctx context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	return a.keys.QueryCurrentServiceKey(ctx, participantType, operator)
}

func (a taskDataAuthority) QueryProfile(ctx context.Context, modelID string, profileVersion uint32) (chaincli.ProfileState, error) {
	return a.profiles.QueryProfile(ctx, modelID, profileVersion)
}

type taskDataLifecycle struct {
	log       *slog.Logger
	store     *taskdata.Store
	policy    taskdata.RecoveryResolver
	authority taskDataTaskAuthority
	interval  time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (l *taskDataLifecycle) Start(ctx context.Context) error {
	if err := l.store.Recover(ctx, l.policy); err != nil {
		return fmt.Errorf("recover task data: %w", err)
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		ticker := time.NewTicker(l.interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				height, err := l.authority.LatestHeight(loopCtx)
				if err != nil || height == 0 {
					if loopCtx.Err() == nil {
						l.log.Warn("taskdata: retention height unavailable; retaining objects")
					}
					continue
				}
				if err := l.store.Sweep(loopCtx, height, l.policy); err != nil && loopCtx.Err() == nil {
					l.log.Warn("taskdata: retention sweep failed", "height", height, "err", err)
				}
			}
		}
	}()
	return nil
}

func (l *taskDataLifecycle) Stop(context.Context) error {
	if l.cancel != nil {
		l.cancel()
		l.wg.Wait()
	}
	return nil
}

func taskDataRoot(dataDir string) string { return filepath.Join(dataDir, "task-data") }

type App struct {
	chainReset       *chainreset.Monitor
	cfg              config.Config
	log              *slog.Logger
	kv               kv.Store
	modules          []module
	beginIngressStop func(context.Context) error
}

type chainEventOptions struct {
	task          []chaincli.Option
	hub           []chaincli.Option
	protocolOnHub bool
}

func newChainEventOptions(store kv.Store, mode config.AuthorityMode) chainEventOptions {
	options := chainEventOptions{
		task: []chaincli.Option{
			chaincli.WithEventStore(store),
			chaincli.WithHeightEvents(2 * time.Second),
		},
	}
	if mode == config.AuthorityHub {
		options.hub = []chaincli.Option{
			chaincli.WithEventStore(store),
			chaincli.WithProtocolEvents(),
		}
		options.protocolOnHub = true
		return options
	}
	options.task = append(options.task, chaincli.WithProtocolEvents())
	return options
}

// New wires up every module (dependency order: bus -> chain -> builder-registration -> relay -> coordinator -> ingress).
func New(cfg config.Config, log *slog.Logger) (*App, error) {
	if err := cfg.TaskData.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateSecurity(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateTransport(); err != nil {
		return nil, err
	}
	// The ingress terminates TLS itself (ADR-0015): the certificate is created by `nexus tls init` and the operator puts the
	// fingerprint on chain via `nexus builder register`; start only loads it and checks it against the on-chain fingerprint in the registration module.
	// When TLS is not enabled it stays plaintext h2c.
	tlsMaterial, err := ingresstls.Load(cfg.Ingress.TLS, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if tlsMaterial.Enabled() {
		log.Info("ingress tls enabled", "tls_pubkey_hash", tlsMaterial.PubKeyHash, "not_after", tlsMaterial.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	// Local persistence: open pebble under DataDir (for crash recovery); failing to open it is treated as a config error and fails outright --
	// silently degrading to memory would quietly disable restart recovery in production.
	// Local state belongs to one chain: it is checked against the chain's identity before anything reads it.
	var identitySource chainreset.Source
	if src, ok := chaincli.New(log, cfg.Chain).(chainreset.Source); ok {
		identitySource = src
	}
	store, chainResetMonitor, err := openLocalState(log, cfg.DataDir, cfg.Chain.ChainID, identitySource)
	if err != nil {
		return nil, err
	}

	// With NATS servers configured, use the real bus; otherwise fall back to the stub (offline / unit tests).
	var bus msgbus.Bus
	if len(cfg.NATS.Servers) > 0 {
		bus = msgbus.NewNATS(log, cfg.NATS)
	} else {
		bus = msgbus.NewStub(log, cfg.NATS.Servers)
	}
	authority, err := cfg.BuilderAuthority()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("builder authority: %w", err)
	}
	eventOptions := newChainEventOptions(store, authority.Mode)
	taskChain := chaincli.New(log, cfg.Chain, eventOptions.task...) // Task Chain: source of truth for task queries, txs and events.
	registrationChain := taskChain
	var hubChain chaincli.Client
	if authority.Mode == config.AuthorityHub {
		hubChain = chaincli.New(log, authority.Chain, eventOptions.hub...)
		registrationChain = hubChain
	} else {
		log.Warn("builder registration using single-chain compatibility mode",
			"authority_chain_id", authority.Chain.ChainID)
	}
	rl := relay.NewKV(log, store) // the credential store is written through to disk so restart recovery still holds the credentials
	taskStore, err := taskdata.NewStore(log, taskDataRoot(cfg.DataDir), store, taskdata.Config{
		InlineMaxBytes: cfg.TaskData.InlineMaxBytes, ChunkSizeBytes: cfg.TaskData.ChunkSizeBytes,
		MaxRangeBytes: cfg.TaskData.MaxRangeBytes, MaxBlobBytes: cfg.TaskData.MaxBlobBytes,
		SpoolReservationBytes:      cfg.TaskData.SpoolReservationBytes,
		DiskAcceptWatermarkPercent: cfg.TaskData.DiskAcceptWatermarkPercent,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("task data: %w", err)
	}

	outputs, err := outputdelivery.New(log, store, outputdelivery.Config{
		RequirePlaintext: cfg.OutputDelivery.RequirePlaintextOutput,
		MaxBytes:         cfg.OutputDelivery.MaxBytes,
		PlaintextTTL:     cfg.OutputDelivery.PlaintextTTL,
		TombstoneTTL:     cfg.OutputDelivery.TombstoneTTL,
		SweepInterval:    cfg.OutputDelivery.SweepInterval,
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("output delivery: %w", err)
	}
	payloads, err := payloadstore.New(log, store, payloadstore.Config{
		MaxBytes: inlinePayloadMax(cfg.PayloadStorage.MaxBytes, cfg.TaskData.InlineMaxBytes),
	}, payloadstore.WithTaskData(taskStore))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("payload storage: %w", err)
	}

	// Signer: with a keystore/private key configured, real signed submission is enabled; otherwise it degrades to the unsigned skeleton mode.
	coordOpts := []coordinator.Option{
		coordinator.WithChainResetSuspect(chainResetMonitor.Suspect),
		coordinator.WithOutputDelivery(outputs),
		coordinator.WithPayloadStore(payloads),
		coordinator.WithDeadlineSweep(coordinator.DeadlineSweepPolicy{
			Enabled:     cfg.Chain.DeadlineSweep.Enabled,
			GraceBlocks: cfg.Chain.DeadlineSweep.GraceBlocks,
		}),
	}
	if eventOptions.protocolOnHub {
		coordOpts = append(coordOpts, coordinator.WithProtocolEventSource(hubChain.Events()))
	}
	sg, err := identity.LoadSigner(cfg.Identity)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("identity: %w", err)
	}
	selfAddr, err := identity.ResolveBuilderAddress(cfg.Identity, sg)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	var registrationModule *module
	var serviceSG signer.Signer
	ingressOpts := []ingress.Option{
		ingress.WithPayloadMaxBytes(inlinePayloadMax(cfg.PayloadStorage.MaxBytes, cfg.TaskData.InlineMaxBytes)),
		ingress.WithReadMaxBytes(cfg.TaskData.ChunkSizeBytes),
	}
	if strings.TrimSpace(cfg.NATS.SentinelFile) != "" {
		// The AUTH account sentinel JWT (public, non-secret data) is distributed to Cortex by the ingress; see GET /v1/nats/sentinel.
		ingressOpts = append(ingressOpts, ingress.WithNATSSentinelFile(cfg.NATS.SentinelFile))
	}
	if len(cfg.NATS.AdvertiseServers) > 0 {
		// The NATS address and certificate go to Cortex with the sentinel (ADR-0016 decision one item 1).
		ingressOpts = append(ingressOpts, ingress.WithNATSAdvertise(cfg.NATS.AdvertiseServers, cfg.NATS.CAFile))
	}
	if tlsMaterial.Enabled() {
		ingressOpts = append(ingressOpts, ingress.WithTLS(tlsMaterial.Certificate))
	}
	if sg != nil {
		log.Info("tx signing enabled", "address", sg.Address())
		var sharedServiceKey bool
		serviceSG, sharedServiceKey, err = identity.LoadServiceSigner(cfg.Identity, sg)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("identity: %w", err)
		}
		if sharedServiceKey {
			log.Warn("builder account and service signatures share one key; configure identity.service_keystore_file for key separation")
		}
		// /.well-known/trueopen-builder.json is now only a convenience document for off-chain discovery: the frozen contract
		// replaced the on-chain descriptor with an endpoints list, and there is no descriptor_uri/hash left to anchor it.
		// So leaving public_endpoint empty (with only identity.service_endpoints configured) is no longer an error,
		// it just means this document is not served.
		if strings.TrimSpace(cfg.Identity.PublicEndpoint) != "" {
			descriptor := nodecontract.BuilderDescriptor{
				SchemaVersion: nodecontract.DescriptorSchemaV1, BuilderAddress: sg.Address(),
				ServiceEndpoint: cfg.Identity.PublicEndpoint, Moniker: cfg.Identity.Moniker, P2PHint: cfg.Identity.P2PHint,
			}
			descriptorBody, _, err := descriptor.Marshal()
			if err != nil {
				_ = store.Close()
				return nil, fmt.Errorf("identity descriptor: %w", err)
			}
			ingressOpts = append(ingressOpts, ingress.WithBuilderDescriptor(descriptorBody))
		}
		coordOpts = append(coordOpts,
			coordinator.WithSubmitter(coordinator.NewSignedSubmitter(log, taskChain, registrationChain, sg, serviceSG, cfg.Chain)),
			coordinator.WithIdentitySigner(sg),
			coordinator.WithBuilderRegistry(registrationChain),
			coordinator.WithBuilderSelectionQuerier(taskChain),              // settlement ordering reads task TaskBuilders; the grace block count reads Hub params
			stage1AdmissionOption(sg, registrationChain, cfg.Chain.ChainID)) // Hub is authoritative for the active BuilderSet.
		registrationModule = newBuilderRegistrationModule(log, store, registrationChain, sg, serviceSG, cfg.Identity, authority, tlsMaterial.PubKeyHash)
	} else {
		log.Warn("tx signing NOT configured (NEXUS_KEYSTORE_FILE or NEXUS_PRIVATE_KEY_FILE/PRIVATE_KEY/HEX); task transactions are disabled and credentials are unsigned (dev only)")
	}

	// A Profile is model registration data on the Hub side (QueryProfile goes through hubQuery), so this takes
	// registrationChain rather than taskChain.
	taskAuthority := newTaskDataAuthority(taskChain, registrationChain, registrationChain)
	if serviceSG != nil {
		// The signing/verification port of BusEnvelopeV1 (contract §5.2): outbound frames are signed with the current
		// service key's private key, inbound frames are verified against the on-chain current binding looked up by (participant_type, operator).
		// No service key configured means not a single task-control frame can be sent or received -- this is fail-closed,
		// not a degradation: the contract does not allow "fall back to unsigned after verification fails".
		coordOpts = append(coordOpts,
			coordinator.WithServiceKey(serviceSG, taskAuthority, cfg.Identity.Bech32Prefix))
	} else {
		log.Warn("service key NOT configured; NATS task-control frames cannot be signed or verified " +
			"(contract §5.2 does not allow unsigned envelopes, so the coordinator emits no trueopen.* frames)")
	}

	coord := coordinator.New(log, bus, taskChain, rl, store, selfAddr, cfg.Chain.ChainID, coordOpts...)
	var taskAuthorizer *taskdata.Authorizer
	if serviceSG != nil {
		// The EIP-712 numeric chainId is read from Hub params only: the Keeper ante uses that same value when verifying a
		// user's order signature, and Nexus must match it when verifying a USER retrieval request; no local config option can override it.
		evmCtx, cancelEVM := context.WithTimeout(context.Background(), 30*time.Second)
		evmChainID, evmErr := registrationChain.QueryEVMChainID(evmCtx)
		cancelEVM()
		if evmErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("query hub evm_chain_id: %w", evmErr)
		}
		log.Info("EIP-712 chain id loaded from hub params", "evm_chain_id", evmChainID, "chain_id", cfg.Chain.ChainID)
		taskAuthorizer, err = taskdata.NewAuthorizer(taskdata.AuthorizerConfig{
			ChainID: cfg.Chain.ChainID, EVMChainID: evmChainID, BuilderAddress: selfAddr, AddressPrefix: cfg.Identity.Bech32Prefix,
			RequestTTLBlocks:     cfg.TaskData.RequestTTLBlocks,
			RetentionLeaseBlocks: cfg.TaskData.RetentionLeaseBlocks,
		}, store, taskAuthority, serviceSG)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("task data authorizer: %w", err)
		}
		taskService, serviceErr := taskdata.NewService(taskStore, taskAuthorizer)
		if serviceErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("task data service: %w", serviceErr)
		}
		ingressOpts = append(ingressOpts, ingress.WithTaskDataService(taskService))
		// OPEN_VERIFY and the Verifier proposal wait for local data-ready (04 §326), which the task
		// data plane answers and announces when the Worker's Finalize succeeds.
		coord.SetResultReadiness(taskService)
		taskService.SetResultFinalizedObserver(coord.OnResultFinalized)
		if stream := cfg.TaskData.OutputStream; stream.Enabled {
			// ADR-0017 streaming OUTPUT: the limits are network-wide uniform (Deployment Baseline) and frames are fanned out to subscribers per Task;
			// enabled by default (cortex only streams); when disabled the three RPCs return Unimplemented.
			taskService.SetOutputStreamConfig(taskdata.OutputStreamConfig{
				MaxLeaves: stream.MaxOutputMMRLeaves, MinFrameBytes: stream.MinFrameBytes,
				MaxFrameBytes: cfg.TaskData.ChunkSizeBytes, MaxAttachmentBytes: stream.MaxAttachmentBytes,
			})
			dispatcher := taskdata.NewOutputDispatcher(int(stream.SubscriberBufferFrames))
			ingressOpts = append(ingressOpts, ingress.WithOutputStream(taskService, dispatcher, store))
			log.Info("streaming output enabled (ADR-0017)",
				"max_output_mmr_leaves", stream.MaxOutputMMRLeaves, "min_frame_bytes", stream.MinFrameBytes,
				"max_frame_bytes", cfg.TaskData.ChunkSizeBytes, "subscriber_buffer_frames", stream.SubscriberBufferFrames)
		}
	} else if cfg.TaskData.OutputStream.Enabled {
		log.Warn("task_data.output_stream.enabled ignored: service key is not configured, task data plane is off")
	}
	recoveryPolicy, err := taskdata.NewRecoveryPolicy(taskAuthority, taskChain, taskAuthorizer, coord)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("task data recovery: %w", err)
	}
	taskDataModule := &taskDataLifecycle{
		log: log, store: taskStore, policy: recoveryPolicy, authority: taskAuthority,
		interval: cfg.TaskData.SweepInterval,
	}
	outputs.SetPreparedResolver(coord.HasAcceptedOutput)
	outputs.SetTaskTerminal(coord.IsTaskTerminal)
	ing, err := ingress.New(log, cfg.Ingress, ingress.AuthParams{
		ChainID:         cfg.Chain.ChainID,
		BuilderAddress:  selfAddr,
		Bech32Prefix:    cfg.Identity.Bech32Prefix,
		RequireEnvelope: cfg.Ingress.RequireSDKEnvelope,
		ServiceKeys:     registrationChain,
	}, coord, ingressOpts...)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("ingress: %w", err)
	}

	modules := []module{
		{"msgbus", bus.Start, bus.Stop},
		{"task-chaincli", taskChain.Start, taskChain.Stop},
	}
	if hubChain != nil {
		modules = append(modules, module{"hub-chaincli", hubChain.Start, hubChain.Stop})
	}
	if registrationModule != nil {
		modules = append(modules, *registrationModule)
	}
	outputModule := outputRecoveryLifecycle{
		lifecycle: outputs,
		complete:  coord.CompleteOutputRecovery,
	}
	modules = append(modules, runtimeModules(taskDataModule, rl, coord, outputModule, ing)...)

	return &App{
		cfg: cfg, log: log, kv: store, modules: modules,
		beginIngressStop: ing.BeginStop,
		chainReset:       chainResetMonitor,
	}, nil
}

func inlinePayloadMax(legacyMax int, inlineMax uint64) int {
	if legacyMax <= 0 {
		return legacyMax
	}
	if inlineMax < uint64(legacyMax) {
		return int(inlineMax)
	}
	return legacyMax
}

func stage1AdmissionOption(accountSigner signer.Signer, registry coordinator.BuilderRegistry, taskChainID string) coordinator.Option {
	if accountSigner == nil {
		return coordinator.WithOrderAdmission(nil)
	}
	return coordinator.WithOrderAdmission(coordinator.NewHubStage1Admission(registry, accountSigner.Address(), taskChainID))
}

func newBuilderRegistrationModule(
	log *slog.Logger,
	store kv.Store,
	chain chaincli.Client,
	accountSigner signer.Signer,
	serviceSigner signer.Signer,
	identityCfg config.IdentityConfig,
	authority config.BuilderAuthority,
	tlsPubKeyHash string,
) *module {
	if accountSigner == nil {
		return nil
	}
	reg := builderreg.New(
		log, store, chain,
		coordinator.NewBuilderSubmitter(log, chain, accountSigner, authority.Chain),
		accountSigner, serviceSigner, identityCfg, authority,
		builderreg.WithTLSPubKeyHash(tlsPubKeyHash),
	)
	return &module{name: "builder-registration", start: reg.Start, stop: reg.Stop}
}

// Start brings the modules up in order; if any fails, the already-started ones are rolled back.
// Fatal delivers an error that requires the process to stop, currently only
// chainreset.ErrChainReset. It never delivers when the chain identity check is off.
func (a *App) Fatal() <-chan error { return a.chainReset.Fatal() }

func (a *App) Start(ctx context.Context) error {
	for i, m := range a.modules {
		if err := m.start(ctx); err != nil {
			a.log.Error("module start failed, rolling back", "module", m.name, "err", err)
			for j := i - 1; j >= 0; j-- {
				_ = a.modules[j].stop(ctx)
			}
			_ = a.kv.Close() // release the pebble file lock so the caller can retry the wiring
			return fmt.Errorf("start %s: %w", m.name, err)
		}
	}
	a.log.Info("nexus started", "ingress", a.cfg.Ingress.ListenAddr)
	return nil
}

// Stop shuts down gracefully in reverse order.
func (a *App) Stop(ctx context.Context) error {
	stopRuntimeModules(ctx, a.modules, a.beginIngressStop, func(name string, err error) {
		a.log.Warn("module stop error", "module", name, "err", err)
	})
	_ = a.kv.Close()
	a.log.Info("nexus stopped")
	return nil
}

func stopRuntimeModules(
	ctx context.Context,
	modules []module,
	beginIngressStop func(context.Context) error,
	onError func(name string, err error),
) {
	if beginIngressStop != nil {
		if err := beginIngressStop(ctx); err != nil {
			onError("ingress-drain", err)
		}
	}
	stopped := make(map[string]bool, 2)
	stopNamed := func(name string) {
		for index := len(modules) - 1; index >= 0; index-- {
			if modules[index].name != name {
				continue
			}
			if err := modules[index].stop(ctx); err != nil {
				onError(name, err)
			}
			stopped[name] = true
			return
		}
	}
	// Wake long-lived output streams before waiting for graceful HTTP shutdown.
	stopNamed("output-delivery")
	stopNamed("ingress")
	for index := len(modules) - 1; index >= 0; index-- {
		current := modules[index]
		if stopped[current.name] {
			continue
		}
		if err := current.stop(ctx); err != nil {
			onError(current.name, err)
		}
	}
}
