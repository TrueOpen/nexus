// Package app is the composition root of nexus: it wires the modules in dependency order and provides a single Start/Stop.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/identity"
	"github.com/TrueOpen/nexus/internal/ingress"
	"github.com/TrueOpen/nexus/internal/ingresstls"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/ops"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/outputdelivery"
	"github.com/TrueOpen/nexus/internal/payloadstore"
	"github.com/TrueOpen/nexus/internal/relay"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
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

func runtimeModules(taskData, rl, coord, outputs, streams, ing lifecycle) []module {
	return []module{
		{"task-data", taskData.Start, taskData.Stop},
		{"relay", rl.Start, rl.Stop},
		{"coordinator", coord.Start, coord.Stop},
		{"output-delivery", outputs.Start, outputs.Stop},
		{"dispatch-stream", streams.Start, streams.Stop},
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
	// dispatch is nil when direct dispatch is not configured.
	dispatch *directDispatch
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

// New wires up every module (dependency order: chain -> builder-registration -> relay -> coordinator -> ingress).
func New(cfg config.Config, log *slog.Logger) (*App, error) {
	if err := cfg.TaskData.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Chain.TxConfirm.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateSecurity(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateTransport(); err != nil {
		return nil, err
	}
	// The ingress terminates TLS itself: the certificate is created by `nexus tls init` and the operator puts the
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

	authority, err := cfg.BuilderAuthority()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("builder authority: %w", err)
	}
	eventOptions := newChainEventOptions(store, authority.Mode)
	// Keys owners register on their sessions: the cache follows the task event streams of the
	// sessions this Builder tracks.
	sessionKeys, err := newRegisteredKeys(cfg.Ingress)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("registered session keys: %w", err)
	}
	// The order path (in-flight ledger, session cache, dispatcher) follows the same session
	// streams and the task chain's events once it is built.
	orders := &orderEvents{keys: sessionKeys.cache}
	eventOptions.task = append(eventOptions.task, chaincli.WithSessionStreamObserver(orders), chaincli.WithEventObserver(orders.observe))
	eventOptions.hub = append(eventOptions.hub, chaincli.WithEventObserver(orders.observeHub))
	// Current service keys are read on every stream message, handraise and Builder signature; the
	// cache keeps them briefly and the SERVICE_KEY_ROTATED event, on whichever client carries the
	// protocol stream, drops a rotated key at once.
	// The same events stop this Builder's ring from signing when its own key is revoked, and end a
	// Cortex stream whose binding key the Cortex rotated out or had revoked.
	keyEvents := &serviceKeyEvents{}
	eventOptions.task = append(eventOptions.task, chaincli.WithEventObserver(keyEvents.observe))
	eventOptions.hub = append(eventOptions.hub, chaincli.WithEventObserver(keyEvents.observe))
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
	if sg != nil && len(cfg.Identity.VRFKeyFiles) > 0 {
		// A dispatching Builder follows the events addressed to it as Builder: compensation claims
		// on its tickets, dispatch challenges on its records and how they ended. The stream resumes
		// from its stored cursor.
		eventOptions.task = append(eventOptions.task, chaincli.WithBuilderRoleEvents(selfAddr))
	}
	taskChain := chaincli.New(log, cfg.Chain, eventOptions.task...) // Task Chain: source of truth for task queries, txs and events.
	sessionKeys.chain = taskChain
	registrationChain := taskChain
	var hubChain chaincli.Client
	if authority.Mode == config.AuthorityHub {
		hubChain = chaincli.New(log, authority.Chain, eventOptions.hub...)
		registrationChain = hubChain
	} else {
		log.Warn("builder registration using single-chain compatibility mode",
			"authority_chain_id", authority.Chain.ChainID)
	}
	keyCache := servicekey.NewCache(registrationChain, servicekey.DefaultCacheTTL)
	keyEvents.cache.Store(keyCache)
	rl := relay.NewKV(log, store) // the credential store is written through to disk so restart recovery still holds the credentials
	taskStore, err := taskdata.NewStore(log, taskDataRoot(cfg.DataDir), store, taskdata.Config{
		InlineMaxBytes: cfg.TaskData.InlineMaxBytes, ChunkSizeBytes: cfg.TaskData.ChunkSizeBytes,
		MaxRangeBytes: cfg.TaskData.MaxRangeBytes, MaxBlobBytes: cfg.TaskData.MaxBlobBytes,
		SpoolReservationBytes:      cfg.TaskData.SpoolReservationBytes,
		DiskAcceptWatermarkPercent: cfg.TaskData.DiskAcceptWatermarkPercent,
		TombstoneRetentionBlocks:   cfg.TaskData.TombstoneRetentionBlocks,
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
		coordinator.WithOutputDelivery(outputs),
		coordinator.WithPayloadStore(payloads),
		coordinator.WithDeadlineSweep(coordinator.DeadlineSweepPolicy{
			Enabled:     cfg.Chain.DeadlineSweep.Enabled,
			GraceBlocks: cfg.Chain.DeadlineSweep.GraceBlocks,
		}),
		coordinator.WithTxConfirmPolicy(coordinator.TxConfirmPolicy{
			BlockInterval: cfg.Chain.TxConfirm.BlockInterval,
			WaitBlocks:    cfg.Chain.TxConfirm.WaitBlocks,
		}),
	}
	if eventOptions.protocolOnHub {
		coordOpts = append(coordOpts, coordinator.WithProtocolEventSource(hubChain.Events()))
	}
	if chainResetMonitor != nil {
		coordOpts = append(coordOpts, coordinator.WithChainResetWatch(chainResetMonitor))
	}
	var registrationModule *module
	var serviceSG signer.Signer
	// serviceRing is serviceSG: it signs with whichever local service key the chain holds current.
	var serviceRing *servicekey.Ring
	var taskSubmitter coordinator.Submitter
	// metrics are the order path's stage timings, skips and Worker outcomes, for the operator
	// status and the public statistics.
	metrics := opsmetrics.New()
	ingressOpts := []ingress.Option{
		ingress.WithMetrics(metrics),
		ingress.WithPayloadMaxBytes(inlinePayloadMax(cfg.PayloadStorage.MaxBytes, cfg.TaskData.InlineMaxBytes)),
		ingress.WithReadMaxBytes(cfg.TaskData.ChunkSizeBytes),
	}
	if tlsMaterial.Enabled() {
		ingressOpts = append(ingressOpts, ingress.WithTLS(tlsMaterial.Certificate))
	}
	if sg != nil {
		log.Info("tx signing enabled", "address", sg.Address())
		serviceKey, sharedServiceKey, err := identity.LoadServiceSigner(cfg.Identity, sg)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("identity: %w", err)
		}
		keys := []signer.Signer{serviceKey}
		nextKey, err := identity.LoadNextServiceSigner(cfg.Identity)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("identity: %w", err)
		}
		if nextKey != nil {
			keys = append(keys, nextKey)
			log.Info("second service key loaded; the chain binding decides which key signs", "address", nextKey.Address())
		}
		// At a cutover the chain makes the registered replacement current; the ring signs new
		// messages with it from its next read. Cortex streams stay up: what was signed before
		// keeps its own nonce. A revoked current key signs nothing until a replacement is current.
		if serviceRing, err = servicekey.NewRing(keyCache, cfg.Identity.Bech32Prefix, selfAddr, logServiceKeySwitch(log), keys...); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("identity: %w", err)
		}
		keyEvents.ring.Store(serviceRing)
		serviceSG = serviceRing
		if sharedServiceKey {
			log.Warn("builder account and service signatures share one key; configure identity.service_keystore_file for key separation")
		}
		// /.well-known/trueopen-builder.json is now only a convenience document for off-chain discovery: the chain
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
		taskSubmitter = coordinator.NewSignedSubmitter(log, taskChain, registrationChain, sg, serviceSG, cfg.Chain)
		coordOpts = append(coordOpts,
			coordinator.WithSubmitter(taskSubmitter),
			coordinator.WithIdentitySigner(sg),
			coordinator.WithBuilderRegistry(registrationChain),
			coordinator.WithBuilderSelectionQuerier(taskChain)) // settlement ordering reads task TaskBuilders; the grace block count reads Hub params
		// The registration proof is made by the configured service key itself: it is what a new
		// Builder registers, and the ring signs nothing before it read a binding.
		registrationModule = newBuilderRegistrationModule(log, store, registrationChain, sg, serviceKey, cfg.Identity, authority, tlsMaterial.PubKeyHash)
	} else {
		log.Warn("tx signing NOT configured (NEXUS_KEYSTORE_FILE or NEXUS_PRIVATE_KEY_FILE/PRIVATE_KEY/HEX); task transactions are disabled (dev only)")
	}

	// A Profile is model registration data on the Hub side (QueryProfile goes through hubQuery), so this takes
	// registrationChain rather than taskChain.
	taskAuthority := newTaskDataAuthority(taskChain, registrationChain, registrationChain)
	if serviceSG != nil {
		// Builder messages to Cortex (OpenVerify, VerifierAssignmentNotify) are signed under the
		// nonce each task froze when the chain recorded it, with the local key of that generation.
		// Without a service key no Builder message is signed or sent: there is no unsigned fallback.
		coordOpts = append(coordOpts, coordinator.WithServiceKey(serviceRing))
	} else {
		log.Warn("service key NOT configured; Builder messages to Cortex cannot be signed, so none are sent")
	}

	// Cortex nodes connect to the IngressAPI DispatchStream; the hub verifies every stream and
	// message against the Cortex's current service key (kept with the other service keys on the
	// registration chain), carries the coordinator's Verifier messages and the standing
	// handraises, and gives every (re)bound stream the latest handraise root.
	dispatch := &directDispatch{log: log}
	streams, err := dispatchstream.New(log, dispatchstream.Config{ChainID: cfg.Chain.ChainID, BuilderOperator: selfAddr},
		dispatchstream.ServiceKeyLookup{Resolver: keyCache, AddressPrefix: cfg.Identity.Bech32Prefix}, store,
		dispatchstream.WithConnectionObserver(dispatch.onConnection), dispatchstream.WithReplayFilter(keepOnReplayAt(time.Now)))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("dispatch stream: %w", err)
	}
	keyEvents.streams.Store(streams)
	coordOpts = append(coordOpts, coordinator.WithCortexLink(streams))
	coord := coordinator.New(log, taskChain, rl, store, selfAddr, cfg.Chain.ChainID, coordOpts...)
	sinks := dispatchstream.Sinks{Verifier: coord}
	var dispatchModule *module
	var orderPath *orderDispatch
	// attempts holds the winning attempt of every order this Builder dispatched; the output data
	// plane authorizes and gates by it. It needs the service key that signs the result headers.
	var attempts *attempt.Book
	if serviceSG != nil {
		if attempts, err = attempt.New(store, serviceRing, log); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("dispatch attempts: %w", err)
		}
		coord.SetAttempts(attempts)
		// A terminal or dropped task's attempt (its signed header) is kept as long as a deleted
		// object's tombstone.
		coord.SetAttemptRetention(cfg.TaskData.TombstoneRetentionBlocks)
	}
	if serviceSG != nil && len(cfg.Identity.VRFKeyFiles) > 0 {
		// Standing handraises and roots are judged on the task chain's height, never below the
		// dispatcher's head; the Hub reads (pool, beacon, VRF keys, epoch length) go to the
		// registration chain.
		if err := newDirectDispatch(dispatch, directDispatchDeps{
			ChainID: cfg.Chain.ChainID, BuilderAddress: selfAddr, AddressPrefix: cfg.Identity.Bech32Prefix,
			Config: cfg.Dispatch, VRFKeyFiles: cfg.Identity.VRFKeyFiles, VRFKeyPassword: cfg.Identity.VRFKeyPasswordFile,
			Store: store, Chain: registrationChain, Keys: keyCache, Height: newCachedHeight(taskChain.LatestHeight),
			Signer: serviceRing, Streams: streams, Groups: coord,
		}); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("direct dispatch: %w", err)
		}
		sinks.Handraise = dispatch
		dispatchModule = &module{"handraise-roots", dispatch.Start, dispatch.Stop}
		paramsCtx, cancelParams := context.WithTimeout(context.Background(), 30*time.Second)
		orderPath, err = newOrderDispatch(paramsCtx, orderDispatchDeps{
			ChainID: cfg.Chain.ChainID, BuilderAddress: selfAddr, Config: cfg.Dispatch, InputChunkBytes: cfg.TaskData.ChunkSizeBytes,
			Signer: serviceRing, Store: store, TaskChain: taskChain, HubChain: registrationChain, Direct: dispatch,
			Records: coordinator.NewRecordSubmitter(log, taskChain, serviceSG, cfg.Chain, taskSubmitter),
			Keys:    handraise.ChainServiceKeys{Resolver: keyCache, AddressPrefix: cfg.Identity.Bech32Prefix, Ring: serviceRing},
			Inputs:  taskStore, Observer: coord, Tasks: coord, Held: coord, Attempts: attempts, Metrics: metrics, Log: log,
		})
		cancelParams()
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("order dispatch: %w", err)
		}
		dispatch.SetDispatchHead(orderPath.Sessions.Head)
		coord.SetDispatcher(orderPath.Dispatcher)
		sinks.Dispatch = orderPath.Dispatcher
		orders.order.Store(orderPath)
	} else {
		log.Warn("direct dispatch NOT configured (needs the service key and identity.vrf_key_files); standing handraises are dropped")
	}
	streams.SetSinks(sinks)
	ingressOpts = append(ingressOpts, ingress.WithDispatchStream(streams))
	var taskAuthorizer *taskdata.Authorizer
	// The output limits and fan-out, when streaming output is on; a group member writes its output
	// replicas under the same limits and hands their frames to the same subscribers.
	var outputConfig taskdata.OutputStreamConfig
	var outputFanout *taskdata.OutputDispatcher
	// User request verification reads the current height (session grant windows) and the key each
	// account holds on chain; found keys are cached, since an account's key never changes.
	userChain := sdkauth.NewCachedChain(taskChain.LatestHeight, taskChain.AccountPubKey,
		func(err error) bool { return errors.Is(err, chaincli.ErrNotFound) }, sdkauth.DefaultAccountKeyCacheSize)
	sessionGrantBlocks := cfg.Ingress.SessionGrantBlocks()
	log.Info("session grant window", "max_session_grant_blocks", sessionGrantBlocks)
	// feeDenom is the feeDenom of the order signing domain, needed to precheck orders signed by a
	// registered key. It is read once: a business_denom change needs a restart.
	var feeDenom string
	if serviceSG != nil {
		denomCtx, cancelDenom := context.WithTimeout(context.Background(), 30*time.Second)
		denom, denomErr := registrationChain.QueryBusinessDenom(denomCtx)
		cancelDenom()
		if denomErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("query hub phase0.business_denom: %w", denomErr)
		}
		feeDenom = denom
		log.Info("registered session keys", "business_denom", feeDenom,
			"session_key_cache_ttl_blocks", cfg.Ingress.SessionKeyCacheTTLBlocks,
			"session_key_lookups_per_second", cfg.Ingress.SessionKeyLookupsPerSecond)
	}
	if serviceSG != nil {
		// A Task data request may expire up to service.max_service_material_expiry_blocks above the
		// current height; the value is read once at startup.
		expiryCtx, cancelExpiry := context.WithTimeout(context.Background(), 30*time.Second)
		requestExpiryBlocks, expiryErr := registrationChain.QueryServiceMaterialExpiryBlocks(expiryCtx)
		cancelExpiry()
		if expiryErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("query hub max_service_material_expiry_blocks: %w", expiryErr)
		}
		log.Info("task data request expiry window", "max_service_material_expiry_blocks", requestExpiryBlocks,
			"open_task_request_ttl_blocks", cfg.TaskData.RequestTTLBlocks, "user_requests_per_minute", cfg.TaskData.UserRequestsPerMinute)
		taskAuthorizer, err = taskdata.NewAuthorizer(taskdata.AuthorizerConfig{
			ChainID: cfg.Chain.ChainID, BuilderAddress: selfAddr, AddressPrefix: cfg.Identity.Bech32Prefix,
			RequestTTLBlocks:       cfg.TaskData.RequestTTLBlocks,
			MaxRequestExpiryBlocks: requestExpiryBlocks,
			RefreshMaxRequestExpiryBlocks: func(ctx context.Context) (uint64, error) {
				refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				return registrationChain.QueryServiceMaterialExpiryBlocks(refreshCtx)
			},
			UserRequestsPerMinute: cfg.TaskData.UserRequestsPerMinute,
			RetentionLeaseBlocks:  cfg.TaskData.RetentionLeaseBlocks,
			SessionGrants: taskdata.SessionGrantEnv{
				Chain: userChain, MaxBlocks: sessionGrantBlocks,
				SessionKeys: sessionKeys.cache, LocalTask: localTaskRecord(coord.TaskOwner),
			},
			Attempts: attempts,
			Log:      log,
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
		// OPEN_VERIFY and the Verifier proposal wait for local data-ready, which the task
		// data plane answers and announces when the Worker's Finalize succeeds.
		coord.SetResultReadiness(taskService)
		taskService.SetResultFinalizedObserver(coord.OnResultFinalized)
		if stream := cfg.TaskData.OutputStream; stream.Enabled {
			// Streaming OUTPUT: the limits are uniform across the network and frames are fanned out to subscribers per Task;
			// enabled by default (cortex only streams); when disabled the three RPCs return Unimplemented.
			// The frame count limit and the minimum frame size are genesis-only task params, read once at startup.
			limitsCtx, cancelLimits := context.WithTimeout(context.Background(), 30*time.Second)
			limits, limitsErr := taskChain.QueryOutputStreamLimits(limitsCtx)
			cancelLimits()
			if limitsErr != nil {
				_ = store.Close()
				return nil, fmt.Errorf("query task params output stream limits: %w", limitsErr)
			}
			if stream, err = stream.WithChainLimits(limits.MaxOutputMMRLeaves, limits.MinFrameBytes, cfg.TaskData.ChunkSizeBytes); err != nil {
				_ = store.Close()
				return nil, err
			}
			outputConfig = taskdata.OutputStreamConfig{
				MaxLeaves: stream.MaxOutputMMRLeaves, MinFrameBytes: stream.MinFrameBytes,
				MaxFrameBytes: cfg.TaskData.ChunkSizeBytes, MaxAttachmentBytes: stream.MaxAttachmentBytes,
			}
			taskService.SetOutputStreamConfig(outputConfig)
			dispatcher := taskdata.NewOutputDispatcher(int(stream.SubscriberBufferFrames))
			outputFanout = dispatcher
			ingressOpts = append(ingressOpts, ingress.WithOutputStream(taskService, dispatcher, store, attempts))
			log.Info("streaming output enabled",
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
	authParams := ingress.AuthParams{
		ChainID:               cfg.Chain.ChainID,
		BuilderAddress:        selfAddr,
		Bech32Prefix:          cfg.Identity.Bech32Prefix,
		RequireEnvelope:       cfg.Ingress.RequireSDKEnvelope,
		ServiceKeys:           registrationChain,
		Chain:                 userChain,
		MaxSessionGrantBlocks: sessionGrantBlocks,
		SessionKeys:           sessionKeys.cache,
		FeeDenom:              feeDenom,
	}
	if orderPath != nil {
		var publish func(taskdata.ObjectKey, taskdata.OutputFrame)
		if outputFanout != nil {
			publish = outputFanout.Publish
		}
		members, err := orderPath.newMembers(membersDeps{
			ChainID: cfg.Chain.ChainID, BuilderAddress: selfAddr, AddressPrefix: cfg.Identity.Bech32Prefix, Keys: keyCache, Groups: coord,
			Store: store, Data: taskStore, OutputConfig: outputConfig, Publish: publish, Chain: taskChain, MaxInputBytes: cfg.TaskData.MaxBlobBytes,
			FeeDenom: feeDenom, SessionKeys: sessionKeys.cache,
		})
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("builder sync: %w", err)
		}
		orderPath.Members = members
		ingressOpts = append(ingressOpts, ingress.WithDispatchRosters(orderPath.Rosters), ingress.WithBuilderSync(members, cfg.Ingress.BuilderSyncRequestsPerSecond, cfg.Ingress.BuilderSyncBurst), ingress.WithMemberReplicas(members, taskChain, cfg.Ingress.ReplicaWait()))
		authParams.Precheck = orderPath.Precheck
		authParams.Takeovers = orderPath.Takeovers
	}
	// The operator monitor: readiness, diagnostics and the drain requests in <data_dir>/ops, and the
	// public readiness verdict and dispatch statistics on the ingress port.
	var directForOps *directDispatch
	if orderPath != nil {
		directForOps = dispatch
	}
	monitor := newOpsMonitor(opsDeps{
		DataDir: cfg.DataDir, BuilderAddress: selfAddr, AddressPrefix: cfg.Identity.Bech32Prefix, Dispatch: cfg.Dispatch,
		Store: store, Height: taskChain.LatestHeight, Keys: keyCache, Streams: streams, Metrics: metrics,
		Direct: directForOps, Orders: orderPath, Log: log,
	})
	ingressOpts = append(ingressOpts,
		ingress.WithRoute("GET "+ops.ReadinessPath, monitor.ReadinessHandler()),
		ingress.WithRoute("GET "+ops.PublicStatsPath, monitor.PublicStatsHandler()))
	ing, err := ingress.New(log, cfg.Ingress, authParams, coord, ingressOpts...)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("ingress: %w", err)
	}

	modules := []module{
		{"task-chaincli", taskChain.Start, taskChain.Stop},
	}
	if hubChain != nil {
		modules = append(modules, module{"hub-chaincli", hubChain.Start, hubChain.Stop})
	}
	if registrationModule != nil {
		modules = append(modules, *registrationModule)
	}
	if serviceRing != nil {
		modules = append(modules, serviceKeyModule(log, serviceRing))
	}
	outputModule := outputRecoveryLifecycle{
		lifecycle: outputs,
		complete:  coord.CompleteOutputRecovery,
	}
	modules = append(modules, runtimeModules(taskDataModule, rl, coord, outputModule, streams, ing)...)
	if dispatchModule != nil {
		// Roots are issued once the coordinator follows the chain, and before streams are served.
		modules = insertBefore(modules, "dispatch-stream", *dispatchModule)
	}
	if orderPath != nil {
		// Orders resume before streams are served, so the answers replayed to them find their tickets.
		modules = insertBefore(modules, "dispatch-stream", module{"order-dispatch", orderPath.Start, orderPath.Stop})
	}
	// A drain request left while the daemon was down is taken before the order path resumes its
	// orders (which would otherwise issue tickets) and before ingress takes new ones.
	opsBefore := "ingress"
	if orderPath != nil {
		opsBefore = "order-dispatch"
	}
	modules = insertBefore(modules, opsBefore, module{"ops", monitor.Start, monitor.Stop})

	app := &App{
		cfg: cfg, log: log, kv: store, modules: modules,
		beginIngressStop: ing.BeginStop,
		chainReset:       chainResetMonitor,
	}
	if dispatchModule != nil {
		app.dispatch = dispatch
	}
	return app, nil
}

// insertBefore returns modules with m placed just before the module named name, or at the end.
func insertBefore(modules []module, name string, m module) []module {
	for i, current := range modules {
		if current.name == name {
			out := append([]module(nil), modules[:i]...)
			out = append(out, m)
			return append(out, modules[i:]...)
		}
	}
	return append(modules, m)
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

// serviceKeyEvents feeds the chain's service key events to what follows them, each set once it
// exists: the key cache drops the operator's stale keys first, this Builder's ring stops signing
// on its own revocation, and the stream hub ends the Cortex streams whose binding key left.
type serviceKeyEvents struct {
	cache   atomic.Pointer[servicekey.Cache]
	ring    atomic.Pointer[servicekey.Ring]
	streams atomic.Pointer[dispatchstream.Hub]
}

func (k *serviceKeyEvents) observe(ev chaincli.ChainEvent) {
	if c := k.cache.Load(); c != nil {
		c.ObserveEvent(ev)
	}
	if r := k.ring.Load(); r != nil {
		r.ObserveEvent(ev)
	}
	if h := k.streams.Load(); h != nil {
		h.ObserveEvent(ev)
	}
}

// logServiceKeySwitch is the ring's onSwitch: it logs a cutover, a revocation of the current key
// and the replacement that ends one.
func logServiceKeySwitch(log *slog.Logger) func(old, current servicekey.Key) {
	return func(old, current servicekey.Key) {
		switch {
		case current.Revoked:
			log.Error("service key revoked: nothing is signed and no order is dispatched until a replacement key is current",
				"nonce", current.Nonce, "service_address", current.Signer.Address())
		case old.Revoked:
			log.Info("service key replacement current: signing and dispatch resume", "old_nonce", old.Nonce, "nonce", current.Nonce,
				"service_address", current.Signer.Address())
		default:
			log.Info("service key cutover: signing with the new current key", "old_nonce", old.Nonce, "nonce", current.Nonce,
				"service_address", current.Signer.Address())
		}
	}
}

// serviceKeyStartupWait bounds the startup read of the service key binding; serviceKeyRetry is
// how often it is read again after that until it succeeds.
var (
	serviceKeyStartupWait = 15 * time.Second
	serviceKeyRetry       = 5 * time.Second
)

// serviceKeyModule reads the BUILDER service key binding before anything is served: the ring
// signs nothing before its first read. A chain that does not answer in time does not stop the
// start; the binding is read again in the background until it does, and nothing is signed until
// then. A revoked current key does not stop the start either: nothing is signed until the ring
// finds a replacement current, which the root registry's periodic key check reads.
func serviceKeyModule(log *slog.Logger, ring *servicekey.Ring) module {
	var cancel context.CancelFunc = func() {}
	done := make(chan struct{})
	close(done)
	start := func(ctx context.Context) error {
		waitCtx, stop := context.WithTimeout(ctx, serviceKeyStartupWait)
		err := ring.Await(waitCtx, serviceKeyRetry)
		stop()
		if err == nil {
			return nil
		}
		if errors.Is(err, servicekey.ErrRevoked) {
			log.Error("service key revoked: nothing is signed and no order is dispatched until a replacement key is current", "err", err)
			return nil
		}
		log.Warn("service key binding not read; nothing is signed until it is", "err", err)
		var bg context.Context
		bg, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		go func(done chan struct{}) {
			defer close(done)
			if err := ring.Await(bg, serviceKeyRetry); err == nil {
				log.Info("service key binding read; signing enabled", "nonce", ring.Key().Nonce)
			}
		}(done)
		return nil
	}
	stop := func(context.Context) error {
		cancel()
		<-done
		return nil
	}
	return module{name: "service-key", start: start, stop: stop}
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

// Fatal delivers an error that requires the process to stop, currently only
// chainreset.ErrChainReset. It never delivers when the chain identity check is off.
func (a *App) Fatal() <-chan error { return a.chainReset.Fatal() }

// Start brings the modules up in order; if any fails, the already-started ones are rolled back.
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
	stopped := make(map[string]bool, 3)
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
	// Wake long-lived output and Cortex dispatch streams before waiting for graceful HTTP shutdown.
	stopNamed("output-delivery")
	stopNamed("dispatch-stream")
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
