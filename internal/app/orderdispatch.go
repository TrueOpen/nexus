package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/dispatchresponse"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/recorder"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// paramsRefreshInterval is how often the dispatch params are read again; a params change on chain
// takes effect within it.
const paramsRefreshInterval = time.Minute

// orderDispatch is the order path of a dispatching Builder: the in-flight ledger, the session
// cache, the OpenTask precheck that reserves orders in the ledger, the dispatcher that walks them
// and the recorder that records the accepted ones, with the gate on this Builder's key and
// compensation account; the evidence every order leaves and the responder that rebuts claims and
// answers challenges with it. Its chain events arrive through orderEvents, which exists before
// the chain client.
type orderDispatch struct {
	log        *slog.Logger
	Ledger     *inflight.Ledger
	Sessions   *inflight.SessionCache
	Precheck   *inflight.Prechecker
	Dispatcher *dispatcher.Dispatcher
	Recorder   *recorder.Recorder
	Gate       *recorder.Gate
	Evidence   *dispatchevidence.Store
	Responder  *dispatchresponse.Responder
	// Rosters serves GetDispatchRoster from the evidence.
	Rosters dispatchevidence.Rosters
	params  func(context.Context) (orderParams, error)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// orderEvents feeds chain events and session stream changes to the order path once it exists.
type orderEvents struct {
	order atomic.Pointer[orderDispatch]
	// keys is the registered key cache, the other observer of session streams.
	keys chaincli.SessionStreamObserver
}

func (e *orderEvents) observe(ev chaincli.ChainEvent) {
	if od := e.order.Load(); od != nil {
		if err := od.Sessions.HandleChainEvent(ev); err != nil {
			od.log.Error("in-flight ledger not updated from a chain event", "type", ev.Type, "session_id", ev.SessionID, "err", err)
		}
		od.Dispatcher.HandleChainEvent(ev)
		od.Recorder.HandleChainEvent(ev)
		od.Responder.HandleChainEvent(ev)
	}
}

// observeHub feeds the Hub chain's events, when the Hub is a chain of its own, to the gate: the
// compensation account lives there.
func (e *orderEvents) observeHub(ev chaincli.ChainEvent) {
	if od := e.order.Load(); od != nil {
		od.Gate.HandleChainEvent(ev)
	}
}

func (e *orderEvents) each(f func(chaincli.SessionStreamObserver)) {
	if e.keys != nil {
		f(e.keys)
	}
	if od := e.order.Load(); od != nil {
		f(od.Sessions)
	}
}

// SessionStreamUp implements chaincli.SessionStreamObserver.
func (e *orderEvents) SessionStreamUp(sessionID string) {
	e.each(func(o chaincli.SessionStreamObserver) { o.SessionStreamUp(sessionID) })
}

// SessionStreamDown implements chaincli.SessionStreamObserver.
func (e *orderEvents) SessionStreamDown(sessionID string) {
	e.each(func(o chaincli.SessionStreamObserver) { o.SessionStreamDown(sessionID) })
}

// SessionStreamClosed implements chaincli.SessionStreamObserver.
func (e *orderEvents) SessionStreamClosed(sessionID string) {
	e.each(func(o chaincli.SessionStreamObserver) { o.SessionStreamClosed(sessionID) })
}

// SessionKeyUpdated implements chaincli.SessionStreamObserver.
func (e *orderEvents) SessionKeyUpdated(sessionID string) {
	e.each(func(o chaincli.SessionStreamObserver) { o.SessionKeyUpdated(sessionID) })
}

// orderDispatchDeps are what newOrderDispatch wires together.
type orderDispatchDeps struct {
	ChainID         string
	BuilderAddress  string
	Config          config.DispatchConfig
	InputChunkBytes uint64
	Signer          signer.Signer
	Store           kv.Store
	// TaskChain answers sessions, heights, task params and transactions, and follows session
	// events.
	TaskChain chaincli.Client
	// HubChain answers the compensation account.
	HubChain chaincli.Client
	// Records sends the record transactions, rebuttals and challenge responses from the service
	// account.
	Records  coordinator.RecordSubmitter
	Direct   *directDispatch
	Keys     handraise.ChainServiceKeys
	Inputs   *taskdata.Store
	Observer dispatcher.Observer
	Tasks    recorder.Tasks
	Log      *slog.Logger
}

// orderParams are the task params the order path applies.
type orderParams struct {
	precheck inflight.Params
	walk     dispatcher.Params
	record   recorder.Params
	evidence dispatchevidence.Params
}

// recordChain is what the recorder reads from the task chain.
type recordChain struct {
	chaincli.Client
	chaincli.TxQuerier
}

// newOrderDispatch reads the dispatch params and builds the order path.
func newOrderDispatch(ctx context.Context, deps orderDispatchDeps) (*orderDispatch, error) {
	txs, ok := deps.TaskChain.(chaincli.TxQuerier)
	if !ok {
		return nil, fmt.Errorf("order dispatch needs a task chain that reads transaction results")
	}
	od := &orderDispatch{log: deps.Log}
	od.params = func(ctx context.Context) (orderParams, error) {
		dispatch, err := deps.TaskChain.QueryDispatchParams(ctx)
		if err != nil {
			return orderParams{}, fmt.Errorf("query task params dispatch: %w", err)
		}
		weights, err := deps.TaskChain.QueryCandidateWeightParams(ctx)
		if err != nil {
			return orderParams{}, fmt.Errorf("query task params weights: %w", err)
		}
		var p orderParams
		if p.precheck, err = inflight.ParamsFromChain(dispatch); err != nil {
			return orderParams{}, err
		}
		if p.walk, err = dispatcher.ParamsFromChain(dispatch, weights); err != nil {
			return orderParams{}, err
		}
		if p.record, err = recorder.ParamsFromChain(dispatch); err != nil {
			return orderParams{}, err
		}
		p.evidence = dispatchevidence.ParamsFromChain(dispatch)
		return p, nil
	}
	params, err := od.params(ctx)
	if err != nil {
		return nil, err
	}
	od.Ledger, err = inflight.NewLedger(deps.Store)
	if err != nil {
		return nil, err
	}
	tracker, _ := deps.TaskChain.(chaincli.SessionEventTracker)
	od.Sessions, err = inflight.NewSessionCache(inflight.SessionCacheConfig{
		Read: deps.TaskChain.QuerySession, LatestHeight: deps.TaskChain.LatestHeight, Tracker: tracker, Ledger: od.Ledger,
	})
	if err != nil {
		return nil, err
	}
	od.Precheck, err = inflight.NewPrechecker(inflight.PrecheckConfig{
		Builder: deps.BuilderAddress, Params: params.precheck, Sessions: od.Sessions, Ledger: od.Ledger,
	})
	if err != nil {
		return nil, err
	}
	od.Gate = recorder.NewGate(recorder.GateConfig{
		Keys: deps.Keys, Builder: deps.BuilderAddress, MinBalance: params.record.MinCompensation, Log: deps.Log,
		Account: func(ctx context.Context) (*hubv1.BuilderCompensationAccountState, error) {
			return deps.HubChain.QueryBuilderCompensationAccount(ctx, deps.BuilderAddress)
		},
	})
	od.Recorder, err = recorder.New(recorder.Config{
		ChainID: deps.ChainID, Builder: deps.BuilderAddress, Signer: deps.Signer, Store: deps.Store, Ledger: od.Ledger,
		GasBase: deps.Config.RecordGasBase, GasPerEntry: deps.Config.RecordGasPerEntry,
		Chain: recordChain{deps.TaskChain, txs}, Tx: deps.Records, Tasks: deps.Tasks, Streams: deps.Direct.Streams,
		Gate: od.Gate, Log: deps.Log,
	}, params.record)
	if err != nil {
		return nil, err
	}
	od.Evidence = dispatchevidence.New(deps.Store, params.evidence)
	od.Dispatcher, err = dispatcher.New(dispatcher.Config{
		ChainID: deps.ChainID, Builder: deps.BuilderAddress, Dispatch: deps.Config, InputChunkBytes: deps.InputChunkBytes,
		Signer: deps.Signer, Store: deps.Store, Ledger: od.Ledger, Sessions: od.Sessions,
		Streams: deps.Direct.Streams, Handraises: deps.Direct.Registry, Drawer: deps.Direct.Drawer, Keys: od.Gate,
		Inputs: storedInputs{deps.Inputs}, Recorder: od.Recorder, Observer: deps.Observer, Evidence: od.Evidence,
		Log: deps.Log,
	}, params.walk)
	if err != nil {
		return nil, err
	}
	od.Recorder.SetOrders(od.Dispatcher)
	od.Responder, err = dispatchresponse.New(dispatchresponse.Config{
		ChainID: deps.ChainID, Builder: deps.BuilderAddress, Responder: deps.Signer.Address(), Store: deps.Store,
		Evidence: od.Evidence, Chain: deps.TaskChain, Tx: deps.Records, Roots: deps.Direct.Registry, Log: deps.Log,
	})
	if err != nil {
		return nil, err
	}
	od.Rosters = dispatchevidence.Rosters{Evidence: od.Evidence, Root: issuedRoot(deps.Direct.Registry)}
	return od, nil
}

// Start follows the sessions the ledger holds, reads the compensation account, starts recording,
// resumes the dispatcher's orders and keeps the params current.
func (od *orderDispatch) Start(ctx context.Context) error {
	od.Sessions.Prewarm()
	if err := od.Gate.Refresh(ctx); err != nil {
		od.log.Warn("compensation account not read; no order is taken until it is", "err", err)
	}
	if err := od.Recorder.Start(ctx); err != nil {
		return err
	}
	if err := od.Dispatcher.Start(ctx); err != nil {
		return err
	}
	if err := od.Responder.Start(ctx); err != nil {
		return err
	}
	refreshCtx, cancel := context.WithCancel(context.Background())
	od.cancel = cancel
	od.wg.Add(1)
	go func() {
		defer od.wg.Done()
		ticker := time.NewTicker(paramsRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				od.refreshParams(refreshCtx)
			}
		}
	}()
	return nil
}

func (od *orderDispatch) refreshParams(ctx context.Context) {
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	params, err := od.params(readCtx)
	if err == nil {
		err = od.Precheck.SetParams(params.precheck)
	}
	if err != nil {
		od.log.Warn("dispatch params not refreshed; the previous ones stay", "err", err)
		return
	}
	od.Dispatcher.SetParams(params.walk)
	od.Recorder.SetParams(params.record)
	od.Evidence.SetParams(params.evidence)
}

// Stop ends the params refresh, the dispatcher's work and the recording.
func (od *orderDispatch) Stop(ctx context.Context) error {
	if od.cancel != nil {
		od.cancel()
		od.wg.Wait()
	}
	err := od.Dispatcher.Stop(ctx)
	if stopErr := od.Recorder.Stop(ctx); err == nil {
		err = stopErr
	}
	if stopErr := od.Responder.Stop(ctx); err == nil {
		err = stopErr
	}
	return err
}

// issuedRoot finds an issued handraise root by its digest for GetDispatchRoster.
func issuedRoot(registry *handraise.Registry) func([32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) {
	return func(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) {
		issued, found, err := registry.RootByDigest(digest)
		if err != nil || !found {
			return nil, found, err
		}
		return issued.Root, true, nil
	}
}

// keepOnReplayAt drops, when a Cortex reconnects, stored handraise root notices (the latest root
// is sent instead) and offers whose accept deadline passed.
func keepOnReplayAt(now func() time.Time) func(string, *nexusv1.DispatchStreamFrameV1) bool {
	return func(operator string, frame *nexusv1.DispatchStreamFrameV1) bool {
		return keepOnReplay(operator, frame) && dispatcher.OfferLive(frame, now())
	}
}

// storedInputs serves an order's INPUT from the task data store, as uploaded with OpenTask.
type storedInputs struct{ store *taskdata.Store }

func (s storedInputs) OpenInput(ctx context.Context, sessionID, taskID, taskHash string) (io.ReadCloser, uint64, error) {
	ref, err := s.store.ResolveObject(ctx, sessionID, taskID, taskdata.ObjectKindInput)
	if err != nil {
		return nil, 0, err
	}
	if ref.TaskHash != taskHash {
		return nil, 0, fmt.Errorf("stored INPUT of task %s is another order version", taskID)
	}
	metadata, err := s.store.Metadata(ctx, ref)
	if err != nil {
		return nil, 0, err
	}
	reader, err := s.store.OpenStored(ctx, ref)
	if err != nil {
		return nil, 0, err
	}
	return reader, metadata.SizeBytes, nil
}
