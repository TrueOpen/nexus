package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// paramsRefreshInterval is how often the dispatch params are read again; a params change on chain
// takes effect within it.
const paramsRefreshInterval = time.Minute

// orderDispatch is the order path of a dispatching Builder: the in-flight ledger, the session
// cache, the OpenTask precheck that reserves orders in the ledger, and the dispatcher that walks
// them. Its chain events arrive through orderEvents, which exists before the chain client.
type orderDispatch struct {
	log        *slog.Logger
	Ledger     *inflight.Ledger
	Sessions   *inflight.SessionCache
	Precheck   *inflight.Prechecker
	Dispatcher *dispatcher.Dispatcher
	params     func(context.Context) (inflight.Params, dispatcher.Params, error)

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
	// TaskChain answers sessions, heights and task params, and follows session events.
	TaskChain chaincli.Client
	Direct    *directDispatch
	Keys      handraise.ChainServiceKeys
	Inputs    *taskdata.Store
	Observer  dispatcher.Observer
	Log       *slog.Logger
}

// newOrderDispatch reads the dispatch params and builds the order path. Nothing records accepted
// orders on chain yet (dispatcher.UnimplementedRecorder), so the dispatcher refuses every new order
// with ErrDispatchUnavailable until a Recorder replaces it.
func newOrderDispatch(ctx context.Context, deps orderDispatchDeps) (*orderDispatch, error) {
	od := &orderDispatch{log: deps.Log}
	od.params = func(ctx context.Context) (inflight.Params, dispatcher.Params, error) {
		dispatch, err := deps.TaskChain.QueryDispatchParams(ctx)
		if err != nil {
			return inflight.Params{}, dispatcher.Params{}, fmt.Errorf("query task params dispatch: %w", err)
		}
		weights, err := deps.TaskChain.QueryCandidateWeightParams(ctx)
		if err != nil {
			return inflight.Params{}, dispatcher.Params{}, fmt.Errorf("query task params weights: %w", err)
		}
		precheck, err := inflight.ParamsFromChain(dispatch)
		if err != nil {
			return inflight.Params{}, dispatcher.Params{}, err
		}
		walk, err := dispatcher.ParamsFromChain(dispatch, weights)
		return precheck, walk, err
	}
	precheckParams, walkParams, err := od.params(ctx)
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
		Builder: deps.BuilderAddress, Params: precheckParams, Sessions: od.Sessions, Ledger: od.Ledger,
	})
	if err != nil {
		return nil, err
	}
	od.Dispatcher, err = dispatcher.New(dispatcher.Config{
		ChainID: deps.ChainID, Builder: deps.BuilderAddress, Dispatch: deps.Config, InputChunkBytes: deps.InputChunkBytes,
		Signer: deps.Signer, Store: deps.Store, Ledger: od.Ledger, Sessions: od.Sessions,
		Streams: deps.Direct.Streams, Handraises: deps.Direct.Registry, Drawer: deps.Direct.Drawer, Keys: deps.Keys,
		Inputs: storedInputs{deps.Inputs}, Recorder: dispatcher.UnimplementedRecorder{Log: deps.Log}, Observer: deps.Observer,
		Log: deps.Log,
	}, walkParams)
	if err != nil {
		return nil, err
	}
	return od, nil
}

// Start follows the sessions the ledger holds, resumes the dispatcher's orders and keeps the params
// current.
func (od *orderDispatch) Start(ctx context.Context) error {
	od.Sessions.Prewarm()
	if err := od.Dispatcher.Start(ctx); err != nil {
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
	precheck, walk, err := od.params(readCtx)
	if err == nil {
		err = od.Precheck.SetParams(precheck)
	}
	if err != nil {
		od.log.Warn("dispatch params not refreshed; the previous ones stay", "err", err)
		return
	}
	od.Dispatcher.SetParams(walk)
}

// Stop ends the params refresh and the dispatcher's work.
func (od *orderDispatch) Stop(ctx context.Context) error {
	if od.cancel != nil {
		od.cancel()
		od.wg.Wait()
	}
	return od.Dispatcher.Stop(ctx)
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
