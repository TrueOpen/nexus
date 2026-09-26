package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	chainStateVersion            = 1
	chainStateKey                = "coordinator"
	reconcileEveryBlocks  uint64 = 10
	reconcileBatchSize           = 32
	reconcileQueryTimeout        = 5 * time.Second
)

type chainStateRecord struct {
	Version              int    `json:"version"`
	LastObservedHeight   uint64 `json:"last_observed_height"`
	LastReconciledHeight uint64 `json:"last_reconciled_height"`
}

type reconcileRequest struct {
	reason       string
	sessionID    string
	taskID       string
	eventHeight  int64
	events       []chaincli.ChainEvent
	builderSet   bool
	retryAttempt uint
}

// settleSelectionFromTaskBuilders converts the frozen Task Builder selection into the locally stored settlement order:
// order is rank (§10.10a).
func settleSelectionFromTaskBuilders(key chaincli.TaskKey, selection chaincli.TaskBuilderSelectionState) chaincli.StageBuilderSelectionState {
	return chaincli.StageBuilderSelectionState{
		SessionID: key.SessionID, TaskID: key.TaskID, Stage: prepareStageSettle,
		SelectedBuilders: append([]string(nil), selection.SelectedBuilders...),
		SelectedHeight:   selection.CreatedHeight,
	}
}

func validateSettleSelection(key chaincli.TaskKey, selection chaincli.StageBuilderSelectionState) error {
	if selection.SessionID != key.SessionID || selection.TaskID != key.TaskID || selection.Stage != prepareStageSettle {
		return fmt.Errorf("settle selection scope mismatch")
	}
	if len(selection.SelectedBuilders) == 0 {
		return fmt.Errorf("settle selection has no builders")
	}
	seen := make(map[string]struct{}, len(selection.SelectedBuilders))
	for _, builder := range selection.SelectedBuilders {
		if builder == "" || strings.TrimSpace(builder) != builder {
			return fmt.Errorf("settle selection contains invalid builder")
		}
		if _, exists := seen[builder]; exists {
			return fmt.Errorf("settle selection contains duplicate builder %q", builder)
		}
		seen[builder] = struct{}{}
	}
	return nil
}

func (c *Coordinator) refreshChainHeight(ctx context.Context) (uint64, error) {
	if c.height == nil {
		return 0, fmt.Errorf("height query is not configured")
	}
	queryCtx, cancel := context.WithTimeout(ctx, reconcileQueryTimeout)
	defer cancel()
	height, err := c.height.LatestHeight(queryCtx)
	if err != nil {
		return 0, err
	}
	if height == 0 {
		return 0, fmt.Errorf("latest height is zero")
	}
	c.chainStateMu.Lock()
	next := c.chainState
	next.Version = chainStateVersion
	// A small step back is a lagging height RPC; a large one is a sign the chain was reset.
	regressed := c.heightAuthoritative && height+chainreset.HeightRegressionBlocks < next.LastObservedHeight
	observed := next.LastObservedHeight
	if !c.heightAuthoritative || height > next.LastObservedHeight {
		next.LastObservedHeight = height
	}
	raw, err := json.Marshal(next)
	if err == nil {
		err = c.kv.Set(kv.NSChainState, chainStateKey, raw)
	}
	if err != nil {
		c.chainStateMu.Unlock()
		return 0, fmt.Errorf("persist chain height: %w", err)
	}
	c.chainState = next
	c.heightAuthoritative = true
	c.chainStateMu.Unlock()
	if regressed {
		c.suspectChainReset(fmt.Sprintf("latest height %d is far below observed height %d", height, observed))
	}
	// The height RPC may briefly lag an already observed block event.
	return next.LastObservedHeight, nil
}

func (c *Coordinator) loadChainState() error {
	raw, ok, err := c.kv.GetWithError(kv.NSChainState, chainStateKey)
	if err != nil {
		return fmt.Errorf("load chain state: %w", err)
	}
	if !ok {
		return nil
	}
	var record chainStateRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("decode chain state: %w", err)
	}
	if record.Version != chainStateVersion {
		return fmt.Errorf("unsupported chain state version %d", record.Version)
	}
	c.chainStateMu.Lock()
	c.chainState = record
	c.heightAuthoritative = false
	c.chainStateMu.Unlock()
	return nil
}

func (c *Coordinator) currentChainHeight() (uint64, bool) {
	c.chainStateMu.RLock()
	defer c.chainStateMu.RUnlock()
	return c.chainState.LastObservedHeight, c.heightAuthoritative
}

func (c *Coordinator) requestReconcile(reason string) {
	c.enqueueReconcile(reconcileRequest{reason: reason})
}

func (c *Coordinator) requestSessionReconcile(sessionID, reason string) {
	c.enqueueReconcile(reconcileRequest{reason: reason, sessionID: sessionID})
}

func (c *Coordinator) requestTaskReconcile(sessionID, taskID string, eventHeight int64, reason string) {
	c.enqueueReconcile(reconcileRequest{reason: reason, sessionID: sessionID, taskID: taskID, eventHeight: eventHeight})
}

func (c *Coordinator) requestTaskEventReconcile(event chaincli.ChainEvent, reason string) {
	request := reconcileRequest{
		reason: reason, sessionID: event.SessionID, taskID: event.TaskID, eventHeight: event.Height,
	}
	request.events = []chaincli.ChainEvent{event}
	c.enqueueReconcile(request)
}

func (c *Coordinator) requestBuilderSetReconcile(eventHeight int64, reason string) {
	c.enqueueReconcile(reconcileRequest{reason: reason, eventHeight: eventHeight, builderSet: true})
}

func (c *Coordinator) enqueueReconcile(request reconcileRequest) {
	key := reconcileRequestKey(request)
	c.reconcilePendingMu.Lock()
	if pending, exists := c.reconcilePending[key]; exists {
		c.reconcilePending[key] = mergeReconcileRequests(pending, request)
		c.reconcilePendingMu.Unlock()
		return
	}
	c.reconcilePending[key] = request
	c.reconcilePendingMu.Unlock()

	select {
	case <-c.reconcileStarted:
		select {
		case c.reconcileRequests <- request:
		case <-c.reconcileStop:
			c.clearPendingReconcile(key)
		}
		return
	default:
	}
	select {
	case c.reconcileRequests <- request:
	default:
		c.clearPendingReconcile(key)
	}
}

func reconcileRequestKey(request reconcileRequest) string {
	if request.builderSet {
		return "builder-set"
	}
	if request.taskID != "" {
		return "task|" + request.sessionID + "|" + request.taskID
	}
	if request.sessionID != "" {
		return "session|" + request.sessionID
	}
	return "global"
}

func mergeReconcileRequests(pending, incoming reconcileRequest) reconcileRequest {
	if incoming.eventHeight > pending.eventHeight {
		pending.eventHeight = incoming.eventHeight
	}
	if incoming.retryAttempt < pending.retryAttempt {
		pending.retryAttempt = incoming.retryAttempt
	}
	if incoming.reason != "" {
		pending.reason = incoming.reason
	}
	for _, event := range incoming.events {
		duplicate := false
		for _, existing := range pending.events {
			if existing.Type == event.Type && existing.EventCode == event.EventCode && existing.Height == event.Height &&
				taskEventVerifier(existing) == taskEventVerifier(event) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			pending.events = append(pending.events, event)
		}
	}
	return pending
}

func taskEventVerifier(event chaincli.ChainEvent) string {
	if verifier := event.Attrs["verifier_operator_address"]; verifier != "" {
		return verifier
	}
	return event.Attrs["verifier"]
}

func (c *Coordinator) clearPendingReconcile(key string) {
	c.reconcilePendingMu.Lock()
	delete(c.reconcilePending, key)
	c.reconcilePendingMu.Unlock()
}

func (c *Coordinator) takePendingReconcile(key string) (reconcileRequest, bool) {
	c.reconcilePendingMu.Lock()
	request, ok := c.reconcilePending[key]
	if ok {
		delete(c.reconcilePending, key)
	}
	c.reconcilePendingMu.Unlock()
	return request, ok
}

func (c *Coordinator) scheduleReconcileRetry(request reconcileRequest) {
	request.retryAttempt++
	delay := c.reconcileRetryBase
	for attempt := uint(1); attempt < request.retryAttempt && delay < c.reconcileRetryMax; attempt++ {
		if delay > c.reconcileRetryMax/2 {
			delay = c.reconcileRetryMax
			break
		}
		delay *= 2
	}
	if delay > c.reconcileRetryMax {
		delay = c.reconcileRetryMax
	}
	time.AfterFunc(delay, func() {
		select {
		case <-c.reconcileStop:
			return
		default:
			c.enqueueReconcile(request)
		}
	})
}

func (c *Coordinator) startReconcileWorker() {
	c.reconcileStartOnce.Do(func() {
		close(c.reconcileStarted)
		go c.reconcileLoop()
	})
}

func (c *Coordinator) stopReconcileWorker() {
	select {
	case <-c.reconcileStarted:
		c.reconcileStopOnce.Do(func() { close(c.reconcileStop) })
		<-c.reconcileDone
	default:
	}
}

func (c *Coordinator) activeTaskKeys(request reconcileRequest) []chaincli.TaskKey {
	c.mu.RLock()
	keys := make([]chaincli.TaskKey, 0, len(c.tasks))
	for _, fsm := range c.tasks {
		if request.sessionID != "" && fsm.sessionID != request.sessionID {
			continue
		}
		if request.taskID != "" && fsm.taskID != request.taskID {
			continue
		}
		keys = append(keys, chaincli.TaskKey{SessionID: fsm.sessionID, TaskID: fsm.taskID})
	}
	c.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SessionID != keys[j].SessionID {
			return keys[i].SessionID < keys[j].SessionID
		}
		return keys[i].TaskID < keys[j].TaskID
	})
	return keys
}

func (c *Coordinator) requestDueLifecycleReconcile(height uint64) {
	c.mu.RLock()
	tasks := make([]*taskFSM, 0, len(c.tasks))
	for _, fsm := range c.tasks {
		tasks = append(tasks, fsm)
	}
	c.mu.RUnlock()
	for _, fsm := range tasks {
		if fsm.lifecycleBoundaryDue(height) {
			c.requestReconcile("task lifecycle boundary due")
			return
		}
	}
}

// reconcileSettleSelection reads two on-chain facts once settlement inputs are complete: the frozen Task Builder
// order (task TaskBuilders) and the grace blocks per rank (Hub parameter). If either is unavailable the task
// is kept for the next reconciliation; rank 1 is never assumed.
func (c *Coordinator) reconcileSettleSelection(fsm *taskFSM) {
	if c.selection == nil || !fsm.needsSettleSelection() {
		return
	}
	key := chaincli.TaskKey{SessionID: fsm.sessionID, TaskID: fsm.taskID}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
	builders, err := c.selection.QueryTaskBuilders(ctx, key)
	cancel()
	if err != nil {
		c.log.Warn("settle selection query failed; retaining task", "task_id", key.TaskID, "err", err)
		return
	}
	selection := settleSelectionFromTaskBuilders(key, builders)
	if err := validateSettleSelection(key, selection); err != nil {
		c.log.Warn("settle selection invalid; retaining task", "task_id", key.TaskID, "err", err)
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), reconcileQueryTimeout)
	grace, err := c.selection.QuerySettlementBuilderGraceBlocks(ctx)
	cancel()
	if err != nil {
		c.log.Warn("settlement grace blocks query failed; retaining task", "task_id", key.TaskID, "err", err)
		return
	}
	fsm.mu.Lock()
	if fsm.state != types.Verifying || fsm.terminal || fsm.settleSelection.SessionID != "" ||
		fsm.consistentVerifyGroup() == nil {
		fsm.mu.Unlock()
		return
	}
	fsm.settleSelection = selection
	fsm.settleGraceBlocks = grace
	if err := fsm.save(); err != nil {
		fsm.settleSelection = chaincli.StageBuilderSelectionState{}
		fsm.settleGraceBlocks = 0
		fsm.mu.Unlock()
		c.log.Warn("settle selection persist failed; retaining task", "task_id", key.TaskID, "err", err)
		return
	}
	fsm.trySettle()
	fsm.mu.Unlock()
}

func (c *Coordinator) markReconciled(height uint64) error {
	c.chainStateMu.Lock()
	defer c.chainStateMu.Unlock()
	next := c.chainState
	next.Version = chainStateVersion
	next.LastReconciledHeight = height
	raw, err := json.Marshal(next)
	if err == nil {
		err = c.kv.Set(kv.NSChainState, chainStateKey, raw)
	}
	if err != nil {
		return fmt.Errorf("persist reconciled height: %w", err)
	}
	c.chainState = next
	return nil
}

func (c *Coordinator) reconcileLoop() {
	defer close(c.reconcileDone)
	for {
		select {
		case <-c.reconcileStop:
			return
		case wake := <-c.reconcileRequests:
			request, ok := c.takePendingReconcile(reconcileRequestKey(wake))
			if !ok {
				continue
			}
			reason := request.reason
			if request.builderSet {
				ctx, cancel := context.WithTimeout(context.Background(), reconcileQueryTimeout)
				err := c.seedBuilderSet(ctx)
				cancel()
				if err != nil {
					c.log.Warn("Hub BuilderSet event reconciliation failed", "height", request.eventHeight, "err", err)
					c.scheduleReconcileRetry(request)
				}
				continue
			}
			global := request.sessionID == "" && request.taskID == ""
			if err := c.retryPayloadCleanup(context.Background()); err != nil {
				c.log.Error("payload cleanup retry failed", "reason", reason, "err", err)
			}
			c.refreshEpochLength(context.Background())
			height, err := c.refreshChainHeight(context.Background())
			if err != nil {
				c.log.Warn("chain reconciliation height refresh failed", "reason", reason, "err", err)
				if global {
					c.scheduleReconcileRetry(request)
					continue
				}
			} else if c.payloads != nil {
				if err := c.payloads.Sweep(context.Background(), height); err != nil {
					c.log.Error("payload reconciliation sweep failed", "height", height, "err", err)
				}
			}
			keys := c.activeTaskKeys(request)
			allTasksReconciled := true
			for start := 0; start < len(keys); start += reconcileBatchSize {
				end := start + reconcileBatchSize
				if end > len(keys) {
					end = len(keys)
				}
				for _, key := range keys[start:end] {
					if !c.reconcileTask(key.SessionID, key.TaskID, request.eventHeight, reason, request.events) {
						allTasksReconciled = false
						continue
					}
				}
				select {
				case <-c.reconcileStop:
					return
				default:
				}
			}
			if !allTasksReconciled {
				c.scheduleReconcileRetry(request)
				continue
			}
			if global && allTasksReconciled {
				if err := c.markReconciled(height); err != nil {
					c.log.Warn("chain reconciliation cursor persist failed", "height", height, "err", err)
					c.scheduleReconcileRetry(request)
				}
			}
		}
	}
}
