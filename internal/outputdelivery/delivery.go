// Package outputdelivery stores final plaintext outputs until the order user
// acknowledges delivery or the bounded retention period expires.
package outputdelivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	statePrepared = "PREPARED"
	stateReady    = "READY"

	statusAcked       = "ACKED"
	statusExpired     = "EXPIRED"
	statusUnavailable = "UNAVAILABLE"

	maxPlaintextTTL = 4 * time.Hour
)

type Config struct {
	RequirePlaintext bool
	MaxBytes         int
	PlaintextTTL     time.Duration
	TombstoneTTL     time.Duration
	SweepInterval    time.Duration
}

type Submission struct {
	SessionID  string
	TaskID     string
	Recipient  string
	OutputText *string
	OutputHash []byte
}

type SubscribeRequest struct {
	SessionID       string
	TaskID          string
	Requester       string
	ActiveTaskOwner string
}

type AckRequest struct {
	SessionID string
	TaskID    string
	OutputID  string
	Requester string
}

type PreparedResolver func(sessionID, taskID string, outputHash []byte) bool
type TaskTerminal func(sessionID, taskID string) bool
type TerminationObserver func(sessionID, taskID string)

// TombstoneObserver is told after a task's tombstone has been deleted at the end of its
// retention period, so the caller can drop what it kept only for that tombstone.
type TombstoneObserver func(sessionID, taskID string)

type Manager interface {
	Start(context.Context) error
	Stop(context.Context) error
	Prepare(Submission) (outputID string, prepared bool, err error)
	Commit(sessionID, taskID, outputID string) error
	Subscribe(context.Context, SubscribeRequest) (types.PlaintextOutput, error)
	Ack(AckRequest) (types.OutputAck, error)
	Terminate(sessionID, taskID, recipient string) error
	Known(sessionID, taskID string) bool
	SetPreparedResolver(PreparedResolver)
	SetTaskTerminal(TaskTerminal)
	SetTerminationObserver(TerminationObserver)
	SetTombstoneObserver(TombstoneObserver)
}

type Option func(*manager)

func WithClock(now func() time.Time) Option {
	return func(m *manager) {
		if now != nil {
			m.now = now
		}
	}
}

type outputRecord struct {
	OutputID  string `json:"output_id"`
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Recipient string `json:"recipient"`
	Text      string `json:"output_text"`
	Hash      []byte `json:"output_hash"`
	State     string `json:"state"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type outputTombstone struct {
	OutputID  string `json:"output_id"`
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Recipient string `json:"recipient"`
	Status    string `json:"status"`
	FinalAt   int64  `json:"final_at"`
}

type pendingTermination struct {
	sessionID string
	taskID    string
	recipient string
}

type terminalSignal struct {
	err error
}

type manager struct {
	log   *slog.Logger
	store kv.Store
	cfg   Config
	now   func() time.Time

	mu         sync.Mutex
	records    map[string]outputRecord
	tombs      map[string]outputTombstone
	waiters    map[string]map[uint64]chan terminalSignal
	nextWaiter uint64
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	started    bool
	loaded     bool
	pending    map[string]pendingTermination
	prepared   PreparedResolver
	terminal   TaskTerminal
	terminated TerminationObserver
	tombGone   TombstoneObserver
}

func New(log *slog.Logger, store kv.Store, cfg Config, opts ...Option) (Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("outputdelivery: nil store")
	}
	if cfg.MaxBytes <= 0 || cfg.PlaintextTTL <= 0 || cfg.PlaintextTTL > maxPlaintextTTL ||
		cfg.TombstoneTTL <= 0 || cfg.SweepInterval <= 0 {
		return nil, fmt.Errorf("outputdelivery: max bytes and durations must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	m := &manager{
		log:     log,
		store:   store,
		cfg:     cfg,
		now:     time.Now,
		records: make(map[string]outputRecord),
		tombs:   make(map[string]outputTombstone),
		waiters: make(map[string]map[uint64]chan terminalSignal),
		stop:    make(chan struct{}),
		pending: make(map[string]pendingTermination),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

func deliveryKey(sessionID, taskID string) string { return sessionID + "|" + taskID }

func outputID(sessionID, taskID string, outputHash []byte) string {
	sum := sdkauth.BodyDigest(
		[]byte("TRUEOPEN_OUTPUT_DELIVERY_V1"),
		[]byte(sessionID),
		[]byte(taskID),
		outputHash,
	)
	return hex.EncodeToString(sum)
}

func (m *manager) Prepare(sub Submission) (string, bool, error) {
	if sub.OutputText == nil {
		if m.cfg.RequirePlaintext {
			return "", false, ErrPlaintextRequired
		}
		return "", false, nil
	}
	if !utf8.ValidString(*sub.OutputText) {
		return "", false, ErrInvalidUTF8
	}
	if len([]byte(*sub.OutputText)) > m.cfg.MaxBytes {
		return "", false, ErrTooLarge
	}
	hash := sha256.Sum256([]byte(*sub.OutputText))
	if !bytes.Equal(hash[:], sub.OutputHash) {
		return "", false, ErrHashMismatch
	}
	id := outputID(sub.SessionID, sub.TaskID, sub.OutputHash)
	key := deliveryKey(sub.SessionID, sub.TaskID)

	m.mu.Lock()
	defer m.mu.Unlock()
	if tomb, ok := m.tombs[key]; ok {
		if tomb.Status == statusExpired {
			return "", false, ErrExpired
		}
		if tomb.Status == statusAcked && tomb.OutputID == id {
			return id, false, nil
		}
		return "", false, ErrConflict
	}
	if current, ok := m.records[key]; ok {
		if current.ExpiresAt <= m.now().UnixMilli() {
			if err := m.finalizeRecordLocked(current, statusExpired); err != nil {
				return "", false, err
			}
			return "", false, ErrExpired
		}
		if current.OutputID != id || current.Recipient != sub.Recipient {
			return "", false, ErrConflict
		}
		return id, true, nil
	}

	now := m.now()
	rec := outputRecord{
		OutputID: id, SessionID: sub.SessionID, TaskID: sub.TaskID,
		Recipient: sub.Recipient, Text: *sub.OutputText,
		Hash: append([]byte(nil), sub.OutputHash...), State: statePrepared,
		CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(m.cfg.PlaintextTTL).UnixMilli(),
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return "", false, fmt.Errorf("%w: encode prepared output: %v", ErrDeliveryFailure, err)
	}
	if err := m.store.Set(kv.NSOutputDelivery, key, raw); err != nil {
		return "", false, fmt.Errorf("%w: persist prepared output: %v", ErrDeliveryFailure, err)
	}
	m.records[key] = rec
	return id, true, nil
}

func (m *manager) Commit(sessionID, taskID, id string) error {
	key := deliveryKey(sessionID, taskID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tombs[key]; ok {
		return ErrConflict
	}
	rec, ok := m.records[key]
	if !ok || rec.OutputID != id {
		return ErrConflict
	}
	if rec.ExpiresAt <= m.now().UnixMilli() {
		if err := m.finalizeRecordLocked(rec, statusExpired); err != nil {
			return err
		}
		return ErrExpired
	}
	if rec.State == stateReady {
		return nil
	}
	return m.promoteReadyLocked(key, rec)
}

func (m *manager) promoteReadyLocked(key string, rec outputRecord) error {
	rec.State = stateReady
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("%w: encode ready output: %v", ErrDeliveryFailure, err)
	}
	if err := m.store.Set(kv.NSOutputDelivery, key, raw); err != nil {
		return fmt.Errorf("%w: persist ready output: %v", ErrDeliveryFailure, err)
	}
	m.records[key] = rec
	m.signalWaitersLocked(key, terminalSignal{})
	return nil
}

func (m *manager) Start(context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	select {
	case <-m.stop:
		m.mu.Unlock()
		return ErrDeliveryFailure
	default:
	}
	resolvePrepared := m.prepared
	m.mu.Unlock()

	tombs, err := m.loadTombstones()
	if err != nil {
		return err
	}
	records, err := m.loadRecords(tombs, resolvePrepared)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.tombs = tombs
	m.records = records
	m.loaded = true
	var pendingErr error
	var finalized []pendingTermination
	for key, pending := range m.pending {
		if err := m.terminateLocked(pending.sessionID, pending.taskID, pending.recipient); err != nil {
			if pendingErr == nil {
				pendingErr = err
			}
			continue
		}
		delete(m.pending, key)
		finalized = append(finalized, pending)
	}
	m.mu.Unlock()
	m.notifyTerminations(finalized)
	if pendingErr != nil {
		return pendingErr
	}
	if err := m.sweep(); err != nil {
		m.log.Error("initial output delivery sweep failed; background retry enabled", "err", err)
	}
	m.mu.Lock()
	select {
	case <-m.stop:
		m.mu.Unlock()
		return ErrDeliveryFailure
	default:
	}
	m.started = true
	m.wg.Add(1)
	m.mu.Unlock()
	go m.runSweeper()
	return nil
}

func (m *manager) Stop(context.Context) error {
	m.stopOnce.Do(func() { close(m.stop) })
	m.wg.Wait()
	return nil
}

func (m *manager) Subscribe(ctx context.Context, req SubscribeRequest) (types.PlaintextOutput, error) {
	key := deliveryKey(req.SessionID, req.TaskID)
	m.mu.Lock()
	select {
	case <-m.stop:
		m.mu.Unlock()
		return types.PlaintextOutput{}, ErrDeliveryFailure
	default:
	}
	if tomb, ok := m.tombs[key]; ok {
		err := tombstoneError(tomb, req.Requester)
		m.mu.Unlock()
		return types.PlaintextOutput{}, err
	}
	if rec, ok := m.records[key]; ok {
		if rec.Recipient != req.Requester {
			m.mu.Unlock()
			return types.PlaintextOutput{}, ErrUnauthorized
		}
		if rec.ExpiresAt <= m.now().UnixMilli() {
			if err := m.finalizeRecordLocked(rec, statusExpired); err != nil {
				m.mu.Unlock()
				return types.PlaintextOutput{}, err
			}
			m.mu.Unlock()
			return types.PlaintextOutput{}, ErrExpired
		}
		if rec.State == stateReady {
			output := plaintextOutput(rec)
			m.mu.Unlock()
			return output, nil
		}
	} else if req.ActiveTaskOwner == "" {
		m.mu.Unlock()
		return types.PlaintextOutput{}, ErrUnavailable
	} else if req.ActiveTaskOwner != req.Requester {
		m.mu.Unlock()
		return types.PlaintextOutput{}, ErrUnauthorized
	}

	m.nextWaiter++
	waiterID := m.nextWaiter
	ch := make(chan terminalSignal, 1)
	if m.waiters[key] == nil {
		m.waiters[key] = make(map[uint64]chan terminalSignal)
	}
	m.waiters[key][waiterID] = ch
	m.mu.Unlock()

	select {
	case signal := <-ch:
		if signal.err != nil {
			return types.PlaintextOutput{}, signal.err
		}
		return m.readReady(req, key)
	case <-ctx.Done():
		m.removeWaiter(key, waiterID)
		return types.PlaintextOutput{}, ctx.Err()
	case <-m.stop:
		m.removeWaiter(key, waiterID)
		return types.PlaintextOutput{}, ErrDeliveryFailure
	}
}

func (m *manager) readReady(req SubscribeRequest, key string) (types.PlaintextOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.stop:
		return types.PlaintextOutput{}, ErrDeliveryFailure
	default:
	}
	if tomb, ok := m.tombs[key]; ok {
		return types.PlaintextOutput{}, tombstoneError(tomb, req.Requester)
	}
	rec, ok := m.records[key]
	if !ok || rec.State != stateReady {
		return types.PlaintextOutput{}, ErrUnavailable
	}
	if rec.Recipient != req.Requester {
		return types.PlaintextOutput{}, ErrUnauthorized
	}
	if rec.ExpiresAt <= m.now().UnixMilli() {
		if err := m.finalizeRecordLocked(rec, statusExpired); err != nil {
			return types.PlaintextOutput{}, err
		}
		return types.PlaintextOutput{}, ErrExpired
	}
	return plaintextOutput(rec), nil
}

func (m *manager) Ack(req AckRequest) (types.OutputAck, error) {
	key := deliveryKey(req.SessionID, req.TaskID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if tomb, ok := m.tombs[key]; ok {
		if tomb.Recipient != req.Requester {
			return types.OutputAck{}, ErrUnauthorized
		}
		if tomb.Status == statusAcked {
			if tomb.OutputID != req.OutputID {
				return types.OutputAck{}, ErrConflict
			}
			return types.OutputAck{Acked: true, AlreadyAcked: true, AckedAt: tomb.FinalAt}, nil
		}
		return types.OutputAck{}, tombstoneStatusError(tomb.Status)
	}
	rec, ok := m.records[key]
	if !ok || rec.State != stateReady {
		return types.OutputAck{}, ErrUnavailable
	}
	if rec.Recipient != req.Requester {
		return types.OutputAck{}, ErrUnauthorized
	}
	if rec.OutputID != req.OutputID {
		return types.OutputAck{}, ErrConflict
	}
	if rec.ExpiresAt <= m.now().UnixMilli() {
		if err := m.finalizeRecordLocked(rec, statusExpired); err != nil {
			return types.OutputAck{}, err
		}
		return types.OutputAck{}, ErrExpired
	}

	tomb := outputTombstone{
		OutputID: rec.OutputID, SessionID: rec.SessionID, TaskID: rec.TaskID,
		Recipient: rec.Recipient, Status: statusAcked, FinalAt: m.now().UnixMilli(),
	}
	raw, err := json.Marshal(tomb)
	if err != nil {
		return types.OutputAck{}, fmt.Errorf("%w: encode ack tombstone: %v", ErrDeliveryFailure, err)
	}
	if err := m.store.Set(kv.NSOutputTombstone, key, raw); err != nil {
		return types.OutputAck{}, fmt.Errorf("%w: persist ack tombstone: %v", ErrDeliveryFailure, err)
	}
	m.tombs[key] = tomb
	delete(m.records, key)
	m.signalWaitersLocked(key, terminalSignal{err: ErrAlreadyAcked})
	if err := m.store.Delete(kv.NSOutputDelivery, key); err != nil {
		m.log.Error("output plaintext cleanup failed",
			"session_id", req.SessionID,
			"task_id", req.TaskID,
			"output_id", req.OutputID,
			"err", err,
		)
	}
	return types.OutputAck{Acked: true, AckedAt: tomb.FinalAt}, nil
}

func (m *manager) Terminate(sessionID, taskID, recipient string) error {
	key := deliveryKey(sessionID, taskID)
	m.mu.Lock()
	if !m.loaded {
		if _, exists := m.pending[key]; !exists {
			m.pending[key] = pendingTermination{
				sessionID: sessionID, taskID: taskID, recipient: recipient,
			}
		}
		m.mu.Unlock()
		return nil
	}
	err := m.terminateLocked(sessionID, taskID, recipient)
	if err != nil {
		m.pending[key] = pendingTermination{
			sessionID: sessionID, taskID: taskID, recipient: recipient,
		}
		m.mu.Unlock()
		return err
	}
	delete(m.pending, key)
	observer := m.terminated
	m.mu.Unlock()
	if observer != nil {
		observer(sessionID, taskID)
	}
	return nil
}

func (m *manager) Known(sessionID, taskID string) bool {
	key := deliveryKey(sessionID, taskID)
	m.mu.Lock()
	defer m.mu.Unlock()
	_, recordExists := m.records[key]
	_, tombExists := m.tombs[key]
	return recordExists || tombExists
}

func (m *manager) terminateLocked(sessionID, taskID, recipient string) error {
	key := deliveryKey(sessionID, taskID)
	if _, ok := m.tombs[key]; ok {
		return nil
	}
	if rec, ok := m.records[key]; ok {
		if rec.State == stateReady && rec.ExpiresAt > m.now().UnixMilli() {
			return nil
		}
		if rec.ExpiresAt <= m.now().UnixMilli() {
			return m.finalizeRecordLocked(rec, statusExpired)
		}
		if rec.State == statePrepared && m.prepared != nil &&
			m.prepared(rec.SessionID, rec.TaskID, rec.Hash) {
			return m.promoteReadyLocked(key, rec)
		}
		return m.finalizeRecordLocked(rec, statusUnavailable)
	}
	return m.finalizeMissingLocked(sessionID, taskID, recipient, statusUnavailable)
}

func (m *manager) SetPreparedResolver(resolve PreparedResolver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prepared = resolve
}

func (m *manager) SetTaskTerminal(terminal TaskTerminal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.terminal = terminal
}

func (m *manager) SetTerminationObserver(observer TerminationObserver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.terminated = observer
}

func (m *manager) SetTombstoneObserver(observer TombstoneObserver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tombGone = observer
}

func (m *manager) notifyTerminations(finalized []pendingTermination) {
	m.mu.Lock()
	observer := m.terminated
	m.mu.Unlock()
	if observer == nil {
		return
	}
	for _, item := range finalized {
		observer(item.sessionID, item.taskID)
	}
}

func plaintextOutput(rec outputRecord) types.PlaintextOutput {
	return types.PlaintextOutput{
		OutputID:  rec.OutputID,
		SessionID: rec.SessionID,
		TaskID:    rec.TaskID,
		Text:      rec.Text,
		Hash:      append([]byte(nil), rec.Hash...),
		CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.ExpiresAt,
	}
}

func tombstoneError(tomb outputTombstone, requester string) error {
	if tomb.Recipient != requester {
		return ErrUnauthorized
	}
	return tombstoneStatusError(tomb.Status)
}

func tombstoneStatusError(status string) error {
	switch status {
	case statusAcked:
		return ErrAlreadyAcked
	case statusExpired:
		return ErrExpired
	default:
		return ErrUnavailable
	}
}

func (m *manager) signalWaitersLocked(key string, signal terminalSignal) {
	for _, waiter := range m.waiters[key] {
		waiter <- signal
	}
	delete(m.waiters, key)
}

func (m *manager) removeWaiter(key string, waiterID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	waiters := m.waiters[key]
	delete(waiters, waiterID)
	if len(waiters) == 0 {
		delete(m.waiters, key)
	}
}

func (m *manager) finalizeRecordLocked(rec outputRecord, status string) error {
	key := deliveryKey(rec.SessionID, rec.TaskID)
	if _, ok := m.tombs[key]; ok {
		return nil
	}
	tomb := outputTombstone{
		OutputID: rec.OutputID, SessionID: rec.SessionID, TaskID: rec.TaskID,
		Recipient: rec.Recipient, Status: status, FinalAt: m.now().UnixMilli(),
	}
	if err := m.persistTombstoneLocked(key, tomb); err != nil {
		return err
	}
	delete(m.records, key)
	m.signalWaitersLocked(key, terminalSignal{err: tombstoneStatusError(status)})
	m.deletePlaintext(key, rec)
	return nil
}

func (m *manager) finalizeMissingLocked(sessionID, taskID, recipient, status string) error {
	key := deliveryKey(sessionID, taskID)
	tomb := outputTombstone{
		SessionID: sessionID, TaskID: taskID, Recipient: recipient,
		Status: status, FinalAt: m.now().UnixMilli(),
	}
	if err := m.persistTombstoneLocked(key, tomb); err != nil {
		return err
	}
	m.signalWaitersLocked(key, terminalSignal{err: tombstoneStatusError(status)})
	return nil
}

func (m *manager) persistTombstoneLocked(key string, tomb outputTombstone) error {
	raw, err := json.Marshal(tomb)
	if err != nil {
		return fmt.Errorf("%w: encode %s tombstone: %v", ErrDeliveryFailure, tomb.Status, err)
	}
	if err := m.store.Set(kv.NSOutputTombstone, key, raw); err != nil {
		return fmt.Errorf("%w: persist %s tombstone: %v", ErrDeliveryFailure, tomb.Status, err)
	}
	m.tombs[key] = tomb
	return nil
}

func (m *manager) deletePlaintext(key string, rec outputRecord) {
	if err := m.store.Delete(kv.NSOutputDelivery, key); err != nil {
		m.log.Error("output plaintext cleanup failed",
			"session_id", rec.SessionID,
			"task_id", rec.TaskID,
			"output_id", rec.OutputID,
			"err", err,
		)
	}
}

func (m *manager) loadTombstones() (map[string]outputTombstone, error) {
	tombs := make(map[string]outputTombstone)
	var scanErr error
	err := m.store.Scan(kv.NSOutputTombstone, func(key string, raw []byte) bool {
		var tomb outputTombstone
		if err := json.Unmarshal(raw, &tomb); err != nil {
			scanErr = fmt.Errorf("%w: decode tombstone %q: %v", ErrDeliveryFailure, key, err)
			return false
		}
		if key != deliveryKey(tomb.SessionID, tomb.TaskID) {
			scanErr = fmt.Errorf("%w: tombstone key mismatch %q", ErrDeliveryFailure, key)
			return false
		}
		tombs[key] = tomb
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("%w: scan output tombstones: %v", ErrDeliveryFailure, err)
	}
	return tombs, scanErr
}

func (m *manager) loadRecords(
	tombs map[string]outputTombstone,
	resolvePrepared PreparedResolver,
) (map[string]outputRecord, error) {
	records := make(map[string]outputRecord)
	var scanErr error
	now := m.now().UnixMilli()
	err := m.store.Scan(kv.NSOutputDelivery, func(key string, raw []byte) bool {
		if _, terminal := tombs[key]; terminal {
			if err := m.store.Delete(kv.NSOutputDelivery, key); err != nil {
				m.log.Error("stale output plaintext cleanup failed", "key", key, "err", err)
			}
			return true
		}
		var rec outputRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			scanErr = fmt.Errorf("%w: decode output %q: %v", ErrDeliveryFailure, key, err)
			return false
		}
		if key != deliveryKey(rec.SessionID, rec.TaskID) {
			scanErr = fmt.Errorf("%w: output key mismatch %q", ErrDeliveryFailure, key)
			return false
		}
		if rec.ExpiresAt <= now {
			tomb := outputTombstone{
				OutputID: rec.OutputID, SessionID: rec.SessionID, TaskID: rec.TaskID,
				Recipient: rec.Recipient, Status: statusExpired, FinalAt: now,
			}
			tombRaw, err := json.Marshal(tomb)
			if err != nil {
				scanErr = fmt.Errorf("%w: encode recovery tombstone: %v", ErrDeliveryFailure, err)
				return false
			}
			if err := m.store.Set(kv.NSOutputTombstone, key, tombRaw); err != nil {
				scanErr = fmt.Errorf("%w: persist recovery tombstone: %v", ErrDeliveryFailure, err)
				return false
			}
			tombs[key] = tomb
			m.deletePlaintext(key, rec)
			return true
		}
		switch rec.State {
		case stateReady:
			records[key] = rec
		case statePrepared:
			if resolvePrepared == nil || !resolvePrepared(rec.SessionID, rec.TaskID, rec.Hash) {
				m.deletePlaintext(key, rec)
				return true
			}
			rec.State = stateReady
			readyRaw, err := json.Marshal(rec)
			if err != nil {
				scanErr = fmt.Errorf("%w: encode recovered output: %v", ErrDeliveryFailure, err)
				return false
			}
			if err := m.store.Set(kv.NSOutputDelivery, key, readyRaw); err != nil {
				scanErr = fmt.Errorf("%w: persist recovered output: %v", ErrDeliveryFailure, err)
				return false
			}
			records[key] = rec
		default:
			scanErr = fmt.Errorf("%w: invalid output state %q", ErrDeliveryFailure, rec.State)
			return false
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("%w: scan output records: %v", ErrDeliveryFailure, err)
	}
	return records, scanErr
}

func (m *manager) runSweeper() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := m.sweep(); err != nil {
				m.log.Error("output delivery sweep failed", "err", err)
			}
		case <-m.stop:
			return
		}
	}
}

func (m *manager) sweep() error {
	now := m.now().UnixMilli()
	m.mu.Lock()
	var firstErr error
	var finalized []pendingTermination
	for key, pending := range m.pending {
		if err := m.terminateLocked(pending.sessionID, pending.taskID, pending.recipient); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		delete(m.pending, key)
		finalized = append(finalized, pending)
	}
	for _, rec := range m.records {
		if rec.ExpiresAt > now {
			continue
		}
		if err := m.finalizeRecordLocked(rec, statusExpired); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	type candidate struct {
		key  string
		tomb outputTombstone
	}
	terminal := m.terminal
	candidates := make([]candidate, 0)
	for key, tomb := range m.tombs {
		_, stale, err := m.store.GetWithError(kv.NSOutputDelivery, key)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: inspect stale plaintext: %v", ErrDeliveryFailure, err)
			}
			continue
		}
		if stale {
			if err := m.store.Delete(kv.NSOutputDelivery, key); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%w: retry plaintext delete: %v", ErrDeliveryFailure, err)
				}
				continue
			}
			_, stillStale, err := m.store.GetWithError(kv.NSOutputDelivery, key)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%w: verify plaintext delete: %v", ErrDeliveryFailure, err)
				}
				continue
			}
			if stillStale {
				continue
			}
		}
		if terminal != nil && tomb.FinalAt+m.cfg.TombstoneTTL.Milliseconds() <= now {
			candidates = append(candidates, candidate{key: key, tomb: tomb})
		}
	}
	m.mu.Unlock()
	m.notifyTerminations(finalized)

	for _, item := range candidates {
		if !terminal(item.tomb.SessionID, item.tomb.TaskID) {
			continue
		}
		m.mu.Lock()
		removed := false
		current, ok := m.tombs[item.key]
		if ok && current == item.tomb {
			if err := m.store.Delete(kv.NSOutputTombstone, item.key); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%w: delete tombstone: %v", ErrDeliveryFailure, err)
				}
			} else {
				delete(m.tombs, item.key)
				removed = true
			}
		}
		observer := m.tombGone
		m.mu.Unlock()
		if removed && observer != nil {
			observer(item.tomb.SessionID, item.tomb.TaskID)
		}
	}
	return firstErr
}
