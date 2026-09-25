package outputdelivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

func testConfig() Config {
	return Config{
		MaxBytes:      1 << 20,
		PlaintextTTL:  4 * time.Hour,
		TombstoneTTL:  24 * time.Hour,
		SweepInterval: time.Minute,
	}
}

func newCoreTestManager(t *testing.T, cfg Config) (*manager, kv.Store, *time.Time) {
	t.Helper()
	store := kv.NewMemStore()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, cfg, &now)
	return m, store, &now
}

func newCoreTestManagerWithStore(t *testing.T, store kv.Store, cfg Config, now *time.Time) *manager {
	t.Helper()
	created, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		store,
		cfg,
		WithClock(func() time.Time { return *now }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m, ok := created.(*manager)
	if !ok {
		t.Fatalf("manager type = %T", created)
	}
	return m
}

func submission(text *string) Submission {
	var hash []byte
	if text != nil {
		sum := sha256.Sum256([]byte(*text))
		hash = sum[:]
	}
	return Submission{
		SessionID:  "session-1",
		TaskID:     "task-1",
		Recipient:  "trueopen1user",
		OutputText: text,
		OutputHash: hash,
	}
}

func loadRecord(t *testing.T, store kv.Store) outputRecord {
	t.Helper()
	raw, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1"))
	if !ok {
		t.Fatal("output record missing")
	}
	var rec outputRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return rec
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	valid := testConfig()
	tests := map[string]Config{
		"zero max bytes":     func() Config { c := valid; c.MaxBytes = 0; return c }(),
		"zero plaintext ttl": func() Config { c := valid; c.PlaintextTTL = 0; return c }(),
		"plaintext ttl above hard limit": func() Config {
			c := valid
			c.PlaintextTTL = 4*time.Hour + time.Nanosecond
			return c
		}(),
		"zero tombstone ttl": func() Config { c := valid; c.TombstoneTTL = 0; return c }(),
		"zero sweep":         func() Config { c := valid; c.SweepInterval = 0; return c }(),
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(log, kv.NewMemStore(), cfg); err == nil {
				t.Fatal("New must reject invalid config")
			}
		})
	}
	if _, err := New(log, nil, valid); err == nil {
		t.Fatal("New must reject nil store")
	}
}

func TestPrepareIsInvisibleUntilCommit(t *testing.T) {
	m, store, _ := newCoreTestManager(t, testConfig())
	text := "hello"
	id, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared || id == "" {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}
	rec := loadRecord(t, store)
	if rec.State != statePrepared || rec.Text != text {
		t.Fatalf("prepared record = %+v", rec)
	}
	if err := m.Commit("session-1", "task-1", id); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	rec = loadRecord(t, store)
	if rec.State != stateReady || rec.OutputID != id {
		t.Fatalf("ready record = %+v", rec)
	}
}

func TestPrepareAcceptsPresentEmptyOutput(t *testing.T) {
	m, _, _ := newCoreTestManager(t, Config{
		RequirePlaintext: true,
		MaxBytes:         16,
		PlaintextTTL:     time.Hour,
		TombstoneTTL:     time.Hour,
		SweepInterval:    time.Minute,
	})
	empty := ""
	id, prepared, err := m.Prepare(submission(&empty))
	if err != nil || !prepared || id == "" {
		t.Fatalf("empty Prepare = %q/%v/%v", id, prepared, err)
	}
}

func TestPrepareRejectsMissingRequiredPlaintext(t *testing.T) {
	required := testConfig()
	required.RequirePlaintext = true
	m, _, _ := newCoreTestManager(t, required)
	if _, _, err := m.Prepare(submission(nil)); !errors.Is(err, ErrPlaintextRequired) {
		t.Fatalf("required missing error = %v", err)
	}

	compatible := testConfig()
	m, _, _ = newCoreTestManager(t, compatible)
	id, prepared, err := m.Prepare(submission(nil))
	if err != nil || prepared || id != "" {
		t.Fatalf("compatible missing = %q/%v/%v", id, prepared, err)
	}
}

func TestPrepareRejectsHashMismatchAndOversize(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBytes = 4
	m, _, _ := newCoreTestManager(t, cfg)

	large := "hello"
	if _, _, err := m.Prepare(submission(&large)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}

	short := "hey"
	bad := submission(&short)
	bad.OutputHash = bytes.Repeat([]byte{0xff}, sha256.Size)
	if _, _, err := m.Prepare(bad); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}

	invalid := string([]byte{0xff})
	if _, _, err := m.Prepare(submission(&invalid)); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestPrepareIsIdempotentWithoutExtendingTTL(t *testing.T) {
	m, store, now := newCoreTestManager(t, testConfig())
	text := "same"
	firstID, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared {
		t.Fatalf("first Prepare = %q/%v/%v", firstID, prepared, err)
	}
	first := loadRecord(t, store)
	*now = now.Add(time.Hour)
	secondID, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared || secondID != firstID {
		t.Fatalf("second Prepare = %q/%v/%v", secondID, prepared, err)
	}
	second := loadRecord(t, store)
	if second.CreatedAt != first.CreatedAt || second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("TTL moved: first=%+v second=%+v", first, second)
	}
}

func TestPrepareRejectsConflictingOutput(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	first := "first"
	if _, _, err := m.Prepare(submission(&first)); err != nil {
		t.Fatalf("first Prepare: %v", err)
	}
	second := "second"
	if _, _, err := m.Prepare(submission(&second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

type subscribeResult struct {
	outputID string
	text     string
	hash     []byte
	err      error
}

type faultStore struct {
	kv.Store
	failTombstoneSet bool
	failOutputDelete bool
	failScanNS       kv.Namespace
	failOutputGet    bool
	failReadySet     bool
}

func (s *faultStore) Set(ns kv.Namespace, key string, val []byte) error {
	if ns == kv.NSOutputTombstone && s.failTombstoneSet {
		return errors.New("injected tombstone write failure")
	}
	if ns == kv.NSOutputDelivery && s.failReadySet {
		var rec outputRecord
		if json.Unmarshal(val, &rec) == nil && rec.State == stateReady {
			return errors.New("injected ready write failure")
		}
	}
	return s.Store.Set(ns, key, val)
}

func (s *faultStore) Delete(ns kv.Namespace, key string) error {
	if ns == kv.NSOutputDelivery && s.failOutputDelete {
		return errors.New("injected plaintext delete failure")
	}
	return s.Store.Delete(ns, key)
}

func (s *faultStore) Scan(ns kv.Namespace, fn func(key string, val []byte) bool) error {
	if ns == s.failScanNS {
		return errors.New("injected scan failure")
	}
	return s.Store.Scan(ns, fn)
}

func (s *faultStore) GetWithError(ns kv.Namespace, key string) ([]byte, bool, error) {
	if ns == kv.NSOutputDelivery && s.failOutputGet {
		return nil, false, errors.New("injected output read failure")
	}
	return s.Store.GetWithError(ns, key)
}

func subscribeAsync(ctx context.Context, m *manager, requester string) <-chan subscribeResult {
	result := make(chan subscribeResult, 1)
	go func() {
		output, err := m.Subscribe(ctx, SubscribeRequest{
			SessionID:       "session-1",
			TaskID:          "task-1",
			Requester:       requester,
			ActiveTaskOwner: "trueopen1user",
		})
		result <- subscribeResult{
			outputID: output.OutputID,
			text:     output.Text,
			hash:     output.Hash,
			err:      err,
		}
	}()
	return result
}

func waitForSubscribers(t *testing.T, m *manager, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.waiters[deliveryKey("session-1", "task-1")])
		m.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("subscriber count did not reach %d", want)
}

func prepareAndCommit(t *testing.T, m *manager, text string) string {
	t.Helper()
	id, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}
	if err := m.Commit("session-1", "task-1", id); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return id
}

func assertDelivered(t *testing.T, result subscribeResult, id, text string) {
	t.Helper()
	if result.err != nil {
		t.Fatalf("Subscribe: %v", result.err)
	}
	wantHash := sha256.Sum256([]byte(text))
	if result.outputID != id || result.text != text || !bytes.Equal(result.hash, wantHash[:]) {
		t.Fatalf("output = id:%q text:%q hash:%x", result.outputID, result.text, result.hash)
	}
}

func TestSubscribeWaitsThenReceivesCommittedOutput(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	text := "hello after subscribe"
	id, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := subscribeAsync(ctx, m, "trueopen1user")
	waitForSubscribers(t, m, 1)
	if err := m.Commit("session-1", "task-1", id); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertDelivered(t, <-result, id, text)
}

func TestSubscribeImmediatelyReplaysReadyOutput(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	text := "ready"
	id := prepareAndCommit(t, m, text)
	result := <-subscribeAsync(context.Background(), m, "trueopen1user")
	assertDelivered(t, result, id, text)
}

func TestSubscribeRejectsWrongRecipient(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	prepareAndCommit(t, m, "private")
	result := <-subscribeAsync(context.Background(), m, "trueopen1other")
	if !errors.Is(result.err, ErrUnauthorized) {
		t.Fatalf("Subscribe error = %v", result.err)
	}
}

func TestConcurrentSubscribersReceiveSameOutputID(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	text := "fanout"
	id, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const count = 4
	results := make([]<-chan subscribeResult, 0, count)
	for range count {
		results = append(results, subscribeAsync(ctx, m, "trueopen1user"))
	}
	waitForSubscribers(t, m, count)
	if err := m.Commit("session-1", "task-1", id); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, result := range results {
		assertDelivered(t, <-result, id, text)
	}
}

func TestAckDeletesPlaintextAndIsIdempotent(t *testing.T) {
	m, store, _ := newCoreTestManager(t, testConfig())
	id := prepareAndCommit(t, m, "delete after ack")
	req := AckRequest{
		SessionID: "session-1",
		TaskID:    "task-1",
		OutputID:  id,
		Requester: "trueopen1user",
	}
	first, err := m.Ack(req)
	if err != nil || !first.Acked || first.AlreadyAcked || first.AckedAt == 0 {
		t.Fatalf("first Ack = %+v/%v", first, err)
	}
	if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
		t.Fatal("plaintext record remains after ACK")
	}
	raw, ok := store.Get(kv.NSOutputTombstone, deliveryKey("session-1", "task-1"))
	if !ok {
		t.Fatal("ACK tombstone missing")
	}
	if bytes.Contains(raw, []byte("output_text")) || bytes.Contains(raw, []byte("delete after ack")) {
		t.Fatalf("tombstone contains plaintext: %s", raw)
	}

	second, err := m.Ack(req)
	if err != nil || !second.Acked || !second.AlreadyAcked || second.AckedAt != first.AckedAt {
		t.Fatalf("second Ack = %+v/%v", second, err)
	}
	result := <-subscribeAsync(context.Background(), m, "trueopen1user")
	if !errors.Is(result.err, ErrAlreadyAcked) {
		t.Fatalf("Subscribe after ACK error = %v", result.err)
	}
}

func TestAckRejectsWrongRecipientAndOutputID(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	id := prepareAndCommit(t, m, "private")
	wrongRecipient := AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1other",
	}
	if _, err := m.Ack(wrongRecipient); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong recipient error = %v", err)
	}
	wrongID := AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: "wrong", Requester: "trueopen1user",
	}
	if _, err := m.Ack(wrongID); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong output ID error = %v", err)
	}
	result := <-subscribeAsync(context.Background(), m, "trueopen1user")
	assertDelivered(t, result, id, "private")
}

func TestExpiryCreatesTombstoneAndDeletesPlaintext(t *testing.T) {
	m, store, now := newCoreTestManager(t, testConfig())
	prepareAndCommit(t, m, "expires")
	*now = now.Add(testConfig().PlaintextTTL)
	if err := m.sweep(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	key := deliveryKey("session-1", "task-1")
	if _, ok := store.Get(kv.NSOutputDelivery, key); ok {
		t.Fatal("expired plaintext remains")
	}
	raw, ok := store.Get(kv.NSOutputTombstone, key)
	if !ok || !bytes.Contains(raw, []byte(`"status":"EXPIRED"`)) {
		t.Fatalf("expired tombstone = %s/%v", raw, ok)
	}
	result := <-subscribeAsync(context.Background(), m, "trueopen1user")
	if !errors.Is(result.err, ErrExpired) {
		t.Fatalf("Subscribe after expiry error = %v", result.err)
	}
}

func TestTerminateCreatesUnavailableTombstoneOnlyWithoutReadyOutput(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		m, store, _ := newCoreTestManager(t, testConfig())
		if err := m.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m.Stop(context.Background()) })
		if err := m.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		raw, ok := store.Get(kv.NSOutputTombstone, deliveryKey("session-1", "task-1"))
		if !ok || !bytes.Contains(raw, []byte(`"status":"UNAVAILABLE"`)) {
			t.Fatalf("unavailable tombstone = %s/%v", raw, ok)
		}
	})

	t.Run("prepared", func(t *testing.T) {
		m, store, _ := newCoreTestManager(t, testConfig())
		if err := m.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m.Stop(context.Background()) })
		text := "never accepted"
		if _, _, err := m.Prepare(submission(&text)); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if err := m.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
			t.Fatal("prepared plaintext remains")
		}
	})

	t.Run("ready", func(t *testing.T) {
		m, store, _ := newCoreTestManager(t, testConfig())
		if err := m.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m.Stop(context.Background()) })
		id := prepareAndCommit(t, m, "keep ready")
		if err := m.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); !ok {
			t.Fatal("ready plaintext was deleted")
		}
		assertDelivered(t, <-subscribeAsync(context.Background(), m, "trueopen1user"), id, "keep ready")
	})
}

func TestTerminatePromotesAcceptedPreparedOutput(t *testing.T) {
	m, store, _ := newCoreTestManager(t, testConfig())
	m.SetPreparedResolver(func(sessionID, taskID string, hash []byte) bool {
		return sessionID == "session-1" && taskID == "task-1" && bytes.Equal(hash, submission(&[]string{"accepted"}[0]).OutputHash)
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	text := "accepted"
	id, prepared, err := m.Prepare(submission(&text))
	if err != nil || !prepared {
		t.Fatalf("Prepare = %q/%v/%v", id, prepared, err)
	}
	if err := m.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if rec := loadRecord(t, store); rec.State != stateReady {
		t.Fatalf("record state = %s, want %s", rec.State, stateReady)
	}
	assertDelivered(t, <-subscribeAsync(context.Background(), m, "trueopen1user"), id, text)
}

func TestTerminateRetriesTransientTombstoneFailure(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base, failTombstoneSet: true}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := subscribeAsync(ctx, m, "trueopen1user")
	waitForSubscribers(t, m, 1)
	if err := m.Terminate("session-1", "task-1", "trueopen1user"); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("Terminate error = %v", err)
	}
	store.failTombstoneSet = false
	if err := m.sweep(); err != nil {
		t.Fatalf("retry sweep: %v", err)
	}
	if got := (<-result).err; !errors.Is(got, ErrUnavailable) {
		t.Fatalf("subscriber error = %v", got)
	}
	if _, ok := base.Get(kv.NSOutputTombstone, deliveryKey("session-1", "task-1")); !ok {
		t.Fatal("retried unavailable tombstone missing")
	}
}

func TestTerminationObserverRunsAfterRetriedPromotion(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base, failReadySet: true}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	m.SetPreparedResolver(func(string, string, []byte) bool { return true })
	notified := make(chan string, 1)
	m.SetTerminationObserver(func(sessionID, taskID string) {
		notified <- deliveryKey(sessionID, taskID)
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	text := "retry promotion"
	if _, _, err := m.Prepare(submission(&text)); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := m.Terminate("session-1", "task-1", "trueopen1user"); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("Terminate error = %v", err)
	}
	select {
	case got := <-notified:
		t.Fatalf("observer ran before durable finalization: %q", got)
	default:
	}
	store.failReadySet = false
	if err := m.sweep(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	select {
	case got := <-notified:
		if got != deliveryKey("session-1", "task-1") {
			t.Fatalf("observer key = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("termination observer was not called")
	}
}

func TestRecoveryRestoresReadyOutput(t *testing.T) {
	store := kv.NewMemStore()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	id := prepareAndCommit(t, m1, "survives restart")

	m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m2.Stop(context.Background()) })
	assertDelivered(t, <-subscribeAsync(context.Background(), m2, "trueopen1user"), id, "survives restart")
}

func TestRecoveryFailsClosedWhenTombstoneScanFails(t *testing.T) {
	base := kv.NewMemStore()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m1 := newCoreTestManagerWithStore(t, base, testConfig(), &now)
	prepareAndCommit(t, m1, "must not restore without tombstones")

	store := &faultStore{Store: base, failScanNS: kv.NSOutputTombstone}
	m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	if err := m2.Start(context.Background()); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("Start error = %v", err)
	}
	if len(m2.records) != 0 {
		t.Fatalf("records restored after tombstone scan failure: %v", m2.records)
	}
}

func TestPreStartTerminateDoesNotOverwriteRecoveredOutput(t *testing.T) {
	t.Run("ready", func(t *testing.T) {
		store := kv.NewMemStore()
		now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
		m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		id := prepareAndCommit(t, m1, "ready before restart")

		m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		if err := m2.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
			t.Fatalf("pre-start Terminate: %v", err)
		}
		if err := m2.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m2.Stop(context.Background()) })
		assertDelivered(t, <-subscribeAsync(context.Background(), m2, "trueopen1user"), id, "ready before restart")
	})

	t.Run("accepted prepared", func(t *testing.T) {
		store := kv.NewMemStore()
		now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
		m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		text := "accepted before restart"
		id, _, err := m1.Prepare(submission(&text))
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}

		m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		m2.SetPreparedResolver(func(string, string, []byte) bool { return true })
		if err := m2.Terminate("session-1", "task-1", "trueopen1user"); err != nil {
			t.Fatalf("pre-start Terminate: %v", err)
		}
		if err := m2.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m2.Stop(context.Background()) })
		assertDelivered(t, <-subscribeAsync(context.Background(), m2, "trueopen1user"), id, text)
	})
}

func TestRecoveryNeverRestoresAckedOrExpiredPlaintext(t *testing.T) {
	t.Run("acked", func(t *testing.T) {
		store := kv.NewMemStore()
		now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
		m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		id := prepareAndCommit(t, m1, "acked")
		stale, _ := json.Marshal(m1.records[deliveryKey("session-1", "task-1")])
		if _, err := m1.Ack(AckRequest{
			SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
		}); err != nil {
			t.Fatalf("Ack: %v", err)
		}
		if err := store.Set(kv.NSOutputDelivery, deliveryKey("session-1", "task-1"), stale); err != nil {
			t.Fatalf("restore stale plaintext: %v", err)
		}

		m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		if err := m2.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m2.Stop(context.Background()) })
		result := <-subscribeAsync(context.Background(), m2, "trueopen1user")
		if !errors.Is(result.err, ErrAlreadyAcked) {
			t.Fatalf("Subscribe error = %v", result.err)
		}
		if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
			t.Fatal("stale acked plaintext remains")
		}
	})

	t.Run("expired", func(t *testing.T) {
		store := kv.NewMemStore()
		now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
		m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		prepareAndCommit(t, m1, "expired")
		now = now.Add(testConfig().PlaintextTTL)

		m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
		if err := m2.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = m2.Stop(context.Background()) })
		result := <-subscribeAsync(context.Background(), m2, "trueopen1user")
		if !errors.Is(result.err, ErrExpired) {
			t.Fatalf("Subscribe error = %v", result.err)
		}
		if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
			t.Fatal("expired plaintext remains after recovery")
		}
	})
}

func TestRecoveryPromotesPreparedWhenFSMAccepted(t *testing.T) {
	store := kv.NewMemStore()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	text := "accepted before crash"
	id, _, err := m1.Prepare(submission(&text))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	m2.SetPreparedResolver(func(sessionID, taskID string, hash []byte) bool {
		return sessionID == "session-1" && taskID == "task-1" && bytes.Equal(hash, submission(&text).OutputHash)
	})
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m2.Stop(context.Background()) })
	assertDelivered(t, <-subscribeAsync(context.Background(), m2, "trueopen1user"), id, text)
	if rec := loadRecord(t, store); rec.State != stateReady {
		t.Fatalf("recovered state = %s", rec.State)
	}
}

func TestRecoveryDropsUnacceptedPreparedRecord(t *testing.T) {
	store := kv.NewMemStore()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m1 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	text := "not accepted"
	if _, _, err := m1.Prepare(submission(&text)); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	m2 := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	m2.SetPreparedResolver(func(string, string, []byte) bool { return false })
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m2.Stop(context.Background()) })
	if _, ok := store.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
		t.Fatal("unaccepted PREPARED record remains")
	}
}

func TestTTLDoesNotMoveOnRetryOrSubscribe(t *testing.T) {
	m, store, now := newCoreTestManager(t, testConfig())
	id := prepareAndCommit(t, m, "stable ttl")
	first := loadRecord(t, store)
	*now = now.Add(time.Hour)
	assertDelivered(t, <-subscribeAsync(context.Background(), m, "trueopen1user"), id, "stable ttl")
	second := loadRecord(t, store)
	if second.CreatedAt != first.CreatedAt || second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("Subscribe moved TTL: first=%+v second=%+v", first, second)
	}
}

func TestStopWakesSubscribers(t *testing.T) {
	m, _, _ := newCoreTestManager(t, testConfig())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := subscribeAsync(ctx, m, "trueopen1user")
	waitForSubscribers(t, m, 1)
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := (<-result).err; !errors.Is(got, ErrDeliveryFailure) {
		t.Fatalf("Subscribe after Stop error = %v", got)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestSweepRetainsTombstoneUntilTTLAndTaskTerminal(t *testing.T) {
	m, store, now := newCoreTestManager(t, testConfig())
	id := prepareAndCommit(t, m, "acked")
	if _, err := m.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	*now = now.Add(testConfig().TombstoneTTL)
	terminal := false
	m.SetTaskTerminal(func(string, string) bool { return terminal })
	var gone []string
	m.SetTombstoneObserver(func(sessionID, taskID string) { gone = append(gone, sessionID+"|"+taskID) })
	if err := m.sweep(); err != nil {
		t.Fatalf("non-terminal sweep: %v", err)
	}
	key := deliveryKey("session-1", "task-1")
	if _, ok := store.Get(kv.NSOutputTombstone, key); !ok {
		t.Fatal("active-task tombstone was deleted")
	}
	if len(gone) != 0 {
		t.Fatalf("observer told about a retained tombstone: %v", gone)
	}
	terminal = true
	if err := m.sweep(); err != nil {
		t.Fatalf("terminal sweep: %v", err)
	}
	if _, ok := store.Get(kv.NSOutputTombstone, key); ok {
		t.Fatal("terminal expired tombstone remains")
	}
	if len(gone) != 1 || gone[0] != "session-1|task-1" {
		t.Fatalf("tombstone observer calls = %v", gone)
	}
}

func TestAckTombstonePreventsReadWhenPlaintextDeleteFails(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base, failOutputDelete: true}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	id := prepareAndCommit(t, m, "physically stale")
	if _, err := m.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	key := deliveryKey("session-1", "task-1")
	if _, ok := base.Get(kv.NSOutputDelivery, key); !ok {
		t.Fatal("fault injection did not leave stale plaintext")
	}
	result := <-subscribeAsync(context.Background(), m, "trueopen1user")
	if !errors.Is(result.err, ErrAlreadyAcked) {
		t.Fatalf("Subscribe with stale plaintext error = %v", result.err)
	}

	restarted := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })
	result = <-subscribeAsync(context.Background(), restarted, "trueopen1user")
	if !errors.Is(result.err, ErrAlreadyAcked) {
		t.Fatalf("Subscribe after restart error = %v", result.err)
	}
}

func TestAckTombstoneFailureLeavesReadyOutputAvailable(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	id := prepareAndCommit(t, m, "retry ack")
	store.failTombstoneSet = true
	if _, err := m.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	}); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("Ack error = %v", err)
	}
	assertDelivered(t, <-subscribeAsync(context.Background(), m, "trueopen1user"), id, "retry ack")
	if _, ok := base.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); !ok {
		t.Fatal("plaintext disappeared after failed tombstone write")
	}
}

func TestSweepRetriesPlaintextDeleteBeforeRemovingTombstone(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base, failOutputDelete: true}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	id := prepareAndCommit(t, m, "delete retry")
	if _, err := m.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	now = now.Add(testConfig().TombstoneTTL)
	m.SetTaskTerminal(func(string, string) bool { return true })
	if err := m.sweep(); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("failed-delete sweep error = %v", err)
	}
	key := deliveryKey("session-1", "task-1")
	if _, ok := base.Get(kv.NSOutputTombstone, key); !ok {
		t.Fatal("tombstone removed while stale plaintext remains")
	}

	store.failOutputDelete = false
	if err := m.sweep(); err != nil {
		t.Fatalf("retry sweep: %v", err)
	}
	if _, ok := base.Get(kv.NSOutputDelivery, key); ok {
		t.Fatal("stale plaintext remains after delete retry")
	}
	if _, ok := base.Get(kv.NSOutputTombstone, key); ok {
		t.Fatal("eligible tombstone remains after plaintext deletion")
	}
}

func TestSweepRetainsTombstoneWhenPlaintextReadFails(t *testing.T) {
	base := kv.NewMemStore()
	store := &faultStore{Store: base, failOutputDelete: true}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	m := newCoreTestManagerWithStore(t, store, testConfig(), &now)
	id := prepareAndCommit(t, m, "read failure")
	if _, err := m.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	now = now.Add(testConfig().TombstoneTTL)
	m.SetTaskTerminal(func(string, string) bool { return true })
	store.failOutputDelete = false
	store.failOutputGet = true
	if err := m.sweep(); !errors.Is(err, ErrDeliveryFailure) {
		t.Fatalf("sweep error = %v", err)
	}
	key := deliveryKey("session-1", "task-1")
	if _, ok := base.Get(kv.NSOutputTombstone, key); !ok {
		t.Fatal("tombstone removed while plaintext existence was unknown")
	}
	if _, ok := base.Get(kv.NSOutputDelivery, key); !ok {
		t.Fatal("fault setup did not retain plaintext")
	}
}

func TestPebbleRestartReplaysUntilAckAndNeverAfter(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)

	store1, err := kv.NewPebble(dir, log)
	if err != nil {
		t.Fatalf("open first Pebble: %v", err)
	}
	m1 := newCoreTestManagerWithStore(t, store1, testConfig(), &now)
	id := prepareAndCommit(t, m1, "durable plaintext")
	if err := store1.Close(); err != nil {
		t.Fatalf("close first Pebble: %v", err)
	}

	store2, err := kv.NewPebble(dir, log)
	if err != nil {
		t.Fatalf("open second Pebble: %v", err)
	}
	m2 := newCoreTestManagerWithStore(t, store2, testConfig(), &now)
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("start second manager: %v", err)
	}
	assertDelivered(t, <-subscribeAsync(context.Background(), m2, "trueopen1user"), id, "durable plaintext")
	ack, err := m2.Ack(AckRequest{
		SessionID: "session-1", TaskID: "task-1", OutputID: id, Requester: "trueopen1user",
	})
	if err != nil || !ack.Acked || ack.AlreadyAcked {
		t.Fatalf("Ack = %+v/%v", ack, err)
	}
	if err := m2.Stop(context.Background()); err != nil {
		t.Fatalf("stop second manager: %v", err)
	}
	if err := store2.Close(); err != nil {
		t.Fatalf("close second Pebble: %v", err)
	}

	store3, err := kv.NewPebble(dir, log)
	if err != nil {
		t.Fatalf("open third Pebble: %v", err)
	}
	t.Cleanup(func() { _ = store3.Close() })
	m3 := newCoreTestManagerWithStore(t, store3, testConfig(), &now)
	if err := m3.Start(context.Background()); err != nil {
		t.Fatalf("start third manager: %v", err)
	}
	t.Cleanup(func() { _ = m3.Stop(context.Background()) })
	result := <-subscribeAsync(context.Background(), m3, "trueopen1user")
	if !errors.Is(result.err, ErrAlreadyAcked) {
		t.Fatalf("Subscribe after ACK restart error = %v", result.err)
	}
	if _, ok := store3.Get(kv.NSOutputDelivery, deliveryKey("session-1", "task-1")); ok {
		t.Fatal("plaintext restored after ACK")
	}
}
