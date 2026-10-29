package inflight

import (
	"context"
	"errors"
	"sync"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// fakeChain answers QuerySession and LatestHeight and counts the reads.
type fakeChain struct {
	mu       sync.Mutex
	state    chaincli.SessionState
	found    bool
	err      error
	height   uint64
	reads    int
	tracked  []string
	trackErr error
}

func (f *fakeChain) read(_ context.Context, sessionID string) (chaincli.SessionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return chaincli.SessionState{}, f.err
	}
	if !f.found {
		return chaincli.SessionState{}, chaincli.ErrNotFound
	}
	s := f.state
	s.SessionID = sessionID
	return s, nil
}

func (f *fakeChain) latest(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height, nil
}

func (f *fakeChain) TrackSessionEvents(sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tracked = append(f.tracked, sessionID)
	return f.trackErr
}

func (f *fakeChain) UntrackSessionEvents(string) {}

func (f *fakeChain) set(edit func(*chaincli.SessionState)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(&f.state)
}

func (f *fakeChain) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func baseSessionState() chaincli.SessionState {
	return chaincli.SessionState{
		Owner: "owner", NextExpectedSequence: 5, Balance: "1000", FrozenTotal: "100",
		PendingWithdrawAmount: "0", BoundBuilder: "builder", BoundChangeHeight: 10, SpendCap: "0", Spent: "0",
	}
}

func newTestCache(t *testing.T, chain *fakeChain) (*SessionCache, *Ledger) {
	t.Helper()
	ledger, err := NewLedger(kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewSessionCache(SessionCacheConfig{
		Read: chain.read, LatestHeight: chain.latest, Tracker: chain, Ledger: ledger,
		Background: func(f func()) { f() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return cache, ledger
}

// warm brings a session into the cache the way production does: the first lookup reads and
// tracks it, the stream comes up, the next lookup reads once more and keeps the state.
func warm(t *testing.T, cache *SessionCache) {
	t.Helper()
	if _, _, err := cache.Lookup(context.Background(), testSession); err != nil {
		t.Fatal(err)
	}
	cache.SessionStreamUp(testSession)
	if _, _, err := cache.Lookup(context.Background(), testSession); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCacheKeepsStateOnlyWhileTheStreamIsUp(t *testing.T) {
	chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
	cache, _ := newTestCache(t, chain)
	ctx := context.Background()

	s, head, err := cache.Lookup(ctx, testSession)
	if err != nil || !s.Found || s.NextExpectedSequence != 5 || head != 100 {
		t.Fatalf("cold lookup = %+v, %d, %v", s, head, err)
	}
	if len(chain.tracked) != 1 || chain.tracked[0] != testSession {
		t.Fatalf("tracked = %v", chain.tracked)
	}
	// No stream yet: the next lookup reads again.
	if _, _, err := cache.Lookup(ctx, testSession); err != nil || chain.readCount() != 2 {
		t.Fatalf("second lookup before the stream: %v after %d reads", err, chain.readCount())
	}
	cache.SessionStreamUp(testSession)
	for i := 0; i < 3; i++ {
		if _, _, err := cache.Lookup(ctx, testSession); err != nil {
			t.Fatal(err)
		}
	}
	if chain.readCount() != 3 {
		t.Fatalf("reads with the stream up = %d, want 3 (one after it came up)", chain.readCount())
	}
	cache.SessionStreamDown(testSession)
	_, _, _ = cache.Lookup(ctx, testSession)
	_, _, _ = cache.Lookup(ctx, testSession)
	if chain.readCount() != 5 {
		t.Fatalf("reads with the stream down = %d, want 5", chain.readCount())
	}
}

func TestSessionCacheUnknownSessionAndFailures(t *testing.T) {
	chain := &fakeChain{height: 100}
	cache, _ := newTestCache(t, chain)
	s, _, err := cache.Lookup(context.Background(), testSession)
	if err != nil || s.Found || len(chain.tracked) != 0 {
		t.Fatalf("unknown session = %+v, %v, tracked %v", s, err, chain.tracked)
	}
	chain.err = errors.New("node down")
	if _, _, err := cache.Lookup(context.Background(), testSession); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed read = %v, want unavailable", err)
	}
	cold, _ := newTestCache(t, &fakeChain{state: baseSessionState(), found: true})
	if _, _, err := cold.Lookup(context.Background(), testSession); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no height = %v, want unavailable", err)
	}
}

func TestSessionCacheHeadFollowsEvents(t *testing.T) {
	chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
	cache, _ := newTestCache(t, chain)
	if err := cache.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 120}); err != nil {
		t.Fatal(err)
	}
	_ = cache.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 110})
	if _, head, _ := cache.Lookup(context.Background(), testSession); head != 120 {
		t.Fatalf("head = %d, want 120 (heights never go back, the chain is not asked)", head)
	}
}

func sessionEvent(height int64, typed chaincli.TypedEvent) chaincli.ChainEvent {
	return chaincli.ChainEvent{Type: chaincli.EventSessionScoped, SessionID: testSession, Height: height, Typed: typed}
}

func TestSessionCacheAppliesSessionEvents(t *testing.T) {
	chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
	cache, ledger := newTestCache(t, chain)
	warm(t, cache)
	events := []chaincli.TypedEvent{
		chaincli.SessionDeposited{SessionID: testSession, Amount: "500", Balance: "1500"},
		chaincli.SessionWithdrawRequested{SessionID: testSession, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT, Amount: "200", EffectiveHeight: 150},
		chaincli.SessionTakeoverRegistered{SessionID: testSession, CandidateBuilder: "other", OrderSequence: 5, RegisteredHeight: 101, ActivationHeight: 131},
		chaincli.SessionKeyChangeRequested{SessionID: testSession, Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR, EffectiveHeight: 160},
		chaincli.OrderCancelRequested{SessionID: testSession, OrderSequence: 5, CancelEffectiveHeight: 140},
	}
	for _, e := range events {
		if err := cache.HandleChainEvent(sessionEvent(101, e)); err != nil {
			t.Fatal(err)
		}
	}
	s, _, _ := cache.Lookup(context.Background(), testSession)
	if s.Balance != "1500" || s.PendingWithdrawAmount != "200" || s.PendingWithdrawEffectiveHeight != 150 ||
		s.PendingTakeover == nil || s.PendingTakeover.CandidateBuilder != "other" || s.PendingTakeover.ActivationHeight != 131 ||
		s.PendingKeyChange == nil || s.PendingKeyChange.Kind != taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_CLEAR {
		t.Fatalf("state after events = %+v", s)
	}
	if !ledger.CancelRequested(testSession, 5) {
		t.Fatal("cancel request not recorded")
	}

	_ = cache.HandleChainEvent(sessionEvent(102, chaincli.SessionTakeoverVoided{SessionID: testSession, CandidateBuilder: "other"}))
	_ = cache.HandleChainEvent(sessionEvent(103, chaincli.SessionWithdrawEffective{
		SessionID: testSession, Kind: taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_AMOUNT, PaidAmount: "200", RemainingBalance: "1300",
	}))
	_ = cache.HandleChainEvent(sessionEvent(104, chaincli.OrderCancelled{SessionID: testSession, OrderSequence: 5}))
	_ = cache.HandleChainEvent(sessionEvent(105, chaincli.SessionBuilderBound{SessionID: testSession, OldBuilder: "builder", NewBuilder: "other", BoundChangeHeight: 105}))
	s, _, _ = cache.Lookup(context.Background(), testSession)
	if s.PendingTakeover != nil || s.Balance != "1300" || s.PendingWithdrawAmount != "0" ||
		s.PendingWithdrawKind != taskv1.SessionWithdrawKindV1_SESSION_WITHDRAW_KIND_V1_UNSPECIFIED ||
		s.NextExpectedSequence != 6 || s.BoundBuilder != "other" || s.BoundChangeHeight != 105 {
		t.Fatalf("state after second events = %+v", s)
	}
	if ledger.CancelRequested(testSession, 5) {
		t.Fatal("cancel mark kept after the cancellation took effect")
	}
	if chain.readCount() != 2 {
		t.Fatalf("events caused chain reads: %d", chain.readCount())
	}
}

func TestSessionCacheSkipsEventsTheStateIncludes(t *testing.T) {
	chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
	cache, _ := newTestCache(t, chain)
	warm(t, cache)
	// Read at head 100: a deposit at 99 arriving late is already in the balance.
	_ = cache.HandleChainEvent(sessionEvent(99, chaincli.SessionDeposited{SessionID: testSession, Balance: "1"}))
	if s, _, _ := cache.Lookup(context.Background(), testSession); s.Balance != "1000" {
		t.Fatalf("late event regressed the balance to %s", s.Balance)
	}
}

func TestSessionCacheDropsWhatEventsCannotUpdate(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*SessionCache)
	}{
		{name: "key set requested", apply: func(c *SessionCache) {
			_ = c.HandleChainEvent(sessionEvent(101, chaincli.SessionKeyChangeRequested{
				SessionID: testSession, Kind: taskv1.SessionKeyChangeKindV1_SESSION_KEY_CHANGE_KIND_V1_SET, EffectiveHeight: 160,
			}))
		}},
		{name: "key updated", apply: func(c *SessionCache) { c.SessionKeyUpdated(testSession) }},
		{name: "resync", apply: func(c *SessionCache) {
			_ = c.HandleChainEvent(chaincli.ChainEvent{Type: chaincli.EventResyncRequired, SessionID: testSession})
		}},
		{name: "record of an order the ledger does not hold", apply: func(c *SessionCache) {
			_ = c.HandleChainEvent(sessionEvent(101, chaincli.DispatchRecorded{SessionID: testSession, OrderSequence: 5, ReservedAmount: "10"}))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
			cache, _ := newTestCache(t, chain)
			warm(t, cache)
			tc.apply(cache)
			_, _, _ = cache.Lookup(context.Background(), testSession)
			if chain.readCount() != 3 {
				t.Fatalf("reads = %d, want 3 (the entry was dropped)", chain.readCount())
			}
		})
	}
}

// A record of an order the ledger holds keeps the cached state: the ledger still counts the order
// until the state includes it, so the old state plus the ledger is exact. The state is then
// refreshed in the background.
func TestSessionCacheRefreshesAfterARecord(t *testing.T) {
	chain := &fakeChain{state: baseSessionState(), found: true, height: 100}
	cache, ledger := newTestCache(t, chain)
	warm(t, cache)
	if err := ledger.put(testSession, Entry{Sequence: 5, TaskHash: "h", MaxFee: 10, Deadline: 130, State: StateAccepted}); err != nil {
		t.Fatal(err)
	}
	if err := cache.HandleChainEvent(sessionEvent(101, chaincli.DispatchRecorded{SessionID: testSession, OrderSequence: 5, ReservedAmount: "10"})); err != nil {
		t.Fatal(err)
	}
	if e, _ := ledger.Get(testSession, 5); e.State != StateRecorded {
		t.Fatalf("ledger entry after the record = %s", e.State)
	}
	chain.set(func(s *chaincli.SessionState) { s.NextExpectedSequence = 6; s.FrozenTotal = "110" })
	s, _, _ := cache.Lookup(context.Background(), testSession) // serves the old state, starts the refresh
	if s.NextExpectedSequence != 5 {
		t.Fatalf("lookup during the refresh = next %d", s.NextExpectedSequence)
	}
	s, _, _ = cache.Lookup(context.Background(), testSession)
	if s.NextExpectedSequence != 6 || s.FrozenTotal != "110" || chain.readCount() != 3 {
		t.Fatalf("after the refresh = next %d frozen %s, %d reads", s.NextExpectedSequence, s.FrozenTotal, chain.readCount())
	}
}
