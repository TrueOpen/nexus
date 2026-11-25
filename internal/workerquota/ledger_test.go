package workerquota

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	facts map[string]Facts
	err   error
	calls int
	// onCall runs inside WorkerQuota, before it answers.
	onCall func()
}

func (f *fakeSource) WorkerQuota(_ context.Context, operator string) (Facts, error) {
	f.calls++
	if f.onCall != nil {
		f.onCall()
	}
	if f.err != nil {
		return Facts{}, f.err
	}
	return f.facts[operator], nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Unix(1_800_000_000, 0)} }
func enforced(remaining uint64) Facts {
	return Facts{Enforced: true, Quota: 1000, Remaining: remaining, Period: 7}
}
func ledger(src Source, c *clock) *Ledger { return New(src, Options{Refresh: time.Second, Now: c.now}) }

const hold = time.Minute

func TestNoSourceAdmitsEverything(t *testing.T) {
	var l *Ledger
	if d := l.Admit(context.Background(), "w", "o1", 1<<60, hold); !d.OK {
		t.Fatalf("nil ledger refused: %+v", d)
	}
	if d := New(nil, Options{}).Admit(context.Background(), "w", "o1", 1<<60, hold); !d.OK {
		t.Fatalf("ledger without a source refused: %+v", d)
	}
}

func TestQuotaNotEnforcedAdmitsAndReservesNothingThatMatters(t *testing.T) {
	c := newClock()
	l := ledger(&fakeSource{facts: map[string]Facts{"w": {Enforced: false, Remaining: 0}}}, c)
	for i, key := range []string{"o1", "o2", "o3"} {
		if d := l.Admit(context.Background(), "w", key, 500, hold); !d.OK || !d.Known {
			t.Fatalf("order %d refused while the quota is not enforced: %+v", i, d)
		}
	}
}

func TestOrdersOutCountAgainstTheChainFigure(t *testing.T) {
	c := newClock()
	l := ledger(&fakeSource{facts: map[string]Facts{"w": enforced(1000)}}, c)
	ctx := context.Background()
	if d := l.Admit(ctx, "w", "o1", 600, hold); !d.OK {
		t.Fatalf("first order refused: %+v", d)
	}
	d := l.Admit(ctx, "w", "o2", 500, hold)
	if d.OK || d.Reason != ReasonQuota || d.Local != 600 {
		t.Fatalf("second order = %+v, want refused for quota with 600 held", d)
	}
	if d := l.Admit(ctx, "w", "o2", 400, hold); !d.OK {
		t.Fatalf("an order that fits was refused: %+v", d)
	}
	// Another Worker has its own quota.
	l.src.(*fakeSource).facts["v"] = enforced(100)
	if d := l.Admit(ctx, "v", "o3", 100, hold); !d.OK {
		t.Fatalf("other Worker refused: %+v", d)
	}
}

func TestNextCandidateOfAnOrderReplacesItsReservation(t *testing.T) {
	c := newClock()
	src := &fakeSource{facts: map[string]Facts{"a": enforced(500), "b": enforced(500)}}
	l := ledger(src, c)
	ctx := context.Background()
	if d := l.Admit(ctx, "a", "o1", 500, hold); !d.OK {
		t.Fatal(d)
	}
	// The ticket to a was rejected: the walk offers the same order to b.
	if d := l.Admit(ctx, "b", "o1", 500, hold); !d.OK {
		t.Fatal(d)
	}
	if d := l.Admit(ctx, "a", "o2", 500, hold); !d.OK {
		t.Fatalf("a's quota was not returned when the order moved on: %+v", d)
	}
}

func TestReleaseAndHoldDeadlineReturnTheValue(t *testing.T) {
	c := newClock()
	l := ledger(&fakeSource{facts: map[string]Facts{"w": enforced(500)}}, c)
	ctx := context.Background()
	l.Admit(ctx, "w", "o1", 500, hold)
	if d := l.Admit(ctx, "w", "o2", 1, hold); d.OK {
		t.Fatal("quota not held")
	}
	l.Release("o1")
	if d := l.Admit(ctx, "w", "o2", 500, hold); !d.OK {
		t.Fatalf("released value not returned: %+v", d)
	}
	// A reservation nobody releases ends at its hold deadline.
	c.add(hold)
	if d := l.Admit(ctx, "w", "o3", 500, hold); !d.OK {
		t.Fatalf("expired reservation still held: %+v", d)
	}
	// Extend keeps it.
	l.Extend("o3", 10*hold)
	c.add(2 * hold)
	if d := l.Admit(ctx, "w", "o4", 1, hold); d.OK {
		t.Fatal("extended reservation was dropped")
	}
}

func TestRecordedOrderIsCountedOnceAcrossTheRefresh(t *testing.T) {
	c := newClock()
	src := &fakeSource{facts: map[string]Facts{"w": enforced(1000)}}
	l := ledger(src, c)
	ctx := context.Background()
	l.Admit(ctx, "w", "o1", 600, hold)
	l.Settle("o1")
	// Before the chain figure is read again the value is still held here.
	if d := l.Admit(ctx, "w", "o2", 500, hold); d.OK {
		t.Fatal("recorded order was forgotten before the chain figure was read again")
	}
	// The chain now counts it; the next read drops the local copy.
	src.facts["w"] = enforced(400)
	c.add(2 * time.Second)
	d := l.Admit(ctx, "w", "o2", 400, hold)
	if !d.OK || d.Local != 0 {
		t.Fatalf("after the refresh = %+v, want admitted with nothing held locally", d)
	}
}

func TestOrderRecordedDuringAReadWaitsForTheNextRead(t *testing.T) {
	c := newClock()
	src := &fakeSource{facts: map[string]Facts{"w": enforced(1000)}}
	l := ledger(src, c)
	ctx := context.Background()
	l.Admit(ctx, "w", "o1", 600, hold)
	c.add(2 * time.Second)
	// The record lands while the next read is in flight: its answer (still 1000) does not count it.
	src.onCall = func() { c.add(time.Millisecond); l.Settle("o1"); c.add(time.Millisecond) }
	if d := l.Admit(ctx, "w", "o2", 500, hold); d.OK {
		t.Fatalf("an order recorded during the read was dropped although the answer does not count it: %+v", d)
	}
	src.onCall = nil
	src.facts["w"] = enforced(400)
	c.add(2 * time.Second)
	if d := l.Admit(ctx, "w", "o2", 400, hold); !d.OK {
		t.Fatalf("after the following read: %+v", d)
	}
}

func TestPausedWorkerIsOfferedNothing(t *testing.T) {
	c := newClock()
	src := &fakeSource{facts: map[string]Facts{"w": {Enforced: false, Paused: true, PauseReasons: PauseLateSubmission}}}
	l := ledger(src, c)
	d := l.Admit(context.Background(), "w", "o1", 1, hold)
	if d.OK || d.Reason != ReasonPaused {
		t.Fatalf("paused Worker = %+v", d)
	}
	// Resumed on chain: offered again after the refresh.
	src.facts["w"] = Facts{}
	c.add(2 * time.Second)
	if d := l.Admit(context.Background(), "w", "o1", 1, hold); !d.OK {
		t.Fatalf("resumed Worker = %+v", d)
	}
}

func TestUnreadableChainLetsTheOrderThroughAndKeepsAnOlderAnswer(t *testing.T) {
	c := newClock()
	src := &fakeSource{err: errors.New("endpoint unavailable")}
	l := ledger(src, c)
	d := l.Admit(context.Background(), "w", "o1", 1<<40, hold)
	if !d.OK || d.Known {
		t.Fatalf("unreadable chain = %+v, want let through and not known", d)
	}
	// With an older answer the Worker stays paused through a failed read.
	src.err, src.facts = nil, map[string]Facts{"w": {Paused: true, PauseReasons: PauseJailed}}
	c.add(2 * time.Second)
	if d := l.Admit(context.Background(), "w", "o2", 1, hold); d.OK {
		t.Fatal("paused Worker admitted")
	}
	src.err = errors.New("endpoint unavailable")
	c.add(2 * time.Second)
	if d := l.Admit(context.Background(), "w", "o2", 1, hold); d.OK || d.Reason != ReasonPaused {
		t.Fatalf("failed read forgot the pause: %+v", d)
	}
}

func TestOlderChainWithoutTheQueryChangesNothing(t *testing.T) {
	c := newClock()
	src := &fakeSource{err: ErrUnsupported}
	l := New(src, Options{Refresh: time.Second, UnsupportedRetry: time.Minute, Now: c.now})
	for i := 0; i < 5; i++ {
		if d := l.Admit(context.Background(), "w", "o", 1<<40, hold); !d.OK {
			t.Fatalf("refused on a chain without the query: %+v", d)
		}
		c.add(2 * time.Second)
	}
	if src.calls != 1 {
		t.Fatalf("the unsupported query was sent %d times within the retry period, want 1", src.calls)
	}
	c.add(time.Minute)
	l.Admit(context.Background(), "w", "o", 1, hold)
	if src.calls != 2 {
		t.Fatalf("the query was not tried again after the retry period (calls %d)", src.calls)
	}
}

func TestSnapshotShowsChainAndLocalFigures(t *testing.T) {
	c := newClock()
	l := ledger(&fakeSource{facts: map[string]Facts{"w": {Enforced: true, Quota: 1000, ReservedValue: 300, Remaining: 700, Period: 9}}}, c)
	l.Admit(context.Background(), "w", "o1", 200, hold)
	got := l.Snapshot()
	if len(got) != 1 || got[0].Operator != "w" || got[0].LocalReserved != 200 || got[0].Remaining != 700 || got[0].ChainReserved != 300 || got[0].Period != 9 {
		t.Fatalf("snapshot = %+v", got)
	}
}
