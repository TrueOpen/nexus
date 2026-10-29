package drain

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	oldKey = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newKey = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeWork struct {
	orders    int
	maxFee    int64
	records   int
	takeovers int
	sync      []SyncPending
}

type fakeKey struct {
	state chaincli.ServiceKeyState
	err   error
}

func (k *fakeKey) read(context.Context) (chaincli.ServiceKeyState, error) { return k.state, k.err }

type env struct {
	t     *testing.T
	store kv.Store
	work  *fakeWork
	key   *fakeKey
	local string
	now   time.Time
	c     *Controller
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, store: kv.NewMemStore(), work: &fakeWork{}, local: oldKey, now: time.UnixMilli(1_800_000_000_000),
		key: &fakeKey{state: chaincli.ServiceKeyState{ServicePubKey: oldKey, AuthorizationNonce: 4, Status: "ACTIVE"}}}
	e.open()
	return e
}

// open builds the controller over the env's store, as after a start.
func (e *env) open() {
	e.t.Helper()
	c, err := New(Config{
		Store: e.store, LocalPubKey: e.local, Key: e.key.read, Now: func() time.Time { return e.now },
		Sources: Sources{
			InFlight:  func() (int, *big.Int) { return e.work.orders, big.NewInt(e.work.maxFee) },
			Records:   func() int { return e.work.records },
			Takeovers: func() int { return e.work.takeovers },
			Sync:      func() []SyncPending { return e.work.sync },
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.c = c
}

func (e *env) begin() {
	e.t.Helper()
	if err := e.c.Begin(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) check(want Phase) Status {
	e.t.Helper()
	s := e.c.Check(context.Background())
	if s.Phase != want {
		e.t.Fatalf("phase = %s, want %s (%+v)", s.Phase, want, s)
	}
	return s
}

func TestServingUntilADrainBegins(t *testing.T) {
	e := newEnv(t)
	if e.c.Draining() {
		t.Fatal("a new Builder is draining")
	}
	e.work.orders = 3
	if s := e.check(PhaseServing); s.Remaining.InFlightOrders != 3 {
		t.Fatalf("remaining work not reported while serving: %+v", s.Remaining)
	}
}

// The drain lasts while in-flight orders, record entries, takeovers or sync items remain, and
// lists what remains.
func TestDrainCompletesWhenEveryKindOfWorkIsDone(t *testing.T) {
	e := newEnv(t)
	e.work = &fakeWork{orders: 2, maxFee: 300, records: 1, takeovers: 1,
		sync: []SyncPending{{SessionID: "s", Sequence: 1, TaskID: "t", Peer: "trueopen1peer", Items: 2, Output: true}}}
	e.begin()
	if !e.c.Draining() {
		t.Fatal("not draining after Begin")
	}
	s := e.check(PhaseDraining)
	want := Remaining{InFlightOrders: 2, InFlightMaxFee: "300", RecordEntries: 1, Takeovers: 1, SyncPending: e.work.sync}
	if !reflect.DeepEqual(s.Remaining, want) || s.Complete {
		t.Fatalf("status = %+v", s)
	}
	if !s.Since.Equal(e.now) {
		t.Fatalf("since = %v", s.Since)
	}
	e.work.orders, e.work.maxFee = 0, 0
	e.check(PhaseDraining)
	e.work.records = 0
	e.check(PhaseDraining)
	e.work.takeovers = 0
	e.check(PhaseDraining)
	e.work.sync = nil
	if s := e.check(PhaseDrained); !s.Complete {
		t.Fatalf("status = %+v", s)
	}
}

// The drain state survives a restart.
func TestDrainSurvivesARestart(t *testing.T) {
	e := newEnv(t)
	e.begin()
	e.now = e.now.Add(time.Hour)
	e.open()
	if !e.c.Draining() {
		t.Fatal("drain lost over a restart")
	}
	if s := e.check(PhaseDrained); !s.Since.Equal(e.now.Add(-time.Hour)) {
		t.Fatalf("since = %v", s.Since)
	}
	if err := e.c.End(); err != nil {
		t.Fatal(err)
	}
	e.open()
	if e.c.Draining() {
		t.Fatal("ended drain came back after a restart")
	}
}

// After the rotation registered, the drain waits for it; once the new key is current it ends by
// itself when this process signs with the new key, and asks for a restart otherwise.
func TestDrainEndsOnceTheNewKeyIsCurrent(t *testing.T) {
	e := newEnv(t)
	e.begin()
	e.check(PhaseDrained)
	e.key.state.PendingRotation = &chaincli.PendingServiceKeyRotation{NextServicePubKey: newKey, NextAuthorizationNonce: 5, EffectiveHeight: 900}
	if s := e.check(PhaseRotationPending); s.Key == nil || s.Key.PendingNonce != 5 || s.Key.PendingEffectiveHeight != 900 || s.Warning != "" {
		t.Fatalf("status = %+v", s)
	}
	e.key.state = chaincli.ServiceKeyState{ServicePubKey: newKey, AuthorizationNonce: 5, Status: "ACTIVE"}
	e.check(PhaseRestartRequired)
	if !e.c.Draining() {
		t.Fatal("drain ended while the process still signs with the old key")
	}
	e.local = newKey
	e.open()
	e.check(PhaseServing)
	if e.c.Draining() {
		t.Fatal("still draining under the new key")
	}
	e.open()
	if e.c.Draining() {
		t.Fatal("automatic end not stored")
	}
}

// A rotation registered while work remains is called out: the remaining items will fail.
func TestRotationBeforeTheDrainCompletedIsWarned(t *testing.T) {
	e := newEnv(t)
	e.work.records = 1
	e.begin()
	e.key.state.PendingRotation = &chaincli.PendingServiceKeyRotation{NextServicePubKey: newKey, NextAuthorizationNonce: 5}
	if s := e.check(PhaseRotationPending); s.Warning == "" {
		t.Fatalf("no warning: %+v", s)
	}
}

// A drain begun while the key cannot be read takes the key binding at the first read that shows
// this process's key current.
func TestDrainBegunWithoutAKeyReadTakesItLater(t *testing.T) {
	e := newEnv(t)
	e.key.err = errors.New("chain down")
	e.begin()
	if s := e.check(PhaseDrained); s.Key != nil {
		t.Fatalf("key = %+v", s.Key)
	}
	e.key.err = nil
	e.check(PhaseDrained)
	e.key.state = chaincli.ServiceKeyState{ServicePubKey: newKey, AuthorizationNonce: 5, Status: "ACTIVE"}
	e.local = newKey
	e.open()
	e.check(PhaseServing)
}

func TestBeginAndEndAreIdempotent(t *testing.T) {
	e := newEnv(t)
	e.begin()
	since := e.c.Check(context.Background()).Since
	e.now = e.now.Add(time.Minute)
	e.begin()
	if got := e.c.Check(context.Background()).Since; !got.Equal(since) {
		t.Fatalf("second Begin moved since to %v", got)
	}
	if err := e.c.End(); err != nil {
		t.Fatal(err)
	}
	if err := e.c.End(); err != nil {
		t.Fatal(err)
	}
	e.check(PhaseServing)
}
