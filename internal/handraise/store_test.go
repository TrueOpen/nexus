package handraise

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/kv"
)

func TestRestartRecoversHandraisesAndRoots(t *testing.T) {
	e := newEnv(t)
	store, err := kv.NewPebble(filepath.Join(t.TempDir(), "kv"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	e.store = store
	e.reg = e.open()

	a := e.addCortex(0x11, 1)
	b := e.addCortex(0x12, 2)
	ha := e.handraise(a, 100, 1)
	e.mustAccept(a, ha)
	e.mustAccept(b, e.handraise(b, 100, 1))
	first := e.mustIssue()
	e.clock.advance(time.Second)
	hb := e.handraise(b, 100, 2)
	e.mustAccept(b, hb)
	second := e.mustIssue()

	// Restart: the signing key and nonce answer the same, but nothing may be re-signed.
	e.reg = e.open()
	if got, ok := e.reg.Current(a.operator()); !ok || !proto.Equal(got, ha) {
		t.Fatalf("recovered current of a = %v", got)
	}
	if got, ok := e.reg.Current(b.operator()); !ok || !proto.Equal(got, hb) {
		t.Fatalf("recovered current of b = %v", got)
	}
	root, leaves, ok := e.reg.Latest()
	if !ok || !proto.Equal(root, second.Root) || len(leaves) != 2 {
		t.Fatalf("recovered latest = %v", root)
	}
	latest, _ := e.reg.LatestRoot()
	if !bytes.Equal(latest.Root.GetBuilderServiceSignature(), second.Root.GetBuilderServiceSignature()) {
		t.Fatal("latest root was re-signed on restart")
	}
	if again := e.issue(); again != nil {
		t.Fatalf("unchanged leaves re-issued after restart as version %d", again.Root.GetRootVersion())
	}
	if got, found, err := e.reg.RootByDigest(first.Digest); err != nil || !found || !proto.Equal(got.Root, first.Root) {
		t.Fatalf("first root after restart: %v %v", found, err)
	}

	// The version continues after the recovered root instead of reusing (height, version).
	e.clock.advance(time.Second)
	e.mustAccept(a, e.handraise(a, 100, 2))
	third := e.mustIssue()
	if third.Root.GetRootHeight() != 100 || third.Root.GetRootVersion() != 2 {
		t.Fatalf("root after restart = (%d, %d), want (100, 2)", third.Root.GetRootHeight(), third.Root.GetRootVersion())
	}

	// Replay protection survives the restart.
	e.reg = e.open()
	e.clock.advance(time.Second)
	wantCode(t, e.accept(a, ha), ErrInvalid)
}

// The TTL clock of a recovered handraise keeps running from when it was received.
func TestRestartKeepsTTL(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	e.clock.advance(5 * time.Second)
	e.reg = e.open()
	if _, ok := e.reg.Current(c.operator()); !ok {
		t.Fatal("handraise lost on restart")
	}
	e.clock.advance(2 * time.Second)
	if _, ok := e.reg.Current(c.operator()); ok {
		t.Fatal("restart refreshed the TTL")
	}
}

func TestRTTThresholdHistory(t *testing.T) {
	e := newEnv(t)
	start := e.clock.Now()
	if ms, since := e.reg.RTTThreshold(); ms != 150 || !since.Equal(start) {
		t.Fatalf("threshold = %d since %v", ms, since)
	}
	e.clock.advance(time.Hour)
	e.reg = e.open() // same threshold: no new entry
	e.clock.advance(time.Hour)
	e.cfg.BuilderRTTAdmitMs = 90
	e.reg = e.open()
	history, err := e.reg.RTTThresholdHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].ThresholdMs != 150 || !history[0].Since.Equal(start) ||
		history[1].ThresholdMs != 90 || !history[1].Since.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("history = %+v", history)
	}
	if ms, since := e.reg.RTTThreshold(); ms != 90 || !since.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("threshold = %d since %v", ms, since)
	}
	// The history is served from memory: the public statistics read it every tick.
	var keys []string
	_ = e.store.Scan(kv.NSHandraise, func(key string, _ []byte) bool {
		if strings.HasPrefix(key, thresholdPrefix) {
			keys = append(keys, key)
		}
		return true
	})
	for _, key := range keys {
		if err := e.store.Delete(kv.NSHandraise, key); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := e.reg.RTTThresholdHistory(); err != nil || len(again) != 2 {
		t.Fatalf("history after the store lost it = %+v, %v", again, err)
	}
}

// A recovered root whose stored bytes do not reproduce its digest stops startup.
func TestRestartRejectsCorruptRoot(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 1)
	e.mustAccept(c, e.handraise(c, 100, 1))
	issued := e.mustIssue()
	key := rootKey(issued.Root.GetRootHeight(), issued.Root.GetRootVersion())
	raw, found := e.store.Get(kv.NSHandraiseRoot, key)
	if !found {
		t.Fatal("root record not stored")
	}
	corrupt := bytes.Replace(raw, []byte(`"leaves":[`), []byte(`"leaves":[],"x":[`), 1)
	if err := e.store.Set(kv.NSHandraiseRoot, key, corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{
		ChainID: testChainID, BuilderAddress: e.builder.Address(), Config: e.cfg, Store: e.store,
		Keys: e.keys, Pool: e.pool, Height: e.height, Signer: e.builder, Now: e.clock.Now,
	}); err == nil {
		t.Fatal("corrupt root was recovered")
	}
}
