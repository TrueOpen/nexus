package coordinator

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/taskgroup"
	"github.com/TrueOpen/nexus/internal/types"
)

func TestCurrentBuilderSetFeedsTheTaskBuildersGroup(t *testing.T) {
	c, _ := newTestCoordinator(t)
	if _, ok := c.CurrentBuilderSet(); ok {
		t.Fatal("a BuilderSet before any chain read")
	}
	if err := taskgroup.Ready(c); err == nil {
		t.Fatal("ready without a BuilderSet snapshot")
	}
	c.active.Update(3, []types.BuilderRef{{Address: "b0", Rank: 1}, {Address: "b1", Rank: 2}, {Address: "b2", Rank: 3}},
		builderSetRef{ID: "set-3", Hash: "0x" + string(bytes.Repeat([]byte("ab"), 32))})
	got, ok := c.CurrentBuilderSet()
	if !ok || got.ID != "set-3" || got.Hash != [32]byte(bytes.Repeat([]byte{0xab}, 32)) || len(got.Members) != 3 || got.Members[2] != "b2" {
		t.Fatalf("snapshot = %+v, %v", got, ok)
	}
	g, err := taskgroup.New(got, "b1")
	if err != nil || g.Members[0] != "b1" || g.Members[2] != "b0" {
		t.Fatalf("group = %+v, %v", g, err)
	}
}

// The snapshot's id, hash and members come from one Update even while Updates race with it: a
// new id with the old members would build Task Builders groups and ranks from a set that never
// existed.
func TestCurrentBuilderSetIsOneUpdate(t *testing.T) {
	c, _ := newTestCoordinator(t)
	sets := []struct {
		ref     builderSetRef
		members []types.BuilderRef
	}{
		{builderSetRef{ID: "set-a", Hash: strings.Repeat("aa", 32)}, []types.BuilderRef{{Address: "a0"}, {Address: "a1"}}},
		{builderSetRef{ID: "set-b", Hash: strings.Repeat("bb", 32)}, []types.BuilderRef{{Address: "b0"}, {Address: "b1"}, {Address: "b2"}}},
	}
	c.active.Update(1, sets[0].members, sets[0].ref)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			s := sets[i%2]
			c.active.Update(uint64(i), s.members, s.ref)
		}
	}()
	defer func() { close(done); wg.Wait() }()
	for range 200000 {
		got, ok := c.CurrentBuilderSet()
		if !ok {
			t.Fatal("no snapshot")
		}
		prefix := got.ID[len("set-"):]
		if got.Hash[0] != map[string]byte{"a": 0xaa, "b": 0xbb}[prefix] {
			t.Fatalf("snapshot %s has hash %x", got.ID, got.Hash)
		}
		for _, m := range got.Members {
			if !strings.HasPrefix(m, prefix) {
				t.Fatalf("snapshot %s has members %v", got.ID, got.Members)
			}
		}
	}
}
