package coordinator

import (
	"bytes"
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
