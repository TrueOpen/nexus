package taskgroup

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

type source struct {
	snapshot Snapshot
	ok       bool
}

func (s source) CurrentBuilderSet() (Snapshot, bool) { return s.snapshot, s.ok }

func hash(b byte) [32]byte {
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{b}, 32))
	return h
}

var current = Snapshot{ID: "set-7", Hash: hash(0x77), Members: []string{"b0", "b1", "b2", "b3"}}

// The dispatching Builder is position 0 and the others follow in snapshot order, wrapping.
func TestGroupStartsAtTheDispatcherAndWraps(t *testing.T) {
	for dispatcher, want := range map[string][]string{
		"b0": {"b0", "b1", "b2", "b3"},
		"b2": {"b2", "b3", "b0", "b1"},
		"b3": {"b3", "b0", "b1", "b2"},
	} {
		g, err := New(current, dispatcher)
		if err != nil || !reflect.DeepEqual(g.Members, want) || g.Dispatcher() != dispatcher {
			t.Fatalf("group of %s = %v, %v; want %v", dispatcher, g.Members, err, want)
		}
	}
	g, _ := New(current, "b2")
	for builder, want := range map[string]int{"b2": 0, "b3": 1, "b0": 2, "b1": 3} {
		if pos, ok := g.Position(builder); !ok || pos != want {
			t.Fatalf("position of %s = %d, %v; want %d", builder, pos, ok, want)
		}
	}
	if _, ok := g.Position("b9"); ok {
		t.Fatal("an outsider has a position")
	}
	if got := g.Others("b0"); !reflect.DeepEqual(got, []string{"b2", "b3", "b1"}) {
		t.Fatalf("others = %v", got)
	}
	if current.Members[0] != "b0" {
		t.Fatal("building a group reordered the snapshot")
	}
	if _, err := New(current, "b9"); err == nil {
		t.Fatal("a dispatcher outside the snapshot built a group")
	}
	if _, err := New(Snapshot{ID: "x", Members: []string{"b0", "b0"}}, "b0"); err == nil {
		t.Fatal("a snapshot with a repeated member built a group")
	}
}

func TestOrderMustNameTheCurrentSnapshot(t *testing.T) {
	src := source{snapshot: current, ok: true}
	order := &taskv1.TaskOrderV3{BuilderSetId: "set-7", BuilderSetHash: bytes.Repeat([]byte{0x77}, 32)}
	g, err := ForOrder(src, order, "b1")
	if err != nil || g.BuilderSetID != "set-7" || g.Members[0] != "b1" {
		t.Fatalf("group = %+v, %v", g, err)
	}
	for name, edit := range map[string]func(*taskv1.TaskOrderV3){
		"other id":   func(o *taskv1.TaskOrderV3) { o.BuilderSetId = "set-6" },
		"other hash": func(o *taskv1.TaskOrderV3) { o.BuilderSetHash = bytes.Repeat([]byte{0x66}, 32) },
		"no hash":    func(o *taskv1.TaskOrderV3) { o.BuilderSetHash = nil },
	} {
		bad := &taskv1.TaskOrderV3{BuilderSetId: order.BuilderSetId, BuilderSetHash: order.BuilderSetHash}
		edit(bad)
		if _, err := CheckOrder(src, bad); !errors.Is(err, ErrBuilderSetStale) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := CheckOrder(source{}, order); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("no snapshot: err = %v", err)
	}
	if err := Ready(source{}); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("readiness without a snapshot: %v", err)
	}
	if err := Ready(src); err != nil {
		t.Fatal(err)
	}
}

func TestFrozenKeepsTheChainOrder(t *testing.T) {
	g, err := Frozen("set-7", hash(0x77), []string{"b2", "b3", "b0"})
	if err != nil || g.Dispatcher() != "b2" {
		t.Fatalf("frozen = %+v, %v", g, err)
	}
	if _, err := Frozen("set-7", hash(0x77), nil); err == nil {
		t.Fatal("an empty frozen group was accepted")
	}
}
