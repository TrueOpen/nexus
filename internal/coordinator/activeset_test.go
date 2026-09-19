package coordinator

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/types"
)

func roster(addrs ...string) []types.BuilderRef {
	out := make([]types.BuilderRef, len(addrs))
	for i, a := range addrs {
		out[i] = types.BuilderRef{Address: a, Endpoint: "https://" + a}
	}
	return out
}

func TestIsActive(t *testing.T) {
	as := newActiveSet("b2")
	if as.IsActive() {
		t.Fatal("empty roster: should not be active")
	}
	as.Update(1, roster("b1", "b3"), testBuilderSetRef)
	if as.IsActive() {
		t.Fatal("self not in roster: should not be active")
	}
	as.Update(2, roster("b1", "b2", "b3"), testBuilderSetRef)
	if !as.IsActive() {
		t.Fatal("self in roster: should be active")
	}

	// empty self => never active.
	none := newActiveSet("")
	none.Update(1, roster("b1", "b2"), testBuilderSetRef)
	if none.IsActive() {
		t.Fatal("empty self should never be active")
	}
}

func TestRankDeterministic(t *testing.T) {
	as := newActiveSet("b1")
	as.Update(1, roster("b1", "b2", "b3", "b4", "b5"), testBuilderSetRef)
	seed := []byte("order-seed-xyz")

	r1, ok1 := as.Rank(seed, "b3")
	r2, ok2 := as.Rank(seed, "b3")
	if !ok1 || !ok2 {
		t.Fatal("b3 should be found")
	}
	if r1 != r2 {
		t.Fatalf("rank not deterministic: %d vs %d", r1, r2)
	}
}

func TestRankOrderingStableAndFullCover(t *testing.T) {
	as := newActiveSet("b1")
	members := roster("b1", "b2", "b3", "b4", "b5")
	as.Update(1, members, testBuilderSetRef)
	seed := []byte("seed-A")

	// Collect the full permutation; ranks must be exactly 1..N with no gaps/dupes,
	// and stable across repeated computation.
	seen := map[int]string{}
	for _, m := range members {
		r, ok := as.Rank(seed, m.Address)
		if !ok {
			t.Fatalf("%s not found", m.Address)
		}
		if r < 1 || r > len(members) {
			t.Fatalf("rank %d out of range for %s", r, m.Address)
		}
		if prev, dup := seen[r]; dup {
			t.Fatalf("rank %d assigned to both %s and %s", r, prev, m.Address)
		}
		seen[r] = m.Address
	}
	if len(seen) != len(members) {
		t.Fatalf("expected %d distinct ranks, got %d", len(members), len(seen))
	}

	// Recompute => identical mapping.
	for _, m := range members {
		r, _ := as.Rank(seed, m.Address)
		if seen[r] != m.Address {
			t.Fatalf("ordering not stable for %s: rank %d now maps to %s", m.Address, r, seen[r])
		}
	}
}

func TestDifferentSeedsCanReorder(t *testing.T) {
	as := newActiveSet("b1")
	members := roster("b1", "b2", "b3", "b4", "b5")
	as.Update(1, members, testBuilderSetRef)

	perm := func(seed []byte) []string {
		ordered := make([]string, len(members))
		for _, m := range members {
			r, _ := as.Rank(seed, m.Address)
			ordered[r-1] = m.Address
		}
		return ordered
	}

	a := perm([]byte("seed-1"))
	b := perm([]byte("seed-2"))
	differs := false
	for i := range a {
		if a[i] != b[i] {
			differs = true
			break
		}
	}
	if !differs {
		t.Fatalf("expected different seeds to (likely) reorder, both gave %v", a)
	}
}

func TestRankAddrNotInSet(t *testing.T) {
	as := newActiveSet("b1")
	as.Update(1, roster("b1", "b2", "b3"), testBuilderSetRef)
	if r, ok := as.Rank([]byte("s"), "ghost"); ok || r != 0 {
		t.Fatalf("ghost should not be in set, got rank=%d inSet=%v", r, ok)
	}

	// Empty roster: nothing is in set.
	empty := newActiveSet("b1")
	if r, ok := empty.Rank([]byte("s"), "b1"); ok || r != 0 {
		t.Fatalf("empty roster should return inSet=false, got rank=%d inSet=%v", r, ok)
	}
}

func TestMyRank(t *testing.T) {
	as := newActiveSet("b3")
	as.Update(1, roster("b1", "b2", "b3"), testBuilderSetRef)
	want, _ := as.Rank([]byte("seed"), "b3")
	got, ok := as.MyRank([]byte("seed"))
	if !ok || got != want {
		t.Fatalf("MyRank=%d(%v) want %d", got, ok, want)
	}

	// empty self => not in set.
	none := newActiveSet("")
	none.Update(1, roster("b1"), testBuilderSetRef)
	if r, ok := none.MyRank([]byte("seed")); ok || r != 0 {
		t.Fatalf("empty self MyRank should be (0,false), got (%d,%v)", r, ok)
	}
}
