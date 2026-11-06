package dispatchdraw

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func TestRosterHashMatchesWireVector(t *testing.T) {
	v := wirefixture.Load(t, dispatchVectors).Vector(t, "dispatch_roster", 0)
	v.CheckPreimage(t)
	roster := vectorRoster(t, vectorPool(t))
	if roster.Hash != v.Digest(t) {
		t.Fatalf("roster hash = %x, want %s", roster.Hash, v.DigestHex)
	}
	msg := roster.Msg
	if string(msg.GetTaskId()) != string(vectorTaskID[:]) || msg.GetReferenceHeight() != vectorRefH || string(msg.GetCandidatePoolSnapshotId()) != string(vectorSnapshot[:]) {
		t.Fatalf("roster message = %v", msg)
	}
	if roster.RootDigest != fill32(0xd1) {
		t.Fatalf("root digest = %x", roster.RootDigest)
	}
}

// A handraise is in the roster only when its leaf is admitted, it serves the order's profile, it
// has a free slot, it has not expired, and its operator is in the pool. Members are in slot order
// and carry the pool's slot version and weight.
func TestRosterFiltersHandraises(t *testing.T) {
	pool := vectorPool(t)
	const height = 150
	root := issuedRoot(
		leaf(vectorOp7, 7, true, 1, height, vectorProfile),                         // expires at this height: still valid
		leaf(vectorOp3, 3, false, 1, 200, vectorProfile),                           // not admitted
		leaf(vectorOp1, 1, true, 1, 200, Profile{ModelID: otherModel, Version: 1}), // other profile
		leaf("trueopen1notinpool", 9, true, 1, 200, vectorProfile),
	)
	roster, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, height, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got := slots(roster.Members()); !reflect.DeepEqual(got, []uint32{7}) {
		t.Fatalf("roster slots = %v, want [7]", got)
	}

	cases := map[string]*struct {
		admitted bool
		free     uint32
		expiry   uint64
		version  uint32
	}{
		"no free slot":    {true, 0, 200, 1},
		"expired":         {true, 1, height - 1, 1},
		"profile version": {true, 1, 200, 2},
		"not admitted":    {false, 1, 200, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := issuedRoot(
				leaf(vectorOp7, 7, tc.admitted, tc.free, tc.expiry, Profile{ModelID: vectorModel, Version: tc.version}),
				leaf(vectorOp3, 3, true, 1, 200, vectorProfile),
			)
			roster, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, height, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if got := slots(roster.Members()); !reflect.DeepEqual(got, []uint32{3}) {
				t.Fatalf("roster slots = %v, want [3]", got)
			}
		})
	}
}

func TestRosterMembersComeFromThePool(t *testing.T) {
	pool := vectorPool(t)
	roster := vectorRoster(t, pool)
	if !reflect.DeepEqual(roster.Members(), pool.Members) {
		t.Fatalf("roster = %+v, want the pool members", roster.Members())
	}
	m := pool.Members[1]
	if !roster.Contains(m) {
		t.Fatal("roster must contain its member")
	}
	m.SlotVersion = 2
	if roster.Contains(m) {
		t.Fatal("a different slot version is a different member")
	}
}

// An empty roster is NO_CAPACITY saying how far the root's leaves got through the roster
// conditions (admitted, serving the profile, a free slot and unexpired, operator in the pool) and
// how the pool was built; CheckRoster gives the same answer without building the roster.
func TestEmptyRosterIsNoCapacity(t *testing.T) {
	pool := vectorPool(t)
	if _, err := BuildRoster(vectorChainID, vectorTaskID, nil, pool, 150, 1<<20); !errors.Is(err, ErrNoCapacity) ||
		err.Error() != "NEXUS_INGRESS_NO_CAPACITY: no handraise root" {
		t.Fatalf("no root yet: %v", err)
	}
	root := issuedRoot(
		leaf(vectorOp7, 7, true, 0, 200, vectorProfile),
		leaf(vectorOp3, 3, false, 1, 200, vectorProfile),
		leaf(vectorOp1, 1, true, 1, 200, Profile{ModelID: otherModel, Version: 1}),
		leaf("trueopen1notinpool", 9, true, 1, 200, vectorProfile),
	)
	_, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, 150, 1<<20)
	want := fmt.Sprintf("%v: empty dispatch roster: root 99 has 4 leaves, 3 admitted, 2 serving the profile, "+
		"1 of those with a free slot and unexpired at height 150, 0 of those in the pool; "+
		"pool of model %x profile 1 at epoch 1: 3 of 3 snapshot members", ErrNoCapacity, vectorModel[:])
	if !errors.Is(err, ErrNoCapacity) || err.Error() != want {
		t.Fatalf("empty roster = %q\nwant           %q", err, want)
	}
	if err := CheckRoster(root, pool, 150); err == nil || err.Error() != want {
		t.Fatalf("CheckRoster = %v", err)
	}
	if err := CheckRoster(issuedRoot(leaf(vectorOp7, 7, true, 1, 200, vectorProfile)), pool, 150); err != nil {
		t.Fatalf("CheckRoster of a root with a roster member = %v", err)
	}
}

func TestRosterSizeLimit(t *testing.T) {
	pool := vectorPool(t)
	full := vectorRoster(t, pool)
	size := uint64(proto.Size(full.Msg))
	root := issuedRoot(
		leaf(vectorOp7, 7, true, 1, 200, vectorProfile),
		leaf(vectorOp1, 1, true, 2, 200, vectorProfile),
		leaf(vectorOp3, 3, true, 1, 200, vectorProfile),
	)
	if _, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, 150, size); err != nil {
		t.Fatalf("roster of exactly the limit: %v", err)
	}
	if _, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, 150, size-1); !errors.Is(err, ErrRosterTooLarge) {
		t.Fatalf("roster above the limit: %v", err)
	}
	if _, err := BuildRoster(vectorChainID, vectorTaskID, root, pool, 150, 0); err == nil {
		t.Fatal("a zero limit must be rejected")
	}
}
