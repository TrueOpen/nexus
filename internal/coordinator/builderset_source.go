package coordinator

import (
	"encoding/hex"
	"strings"

	"github.com/TrueOpen/nexus/internal/taskgroup"
)

// CurrentBuilderSet implements taskgroup.Source with the BuilderSet snapshot last read from the
// chain: id, hash and members from one read, members in snapshot order. False before the first
// read, or when the read gave no usable hash.
func (c *Coordinator) CurrentBuilderSet() (taskgroup.Snapshot, bool) {
	ref, members, ok := c.active.Snapshot()
	if !ok {
		return taskgroup.Snapshot{}, false
	}
	hash, err := hex.DecodeString(strings.TrimPrefix(ref.Hash, "0x"))
	if err != nil || len(hash) != 32 {
		return taskgroup.Snapshot{}, false
	}
	if len(members) == 0 {
		return taskgroup.Snapshot{}, false
	}
	out := taskgroup.Snapshot{ID: ref.ID, Members: make([]string, len(members))}
	copy(out.Hash[:], hash)
	for i, m := range members {
		out.Members[i] = m.Address
	}
	return out, true
}
