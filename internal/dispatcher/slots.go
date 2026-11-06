package dispatcher

import (
	"sync"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// slotBook counts, per Worker, the tickets it accepted since its current standing handraise was
// signed: its local free slot count is the handraise's minus those, until it signs a new one.
type slotBook struct {
	mu   sync.Mutex
	used map[string]slotUse
}

// slotUse is the accepted count against one handraise, named by (issued_height, handraise_nonce).
type slotUse struct {
	issued, nonce uint64
	accepted      uint32
}

func (b *slotBook) accepted(operator string, current *taskv1.StandingHandraiseV1) {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.used[operator]
	if u.issued != current.GetIssuedHeight() || u.nonce != current.GetHandraiseNonce() {
		u = slotUse{issued: current.GetIssuedHeight(), nonce: current.GetHandraiseNonce()}
	}
	u.accepted++
	b.used[operator] = u
}

// free is the local free slot count of operator under its current handraise; 0 without one.
func (b *slotBook) free(operator string, current *taskv1.StandingHandraiseV1) uint32 {
	if current == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.used[operator]
	if u.issued != current.GetIssuedHeight() || u.nonce != current.GetHandraiseNonce() {
		return current.GetFreeSlotCount()
	}
	if u.accepted >= current.GetFreeSlotCount() {
		return 0
	}
	return current.GetFreeSlotCount() - u.accepted
}
