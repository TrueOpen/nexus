// Per-task event journal: backs IngressAPI GetTaskEvents.
// The event stream is only for UX hints and reconnect recovery (cursor replay); on-chain state is what the chain query
// says, so a slow consumer losing live events is acceptable -- the client reconnects with its cursor to catch up.
package coordinator

import (
	"sync"

	"github.com/TrueOpen/nexus/internal/types"
)

// maxJournalEntries is the per-task event retention cap (a full happy path is ~11 entries; generous headroom).
const maxJournalEntries = 256

type journal struct {
	mu      sync.Mutex
	seq     uint64
	entries []types.TaskEvent
	subs    map[int]chan types.TaskEvent
	nextSub int
}

func newJournal() *journal {
	return &journal{subs: make(map[int]chan types.TaskEvent)}
}

// append records an event and broadcasts to live subscribers (non-blocking: slow consumers lose events and rely on cursor replay).
func (j *journal) append(ev types.TaskEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	ev.Seq = j.seq
	j.entries = append(j.entries, ev)
	if len(j.entries) > maxJournalEntries {
		j.entries = j.entries[len(j.entries)-maxJournalEntries:]
	}
	for _, ch := range j.subs {
		select {
		case ch <- ev:
		default: // full -> drop; the client replays by cursor
		}
	}
}

// subscribe returns the history replay after cursor + a live channel + an unsubscribe func.
// Replay and registration happen in the same critical section, guaranteeing no gaps and no duplicates.
func (j *journal) subscribe(fromCursor uint64) (replay []types.TaskEvent, live <-chan types.TaskEvent, cancel func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.entries {
		if e.Seq > fromCursor {
			replay = append(replay, e)
		}
	}
	id := j.nextSub
	j.nextSub++
	ch := make(chan types.TaskEvent, 64)
	j.subs[id] = ch
	cancel = func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		if c, ok := j.subs[id]; ok {
			delete(j.subs, id)
			close(c)
		}
	}
	return replay, ch, cancel
}

// snapshot returns a copy of the event history (for task snapshot persistence).
func (j *journal) snapshot() []types.TaskEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]types.TaskEvent(nil), j.entries...)
}

// restoreEntries rebuilds the journal from persisted history (restart recovery): seq continues from the tail
// so GetTaskEvents cursor semantics survive restarts. Only call with no subscribers.
func (j *journal) restoreEntries(entries []types.TaskEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(entries) == 0 || len(j.entries) > 0 {
		return // already has content (duplicate restore); do not overwrite
	}
	j.entries = append([]types.TaskEvent(nil), entries...)
	j.seq = entries[len(entries)-1].Seq
}

// Event codes (GetTaskEvents.event_code): the closed Nexus lifecycle set the wire contract lists
// above GetTaskEventsResponse, separate from the Node's protocol event codes. The SDK relies on
// them; never change one. ASSIGN_REJECTED, ASSIGN_ACCEPTED and ASSIGNMENT_FINALIZED are retired
// codes of the earlier assignment flow: never reuse them.
const (
	EvOrderReceived    = "ORDER_RECEIVED"
	EvAssignTimeout    = "ASSIGN_TIMEOUT"    // no on-chain task before order deadline
	EvDispatchAccepted = "DISPATCH_ACCEPTED" // a Worker accepted a ticket; the record is not on chain yet
	EvDispatchRecorded = "DISPATCH_RECORDED" // the chain recorded the dispatch: the winner is final
	EvNoCapacity       = "NO_CAPACITY"       // no Worker accepted within max_skips; the sequence is unused
	EvRecordRejected   = "RECORD_REJECTED"   // the chain refused the dispatch entry or it missed its record deadline
	EvTakeoverPending  = "TAKEOVER_PENDING"  // the chain registered this Builder's takeover of the session; chain_height is the activation height
	EvTakeoverRecorded = "TAKEOVER_RECORDED" // the takeover took effect: the session is bound here and the order is dispatched from scratch
	EvTakeoverVoided   = "TAKEOVER_VOIDED"   // the takeover will not take effect (the order was recorded or cancelled, the session closed or went to another Builder)
	EvOrderExpired     = "ORDER_EXPIRED"     // the held order expired: before its takeover registered (the session stays with its Builder; a re-signed resend registers again) or before it could be recorded once the takeover took effect (resend it re-signed here)
	// EvInferReceiptReceived is the Worker's signed InferReceipt; the contract keeps the name
	// OUTPUT_REF_RECEIVED for it.
	EvInferReceiptReceived     = "OUTPUT_REF_RECEIVED"
	EvOpenVerifyAccepted       = "OPEN_VERIFY_ACCEPTED"        // formal Verifiers decided (no seed)
	EvSampleReady              = "SAMPLE_READY"                // sampling seed ready
	EvWorkerRevealAccepted     = "WORKER_REVEAL_ACCEPTED"      // Worker reveal receipt on-chain
	EvFullResultRevealAccepted = "FULL_RESULT_REVEAL_ACCEPTED" // Verifier self-rescue on-chain
	EvSettleAccepted           = "SETTLE_ACCEPTED"             // settlement included in a block
	EvSweepObserved            = "SWEEP_OBSERVED"              // deadline sweep converged
	EvTaskFailed               = "TASK_FAILED"                 // authoritative chain query reached a failed terminal state
	EvTaskClosed               = "TASK_CLOSED"                 // challenge window ended, held credentials released
	EvTaskRecovered            = "TASK_RECOVERED"              // restored from snapshot after process restart (incl. on-chain reconciliation)
)
