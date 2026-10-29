package dispatcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

// phase is where an order's dispatch stands.
type phase string

const (
	// phaseDispatching: tickets are being offered, or the order waits to offer the next one.
	phaseDispatching phase = "DISPATCHING"
	// phaseAccepted: a Worker accepted a ticket; the dispatch entry went to the Recorder.
	phaseAccepted phase = "ACCEPTED"
	// phaseFailed: the attempt ended without a winner. The state stays so that a retry of the
	// sequence in the same epoch continues the order as a new round.
	phaseFailed phase = "FAILED"
)

// attemptState is one ticket of an order: the exact signed bytes offered and what came of it.
type attemptState struct {
	// Ticket is the signed DispatchTicketV1; it is never signed again.
	Ticket []byte `json:"ticket"`
	Hash   []byte `json:"hash"`
	Rank   uint32 `json:"rank"`
	// Operator is the target's operator address.
	Operator   string `json:"operator"`
	DeadlineMs uint64 `json:"deadline_ms"`
	Tier       uint32 `json:"tier"`
	// Sent is false for a ticket whose target could not be reached when it was issued: it was
	// never offered and timed out at once.
	Sent bool `json:"sent"`
	// Outcome is UNSPECIFIED while the ticket is out.
	Outcome taskv1.DispatchAttemptOutcomeV1 `json:"outcome"`
	// Reject is the signed DispatchRejectV1 of a REJECTED attempt as received, RejectDigest its
	// dispatch_reject_digest; the Builder shows them when a skip is challenged.
	Reject       []byte `json:"reject,omitempty"`
	RejectDigest []byte `json:"reject_digest,omitempty"`
}

// roundState is one dispatch round: the handraise root its tickets bind, its frozen roster and
// its attempts. A round is stored once its first ticket is issued.
type roundState struct {
	Number     uint32         `json:"number"`
	RootDigest []byte         `json:"root_digest"`
	Roster     []byte         `json:"roster"` // DispatchRosterV1
	Attempts   []attemptState `json:"attempts"`
}

// epochState is the randomness context shared by every ticket of the order.
type epochState struct {
	Number          uint64 `json:"number"`
	ReferenceHeight uint64 `json:"reference_height"`
	SnapshotID      []byte `json:"snapshot_id"`
	VRFOutput       []byte `json:"vrf_output"`
	VRFProof        []byte `json:"vrf_proof"`
}

// orderState is the persisted dispatch state of one order (session, sequence).
type orderState struct {
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id"`
	TaskHash  string `json:"task_hash"`
	// SignedOrder is the SignedOrderV2 of the version being dispatched.
	SignedOrder []byte `json:"signed_order"`
	Phase       phase  `json:"phase"`
	FailReason  string `json:"fail_reason,omitempty"`

	// Epoch and Members are set once the order is drawn; Members is the complete order (after
	// any sticky promotion), whose index is the ticket rank.
	Epoch         *epochState             `json:"epoch,omitempty"`
	Members       []dispatch.RosterMember `json:"members,omitempty"`
	StickyApplied bool                    `json:"sticky_applied,omitempty"`
	StickyAnchor  uint64                  `json:"sticky_anchor,omitempty"`
	StickyRun     uint32                  `json:"sticky_run,omitempty"`
	// Cursor is the first rank not considered yet; Skips counts REJECTED and TIMEOUT attempts.
	Cursor uint32 `json:"cursor"`
	Skips  uint32 `json:"skips"`
	// BoundChangeHeight is the session's bound_change_height the current round's tickets commit.
	BoundChangeHeight uint64 `json:"bound_change_height"`
	// NewRound is set when the next ticket must open a new round (a retry or a voiding binding
	// change); otherwise the last stored round goes on.
	NewRound bool         `json:"new_round,omitempty"`
	Rounds   []roundState `json:"rounds,omitempty"`

	// Accept is the winner's signed DispatchAcceptV1 as received, AcceptDigest its
	// dispatch_accept_digest; Record the signed DispatchRecordV1 built from it.
	Accept       []byte `json:"accept,omitempty"`
	AcceptDigest []byte `json:"accept_digest,omitempty"`
	Record       []byte `json:"record,omitempty"`
}

// pending returns the attempt whose ticket is out, if any.
func (s *orderState) pending() *attemptState {
	if len(s.Rounds) == 0 {
		return nil
	}
	r := &s.Rounds[len(s.Rounds)-1]
	if n := len(r.Attempts); n > 0 && r.Attempts[n-1].Outcome == taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED {
		return &r.Attempts[n-1]
	}
	return nil
}

// winner returns the ACCEPTED attempt of the last round, if any.
func (s *orderState) winner() *attemptState {
	if len(s.Rounds) == 0 {
		return nil
	}
	r := &s.Rounds[len(s.Rounds)-1]
	if n := len(r.Attempts); n > 0 && r.Attempts[n-1].Outcome == taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_ACCEPTED {
		return &r.Attempts[n-1]
	}
	return nil
}

// attemptByHash finds the attempt of a ticket hash.
func (s *orderState) attemptByHash(hash []byte) *attemptState {
	for i := range s.Rounds {
		for j := range s.Rounds[i].Attempts {
			if string(s.Rounds[i].Attempts[j].Hash) == string(hash) {
				return &s.Rounds[i].Attempts[j]
			}
		}
	}
	return nil
}

func (s *orderState) signedOrder() (*taskv1.SignedOrderV2, error) {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(s.SignedOrder, &signed); err != nil {
		return nil, fmt.Errorf("decode stored signed order: %w", err)
	}
	return &signed, nil
}

// Keys of kv.NSDispatch: "order/<session>/<zero-padded sequence>".
const orderPrefix = "order/"

func stateKey(sessionID string, seq uint64) string {
	return fmt.Sprintf("%s%s/%020d", orderPrefix, sessionID, seq)
}

func saveState(store kv.Store, s *orderState) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode dispatch state: %w", err)
	}
	if err := store.Set(kv.NSDispatch, stateKey(s.SessionID, s.Sequence), raw); err != nil {
		return fmt.Errorf("write dispatch state: %w", err)
	}
	return nil
}

func deleteState(store kv.Store, sessionID string, seq uint64) error {
	return store.Delete(kv.NSDispatch, stateKey(sessionID, seq))
}

// loadStates reads every stored dispatch state. A state that does not parse fails the load: its
// tickets may be out and must not be signed again differently.
func loadStates(store kv.Store) ([]*orderState, error) {
	var out []*orderState
	var loadErr error
	err := store.Scan(kv.NSDispatch, func(key string, val []byte) bool {
		if !strings.HasPrefix(key, orderPrefix) {
			return true
		}
		var s orderState
		if err := json.Unmarshal(val, &s); err != nil || stateKey(s.SessionID, s.Sequence) != key {
			loadErr = fmt.Errorf("dispatch state %q is malformed", key)
			return false
		}
		out = append(out, &s)
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("scan dispatch states: %w", err)
	}
	return out, loadErr
}
