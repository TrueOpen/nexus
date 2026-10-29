package inflight

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/nexus/internal/sdkauth"
)

// Precheck failures. The text is the Ingress error code; none of them creates a task or uses the
// order's sequence. Session key failures are registeredkey errors (sdkauth.OrderKeyErr maps them).
var (
	// ErrOrderExpired: the order may expire before its record deadline.
	ErrOrderExpired = errors.New("NEXUS_INGRESS_ORDER_EXPIRED")
	// ErrOrderStale: earliest_submit_height is more than order_freshness_margin_blocks below the head.
	ErrOrderStale = errors.New("NEXUS_INGRESS_ORDER_STALE")
	// ErrOrderFuture: earliest_submit_height is more than one block above the head.
	ErrOrderFuture = errors.New("NEXUS_INGRESS_ORDER_FUTURE")
	// ErrTakeoverPending: a takeover of the session is registered; see TakeoverPendingError.
	ErrTakeoverPending = errors.New("NEXUS_INGRESS_TAKEOVER_PENDING")
	// ErrSessionBoundElsewhere: the session is bound to another Builder.
	ErrSessionBoundElsewhere = errors.New("NEXUS_INGRESS_SESSION_BOUND_ELSEWHERE")
	// ErrOrderSequenceConflict: the sequence is not the first free sequence after the chain's next
	// expected sequence and this Builder's in-flight orders, or a cancellation of it is registered.
	ErrOrderSequenceConflict = errors.New("NEXUS_INGRESS_ORDER_SEQUENCE_CONFLICT")
	// ErrInflightLimit: the session already has builder_max_inflight_per_session or
	// max_pending_per_session in-flight orders.
	ErrInflightLimit = errors.New("NEXUS_INGRESS_INFLIGHT_LIMIT")
	// ErrSessionSuspended: dispatch for the session is suspended after a failed record, and the
	// order is not the resend of the suspended sequence.
	ErrSessionSuspended = errors.New("NEXUS_INGRESS_SESSION_SUSPENDED")
	// ErrSessionBalanceInsufficient: balance - frozen_total - pending withdrawal - in-flight
	// max_fee is below the order's max_fee.
	ErrSessionBalanceInsufficient = errors.New("NEXUS_INGRESS_SESSION_BALANCE_INSUFFICIENT")
	// ErrSessionClosing: a CLOSE withdrawal is registered, or the session is closed.
	ErrSessionClosing = errors.New("NEXUS_INGRESS_SESSION_CLOSING")
	// ErrOrderReplacementUnsupported: another version of an order still being dispatched.
	ErrOrderReplacementUnsupported = errors.New("NEXUS_INGRESS_ORDER_REPLACEMENT_UNSUPPORTED")
	// ErrOrderLocked: another version of an order a Worker already accepted.
	ErrOrderLocked = errors.New("NEXUS_INGRESS_ORDER_LOCKED")
	// ErrTaskTerminal: another version of an order the chain already admitted.
	ErrTaskTerminal = errors.New("NEXUS_INGRESS_TASK_TERMINAL")
	// ErrUnavailable: the session state or the head could not be read; retryable, never a verdict.
	// It is the request verification's chain-unavailable code.
	ErrUnavailable = sdkauth.ErrUnavailable
)

// TakeoverPendingError is ErrTakeoverPending with the registered candidate and the height the
// takeover takes effect at.
type TakeoverPendingError struct {
	Candidate        string
	ActivationHeight uint64
}

func (e *TakeoverPendingError) Error() string {
	return fmt.Sprintf("%s: candidate %s takes the session over at height %d", ErrTakeoverPending, e.Candidate, e.ActivationHeight)
}

func (e *TakeoverPendingError) Unwrap() error { return ErrTakeoverPending }
