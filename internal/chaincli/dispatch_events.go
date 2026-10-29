package chaincli

import (
	"bytes"
	"encoding/hex"
	"fmt"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Phase 1 dispatch, session and Hub events reach ChainEvent.Typed decoded from their typed wire
// payloads. Like every chain event they are notifications: a consumer that acts on one reconciles
// with the matching Query first. Session and task IDs are lowercase hex like the rest of
// ChainEvent; hashes are raw 32 bytes; amounts are decimal atomic units.
const (
	// EventSessionScoped is a session-level event (no task_id) on a tracked session's stream.
	EventSessionScoped = "SessionScoped"
	// EventBuilderRole is an event addressed to this Builder on its role stream.
	EventBuilderRole = "BuilderRole"
	// EventBuilderRoleResync is sent when the role stream (re)connects: events of the gap may be missed.
	EventBuilderRoleResync = "BuilderRoleResync"
	// EventHubOperational is a Hub event on the protocol stream other than BuilderSet rotation.
	EventHubOperational = "HubOperational"
)

// TypedEvent is one decoded Phase 1 event; consumers type-switch on the concrete type.
type TypedEvent interface{ typedEvent() }

// DispatchRecorded: one dispatch entry was admitted and its Task created.
type DispatchRecorded struct {
	SessionID       string
	TaskID          string
	OrderSequence   uint64
	Builder         string
	WinnerWorker    string
	RecordHash      []byte
	TicketHash      []byte // the winner ticket
	ReferenceHeight uint64
	ReservedAmount  string
	InferDeadline   uint64
}

// SessionBuilderBound: the session's Builder binding was created or moved by a takeover.
type SessionBuilderBound struct {
	SessionID         string
	OldBuilder        string // empty on CREATE
	NewBuilder        string
	Trigger           taskv1.SessionBuilderBoundTriggerV1
	BoundChangeHeight uint64
}

// SessionTakeoverRegistered: a takeover candidate registered for an unconsumed sequence.
type SessionTakeoverRegistered struct {
	SessionID        string
	BoundBuilder     string
	CandidateBuilder string
	OrderSequence    uint64
	RegisteredHeight uint64
	ActivationHeight uint64
}

// SessionTakeoverVoided: a pending takeover was cleared without binding the candidate.
type SessionTakeoverVoided struct {
	SessionID        string
	CandidateBuilder string
	OrderSequence    uint64
	Reason           taskv1.SessionTakeoverVoidReasonV1
}

// DispatchCompensationClaimed: a Worker claimed compensation on a ticket; the Builder may rebut
// until RebuttalDeadlineHeight.
type DispatchCompensationClaimed struct {
	TicketHash             []byte
	TaskID                 string
	Builder                string
	Worker                 string
	Amount                 string
	RebuttalDeadlineHeight uint64
}

// DispatchCompensationPaid: an unrebutted claim was paid from the Builder's compensation account.
type DispatchCompensationPaid struct {
	TicketHash     []byte
	TaskID         string
	Builder        string
	Worker         string
	Amount         string
	PaidAmount     string
	UnfilledAmount string
}

// DispatchCompensationRebutted: a rebuttal dismissed the claim.
type DispatchCompensationRebutted struct {
	TicketHash          []byte
	TaskID              string
	Builder             string
	Worker              string
	Responder           string
	AttemptOutcome      taskv1.DispatchAttemptOutcomeV1
	WorkerFaultRecorded bool
}

// DispatchChallengeOpened: a dispatch challenge was opened against a recorded task.
type DispatchChallengeOpened struct {
	ChallengeID         []byte
	TaskID              string
	Kind                sharedv1.DispatchChallengeKindV1
	Challenger          string
	ProofDeadlineHeight uint64 // zero when the kind takes no response
}

// DispatchChallengeResolved: a dispatch challenge reached its final status.
type DispatchChallengeResolved struct {
	ChallengeID []byte
	TaskID      string
	Kind        sharedv1.DispatchChallengeKindV1
	Outcome     taskv1.DispatchChallengeStatusV1
}

// BuilderDispatchFaultRecorded: an upheld challenge recorded a dispatch fault against a Builder.
type BuilderDispatchFaultRecorded struct {
	Builder           string
	FaultID           []byte
	Kind              sharedv1.DispatchChallengeKindV1
	TaskID            string
	PenaltyAmount     string
	UnfilledAmount    string
	CompensatedWorker string // empty when none
}

// SessionDeposited: funds were added to the session balance.
type SessionDeposited struct {
	SessionID string
	Owner     string
	Amount    string
	Balance   string
}

// SessionWithdrawRequested: an AMOUNT or CLOSE withdrawal was registered.
type SessionWithdrawRequested struct {
	SessionID       string
	Kind            taskv1.SessionWithdrawKindV1
	Amount          string
	EffectiveHeight uint64
}

// SessionWithdrawEffective: a pending withdrawal matured and was paid.
type SessionWithdrawEffective struct {
	SessionID        string
	Kind             taskv1.SessionWithdrawKindV1
	PaidAmount       string
	RemainingBalance string
}

// SessionKeyChangeRequested: a delayed session key SET or CLEAR was registered.
type SessionKeyChangeRequested struct {
	SessionID       string
	Kind            taskv1.SessionKeyChangeKindV1
	EffectiveHeight uint64
}

// OrderCancelRequested: a delayed cancellation of one order sequence was registered.
type OrderCancelRequested struct {
	SessionID             string
	OrderSequence         uint64
	CancelEffectiveHeight uint64
}

// OrderCancelled: one order sequence became CANCELLED.
type OrderCancelled struct {
	SessionID     string
	OrderSequence uint64
	TaskID        string
}

// ServiceKeyRotated: an operator's current service key changed; keys cached for it are stale.
type ServiceKeyRotated struct {
	ParticipantType    sharedv1.ParticipantType
	Operator           string
	OldServiceAddress  string
	NewServiceAddress  string
	AuthorizationNonce uint64
}

// ServiceKeyRotationRegistered: an operator registered a replacement key. The current key stays
// in force until activation (ServiceKeyRotated), but a cached binding no longer shows the pending
// state.
type ServiceKeyRotationRegistered struct {
	ParticipantType           sharedv1.ParticipantType
	Operator                  string
	CurrentAuthorizationNonce uint64
	NextAuthorizationNonce    uint64
	EffectiveHeight           uint64
}

// BuilderCompensationFunded: a Builder's compensation account was funded.
type BuilderCompensationFunded struct {
	Builder string
	Amount  string
	Balance string
}

// CandidatePoolPublished: the candidate pool snapshot of an epoch became ACTIVE.
type CandidatePoolPublished struct {
	Epoch           uint64
	SnapshotID      []byte
	PoolHash        []byte
	ActiveCount     uint32
	EffectiveHeight uint64
	ExpiresHeight   uint64
}

// CandidatePoolExpired: an epoch's ACTIVE snapshot expired and the current pool pointer was
// cleared.
type CandidatePoolExpired struct {
	Epoch         uint64
	SnapshotID    []byte
	PoolHash      []byte
	ExpiresHeight uint64
}

func (CandidatePoolPublished) typedEvent()       {}
func (CandidatePoolExpired) typedEvent()         {}
func (DispatchRecorded) typedEvent()             {}
func (SessionBuilderBound) typedEvent()          {}
func (SessionTakeoverRegistered) typedEvent()    {}
func (SessionTakeoverVoided) typedEvent()        {}
func (DispatchCompensationClaimed) typedEvent()  {}
func (DispatchCompensationPaid) typedEvent()     {}
func (DispatchCompensationRebutted) typedEvent() {}
func (DispatchChallengeOpened) typedEvent()      {}
func (DispatchChallengeResolved) typedEvent()    {}
func (BuilderDispatchFaultRecorded) typedEvent() {}
func (SessionDeposited) typedEvent()             {}
func (SessionWithdrawRequested) typedEvent()     {}
func (SessionWithdrawEffective) typedEvent()     {}
func (SessionKeyChangeRequested) typedEvent()    {}
func (OrderCancelRequested) typedEvent()         {}
func (OrderCancelled) typedEvent()               {}
func (ServiceKeyRotated) typedEvent()            {}
func (ServiceKeyRotationRegistered) typedEvent() {}
func (BuilderCompensationFunded) typedEvent()    {}

// typedTaskEvent decodes the Phase 1 Task payloads. It returns nil, nil for every other payload,
// which keeps its existing mapping.
func typedTaskEvent(payload *taskv1.TaskProtocolEventPayloadV1) (TypedEvent, error) {
	switch p := payload.GetTypedEvent().(type) {
	case *taskv1.TaskProtocolEventPayloadV1_DispatchRecorded:
		e := p.DispatchRecorded
		if err := hash32Fields("dispatch_recorded", e.GetDispatchRecordHash(), e.GetDispatchTicketHash()); err != nil {
			return nil, err
		}
		return DispatchRecorded{
			SessionID: hex.EncodeToString(e.GetSessionId()), TaskID: hex.EncodeToString(e.GetTaskId()),
			OrderSequence: e.GetOrderSequence(), Builder: e.GetBuilder(), WinnerWorker: e.GetWinnerWorker(),
			RecordHash: bytes.Clone(e.GetDispatchRecordHash()), TicketHash: bytes.Clone(e.GetDispatchTicketHash()),
			ReferenceHeight: e.GetReferenceHeight(), ReservedAmount: e.GetReservedAmount().GetAtomicUnits(),
			InferDeadline: e.GetInferDeadline(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionBuilderBound:
		e := p.SessionBuilderBound
		return SessionBuilderBound{
			SessionID: hex.EncodeToString(e.GetSessionId()), OldBuilder: e.GetOldBuilderOrEmpty(), NewBuilder: e.GetNewBuilder(),
			Trigger: e.GetTrigger(), BoundChangeHeight: e.GetBoundChangeHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionTakeoverRegistered:
		e := p.SessionTakeoverRegistered
		return SessionTakeoverRegistered{
			SessionID: hex.EncodeToString(e.GetSessionId()), BoundBuilder: e.GetBoundBuilder(), CandidateBuilder: e.GetCandidateBuilder(),
			OrderSequence: e.GetOrderSequence(), RegisteredHeight: e.GetRegisteredHeight(), ActivationHeight: e.GetActivationHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionTakeoverVoided:
		e := p.SessionTakeoverVoided
		return SessionTakeoverVoided{
			SessionID: hex.EncodeToString(e.GetSessionId()), CandidateBuilder: e.GetCandidateBuilder(),
			OrderSequence: e.GetOrderSequence(), Reason: e.GetReason(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_DispatchCompensationClaimed:
		e := p.DispatchCompensationClaimed
		if err := hash32Fields("dispatch_compensation_claimed", e.GetDispatchTicketHash()); err != nil {
			return nil, err
		}
		return DispatchCompensationClaimed{
			TicketHash: bytes.Clone(e.GetDispatchTicketHash()), TaskID: hex.EncodeToString(e.GetTaskId()),
			Builder: e.GetBuilder(), Worker: e.GetWorker(), Amount: e.GetAmount().GetAtomicUnits(),
			RebuttalDeadlineHeight: e.GetRebuttalDeadlineHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_DispatchCompensationPaid:
		e := p.DispatchCompensationPaid
		if err := hash32Fields("dispatch_compensation_paid", e.GetDispatchTicketHash()); err != nil {
			return nil, err
		}
		return DispatchCompensationPaid{
			TicketHash: bytes.Clone(e.GetDispatchTicketHash()), TaskID: hex.EncodeToString(e.GetTaskId()),
			Builder: e.GetBuilder(), Worker: e.GetWorker(), Amount: e.GetAmount().GetAtomicUnits(),
			PaidAmount: e.GetPaidAmount().GetAtomicUnits(), UnfilledAmount: e.GetUnfilledAmount().GetAtomicUnits(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_DispatchCompensationRebutted:
		e := p.DispatchCompensationRebutted
		if err := hash32Fields("dispatch_compensation_rebutted", e.GetDispatchTicketHash()); err != nil {
			return nil, err
		}
		return DispatchCompensationRebutted{
			TicketHash: bytes.Clone(e.GetDispatchTicketHash()), TaskID: hex.EncodeToString(e.GetTaskId()),
			Builder: e.GetBuilder(), Worker: e.GetWorker(), Responder: e.GetResponder(),
			AttemptOutcome: e.GetAttemptOutcome(), WorkerFaultRecorded: e.GetWorkerFaultRecorded(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_DispatchChallengeOpened:
		e := p.DispatchChallengeOpened
		if err := hash32Fields("dispatch_challenge_opened", e.GetChallengeId()); err != nil {
			return nil, err
		}
		return DispatchChallengeOpened{
			ChallengeID: bytes.Clone(e.GetChallengeId()), TaskID: hex.EncodeToString(e.GetTaskId()),
			Kind: e.GetKind(), Challenger: e.GetChallenger(), ProofDeadlineHeight: e.GetProofDeadlineHeightOrZero(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_DispatchChallengeResolved:
		e := p.DispatchChallengeResolved
		if err := hash32Fields("dispatch_challenge_resolved", e.GetChallengeId()); err != nil {
			return nil, err
		}
		return DispatchChallengeResolved{
			ChallengeID: bytes.Clone(e.GetChallengeId()), TaskID: hex.EncodeToString(e.GetTaskId()),
			Kind: e.GetKind(), Outcome: e.GetOutcome(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_BuilderDispatchFaultRecorded:
		e := p.BuilderDispatchFaultRecorded
		if err := hash32Fields("builder_dispatch_fault_recorded", e.GetFaultId()); err != nil {
			return nil, err
		}
		return BuilderDispatchFaultRecorded{
			Builder: e.GetBuilder(), FaultID: bytes.Clone(e.GetFaultId()), Kind: e.GetKind(), TaskID: hex.EncodeToString(e.GetTaskId()),
			PenaltyAmount: e.GetPenaltyAmount().GetAtomicUnits(), UnfilledAmount: e.GetUnfilledAmount().GetAtomicUnits(),
			CompensatedWorker: e.GetCompensatedWorkerOrEmpty(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionDeposited:
		e := p.SessionDeposited
		return SessionDeposited{
			SessionID: hex.EncodeToString(e.GetSessionId()), Owner: e.GetOwner(),
			Amount: e.GetAmount().GetAtomicUnits(), Balance: e.GetBalance().GetAtomicUnits(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionWithdrawRequested:
		e := p.SessionWithdrawRequested
		return SessionWithdrawRequested{
			SessionID: hex.EncodeToString(e.GetSessionId()), Kind: e.GetKind(),
			Amount: e.GetAmount().GetAtomicUnits(), EffectiveHeight: e.GetEffectiveHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionWithdrawEffective:
		e := p.SessionWithdrawEffective
		return SessionWithdrawEffective{
			SessionID: hex.EncodeToString(e.GetSessionId()), Kind: e.GetKind(),
			PaidAmount: e.GetPaidAmount().GetAtomicUnits(), RemainingBalance: e.GetRemainingBalance().GetAtomicUnits(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_SessionKeyChangeRequested:
		e := p.SessionKeyChangeRequested
		return SessionKeyChangeRequested{
			SessionID: hex.EncodeToString(e.GetSessionId()), Kind: e.GetKind(), EffectiveHeight: e.GetEffectiveHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_OrderCancelRequested:
		e := p.OrderCancelRequested
		return OrderCancelRequested{
			SessionID: hex.EncodeToString(e.GetSessionId()), OrderSequence: e.GetOrderSequence(),
			CancelEffectiveHeight: e.GetCancelEffectiveHeight(),
		}, nil
	case *taskv1.TaskProtocolEventPayloadV1_OrderCancelled:
		e := p.OrderCancelled
		return OrderCancelled{
			SessionID: hex.EncodeToString(e.GetSessionId()), OrderSequence: e.GetOrderSequence(), TaskID: hex.EncodeToString(e.GetTaskId()),
		}, nil
	}
	return nil, nil
}

// typedHubEvent decodes the Hub payloads Phase 1 consumes besides BuilderSet rotation; nil, nil
// for any other payload.
func typedHubEvent(payload *hubv1.ProtocolEventPayloadV1) (TypedEvent, error) {
	switch p := payload.GetTypedEvent().(type) {
	case *hubv1.ProtocolEventPayloadV1_ServiceKeyRotated:
		e := p.ServiceKeyRotated
		if e.GetOperator() == "" {
			return nil, fmt.Errorf("service_key_rotated: operator is required")
		}
		return ServiceKeyRotated{
			ParticipantType: e.GetParticipantType(), Operator: e.GetOperator(),
			OldServiceAddress: e.GetOldServiceAddress(), NewServiceAddress: e.GetNewServiceAddress(),
			AuthorizationNonce: e.GetAuthorizationNonce(),
		}, nil
	case *hubv1.ProtocolEventPayloadV1_ServiceKeyRotationRegistered:
		e := p.ServiceKeyRotationRegistered.GetPendingRotation()
		if e.GetOperatorAddress() == "" {
			return nil, fmt.Errorf("service_key_rotation_registered: operator is required")
		}
		return ServiceKeyRotationRegistered{
			ParticipantType: e.GetParticipantType(), Operator: e.GetOperatorAddress(),
			CurrentAuthorizationNonce: e.GetCurrentServiceAuthorizationNonce(),
			NextAuthorizationNonce:    e.GetNextServiceAuthorizationNonce(), EffectiveHeight: e.GetEffectiveHeight(),
		}, nil
	case *hubv1.ProtocolEventPayloadV1_CandidatePoolPublished:
		e := p.CandidatePoolPublished
		if err := hash32Fields("candidate_pool_published", e.GetSnapshotId()); err != nil {
			return nil, err
		}
		return CandidatePoolPublished{
			Epoch: e.GetEpoch(), SnapshotID: bytes.Clone(e.GetSnapshotId()), PoolHash: bytes.Clone(e.GetPoolHash()),
			ActiveCount: e.GetActiveCount(), EffectiveHeight: e.GetEffectiveHeight(), ExpiresHeight: e.GetExpiresHeight(),
		}, nil
	case *hubv1.ProtocolEventPayloadV1_CandidatePoolExpired:
		e := p.CandidatePoolExpired
		if err := hash32Fields("candidate_pool_expired", e.GetSnapshotId()); err != nil {
			return nil, err
		}
		return CandidatePoolExpired{
			Epoch: e.GetEpoch(), SnapshotID: bytes.Clone(e.GetSnapshotId()), PoolHash: bytes.Clone(e.GetPoolHash()),
			ExpiresHeight: e.GetExpiresHeight(),
		}, nil
	case *hubv1.ProtocolEventPayloadV1_BuilderCompensationFunded:
		e := p.BuilderCompensationFunded
		if e.GetBuilder() == "" {
			return nil, fmt.Errorf("builder_compensation_funded: builder is required")
		}
		return BuilderCompensationFunded{
			Builder: e.GetBuilder(), Amount: e.GetAmount().GetAtomicUnits(), Balance: e.GetBalance().GetAtomicUnits(),
		}, nil
	}
	return nil, nil
}

func hash32Fields(event string, values ...[]byte) error {
	for _, value := range values {
		if len(value) != 32 {
			return fmt.Errorf("%s: hash is %d bytes, want 32", event, len(value))
		}
	}
	return nil
}
