package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/stagetiming"
	"github.com/TrueOpen/nexus/internal/types"
)

// CortexLink delivers Builder-signed Verifier messages to the Cortex dispatch streams.
type CortexLink interface {
	// Broadcast sends an OpenVerifyV1 or VerifierAssignmentNotifyV1 to every connected stream and
	// keeps it for streams that connect later, until Retire.
	Broadcast(ctx context.Context, frame *nexusv1.DispatchStreamFrameV1) error
	// Retire stops giving the messages of (task_id, verify_round) to streams that connect later.
	Retire(taskID []byte, verifyRound uint32)
}

// WithCortexLink wires the downlink to connected Cortex streams. Without it the coordinator signs
// nothing and sends nothing; the chain stays the source of every fact the messages announce.
func WithCortexLink(link CortexLink) Option {
	return func(c *Coordinator) { c.cortex = link }
}

// errBuilderMessageUnsigned reports that a Builder message cannot be signed: no service key is
// configured, or the chain does not hold this node's current binding.
var errBuilderMessageUnsigned = errors.New("builder message signing is not available")

// errRotationPendingTask refuses a Builder message for a Task recorded at or after the block before
// this Builder registered its service key replacement: the evidence context of such a Task reserves
// the pending next nonce, so the current nonce cannot sign for it, and the next key is not usable
// before it activates. The other members of the Task Builders group send it.
var errRotationPendingTask = errors.New("builder message for a task recorded during this Builder's key rotation")

// builderMessages signs the Phase 1 Builder messages of one coordinator and hands them to the
// CortexLink. It is shared by every task FSM.
type builderMessages struct {
	coord *Coordinator
}

// signOpenVerify fills the signed binding and builder_service_signature of an OpenVerifyV1. The
// signature is over dispatch.SigningDigest("nexus.v1.OpenVerifyV1", ...) of the message without it.
// recordHeight is the height the chain recorded the task's dispatch (0 when not known).
func (m builderMessages) signOpenVerify(ctx context.Context, msg *nexusv1.OpenVerifyV1, recordHeight uint64) error {
	if m.coord == nil {
		return errBuilderMessageUnsigned
	}
	binding, err := m.coord.builderBinding(ctx, recordHeight)
	if err != nil {
		return err
	}
	msg.Binding, msg.BuilderServiceSignature = binding, nil
	signature, err := m.coord.signBuilderMessage("nexus.v1.OpenVerifyV1", msg)
	if err != nil {
		return err
	}
	msg.BuilderServiceSignature = signature
	return nil
}

// signVerifierAssignment fills the signed binding and builder_service_signature of a
// VerifierAssignmentNotifyV1, signed like signOpenVerify.
func (m builderMessages) signVerifierAssignment(ctx context.Context, msg *nexusv1.VerifierAssignmentNotifyV1, recordHeight uint64) error {
	if m.coord == nil {
		return errBuilderMessageUnsigned
	}
	binding, err := m.coord.builderBinding(ctx, recordHeight)
	if err != nil {
		return err
	}
	msg.Binding, msg.BuilderServiceSignature = binding, nil
	signature, err := m.coord.signBuilderMessage("nexus.v1.VerifierAssignmentNotifyV1", msg)
	if err != nil {
		return err
	}
	msg.BuilderServiceSignature = signature
	return nil
}

// broadcast sends one frame to every connected Cortex stream. The stream layer owns stream_nonce and
// cursor; the frame carries only the signed business message.
func (m builderMessages) broadcast(ctx context.Context, frame *nexusv1.DispatchStreamFrameV1) error {
	if m.coord == nil || m.coord.cortex == nil {
		return fmt.Errorf("cortex link is not configured")
	}
	return m.coord.cortex.Broadcast(ctx, frame)
}

// builderBinding is the signed identity of a Builder message for a task the chain recorded at
// recordHeight: the Task chain, this Builder's operator address and the authorization nonce of its
// current service key. While a replacement key is pending, a task recorded at or after the block
// before its registration (or at an unknown height) gets no message from this Builder
// (errRotationPendingTask); older tasks keep the current nonce. No other nonce is ever signed.
func (c *Coordinator) builderBinding(ctx context.Context, recordHeight uint64) (*nexusv1.BuilderMessageBindingV1, error) {
	if c.serviceSigner == nil || c.serviceKeys == nil || c.active.self == "" {
		return nil, errBuilderMessageUnsigned
	}
	nonce, pending, err := c.selfAuthorizationNonce(ctx)
	if err != nil {
		return nil, err
	}
	if pending != nil && (recordHeight == 0 || recordHeight+1 >= pending.RegisteredHeight) {
		return nil, fmt.Errorf("%w: recorded at %d, rotation registered at %d", errRotationPendingTask, recordHeight, pending.RegisteredHeight)
	}
	return &nexusv1.BuilderMessageBindingV1{
		ChainId: c.chainID, BuilderAddress: c.active.self, ServiceAuthorizationNonce: nonce,
	}, nil
}

// signBuilderMessage signs the wire signing digest of a message registered in the wire dispatch
// tables with the current service key.
func (c *Coordinator) signBuilderMessage(name string, msg proto.Message) ([]byte, error) {
	digest, err := builderMessageDigest(name, msg)
	if err != nil {
		return nil, err
	}
	return c.serviceSigner.SignDigest(digest)
}

// builderMessageDigest is the wire signing digest of a Builder message: its deterministic encoding
// projected by dispatch.SigningDigest, which leaves the signature field out.
func builderMessageDigest(name string, msg proto.Message) ([32]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode %s: %w", name, err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s signing digest: %w", name, err)
	}
	return digest, nil
}

// selfAuthorizationNonce reads the authorization nonce of this node's current Builder binding, and
// its pending replacement if any, and asserts that the on-chain public key is this local private
// key's: a message signed by any other key can never verify at the receiver.
func (c *Coordinator) selfAuthorizationNonce(ctx context.Context) (uint64, *chaincli.PendingServiceKeyRotation, error) {
	readAt := time.Now()
	publicKey, state, err := servicekey.Current(
		ctx, c.serviceKeys, c.addressPrefix, servicekey.ParticipantBuilder, c.active.self)
	stagetiming.From(ctx).Since("chain_service_key", readAt)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", errBuilderMessageUnsigned, err)
	}
	if !bytes.Equal(publicKey, c.serviceSigner.PubKeyCompressed()) {
		return 0, nil, fmt.Errorf("%w: on-chain service key does not match the local signer", errBuilderMessageUnsigned)
	}
	if state.AuthorizationNonce == 0 {
		return 0, nil, fmt.Errorf("%w: service binding has no authorization nonce", errBuilderMessageUnsigned)
	}
	return state.AuthorizationNonce, state.PendingRotation, nil
}

// HandleVerifierHandraise takes a Verifier handraise that arrived on a Cortex dispatch stream. The
// stream layer has already authenticated cortexOperator; the handraise must name that operator as
// its member. The handraise itself is checked like any other (validVerifierHandraise) and its
// Cortex signature is checked by the chain when it is proposed.
func (c *Coordinator) HandleVerifierHandraise(_ context.Context, cortexOperator string, m *taskv1.VerifierHandraiseV1) error {
	if m == nil {
		return fmt.Errorf("%w: verifier handraise is required", types.ErrInvalidArgument)
	}
	if cortexOperator == "" || m.GetMember().GetOperatorAddress() != cortexOperator {
		return fmt.Errorf("%w: verifier handraise member is not the stream's Cortex", types.ErrUnauthorized)
	}
	fsm, err := c.fsmForTaskID(m.GetTaskId())
	if err != nil {
		return err
	}
	fsm.onVerifierHandraise(m)
	return nil
}

// HandleVerifyResultSubmitted takes a selected Verifier's notice that it put its commit or result on
// chain. The notice is a wake-up, not a fact: it only makes this Builder read the task from the
// chain now instead of at the next periodic reconciliation. It is taken while the task is Assigned
// too, since the notice can arrive before this Builder has seen the assignment.
func (c *Coordinator) HandleVerifyResultSubmitted(_ context.Context, cortexOperator string, m *nexusv1.VerifyResultSubmittedNoticeV1) error {
	if m == nil {
		return fmt.Errorf("%w: verify result notice is required", types.ErrInvalidArgument)
	}
	if cortexOperator == "" || m.GetOperatorAddress() != cortexOperator {
		return fmt.Errorf("%w: verify result notice operator is not the stream's Cortex", types.ErrUnauthorized)
	}
	if uint64(m.GetVerifyRound()) != nodecontract.SupportedVerifyRoundV1 {
		return fmt.Errorf("%w: unsupported verify round %d", types.ErrInvalidArgument, m.GetVerifyRound())
	}
	fsm, err := c.fsmForTaskID(m.GetTaskId())
	if err != nil {
		return err
	}
	fsm.mu.Lock()
	taskHash := fsm.taskHashBytes()
	selected := containsString(fsm.verifiers, cortexOperator)
	state := fsm.state
	fsm.mu.Unlock()
	switch {
	case !bytes.Equal(m.GetTaskHash(), taskHash):
		return fmt.Errorf("%w: task_hash does not match this task", types.ErrInvalidArgument)
	case state != types.Assigned && state != types.Verifying:
		return fmt.Errorf("%w: task is not in the verify stage (state %s)", types.ErrFailedPrecondition, state)
	case state == types.Verifying && !selected:
		// Only once Verifying does this Builder know the selected set; before that the notice
		// may be the first sign that the assignment exists.
		return fmt.Errorf("%w: verifier is not selected for this task", types.ErrUnauthorized)
	}
	c.requestTaskReconcile(fsm.sessionID, fsm.taskID, 0, "verify result submitted notice")
	return nil
}

// fsmForTaskID finds the live task of a raw task_id. Stream messages carry only the on-chain
// task_id; the session comes from the index written with the task snapshot.
func (c *Coordinator) fsmForTaskID(raw []byte) (*taskFSM, error) {
	if len(raw) != hash32Len {
		return nil, fmt.Errorf("%w: task_id must be 32 bytes", types.ErrInvalidArgument)
	}
	taskID := hex.EncodeToString(raw)
	sessionID, err := c.SessionForTask(context.Background(), taskID)
	if err != nil {
		return nil, err
	}
	fsm, ok := c.getFSM(sessionID, taskID)
	if !ok {
		return nil, ErrTaskNotFound
	}
	return fsm, nil
}

// retireVerifierMessages tells the CortexLink that a closed task has left its verification round,
// so its OpenVerifyV1 and VerifierAssignmentNotifyV1 are no longer given to streams that connect
// later.
func (c *Coordinator) retireVerifierMessages(taskID string) {
	raw, err := hex.DecodeString(taskID)
	if c.cortex == nil || err != nil || len(raw) != hash32Len {
		return
	}
	c.cortex.Retire(raw, uint32(nodecontract.SupportedVerifyRoundV1))
}
