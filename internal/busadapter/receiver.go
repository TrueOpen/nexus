package busadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// ErrAuthorityUnavailable means "could not be checked" rather than "determined invalid": when the on-chain
// query itself fails, the receiver must fail closed and let JetStream redeliver (Nak) instead of acking the
// message away as a bad one. Same semantics as the existing coordinator errBusEnvelopeAuthority.
var ErrAuthorityUnavailable = errors.New("bus authority unavailable")

// payloadMessageForType returns the empty proto message for a payload_type (the frozen mapping is
// documented in the gen/bus/v1 BusPayloadType comments). On-chain payloads reuse the frozen
// task.v1 messages rather than declaring a second copy.
func payloadMessageForType(payloadType int32) (proto.Message, bool) {
	switch payloadType {
	case bus.PayloadTypeOrderBroadcastV1:
		return &busv1.OrderBroadcastV1{}, true
	case bus.PayloadTypeWorkerHandraiseV1:
		return &taskv1.WorkerHandraiseV1{}, true
	case bus.PayloadTypeWorkerAssignmentNotifyV1:
		return &busv1.WorkerAssignmentNotifyV1{}, true
	case bus.PayloadTypeOutputAvailableV1:
		return &busv1.OutputAvailableV1{}, true
	case bus.PayloadTypeOpenVerifyV1:
		return &busv1.OpenVerifyV1{}, true
	case bus.PayloadTypeVerifierHandraiseV1:
		return &taskv1.VerifierHandraiseV1{}, true
	case bus.PayloadTypeVerifierAssignmentNotifyV1:
		return &busv1.VerifierAssignmentNotifyV1{}, true
	case bus.PayloadTypeVerifyResultV1:
		return &taskv1.ResultReceiptV2{}, true
	default:
		return nil, false
	}
}

// BindingLookup queries the chain for the sender's current service binding. When the query infrastructure
// fails, the returned error should satisfy errors.Is(err, ErrAuthorityUnavailable) (or be wrapped as such
// by the caller) so it can be distinguished from "the binding is invalid".
type BindingLookup func(ctx context.Context, participantType int32, operatorAddress string) (bus.KeyBinding, error)

// ReceiverConfig is every local fact needed to verify one inbound envelope.
type ReceiverConfig struct {
	ChainID       string
	LookupBinding BindingLookup
	Replay        bus.ReplayStore
	// MaxEnvelopeBytes is the local early-rejection bound, only there to stop oversized messages before
	// decoding. Since wire v0.4.1 bus.Verify checks against the protocol constant
	// bus.MaxEnvelopeBytes itself and no longer accepts a caller-supplied value, so this must equal
	// that constant: a looser local value is the same as no check, and a stricter one would reject
	// envelopes the protocol allows.
	MaxEnvelopeBytes int
	// ReplaySafetyMarginMS is how long a replay tombstone is kept after expires_at.
	ReplaySafetyMarginMS uint64
	// Now returns the current Unix milliseconds; injected by tests.
	Now func() uint64
}

// Inbound is one inbound message that passed every verification step.
type Inbound struct {
	Envelope *busv1.BusEnvelopeV1
	// Payload is the concrete message decoded via the frozen mapping, only after the signature verified.
	Payload proto.Message
}

// Receiver decodes inbound envelopes and verifies them in the frozen 7-step order of wire bus.
type Receiver struct {
	cfg ReceiverConfig
}

// NewReceiver constructs the receiver.
func NewReceiver(cfg ReceiverConfig) *Receiver {
	return &Receiver{cfg: cfg}
}

// Receive handles one inbound frame. Disposition rules when it returns an error: infrastructure failures
// (ErrAuthorityUnavailable, bus.ErrStoreFailure) -> Nak and await redelivery; everything else -> ack
// and discard.
// A redelivery with the same key and the same digest never reaches here as bus.ErrReplay: that is a
// legitimate retry and Verify lets it through.
func (r *Receiver) Receive(ctx context.Context, subject string, data []byte) (*Inbound, error) {
	if r.cfg.MaxEnvelopeBytes > 0 && len(data) > r.cfg.MaxEnvelopeBytes {
		return nil, fmt.Errorf("bus receive: %w: envelope exceeds %d bytes",
			bus.ErrStructure, r.cfg.MaxEnvelopeBytes)
	}
	var envelope busv1.BusEnvelopeV1
	if err := proto.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("bus receive: %w: decode envelope: %v", bus.ErrStructure, err)
	}
	if unknown := envelope.ProtoReflect().GetUnknown(); len(unknown) > 0 {
		// The frozen contract allows no unknown fields: an extra field means the peer is sending against a different field table.
		return nil, fmt.Errorf("bus receive: %w: unknown envelope fields", bus.ErrStructure)
	}
	fields := bus.Fields{
		SchemaVersion:             envelope.GetSchemaVersion(),
		ChainID:                   envelope.GetChainId(),
		Subject:                   envelope.GetSubject(),
		Kind:                      int32(envelope.GetKind()),
		SenderParticipantType:     int32(envelope.GetSenderParticipantType()),
		SenderOperatorAddress:     envelope.GetSenderOperatorAddress(),
		ServiceAuthorizationNonce: envelope.GetServiceAuthorizationNonce(),
		MessageID:                 envelope.GetMessageId(),
		Nonce:                     envelope.GetNonce(),
		IssuedAtUnixMS:            envelope.GetIssuedAtUnixMs(),
		ExpiresAtUnixMS:           envelope.GetExpiresAtUnixMs(),
		PayloadType:               int32(envelope.GetPayloadType()),
		PayloadDigest:             envelope.GetPayloadDigest(),
	}
	// The wire KeyLookup takes no ctx and does not distinguish error classes; the closure carries ctx in and
	// records chain lookup failures on the side, so a verification failure can be reclassified as a Nak afterwards.
	var authorityErr error
	lookup := func(participantType int32, operator string) (bus.KeyBinding, error) {
		binding, err := r.cfg.LookupBinding(ctx, participantType, operator)
		if err != nil {
			authorityErr = err
		}
		return binding, err
	}
	err := bus.Verify(fields, envelope.GetPayload(), envelope.GetServiceSignature(), bus.VerifyOptions{
		ChainID:              r.cfg.ChainID,
		Subject:              subject,
		NowUnixMS:            r.cfg.Now(),
		RawSize:              len(data),
		LookupKey:            lookup,
		Replay:               r.cfg.Replay,
		ReplaySafetyMarginMS: r.cfg.ReplaySafetyMarginMS,
	})
	if err != nil {
		if errors.Is(err, bus.ErrKeyBinding) && authorityErr != nil &&
			errors.Is(authorityErr, ErrAuthorityUnavailable) {
			return nil, fmt.Errorf("bus receive: %w: %v", ErrAuthorityUnavailable, err)
		}
		return nil, fmt.Errorf("bus receive: %w", err)
	}
	// Decode the payload only after the signature verified (contract: decode only after verify).
	payload, ok := payloadMessageForType(fields.PayloadType)
	if !ok {
		return nil, fmt.Errorf("bus receive: %w: unknown payload type %d",
			bus.ErrRouting, fields.PayloadType)
	}
	if err := proto.Unmarshal(envelope.GetPayload(), payload); err != nil {
		return nil, fmt.Errorf("bus receive: %w: decode payload: %v", bus.ErrPayload, err)
	}
	if unknown := payload.ProtoReflect().GetUnknown(); len(unknown) > 0 {
		// Only top-level unknown fields are checked; unknown fields in nested messages (for example inside
		// OrderBroadcastV1.signed_order) are silently retained by protobuf. The signature binds the original
		// payload bytes and the keeper recomputes on-chain facts over the frozen shape, so deeply nested
		// unknown fields cannot change any verified value.
		return nil, fmt.Errorf("bus receive: %w: unknown payload fields", bus.ErrPayload)
	}
	return &Inbound{Envelope: &envelope, Payload: payload}, nil
}
