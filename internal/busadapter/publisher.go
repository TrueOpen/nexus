package busadapter

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	"github.com/TrueOpen/nexus/internal/signer"
)

// PublishBus is the minimum bus capability the publisher needs (a subset of msgbus.Bus).
// The Core tier is best effort; in the JetStream tier the message_id doubles as Nats-Msg-Id and the broker deduplicates.
type PublishBus interface {
	Publish(subject string, data []byte) error
	JSPublish(subject string, data []byte, msgID string) error
}

// Tier is the message tier; its values match the tier column of Interface & Topic Catalogue §5.1.
type Tier uint8

const (
	// TierCore is best effort / lowest latency (hand-raise solicitation messages).
	TierCore Tier = 1
	// TierJetStream is at-least-once + broker dedup (notification messages).
	TierJetStream Tier = 2
)

// PublisherConfig is every local fact needed to assemble one outbound envelope.
type PublisherConfig struct {
	ChainID         string
	OperatorAddress string // field 6: this node's operator address
	ParticipantType int32  // bus.Participant*, always Builder for Nexus
	// Signer is the current service key. It SHA-256s the message before signing, so calling Sign on
	// SigningPreimage yields exactly "a direct signature over the H_FIELDS digest".
	Signer signer.Signer
	// AuthorizationNonce queries the chain for the authorization nonce of the current service binding
	// (field 7). A failed query must return an error and must not fall back to a stale cached value.
	AuthorizationNonce func(ctx context.Context) (uint64, error)
	Outbox             *Outbox
	Bus                PublishBus
	// TTLMS is expires_at - issued_at (milliseconds).
	TTLMS uint64
	// Now returns the current Unix milliseconds; injected by tests.
	Now func() uint64
}

// Publisher assembles, signs and publishes BusEnvelopeV1 (the proto version).
// The order is mandatory: serialize the payload exactly once -> sign -> persist to the outbox -> publish.
// A retry or a resend after a restart may only take the original bytes from the outbox (Republish), never
// reassemble and re-sign them.
type Publisher struct {
	cfg PublisherConfig
}

// NewPublisher constructs the publisher.
func NewPublisher(cfg PublisherConfig) *Publisher {
	return &Publisher{cfg: cfg}
}

// newEnvelopeIdentity generates a UUIDv7 message_id and a 32-byte CSPRNG nonce.
// Contract: generated once and reused on retry (reuse is the outbox's job; this function only covers the first time).
func newEnvelopeIdentity(unixMS uint64) (string, []byte, error) {
	var uuid [16]byte
	binary.BigEndian.PutUint64(uuid[:8], unixMS<<16)
	if _, err := rand.Read(uuid[6:]); err != nil {
		return "", nil, fmt.Errorf("generate message_id: %w", err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x70 // version 7
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // RFC 4122 variant
	nonce := make([]byte, bus.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("generate nonce: %w", err)
	}
	encoded := hex.EncodeToString(uuid[:])
	messageID := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:]
	return messageID, nonce, nil
}

// Publish publishes one application message: kind is one of bus.Kind*, and payload is the proto message
// frozen against that kind (the mapping is documented in the gen/bus/v1 BusPayloadType comments).
// It returns the message_id (which is also the JetStream Nats-Msg-Id).
//
// When publishing fails the outbox entry is kept: the caller simply calls Republish later to resend the
// bytes verbatim, which is exactly why the outbox exists. Do not delete the entry on the failure path or
// run through this function again.
func (p *Publisher) Publish(
	ctx context.Context, subject string, kind int32, payload proto.Message, tier Tier,
) (string, error) {
	if tier != TierCore && tier != TierJetStream {
		return "", fmt.Errorf("bus publish: unknown tier %d", tier)
	}
	payloadType, ok := bus.PayloadTypeForKind(kind)
	if !ok {
		return "", fmt.Errorf("bus publish: unknown kind %d", kind)
	}
	expected, ok := payloadMessageForType(payloadType)
	if !ok || proto.MessageName(expected) != proto.MessageName(payload) {
		return "", fmt.Errorf("bus publish: payload %T does not match kind %d", payload, kind)
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bus publish: marshal payload: %w", err)
	}
	if len(payloadBytes) == 0 {
		return "", fmt.Errorf("bus publish: empty payload")
	}
	authorizationNonce, err := p.cfg.AuthorizationNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("bus publish: %w: %v", ErrAuthorityUnavailable, err)
	}
	now := p.cfg.Now()
	messageID, nonce, err := newEnvelopeIdentity(now)
	if err != nil {
		return "", fmt.Errorf("bus publish: %w", err)
	}
	digest := bus.PayloadDigest(payloadBytes)
	fields := bus.Fields{
		SchemaVersion:             1,
		ChainID:                   p.cfg.ChainID,
		Subject:                   subject,
		Kind:                      kind,
		SenderParticipantType:     p.cfg.ParticipantType,
		SenderOperatorAddress:     p.cfg.OperatorAddress,
		ServiceAuthorizationNonce: authorizationNonce,
		MessageID:                 messageID,
		Nonce:                     nonce,
		IssuedAtUnixMS:            now,
		ExpiresAtUnixMS:           now + p.cfg.TTLMS,
		PayloadType:               payloadType,
		PayloadDigest:             digest[:],
	}
	preimage, err := bus.SigningPreimage(fields)
	if err != nil {
		return "", fmt.Errorf("bus publish: %w", err)
	}
	// signer.Sign SHA-256s internally: sha256(preimage) is the SigningDigest, so the result is precisely a
	// direct signature over the H_FIELDS digest (64-byte compact low-S).
	signature, err := p.cfg.Signer.Sign(preimage)
	if err != nil {
		return "", fmt.Errorf("bus publish: sign: %w", err)
	}
	if len(signature) != bus.SignatureSize {
		return "", fmt.Errorf("bus publish: signature is %d bytes, want %d",
			len(signature), bus.SignatureSize)
	}
	envelope := &busv1.BusEnvelopeV1{
		SchemaVersion:             fields.SchemaVersion,
		ChainId:                   fields.ChainID,
		Subject:                   fields.Subject,
		Kind:                      busv1.BusMessageKind(kind),
		SenderParticipantType:     sharedv1.ParticipantType(fields.SenderParticipantType),
		SenderOperatorAddress:     fields.SenderOperatorAddress,
		ServiceAuthorizationNonce: fields.ServiceAuthorizationNonce,
		MessageId:                 fields.MessageID,
		Nonce:                     fields.Nonce,
		IssuedAtUnixMs:            fields.IssuedAtUnixMS,
		ExpiresAtUnixMs:           fields.ExpiresAtUnixMS,
		PayloadType:               busv1.BusPayloadType(payloadType),
		Payload:                   payloadBytes,
		PayloadDigest:             fields.PayloadDigest,
		ServiceSignature:          signature,
	}
	wire, err := proto.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("bus publish: marshal envelope: %w", err)
	}
	if err := p.cfg.Outbox.Put(OutboxEntry{
		MessageID:       messageID,
		Subject:         subject,
		Tier:            tier,
		Wire:            wire,
		ExpiresAtUnixMS: fields.ExpiresAtUnixMS,
	}); err != nil {
		return "", fmt.Errorf("bus publish: %w", err)
	}
	if err := p.send(subject, wire, messageID, tier); err != nil {
		return "", fmt.Errorf("bus publish: %w", err)
	}
	return messageID, nil
}

func (p *Publisher) send(subject string, wire []byte, messageID string, tier Tier) error {
	if tier == TierCore {
		return p.cfg.Bus.Publish(subject, wire)
	}
	return p.cfg.Bus.JSPublish(subject, wire, messageID)
}

// Republish resends every unexpired outbox entry verbatim (the recovery path after a process restart or a
// failed publish). Neither the bytes nor the message_id change: the receiver treats the same key with the
// same digest as a legitimate retry.
//
// Each round attempts every entry and returns the aggregated failures: one persistently failing entry (for
// example while JetStream has not recovered yet) must not block entries on other subjects or tiers in the
// same batch, or those would be dropped within the 30-second TTL without ever being attempted.
func (p *Publisher) Republish(ctx context.Context) error {
	_ = ctx
	pending, err := p.cfg.Outbox.Pending(p.cfg.Now())
	if err != nil {
		return fmt.Errorf("bus republish: %w", err)
	}
	var failures []error
	for _, entry := range pending {
		if err := p.send(entry.Subject, entry.Wire, entry.MessageID, entry.Tier); err != nil {
			failures = append(failures, fmt.Errorf("bus republish %s: %w", entry.MessageID, err))
		}
	}
	return errors.Join(failures...)
}
