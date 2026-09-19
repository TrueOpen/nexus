package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/busadapter"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	envelopeTTL = 30 * time.Second

	// mockBech32Prefix is the prefix the mock uses to derive service addresses.
	mockBech32Prefix = "trueopen"

	// mockServiceAuthorizationNonce is the current binding nonce the mock reports for itself
	// (envelope field 7). A real Nexus compares it byte for byte against the nonce of the on-chain binding,
	// so unless the mock worker's service key is registered on chain with this nonce,
	// Nexus rejects these frames at verification step 5 -- that is fail-closed, not a bug.
	mockServiceAuthorizationNonce uint64 = 1
)

// ordersWildcard is the wildcard ORDER_BROADCAST subject the mock subscribes to (contract §5.1).
const ordersWildcard = subjectTaskOpenPrefix + "*"

const subjectTaskOpenPrefix = "trueopen.task.open."

// publishMessage is a captured (subject, wire bytes) record used by tests.
type publishMessage struct {
	Subject string
	Data    []byte
}

type responderConfig struct {
	WorkerCount   int
	ResponseDelay time.Duration
	Now           func() time.Time
}

type orderResponder struct {
	config  responderConfig
	publish func(subject string, data []byte) error

	mu   sync.Mutex
	seen map[string]struct{}
}

func newOrderResponder(config responderConfig, publish func(subject string, data []byte) error) *orderResponder {
	if config.Now == nil {
		config.Now = time.Now
	}
	return &orderResponder{
		config:  config,
		publish: publish,
		seen:    make(map[string]struct{}),
	}
}

// publishBusFunc adapts the mock's bare publish function to busadapter.PublishBus.
// The mock does not connect to JetStream, so both tiers go through the same core publish.
type publishBusFunc func(subject string, data []byte) error

func (f publishBusFunc) Publish(subject string, data []byte) error { return f(subject, data) }
func (f publishBusFunc) JSPublish(subject string, data []byte, _ string) error {
	return f(subject, data)
}

func (r *orderResponder) Handle(ctx context.Context, subject string, data []byte) error {
	envelope, order, err := decodeOrderBroadcast(subject, data, r.config.Now())
	if err != nil {
		return err
	}
	taskIDHex, taskHashHex, err := orderIdentity(order)
	if err != nil {
		return err
	}

	key := taskIDHex
	r.mu.Lock()
	if _, exists := r.seen[key]; exists {
		r.mu.Unlock()
		return nil
	}
	r.seen[key] = struct{}{}
	r.mu.Unlock()

	if err := waitForResponse(ctx, r.config.ResponseDelay); err != nil {
		r.forget(key)
		return err
	}
	if err := r.publishWorkerHandraises(ctx, envelope, order, taskIDHex, taskHashHex); err != nil {
		r.forget(key)
		return err
	}
	return nil
}

func (r *orderResponder) forget(key string) {
	r.mu.Lock()
	delete(r.seen, key)
	r.mu.Unlock()
}

func waitForResponse(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// decodeOrderBroadcast decodes an inbound ORDER_BROADCAST frame and checks its routing and freshness.
//
// It does **not** verify signatures: the mock has no on-chain QueryCurrentServiceKey and cannot obtain the Builder's current
// binding. A real Cortex must run all 7 steps of wire bus.Verify; do not treat this as a reference implementation.
// The payload digest is still checked -- it needs no consensus fact, and skipping it would drop half the contract.
func decodeOrderBroadcast(
	subject string, data []byte, now time.Time,
) (*busv1.BusEnvelopeV1, *taskv1.TaskOrderV2, error) {
	var envelope busv1.BusEnvelopeV1
	if err := proto.Unmarshal(data, &envelope); err != nil {
		return nil, nil, fmt.Errorf("decode order envelope: %w", err)
	}
	switch {
	case envelope.GetSchemaVersion() != 1:
		return nil, nil, fmt.Errorf("unsupported envelope schema_version %d", envelope.GetSchemaVersion())
	case envelope.GetKind() != busv1.BusMessageKind_BUS_MESSAGE_KIND_ORDER_BROADCAST:
		return nil, nil, fmt.Errorf("unexpected envelope kind %s", envelope.GetKind())
	case envelope.GetSenderParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		return nil, nil, fmt.Errorf("sender %s may not broadcast orders", envelope.GetSenderParticipantType())
	case envelope.GetPayloadType() != busv1.BusPayloadType_BUS_PAYLOAD_TYPE_ORDER_BROADCAST_V1:
		return nil, nil, fmt.Errorf("unexpected payload type %s", envelope.GetPayloadType())
	case subject != envelope.GetSubject():
		return nil, nil, fmt.Errorf("order subject mismatch: actual=%q envelope=%q", subject, envelope.GetSubject())
	case envelope.GetExpiresAtUnixMs() > 0 && uint64(now.UnixMilli()) > envelope.GetExpiresAtUnixMs():
		return nil, nil, fmt.Errorf("order envelope expired at %d", envelope.GetExpiresAtUnixMs())
	}
	digest := bus.PayloadDigest(envelope.GetPayload())
	if hex.EncodeToString(digest[:]) != hex.EncodeToString(envelope.GetPayloadDigest()) {
		return nil, nil, fmt.Errorf("order payload digest mismatch")
	}
	var broadcast busv1.OrderBroadcastV1
	if err := proto.Unmarshal(envelope.GetPayload(), &broadcast); err != nil {
		return nil, nil, fmt.Errorf("decode order payload: %w", err)
	}
	order := broadcast.GetSignedOrder().GetOrder()
	if order == nil {
		return nil, nil, fmt.Errorf("order broadcast has no signed order")
	}
	if wantSubject := msgbus.SubjectTaskOpen(order.GetModelId()); subject != wantSubject {
		return nil, nil, fmt.Errorf("order subject mismatch: actual=%q model=%q", subject, wantSubject)
	}
	return &envelope, order, nil
}

// orderIdentity recomputes task_id / task_hash from the signed order as the contract requires (OrderBroadcastV1 comments):
// the hand-raiser may not invent its own and must carry back the recomputed values.
func orderIdentity(order *taskv1.TaskOrderV2) (taskIDHex, taskHashHex string, err error) {
	taskID, err := nodecontract.DeriveTaskIDFromRawSession(order.GetSessionId(), order.GetOrderSequence())
	if err != nil {
		return "", "", fmt.Errorf("derive task_id: %w", err)
	}
	taskHash, err := nodecontract.TaskOrderHashV2(order)
	if err != nil {
		return "", "", fmt.Errorf("derive task_hash: %w", err)
	}
	return hex.EncodeToString(taskID[:]), hex.EncodeToString(taskHash[:]), nil
}

// mockServiceSigner gives each mock worker a deterministically derived secp256k1 service key.
// It is the mock's **test** key and not any real identity; a production Cortex uses the current service key
// registered on chain.
func mockServiceSigner(index int) (signer.Signer, error) {
	seed := sha256.Sum256([]byte(fmt.Sprintf("mock-cortex-service-key|%d", index)))
	return signer.NewFromBytes(seed[:], mockBech32Prefix)
}

// publishWorkerHandraises assembles and publishes one fully signed TRUEOPEN_BUS_ENVELOPE_V2 frame per mock worker,
// whose payload is the frozen contract's task.v1.WorkerHandraiseV1.
// chain_id is carried over from the inbound ORDER_BROADCAST: the mock may not switch to another chain.
func (r *orderResponder) publishWorkerHandraises(
	ctx context.Context, inbound *busv1.BusEnvelopeV1, order *taskv1.TaskOrderV2,
	taskIDHex, taskHashHex string,
) error {
	if r.config.WorkerCount < 3 {
		return fmt.Errorf("worker count must be at least 3")
	}
	taskID, err := hex.DecodeString(taskIDHex)
	if err != nil {
		return err
	}
	taskHash, err := hex.DecodeString(taskHashHex)
	if err != nil {
		return err
	}
	// candidate_pool_snapshot_id is a Hash32 in the frozen contract; the mock derives one deterministically.
	snapshotID := hashBytes("candidate-pool-snapshot", taskIDHex)
	subject := msgbus.SubjectWorkerHandraiseV1(taskIDHex)
	now := uint64(r.config.Now().UnixMilli())
	profileVersion := order.GetProfileVersion()
	if profileVersion == 0 {
		profileVersion = 1
	}
	// A hand-raise's expiry_height must not be later than the order's expiry height (TaskOrderV2 field 19).
	expiryHeight := order.GetOrderExpireHeight()
	if expiryHeight == 0 {
		return fmt.Errorf("order is missing order_expire_height")
	}

	for slot := 0; slot < r.config.WorkerCount; slot++ {
		serviceSigner, err := mockServiceSigner(slot)
		if err != nil {
			return fmt.Errorf("mock service key %d: %w", slot, err)
		}
		candidate := serviceSigner.Address()
		handraise := &taskv1.WorkerHandraiseV1{
			SchemaVersion:  1,
			ChainId:        inbound.GetChainId(),
			TaskId:         taskID,
			TaskHash:       taskHash,
			ModelId:        order.GetModelId(),
			ProfileVersion: profileVersion,
			Member: &taskv1.CandidateMemberRefV1{
				CandidatePoolSnapshotId: snapshotID,
				Slot:                    uint32(slot),
				SlotVersion:             1,
				OperatorAddress:         candidate,
			},
			Duty:                      sharedv1.Duty_DUTY_WORKER,
			ServiceAuthorizationNonce: mockServiceAuthorizationNonce,
			ExpiryHeight:              expiryHeight,
			// service_signature is the H_FIELDS digest signature the Keeper verifies; the mock supplies a
			// deterministic 64-byte placeholder: Nexus only length-checks it and passes it through, verification happens in the Keeper.
			ServiceSignature: append(
				hashBytes("service-signature", taskIDHex, candidate),
				hashBytes("service-signature-hi", taskIDHex, candidate)...),
		}
		publisher := busadapter.NewPublisher(busadapter.PublisherConfig{
			ChainID:         inbound.GetChainId(),
			OperatorAddress: candidate,
			ParticipantType: bus.ParticipantCortex,
			Signer:          serviceSigner,
			AuthorizationNonce: func(context.Context) (uint64, error) {
				return mockServiceAuthorizationNonce, nil
			},
			Outbox: busadapter.NewOutbox(kv.NewMemStore()),
			Bus:    publishBusFunc(r.publish),
			TTLMS:  uint64(envelopeTTL.Milliseconds()),
			Now:    func() uint64 { return now },
		})
		if _, err := publisher.Publish(ctx, subject, bus.KindWorkerHandraise,
			handraise, busadapter.TierCore); err != nil {
			return fmt.Errorf("publish %s: %w", subject, err)
		}
	}
	return nil
}

func hashBytes(parts ...string) []byte {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return digest[:]
}
