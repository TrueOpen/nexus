package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/nexus/gen/bus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// testSignedOrder has the same shape as the §5.13 fixture in coordinator submitter_test: a complete TaskOrderV2
// that TaskOrderHashV2 can derive from.
func testSignedOrder() *taskv1.SignedOrderV2 {
	return &taskv1.SignedOrderV2{
		Order: &taskv1.TaskOrderV2{
			SchemaVersion: 2, ChainId: "trueopen-localnet",
			UserAddress: "trueopen1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rsxm9a",
			SessionId:   bytes.Repeat([]byte{0x11}, 32), OrderSequence: 7,
			ModelId: "model-1", ProfileVersion: 2,
			TaskType:  sharedv1.TaskType_TASK_TYPE_TEXT_GENERATION,
			InputHash: bytes.Repeat([]byte{0x22}, 32), InputSizeBytes: 512,
			InputBucket: 1, OutputBudgetBucket: 2,
			GenerationParams: &taskv1.GenerationParamsV1{
				GenerationParamsSchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
				DecodingParams: &taskv1.DecodingParamsV1{},
			},
			PriceBid:              &sharedv1.Amount{AtomicUnits: "4"},
			MaxFee:                &sharedv1.Amount{AtomicUnits: "100"},
			AssignmentPriorityFee: &sharedv1.Amount{AtomicUnits: "0"},
			TxFeeReserve:          &sharedv1.Amount{AtomicUnits: "5"},
			EarliestSubmitHeight:  100, OrderExpireHeight: 1000,
			DeadlinePolicy: &taskv1.DeadlinePolicyV1{
				LatencyClass: taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD,
			},
			TimeoutBucketVersion:   4,
			SessionAnchorHeight:    90,
			SessionAnchorBlockHash: bytes.Repeat([]byte{0x33}, 32),
			BuilderSetId:           "term-1",
			BuilderSetHash:         bytes.Repeat([]byte{0x44}, 32),
		},
		SignatureScheme: "eip712",
		UserSignature:   append(bytes.Repeat([]byte{0x55}, 64), 27),
	}
}

// testOrderBroadcastFrame builds a structurally valid ORDER_BROADCAST frame (the signature is a placeholder:
// the mock does not verify signatures, see the note on decodeOrderBroadcast; the payload digest is real).
func testOrderBroadcastFrame(t *testing.T, signedOrder *taskv1.SignedOrderV2, subject string) []byte {
	t.Helper()
	payload, err := proto.Marshal(&busv1.OrderBroadcastV1{SignedOrder: signedOrder})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	digest := bus.PayloadDigest(payload)
	envelope := &busv1.BusEnvelopeV1{
		SchemaVersion:             1,
		ChainId:                   "trueopen-localnet",
		Subject:                   subject,
		Kind:                      busv1.BusMessageKind_BUS_MESSAGE_KIND_ORDER_BROADCAST,
		SenderParticipantType:     sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
		SenderOperatorAddress:     "trueopen1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rsxm9a",
		ServiceAuthorizationNonce: 23,
		MessageId:                 "01a01a8e-6de8-74d5-aa3b-08196e7f4c5d",
		Nonce:                     bytes.Repeat([]byte{0x11}, bus.NonceSize),
		IssuedAtUnixMs:            1_786_060_800_000,
		ExpiresAtUnixMs:           1_786_060_830_000,
		PayloadType:               busv1.BusPayloadType_BUS_PAYLOAD_TYPE_ORDER_BROADCAST_V1,
		Payload:                   payload,
		PayloadDigest:             digest[:],
		ServiceSignature:          bytes.Repeat([]byte{0x22}, bus.SignatureSize),
	}
	data, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return data
}

// TestPublishWorkerHandraisesMatchesNexusWireContract checks that the WORKER_HANDRAISE the mock emits is a
// conforming TRUEOPEN_BUS_ENVELOPE_V2 frame: all fields present, the frozen kind/payload_type pairing holds,
// task_id/task_hash are recomputed from the signed order, and the envelope signature is produced by that
// worker's service key over the V2 digest.
func TestPublishWorkerHandraisesMatchesNexusWireContract(t *testing.T) {
	now := time.UnixMilli(1_786_060_800_000)
	signedOrder := testSignedOrder()
	subject := msgbus.SubjectTaskOpen(signedOrder.GetOrder().GetModelId())
	data := testOrderBroadcastFrame(t, signedOrder, subject)

	var published []publishMessage
	responder := newOrderResponder(responderConfig{
		WorkerCount: 3, Now: func() time.Time { return now },
	}, func(subject string, data []byte) error {
		published = append(published, publishMessage{Subject: subject, Data: append([]byte(nil), data...)})
		return nil
	})
	if err := responder.Handle(context.Background(), subject, data); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(published) != 3 {
		t.Fatalf("messages=%d, want 3", len(published))
	}

	wantTaskID, err := nodecontract.DeriveTaskIDFromRawSession(
		signedOrder.GetOrder().GetSessionId(), signedOrder.GetOrder().GetOrderSequence())
	if err != nil {
		t.Fatal(err)
	}
	wantTaskHash, err := nodecontract.TaskOrderHashV2(signedOrder.GetOrder())
	if err != nil {
		t.Fatal(err)
	}
	wantSubject := msgbus.SubjectWorkerHandraiseV1(hex.EncodeToString(wantTaskID[:]))
	candidates := make(map[string]struct{}, len(published))
	for i, message := range published {
		if message.Subject != wantSubject {
			t.Fatalf("message[%d] subject=%q, want %q", i, message.Subject, wantSubject)
		}
		var envelope busv1.BusEnvelopeV1
		if err := proto.Unmarshal(message.Data, &envelope); err != nil {
			t.Fatalf("decode envelope[%d]: %v", i, err)
		}
		if envelope.GetSchemaVersion() != 1 ||
			envelope.GetKind() != busv1.BusMessageKind_BUS_MESSAGE_KIND_WORKER_HANDRAISE ||
			envelope.GetPayloadType() != busv1.BusPayloadType_BUS_PAYLOAD_TYPE_WORKER_HANDRAISE_V1 ||
			envelope.GetChainId() != "trueopen-localnet" || envelope.GetSubject() != message.Subject ||
			envelope.GetSenderParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX ||
			envelope.GetMessageId() == "" || len(envelope.GetNonce()) != bus.NonceSize ||
			len(envelope.GetServiceSignature()) != bus.SignatureSize ||
			envelope.GetServiceAuthorizationNonce() == 0 {
			t.Fatalf("incomplete envelope[%d]: %+v", i, &envelope)
		}
		if envelope.GetIssuedAtUnixMs() != uint64(now.UnixMilli()) ||
			envelope.GetExpiresAtUnixMs() <= envelope.GetIssuedAtUnixMs() {
			t.Fatalf("invalid envelope timestamps[%d]: %+v", i, &envelope)
		}
		digest := bus.PayloadDigest(envelope.GetPayload())
		if !bytes.Equal(digest[:], envelope.GetPayloadDigest()) {
			t.Fatalf("envelope[%d] payload digest mismatch", i)
		}
		// The envelope signature must verify against that candidate's service key (V2 signs the digest directly),
		// otherwise Nexus rejects it at step 6.
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
		signingDigest, err := bus.SigningDigest(fields)
		if err != nil {
			t.Fatalf("signing digest[%d]: %v", i, err)
		}
		serviceSigner, err := mockServiceSigner(i)
		if err != nil {
			t.Fatalf("mock service key[%d]: %v", i, err)
		}
		if envelope.GetSenderOperatorAddress() != serviceSigner.Address() {
			t.Fatalf("envelope[%d] sender is not the slot-%d mock worker", i, i)
		}
		if err := bus.VerifyDigestSignature(
			serviceSigner.PubKeyCompressed(), signingDigest[:], envelope.GetServiceSignature()); err != nil {
			t.Fatalf("envelope[%d] signature does not verify: %v", i, err)
		}

		var handraise taskv1.WorkerHandraiseV1
		if err := proto.Unmarshal(envelope.GetPayload(), &handraise); err != nil {
			t.Fatalf("decode payload[%d]: %v", i, err)
		}
		worker := handraise.GetMember().GetOperatorAddress()
		if handraise.GetSchemaVersion() != 1 || handraise.GetChainId() != "trueopen-localnet" ||
			!bytes.Equal(handraise.GetTaskId(), wantTaskID[:]) ||
			!bytes.Equal(handraise.GetTaskHash(), wantTaskHash[:]) ||
			handraise.GetModelId() != "model-1" || handraise.GetProfileVersion() != 2 ||
			worker == "" || len(handraise.GetMember().GetCandidatePoolSnapshotId()) != 32 ||
			handraise.GetMember().GetSlotVersion() == 0 ||
			handraise.GetDuty() != sharedv1.Duty_DUTY_WORKER ||
			handraise.GetServiceAuthorizationNonce() == 0 ||
			handraise.GetExpiryHeight() != signedOrder.GetOrder().GetOrderExpireHeight() ||
			len(handraise.GetServiceSignature()) != 64 {
			t.Fatalf("incomplete handraise[%d]: %+v", i, &handraise)
		}
		if _, exists := candidates[worker]; exists {
			t.Fatalf("duplicate candidate %q", worker)
		}
		candidates[worker] = struct{}{}
	}
}

func TestResponderPublishesOneSetForDuplicateOrder(t *testing.T) {
	signedOrder := testSignedOrder()
	subject := msgbus.SubjectTaskOpen(signedOrder.GetOrder().GetModelId())
	data := testOrderBroadcastFrame(t, signedOrder, subject)

	var published []publishMessage
	responder := newOrderResponder(responderConfig{
		WorkerCount:   3,
		ResponseDelay: 0,
		Now:           func() time.Time { return time.UnixMilli(1_786_060_800_000) },
	}, func(subject string, data []byte) error {
		published = append(published, publishMessage{Subject: subject, Data: append([]byte(nil), data...)})
		return nil
	})

	if err := responder.Handle(context.Background(), subject, data); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := responder.Handle(context.Background(), subject, data); err != nil {
		t.Fatalf("duplicate handle: %v", err)
	}
	if len(published) != 3 {
		t.Fatalf("published=%d, want 3", len(published))
	}
}

func TestResponderRejectsMismatchedOrderSubject(t *testing.T) {
	signedOrder := testSignedOrder()
	subject := msgbus.SubjectTaskOpen(signedOrder.GetOrder().GetModelId())
	data := testOrderBroadcastFrame(t, signedOrder, subject)

	responder := newOrderResponder(responderConfig{WorkerCount: 3}, func(string, []byte) error {
		t.Fatal("unexpected publish")
		return nil
	})
	if err := responder.Handle(context.Background(), msgbus.SubjectTaskOpen("other-model"), data); err == nil {
		t.Fatal("expected subject mismatch error")
	}
}
