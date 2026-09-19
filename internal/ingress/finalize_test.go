package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// FinalizeTaskResult conversion layer: scope carries only (session, task) (Finalize does not target a single
// object), the receipt is converted field by field to the internal shape, and the confirmation is returned with the wire's nine fields.
func TestFinalizeTaskResultConvertsRequestAndConfirmations(t *testing.T) {
	outputRef := testObjectKey(taskdata.ObjectKindOutput)
	bundleRef := testObjectKey(taskdata.ObjectKindEvidenceManifest)
	api := &fakeTaskDataAPI{resultOutcome: taskdata.FinalizeResultOutcome{
		OutputConfirmation: taskdata.StorageConfirmation{
			SchemaVersion: taskdata.StorageConfirmationSchemaVersionV1, ChainID: "chain",
			BuilderOperator: testPBBuilder, ServiceAuthorizationNonce: 7,
			Ref: outputRef, SizeBytes: 1024, RetentionUntilHeight: 5000,
			Signature: bytes.Repeat([]byte{1}, 64),
		},
		EvidenceConfirmations: []taskdata.StorageConfirmation{{
			SchemaVersion: taskdata.StorageConfirmationSchemaVersionV1, ChainID: "chain",
			BuilderOperator: testPBBuilder, ServiceAuthorizationNonce: 7,
			Ref: bundleRef, SizeBytes: 556, ArtifactTotalSizeBytes: 4096, RetentionUntilHeight: 5000,
			Signature: bytes.Repeat([]byte{2}, 64),
		}},
	}}
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, api,
		AuthParams{ChainID: "chain", Bech32Prefix: "trueopen"})

	response, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{
		TaskHash: testPBHash, SessionId: testPBSession, TaskId: testPBTask,
		Receipt:     finalizeReceiptPB(),
		RequestAuth: testAuthPB("FinalizeTaskResult", 9),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Msg.GetAccepted() || len(response.Msg.GetEvidenceBundleConfirmations()) != 1 {
		t.Fatalf("response = %#v", response.Msg)
	}
	output := response.Msg.GetOutputConfirmation()
	if output.GetSchemaVersion() != 1 || output.GetSizeBytes() != 1024 ||
		output.GetArtifactTotalSizeBytes() != 0 || len(output.GetServiceSignature()) != 64 ||
		output.GetObjectRef().GetContentHash() != testPBContent {
		t.Fatalf("output confirmation = %#v", output)
	}
	bundle := response.Msg.GetEvidenceBundleConfirmations()[0]
	if bundle.GetArtifactTotalSizeBytes() != 4096 || bundle.GetSizeBytes() != 556 {
		t.Fatalf("bundle confirmation = %#v", bundle)
	}

	// Finalize's scope is only (session, task): it does not target a single object, so the remaining ref fields
	// must not be filled in out of thin air.
	got := api.finalizeResult
	if got.Auth.Key.SessionID != testPBSession || got.Auth.Key.TaskID != testPBTask ||
		got.Auth.Key.Kind != taskdata.ObjectKindUnspecified || got.Auth.Key.ContentHash != "" ||
		got.Auth.Key.TaskHash != "" {
		t.Fatalf("scope = %#v", got.Auth.Key)
	}
	if got.TaskHash != testPBHash {
		t.Fatalf("task_hash = %q", got.TaskHash)
	}
	if got.Receipt.OutputHash != testPBContent || got.Receipt.OutputSizeBytes != 1024 ||
		len(got.Receipt.EvidenceCommitments) != 1 ||
		got.Receipt.EvidenceCommitments[0].HashOrRoot != strings.Repeat("cc", 32) {
		t.Fatalf("receipt = %#v", got.Receipt)
	}
	if len(got.Receipt.ServiceSignature) != 128 {
		t.Fatalf("service_signature = %q", got.Receipt.ServiceSignature)
	}
}

// session_id / task_id must be canonical lowercase 64-hex: Finalize's body digest puts them
// into the preimage as Hash32, and placeholder strings would only fail deep inside.
func TestFinalizeTaskResultRejectsNonCanonicalScope(t *testing.T) {
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, &fakeTaskDataAPI{},
		AuthParams{ChainID: "chain", Bech32Prefix: "trueopen"})
	_, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{
		TaskHash: testPBHash, SessionId: "session-1", TaskId: testPBTask,
		Receipt:     finalizeReceiptPB(),
		RequestAuth: testAuthPB("FinalizeTaskResult", 9),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}

// receipt is required: without it the body digest cannot be computed, so there is no verifiable authorization.
func TestFinalizeTaskResultRequiresReceipt(t *testing.T) {
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, &fakeTaskDataAPI{},
		AuthParams{ChainID: "chain", Bech32Prefix: "trueopen"})
	_, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{
		TaskHash: testPBHash, SessionId: testPBSession, TaskId: testPBTask,
		RequestAuth: testAuthPB("FinalizeTaskResult", 9),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}

func finalizeReceiptPB() *taskv1.InferReceiptV2 {
	return &taskv1.InferReceiptV2{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainId: "chain",
		TaskId: mustHex(testPBTask), TaskHash: mustHex(testPBHash),
		WorkerOperatorAddress: testPBCaller, ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: bytes.Repeat([]byte{0xbb}, sha256.Size),
		OutputHash:             mustHex(testPBContent), OutputSizeBytes: 1024,
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind:       sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING,
			EvidenceHashOrRoot: bytes.Repeat([]byte{0xcc}, sha256.Size),
			EncodedSizeBytes:   556,
		}},
		ExpiryHeight: 1200, ServiceSignature: bytes.Repeat([]byte{3}, 64),
		GeneratedTokenCount: 17, OutputLeafCount: 3,
	}
}

func mustHex(value string) []byte {
	raw, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return raw
}
