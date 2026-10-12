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
		AuthParams{Chain: testUserChain, ChainID: "chain", Bech32Prefix: "trueopen"})

	response, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{
		TaskHash: wireID(testPBHash), SessionId: wireID(testPBSession), TaskId: wireID(testPBTask),
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
		output.GetObjectRef().GetContentHash() != wireID(testPBContent) {
		t.Fatalf("output confirmation = %#v", output)
	}
	bundle := response.Msg.GetEvidenceBundleConfirmations()[0]
	if bundle.GetArtifactTotalSizeBytes() != 4096 || bundle.GetSizeBytes() != 556 {
		t.Fatalf("bundle confirmation = %#v", bundle)
	}

	// Finalize's scope is only (session, task): it does not target a single object, so the remaining ref fields
	// must not be filled in out of thin air. Scope and task_hash reach taskdata in the internal spelling.
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

// session_id / task_id / task_hash must be "0x" + 64 lowercase hex: Finalize's body digest puts them
// into the preimage as Hash32, and placeholder strings would only fail deep inside. The bare internal
// spelling is malformed on the wire too.
func TestFinalizeTaskResultRejectsNonCanonicalScope(t *testing.T) {
	for name, edit := range map[string]func(*nexusv1.FinalizeTaskResultRequest){
		"text session_id": func(r *nexusv1.FinalizeTaskResultRequest) { r.SessionId = "session-1" },
		"bare session_id": func(r *nexusv1.FinalizeTaskResultRequest) { r.SessionId = testPBSession },
		"bare task_id":    func(r *nexusv1.FinalizeTaskResultRequest) { r.TaskId = testPBTask },
		"bare task_hash":  func(r *nexusv1.FinalizeTaskResultRequest) { r.TaskHash = testPBHash },
		"0X task_id":      func(r *nexusv1.FinalizeTaskResultRequest) { r.TaskId = "0X" + testPBTask },
		// testPBTask is all digits, so the uppercase row uses a value with hex letters.
		"uppercase hex task_id": func(r *nexusv1.FinalizeTaskResultRequest) { r.TaskId = "0x" + strings.Repeat("AB", 32) },
		"bare body_digest":      func(r *nexusv1.FinalizeTaskResultRequest) { r.RequestAuth.BodyDigest = strings.Repeat("5", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeTaskDataAPI{}
			client := newTaskDataClientWithHandler(t, &fakeHandler{}, api,
				AuthParams{Chain: testUserChain, ChainID: "chain", Bech32Prefix: "trueopen"})
			request := &nexusv1.FinalizeTaskResultRequest{
				TaskHash: wireID(testPBHash), SessionId: wireID(testPBSession), TaskId: wireID(testPBTask),
				Receipt:     finalizeReceiptPB(),
				RequestAuth: testAuthPB("FinalizeTaskResult", 9),
			}
			edit(request)
			_, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(request))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "must be 0x") {
				t.Fatalf("error = %v, want InvalidArgument naming the 0x spelling", err)
			}
			if api.finalizeResult.Auth.Key.SessionID != "" {
				t.Fatalf("malformed request reached taskdata: %#v", api.finalizeResult)
			}
		})
	}
}

// FinalizeVerifierEvidence reads the same scope: a bare session_id, task_id or task_hash is malformed.
func TestFinalizeVerifierEvidenceRejectsBareScope(t *testing.T) {
	for name, edit := range map[string]func(*nexusv1.FinalizeVerifierEvidenceRequest){
		"bare session_id": func(r *nexusv1.FinalizeVerifierEvidenceRequest) { r.SessionId = testPBSession },
		"bare task_id":    func(r *nexusv1.FinalizeVerifierEvidenceRequest) { r.TaskId = testPBTask },
		"bare task_hash":  func(r *nexusv1.FinalizeVerifierEvidenceRequest) { r.TaskHash = testPBHash },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeTaskDataAPI{}
			client := newTaskDataClientWithHandler(t, &fakeHandler{}, api,
				AuthParams{Chain: testUserChain, ChainID: "chain", Bech32Prefix: "trueopen"})
			request := &nexusv1.FinalizeVerifierEvidenceRequest{
				TaskHash: wireID(testPBHash), SessionId: wireID(testPBSession), TaskId: wireID(testPBTask),
				VerifyRound: 1, VerifierOperator: testPBCaller,
				RequestAuth: testAuthPB("FinalizeVerifierEvidence", 10),
			}
			edit(request)
			_, err := client.FinalizeVerifierEvidence(context.Background(), connect.NewRequest(request))
			if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "must be 0x") {
				t.Fatalf("error = %v, want InvalidArgument naming the 0x spelling", err)
			}
			if api.finalizeVerifier.Auth.Key.SessionID != "" {
				t.Fatalf("malformed request reached taskdata: %#v", api.finalizeVerifier)
			}
		})
	}
}

// receipt is required: without it the body digest cannot be computed, so there is no verifiable authorization.
func TestFinalizeTaskResultRequiresReceipt(t *testing.T) {
	client := newTaskDataClientWithHandler(t, &fakeHandler{}, &fakeTaskDataAPI{},
		AuthParams{Chain: testUserChain, ChainID: "chain", Bech32Prefix: "trueopen"})
	_, err := client.FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{
		TaskHash: wireID(testPBHash), SessionId: wireID(testPBSession), TaskId: wireID(testPBTask),
		RequestAuth: testAuthPB("FinalizeTaskResult", 9),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}

func finalizeReceiptPB() *taskv1.InferReceiptV3 {
	return &taskv1.InferReceiptV3{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV3, ChainId: "chain",
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
