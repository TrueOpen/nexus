package ingress

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/types"
)

// From wire v0.4.1 on, the three relay requests carry only the on-chain message body: no session_id, no
// request_auth and no SDK envelope. Authorization is the message's own service_signature over the on-chain digest,
// and the public key is read from the chain by (CORTEX, operator) -- a public key presented by the caller is never trusted.
//
// So every case here is "build the on-chain message -> sign the on-chain digest -> send". Cases that tamper with a field
// deliberately do not re-sign: the digest changes with the field, so the original signature necessarily fails, which is the
// observable form of the binding taking effect.

func relayTaskID(seed string) []byte {
	id := make([]byte, 32)
	copy(id, seed)
	for i := len(seed); i < 32; i++ {
		id[i] = byte(i)
	}
	return id
}

func signCommit(t *testing.T, commit *taskv1.VerifyCommitV1, keyHex string) *taskv1.VerifyCommitV1 {
	t.Helper()
	commit.ServiceSignature = nil
	digest, err := nodecontract.VerifyCommitSigningDigest(commit)
	if err != nil {
		t.Fatal(err)
	}
	commit.ServiceSignature = mustSignDigest(t, keyHex, digest[:])
	return commit
}

func validCommit(t *testing.T, taskID []byte, verifier, keyHex string) *taskv1.VerifyCommitV1 {
	t.Helper()
	return signCommit(t, &taskv1.VerifyCommitV1{
		SchemaVersion: nodecontract.VerifyCommitSchemaVersionV1, ChainId: "trueopen-localnet",
		TaskId: taskID, VerifyRound: 1, VerifierOperatorAddress: verifier,
		ServiceAuthorizationNonce: 7, CommitHash: bytes.Repeat([]byte{0xaa}, 32), ExpiryHeight: 900,
	}, keyHex)
}

func validResultReceipt(t *testing.T, taskID []byte, verifier, keyHex string) *taskv1.ResultReceiptV2 {
	t.Helper()
	topk := uint32(750000)
	receipt := &taskv1.ResultReceiptV2{
		SchemaVersion: nodecontract.ResultReceiptSchemaVersionV2, ChainId: "trueopen-localnet",
		TaskId: taskID, VerifyRound: 1, VerifierOperatorAddress: verifier,
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    bytes.Repeat([]byte{0xee}, 32),
		MetricRoot:                bytes.Repeat([]byte{0xbb}, 32),
		MetricSummary: &taskv1.MetricSummaryV1{
			FiniteCount: 128, MeanAbsLogprobDiffFp_1E6: 1200,
			AbsLogprobDiffP95Fp_1E6: 3000, AbsLogprobDiffP99Fp_1E6: 5000, RankDeltaNonzeroRateFp_1E6: 100,
			TopkJaccardMeanFp_1E6: &topk, ComparedTopkCount: 128, ComparedRankCount: 128,
		},
		AggregateProofHash:                bytes.Repeat([]byte{0xcc}, 32),
		VerifierEvidenceBundleHash:        bytes.Repeat([]byte{0xdd}, 32),
		VerifierEvidenceManifestSizeBytes: 145,
		Salt:                              bytes.Repeat([]byte{0xef}, 32),
		ExpiryHeight:                      900,
	}
	digest, err := nodecontract.ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature = mustSignDigest(t, keyHex, digest[:])
	return receipt
}

func validRelayReceipt(t *testing.T, taskID []byte, worker, keyHex string) *taskv1.InferReceiptV2 {
	t.Helper()
	receipt := &taskv1.InferReceiptV2{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainId: "trueopen-localnet",
		TaskId: taskID, TaskHash: bytes.Repeat([]byte{0x2a}, 32),
		WorkerOperatorAddress: worker, ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: bytes.Repeat([]byte{0x3b}, 32),
		OutputHash:             bytes.Repeat([]byte{0x4c}, 32),
		OutputSizeBytes:        16,
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{{
			EvidenceKind:       1,
			EvidenceHashOrRoot: bytes.Repeat([]byte{0x5d}, 32),
			EncodedSizeBytes:   4096,
		}},
		ExpiryHeight: 1200, GeneratedTokenCount: 128, OutputLeafCount: 3,
		// service_signature is not part of the preimage, but the shape check runs first: fill a placeholder of valid length.
		ServiceSignature: make([]byte, 64),
	}
	// The fixture and the server must digest the same bytes, so reuse the production conversion path.
	submission, err := inferReceiptFromPB(&nexusv1.SubmitInferReceiptRequest{Receipt: receipt}, "trueopen-localnet")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodecontract.InferReceiptSigningDigestFromSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature = mustSignDigest(t, keyHex, digest[:])
	return receipt
}

func cortexResolver(t *testing.T, operator, keyHex, domain string) *fakeServiceKeyResolver {
	t.Helper()
	service := mustSigner(t, keyHex)
	return &fakeServiceKeyResolver{states: map[string]chaincli.ServiceKeyState{
		domain + "|" + operator: activeServiceKey(domain, operator, service),
	}}
}

func relayAuth(t *testing.T, operator, keyHex, domain string) AuthParams {
	t.Helper()
	return AuthParams{
		ChainID: "trueopen-localnet", Bech32Prefix: "trueopen",
		ServiceKeys: cortexResolver(t, operator, keyHex, domain),
	}
}

// The query domain must be CORTEX: WORKER / VERIFIER are sender_role values, and neither domain exists on chain.
// Being registered only there must yield a lookup miss and a rejection -- no fallback to another domain, and no operator self-signing path.
func TestVerifierServiceKeyAuthenticatesFromCortexDomain(t *testing.T) {
	operator := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("verify-relay-domain")

	tests := []struct {
		name   string
		domain string
		// Once authenticated, the relay succeeds (no error); otherwise Unauthenticated is reported first.
		want connect.Code
	}{
		{name: "CORTEX domain authenticates", domain: servicekey.ParticipantCortex, want: connect.CodeUnknown},
		{name: "VERIFIER sender_role domain is never queried", domain: "VERIFIER", want: connect.CodeUnauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &fakeHandler{verifyRelayAck: types.VerifyRelayAck{TxHash: []byte{0xab}}}
			client := newTestClient(t, handler, relayAuth(t, operator.Address(), alternateKeyHex, tt.domain))

			_, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
				&nexusv1.SubmitVerifyCommitRequest{
					Commit: validCommit(t, taskID, operator.Address(), alternateKeyHex),
				}))
			if (tt.want == connect.CodeUnknown && err != nil) ||
				(tt.want != connect.CodeUnknown && connect.CodeOf(err) != tt.want) {
				t.Fatalf("SubmitVerifyCommit code = %v, err = %v; want %v", connect.CodeOf(err), err, tt.want)
			}

			_, err = client.SubmitVerifyResult(context.Background(), connect.NewRequest(
				&nexusv1.SubmitVerifyResultRequest{
					Receipt: validResultReceipt(t, taskID, operator.Address(), alternateKeyHex),
				}))
			if (tt.want == connect.CodeUnknown && err != nil) ||
				(tt.want != connect.CodeUnknown && connect.CodeOf(err) != tt.want) {
				t.Fatalf("SubmitVerifyResult code = %v, err = %v; want %v", connect.CodeOf(err), err, tt.want)
			}
		})
	}
}

// A public key presented by the caller does not count: the signature must verify against the current service key on chain.
func TestRelayRejectsSignatureFromAnotherKey(t *testing.T) {
	operator := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("foreign-key")
	client := newTestClient(t, &fakeHandler{},
		// alternateKeyHex is what is registered on chain, but the message is signed with the operator's own key.
		relayAuth(t, operator.Address(), alternateKeyHex, servicekey.ParticipantCortex))
	_, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
		&nexusv1.SubmitVerifyCommitRequest{Commit: validCommit(t, taskID, operator.Address(), workerKeyHex)}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, err = %v", connect.CodeOf(err), err)
	}
}

func TestSubmitInferReceiptAcceptsRelayResponsibility(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("receipt")
	fake := &fakeHandler{sessionForTask: "sess-receipt"}
	client := newTestClient(t, fake, relayAuth(t, worker.Address(), alternateKeyHex, servicekey.ParticipantCortex))

	resp, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(
		&nexusv1.SubmitInferReceiptRequest{
			Receipt: validRelayReceipt(t, taskID, worker.Address(), alternateKeyHex),
		}))
	if err != nil {
		t.Fatalf("SubmitInferReceipt: %v", err)
	}
	// infer_receipt_hash is the digest recomputed locally under TRUEOPEN_INFER_RECEIPT_V2, not a wire field.
	wantDigest, err := nodecontract.InferReceiptSigningDigestFromSubmission(fake.lastInferReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.GetRelayAccepted() || resp.Msg.GetInferReceiptHash() != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("response = %+v", resp.Msg)
	}
	got := fake.lastInferReceipt
	// The wire v0.4.1 request carries only InferReceiptV2, no session_id; ingress must look the session up by task_id
	// (SessionForTask) before handing it to the coordinator, otherwise OnInferReceipt always reports an empty session_id.
	if got.SessionID != "sess-receipt" {
		t.Fatalf("relayed receipt session_id = %q, want the SessionForTask lookup", got.SessionID)
	}
	if got.TaskID != hex.EncodeToString(taskID) || got.WorkerAddress != worker.Address() ||
		got.SchemaVersion != nodecontract.InferReceiptSchemaVersionV2 || got.ChainID != "trueopen-localnet" ||
		got.ServiceAuthorizationNonce != 7 || got.ExpiryHeight != 1200 ||
		got.GeneratedTokenCount != 128 || got.OutputLeafCount != 3 || len(got.EvidenceCommitments) != 1 {
		t.Fatalf("relayed receipt = %#v", got)
	}
}

// Input with an invalid shape is rejected in the conversion layer. Each case is a shape the chain would certainly not accept,
// and letting it through would only hand Cortex a receipt that passes locally and never passes on chain.
func TestSubmitInferReceiptRejectsMalformedMaterial(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("malformed")
	tests := map[string]func(*taskv1.InferReceiptV2){
		// From V2 on, schema_version is 2; falling back to 1 is an old receipt that Phase 0 explicitly does not accept.
		"wrong schema version": func(r *taskv1.InferReceiptV2) { r.SchemaVersion = 1 },
		"cross chain":          func(r *taskv1.InferReceiptV2) { r.ChainId = "trueopen-other" },
		"short task id":        func(r *taskv1.InferReceiptV2) { r.TaskId = r.TaskId[:31] },
		"short task hash":      func(r *taskv1.InferReceiptV2) { r.TaskHash = r.TaskHash[:31] },
		"zero output size":     func(r *taskv1.InferReceiptV2) { r.OutputSizeBytes = 0 },
		"zero nonce":           func(r *taskv1.InferReceiptV2) { r.ServiceAuthorizationNonce = 0 },
		"zero expiry":          func(r *taskv1.InferReceiptV2) { r.ExpiryHeight = 0 },
		"short signature":      func(r *taskv1.InferReceiptV2) { r.ServiceSignature = r.ServiceSignature[:32] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, &fakeHandler{},
				relayAuth(t, worker.Address(), alternateKeyHex, servicekey.ParticipantCortex))
			receipt := validRelayReceipt(t, taskID, worker.Address(), alternateKeyHex)
			mutate(receipt)
			_, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(
				&nexusv1.SubmitInferReceiptRequest{Receipt: receipt}))
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("code = %v, err = %v; want InvalidArgument", connect.CodeOf(err), err)
			}
		})
	}
}

func TestSubmitInferReceiptMapsHandlerErrors(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("handler-errors")
	tests := map[string]struct {
		err  error
		code connect.Code
	}{
		"not found":    {types.ErrTaskNotFound, connect.CodeNotFound},
		"unauthorized": {types.ErrUnauthorized, connect.CodePermissionDenied},
		"invalid":      {types.ErrInvalidArgument, connect.CodeInvalidArgument},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, &fakeHandler{inferReceiptErr: tt.err},
				relayAuth(t, worker.Address(), alternateKeyHex, servicekey.ParticipantCortex))
			_, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(
				&nexusv1.SubmitInferReceiptRequest{
					Receipt: validRelayReceipt(t, taskID, worker.Address(), alternateKeyHex),
				}))
			if connect.CodeOf(err) != tt.code {
				t.Fatalf("code = %v, err = %v; want %v", connect.CodeOf(err), err, tt.code)
			}
		})
	}
}

// The session is looked up by task_id: the request does not carry it. A lookup miss is NotFound; one must not be invented.
func TestRelayResolvesSessionFromTaskID(t *testing.T) {
	verifier := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("session-lookup")
	auth := relayAuth(t, verifier.Address(), alternateKeyHex, servicekey.ParticipantCortex)

	t.Run("resolved", func(t *testing.T) {
		fake := &fakeHandler{sessionForTask: "sess-from-index", verifyRelayAck: types.VerifyRelayAck{TxHash: []byte{1}}}
		client := newTestClient(t, fake, auth)
		commit := validCommit(t, taskID, verifier.Address(), alternateKeyHex)
		response, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
			&nexusv1.SubmitVerifyCommitRequest{Commit: commit}))
		if err != nil {
			t.Fatalf("SubmitVerifyCommit: %v", err)
		}
		if fake.lastVerifyCommit == nil {
			t.Fatal("commit was not relayed")
		}
		// commit_key in the acknowledgement is the primary key of the Keeper CommitState (Keeper Interface Contract §10.9);
		// Cortex requires a non-zero Hash32, whereas an empty string used to be returned.
		wantKey, err := nodecontract.CommitKey(commit.GetChainId(), commit.GetTaskId(), commit.GetVerifyRound(), commit.GetVerifierOperatorAddress())
		if err != nil {
			t.Fatal(err)
		}
		if response.Msg.GetCommitKey() != hex.EncodeToString(wantKey[:]) {
			t.Fatalf("commit_key = %q, want %x", response.Msg.GetCommitKey(), wantKey)
		}
	})

	t.Run("unknown task", func(t *testing.T) {
		client := newTestClient(t, &fakeHandler{sessionForTaskErr: types.ErrTaskNotFound}, auth)
		_, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
			&nexusv1.SubmitVerifyCommitRequest{
				Commit: validCommit(t, taskID, verifier.Address(), alternateKeyHex),
			}))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("code = %v, err = %v; want NotFound", connect.CodeOf(err), err)
		}
	})
}

func TestSubmitVerifyCommitRelaysAfterValidation(t *testing.T) {
	verifier := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("commit-relay")
	fake := &fakeHandler{verifyRelayAck: types.VerifyRelayAck{TxHash: []byte{0xcd}, Idempotent: true}}
	client := newTestClient(t, fake, relayAuth(t, verifier.Address(), alternateKeyHex, servicekey.ParticipantCortex))

	commit := validCommit(t, taskID, verifier.Address(), alternateKeyHex)
	resp, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
		&nexusv1.SubmitVerifyCommitRequest{Commit: commit}))
	if err != nil {
		t.Fatalf("SubmitVerifyCommit: %v", err)
	}
	wantDigest, err := nodecontract.VerifyCommitSigningDigest(commit)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.GetRelayAccepted() || !resp.Msg.GetIdempotent() ||
		resp.Msg.GetVerifyCommitSigningDigest() != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("response = %+v", resp.Msg)
	}
	// The body is relayed verbatim: nexus rewrites no field and fills in none.
	if fake.lastVerifyCommit == nil ||
		!bytes.Equal(fake.lastVerifyCommit.GetCommitHash(), commit.GetCommitHash()) ||
		fake.lastVerifyCommit.GetVerifierOperatorAddress() != verifier.Address() {
		t.Fatalf("relayed commit = %#v", fake.lastVerifyCommit)
	}
}

func TestSubmitVerifyCommitMapsRelayErrors(t *testing.T) {
	verifier := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("commit-errors")
	tests := map[string]struct {
		err  error
		code connect.Code
	}{
		"not found":    {types.ErrTaskNotFound, connect.CodeNotFound},
		"unauthorized": {types.ErrUnauthorized, connect.CodePermissionDenied},
		// A temporarily unreachable chain is a transient failure: it maps to Unavailable, so the caller can retry or switch to direct submission per the contract.
		"chain down": {errors.New("chain unreachable"), connect.CodeUnavailable},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, &fakeHandler{verifyRelayErr: tt.err},
				relayAuth(t, verifier.Address(), alternateKeyHex, servicekey.ParticipantCortex))
			_, err := client.SubmitVerifyCommit(context.Background(), connect.NewRequest(
				&nexusv1.SubmitVerifyCommitRequest{
					Commit: validCommit(t, taskID, verifier.Address(), alternateKeyHex),
				}))
			if connect.CodeOf(err) != tt.code {
				t.Fatalf("code = %v, err = %v; want %v", connect.CodeOf(err), err, tt.code)
			}
		})
	}
}

func TestSubmitVerifyResultRelaysAfterValidation(t *testing.T) {
	verifier := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("result-relay")
	fake := &fakeHandler{verifyRelayAck: types.VerifyRelayAck{TxHash: []byte{0xef}}}
	client := newTestClient(t, fake, relayAuth(t, verifier.Address(), alternateKeyHex, servicekey.ParticipantCortex))

	receipt := validResultReceipt(t, taskID, verifier.Address(), alternateKeyHex)
	resp, err := client.SubmitVerifyResult(context.Background(), connect.NewRequest(
		&nexusv1.SubmitVerifyResultRequest{Receipt: receipt}))
	if err != nil {
		t.Fatalf("SubmitVerifyResult: %v", err)
	}
	wantDigest, err := nodecontract.ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.GetRelayAccepted() ||
		resp.Msg.GetResultReceiptSigningDigest() != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("response = %+v", resp.Msg)
	}
	// The optional fields of metric_summary pass through as-is: absent and set to 0 are two different commitments.
	relayed := fake.lastVerifyResult
	if relayed == nil || relayed.GetMetricSummary().TopkJaccardMeanFp_1E6 == nil ||
		relayed.GetMetricSummary().UnionJsP99Fp_1E6 != nil {
		t.Fatalf("relayed summary = %#v", relayed.GetMetricSummary())
	}
	if !bytes.Equal(relayed.GetSalt(), receipt.GetSalt()) ||
		relayed.GetVerifierEvidenceManifestSizeBytes() != 145 {
		t.Fatalf("relayed receipt = %#v", relayed)
	}
}

// All three fields V2 adds over V1 enter the signing preimage: change one without re-signing and the original signature necessarily fails.
// Without this, a V1-era signature could pass itself off as a V2 receipt.
func TestSubmitVerifyResultBindsV2Fields(t *testing.T) {
	verifier := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("v2-binding")
	auth := relayAuth(t, verifier.Address(), alternateKeyHex, servicekey.ParticipantCortex)
	for name, mutate := range map[string]func(*taskv1.ResultReceiptV2){
		"evidence bundle hash": func(r *taskv1.ResultReceiptV2) {
			r.VerifierEvidenceBundleHash = bytes.Repeat([]byte{0x11}, 32)
		},
		"manifest size": func(r *taskv1.ResultReceiptV2) { r.VerifierEvidenceManifestSizeBytes = 146 },
		"salt":          func(r *taskv1.ResultReceiptV2) { r.Salt = bytes.Repeat([]byte{0x22}, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, &fakeHandler{}, auth)
			receipt := validResultReceipt(t, taskID, verifier.Address(), alternateKeyHex)
			mutate(receipt)
			_, err := client.SubmitVerifyResult(context.Background(), connect.NewRequest(
				&nexusv1.SubmitVerifyResultRequest{Receipt: receipt}))
			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, err = %v; want Unauthenticated", connect.CodeOf(err), err)
			}
		})
	}
}

func TestRelayRejectsMissingMessage(t *testing.T) {
	client := newTestClient(t, &fakeHandler{}, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	for name, call := range map[string]func() error{
		"infer receipt": func() error {
			_, err := client.SubmitInferReceipt(context.Background(),
				connect.NewRequest(&nexusv1.SubmitInferReceiptRequest{}))
			return err
		},
		"verify commit": func() error {
			_, err := client.SubmitVerifyCommit(context.Background(),
				connect.NewRequest(&nexusv1.SubmitVerifyCommitRequest{}))
			return err
		},
		"verify result": func() error {
			_, err := client.SubmitVerifyResult(context.Background(),
				connect.NewRequest(&nexusv1.SubmitVerifyResultRequest{}))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("code = %v, err = %v", connect.CodeOf(err), err)
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// When task_id resolves to no session (this Builder is not tracking the task) -> NotFound, rather than passing an empty session downstream.
func TestSubmitInferReceiptRejectsUnknownTask(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	taskID := relayTaskID("receipt-unknown")
	fake := &fakeHandler{sessionForTaskErr: types.ErrTaskNotFound}
	client := newTestClient(t, fake, relayAuth(t, worker.Address(), alternateKeyHex, servicekey.ParticipantCortex))

	_, err := client.SubmitInferReceipt(context.Background(), connect.NewRequest(
		&nexusv1.SubmitInferReceiptRequest{
			Receipt: validRelayReceipt(t, taskID, worker.Address(), alternateKeyHex),
		}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("error = %v, want NotFound", err)
	}
	if fake.lastInferReceipt.TaskID != "" {
		t.Fatal("receipt must not reach the coordinator when the task is unknown")
	}
}
