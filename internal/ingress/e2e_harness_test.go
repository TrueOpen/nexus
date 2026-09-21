//go:build e2eharness

package ingress

// Cross-language harness, not part of the default suite (see README "Cross-language output stream
// harness"): starts the real IngressAPI on a loopback httptest TLS server with a fake chain
// authority, has a Worker upload three chunks plus a Fin, writes a JSON descriptor for an external
// SDK process, then serves SubscribeOutput until E2E_STOP appears or three minutes pass.
//
//	E2E_OUT=<descriptor.json> E2E_STOP=<stop file> [E2E_FIN_MODE=signed|unsigned|badreason] \
//	  go test -tags e2eharness -run '^TestE2EHarness$' ./internal/ingress/
//
// E2E_FIN_MODE=unsigned sends a pre-wire-v0.1.1 Fin (no reason, no signature); badreason signs
// over EOS_TOKEN but claims STOP_SEQUENCE. nexus accepts both today because it does not verify
// the Fin signature yet; the signed-Fin follow-up is expected to flip that.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// newE2EFixture is newStreamFixture with the httptest server exposed (URL and certificate).
func newE2EFixture(t *testing.T) (*streamFixture, *httptest.Server) {
	t.Helper()
	user := mustSigner(t, testKeyHex)
	worker := mustSigner(t, workerKeyHex)
	builderService := mustSigner(t, "0000000000000000000000000000000000000000000000000000000000000002")
	backend := kv.NewMemStore()
	store, err := taskdata.NewStore(
		slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "task-data"), backend,
		taskdata.Config{
			InlineMaxBytes: 16, ChunkSizeBytes: 16, MaxRangeBytes: 64, MaxBlobBytes: 64,
			SpoolReservationBytes: 128, DiskAcceptWatermarkPercent: 99,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := &streamTaskAuthority{height: 100, keys: map[string]chaincli.ServiceKeyState{
		"BUILDER|" + integrationBuilderAddress: streamServiceKey("BUILDER", integrationBuilderAddress, builderService),
		"CORTEX|" + worker.Address():           streamServiceKey("CORTEX", worker.Address(), worker),
	}}
	authorizer, err := taskdata.NewAuthorizer(taskdata.AuthorizerConfig{
		ChainID: "trueopen-localnet", EVMChainID: 31337, BuilderAddress: integrationBuilderAddress, AddressPrefix: "trueopen",
		RequestTTLBlocks: 20, RetentionLeaseBlocks: 50,
	}, backend, authority, builderService)
	if err != nil {
		t.Fatal(err)
	}
	dataService, err := taskdata.NewService(store, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	dataService.SetOutputStreamConfig(taskdata.OutputStreamConfig{MaxLeaves: 8, MinFrameBytes: 2, MaxFrameBytes: 16, MaxAttachmentBytes: 8})
	options := []Option{
		WithPayloadMaxBytes(16), WithReadMaxBytes(16), WithTaskDataService(dataService),
		WithOutputStream(dataService, taskdata.NewOutputDispatcher(8), backend),
	}
	server, err := New(
		slog.New(slog.NewTextHandler(os.Stderr, nil)), config.IngressConfig{},
		AuthParams{ChainID: "trueopen-localnet", BuilderAddress: integrationBuilderAddress, Bech32Prefix: "trueopen"},
		&fakeHandler{taskOwner: user.Address()}, options...,
	)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(server.handler())
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	session := testSessionID("session-e2e")
	taskID := mustDeriveTaskID(t, session, 1)
	taskHash := sha256.Sum256([]byte("accepted-task-" + taskID))
	authority.task = chaincli.OnChainTask{
		SessionID: session, TaskID: taskID, State: types.Assigned,
		Assignment: chaincli.TaskAssignmentState{
			UserAddress: user.Address(), SelectedWorkerOperatorAddress: worker.Address(),
			AcceptedTaskHash: hex.EncodeToString(taskHash[:]),
		},
	}
	return &streamFixture{
		client: nexusv1connect.NewIngressAPIClient(httpServer.Client(), httpServer.URL),
		user:   user, worker: worker, authority: authority, session: session, taskID: taskID, taskHash: taskHash[:],
		key: taskdata.ObjectKey{
			TaskHash: hex.EncodeToString(taskHash[:]), SessionID: session, TaskID: taskID,
			Kind: taskdata.ObjectKindOutput, ContentHash: strings.Repeat("7", 64),
		},
	}, httpServer
}

func TestE2EHarness(t *testing.T) {
	out, stop := os.Getenv("E2E_OUT"), os.Getenv("E2E_STOP")
	if out == "" || stop == "" {
		t.Skip("E2E_OUT / E2E_STOP not set")
	}
	f, httpServer := newE2EFixture(t)
	ctx := context.Background()

	up := f.client.UploadTaskOutputStream(ctx)
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: &nexusv1.OutputStreamHeaderV1{
		SessionId: f.session, TaskId: f.taskID, TaskHash: hex.EncodeToString(f.taskHash),
		RequestAuth: streamHeaderAuth(t, f.worker, workerKeyHex, f.key, 110, []byte("nonce-e2e-header-0001")),
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Receive(); err != nil {
		t.Fatalf("progress: %v", err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	texts := []string{"Hello, ", "stream", "!"}
	for i, text := range texts {
		f.sendChunk(t, up, acc, uint64(i), text)
	}
	final := acc.Root()
	finalSeq := uint64(len(texts) - 1)
	reason := taskv1.FinishReasonV1_FINISH_REASON_V1_EOS_TOKEN
	digest, err := nodecontract.OutputFinSigningDigest("trueopen-localnet", f.taskHash, finalSeq, final[:], uint32(reason))
	if err != nil {
		t.Fatal(err)
	}
	fin := &nexusv1.OutputFinV1{FinalSeq: finalSeq, OutputMmrRoot: final[:], FinishReason: reason, WorkerSignature: signDigestRaw64(t, workerKeyHex, digest[:])}
	switch os.Getenv("E2E_FIN_MODE") {
	case "unsigned": // pre-wire-v0.1.1 Worker: no reason, no signature
		fin.FinishReason, fin.WorkerSignature = 0, nil
	case "badreason": // signature made over EOS_TOKEN but the frame claims STOP_SEQUENCE
		fin.FinishReason = taskv1.FinishReasonV1_FINISH_REASON_V1_STOP_SEQUENCE
	}
	if err := up.Send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Fin{Fin: fin}}); err != nil {
		t.Fatal(err)
	}
	if err := up.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	last, err := up.Receive()
	if err != nil || !last.GetResult().GetAccepted() {
		t.Fatalf("fin result = %v / %v", last, err)
	}
	_ = up.CloseResponse()

	descriptor := map[string]any{
		"url":               httpServer.URL,
		"cert_der_b64":      base64.StdEncoding.EncodeToString(httpServer.Certificate().Raw),
		"chain_id":          "trueopen-localnet",
		"session_id":        f.session,
		"task_id":           f.taskID,
		"task_hash_hex":     hex.EncodeToString(f.taskHash),
		"worker_pubkey_hex": hex.EncodeToString(f.worker.PubKeyCompressed()),
		"user_privkey_hex":  testKeyHex, // the fixed test-only key of this test package, never a real identity
		"user_address":      f.user.Address(),
		"texts":             texts,
		"final_seq":         finalSeq,
		"output_mmr_root":   hex.EncodeToString(final[:]),
		"finish_reason":     uint32(reason),
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("harness ready at %s, waiting for %s", httpServer.URL, stop)
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(stop); err == nil {
			t.Log("stop file seen, shutting down")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("harness timed out waiting for stop file")
}
