package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// The Builder operator enters the preimage as the address codec's 20 bytes; a placeholder string will not pass validation.
const integrationBuilderAddress = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"

// TODO(wire): OpenTaskHeader carries nothing from which the canonical task_hash can be derived -- it only carries
// the old JSON order_envelope, while task_hash can only be computed from the frozen SignedOrderV2 under
// TRUEOPEN_TASK_ORDER_V2 (nodecontract.TaskOrderHashHexV2). Meanwhile task_hash is the mandatory first field of
// TaskDataObjectRefV1, so the OpenTask path cannot create an INPUT object.
//
// This is a contract gap, not an implementation problem: either OpenTaskHeader adds SignedOrderV2 / task_hash,
// or the INPUT ref allows task_hash to be absent. Reported to wire; this case will be restored once it is decided.
// Production now rejects explicitly (NEXUS_INGRESS_ORDER_HAS_NO_TASK_HASH) instead of proceeding with an empty identity.
func TestTaskDataIntegrationCortexAcceptancePath(t *testing.T) {
	t.Skip("OpenTaskHeader cannot supply a canonical task_hash; awaiting the wire contract answer")
	ctx := context.Background()
	user := mustSigner(t, testKeyHex)
	worker := mustSigner(t, workerKeyHex)
	builderService := mustSigner(t, "0000000000000000000000000000000000000000000000000000000000000002")
	backend := kv.NewMemStore()
	store, err := taskdata.NewStore(
		slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "task-data"), backend,
		taskdata.Config{
			InlineMaxBytes: 16, ChunkSizeBytes: 4, MaxRangeBytes: 8, MaxBlobBytes: 32,
			SpoolReservationBytes: 64, DiskAcceptWatermarkPercent: 99,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := &integrationTaskAuthority{
		height: 100,
		builderKey: chaincli.ServiceKeyState{
			ParticipantType: "BUILDER", OperatorAddress: integrationBuilderAddress,
			ServiceAddress: builderService.Address(), ServicePubKey: hex.EncodeToString(builderService.PubKeyCompressed()),
			AuthorizationNonce: 1, UpdatedHeight: 100, Status: "ACTIVE",
		},
	}
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
	handler := &fakeHandler{}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{},
		AuthParams{ChainID: "trueopen-localnet", BuilderAddress: integrationBuilderAddress, Bech32Prefix: "trueopen"},
		handler, WithPayloadMaxBytes(16), WithReadMaxBytes(4), WithTaskDataService(dataService),
	)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.handler())
	t.Cleanup(httpServer.Close)
	client := nexusv1connect.NewIngressAPIClient(httpServer.Client(), httpServer.URL)

	payload := []byte("cortex-input")
	header := openTaskHeader(t, user, testSessionID("session-integration"), 7, payload)
	open := client.OpenTask(ctx)
	if err := open.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}}); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(payload); start += 4 {
		end := start + 4
		if end > len(payload) {
			end = len(payload)
		}
		if err := open.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: payload[start:end]}}); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := open.CloseAndReceive()
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustDeriveTaskID(t, header.GetSessionId(), header.GetOrderSequence())
	if !opened.Msg.GetAccepted() || opened.Msg.GetTaskId() != taskID || opened.Msg.GetInputMetadata() == nil {
		t.Fatalf("OpenTask response = %#v", opened.Msg)
	}

	authority.setTask(chaincli.OnChainTask{
		SessionID: header.GetSessionId(), TaskID: taskID,
		Assignment: chaincli.TaskAssignmentState{
			UserAddress: user.Address(), SelectedWorkerOperatorAddress: worker.Address(),
		},
	})
	key := taskdata.ObjectKey{SessionID: header.GetSessionId(), TaskID: taskID, Kind: taskdata.ObjectKindInput}
	metadataBody, err := taskdata.TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	metadataAuth := signedTaskDataRequest(t, worker, workerKeyHex, taskdata.MethodGetMetadata, key, 110,
		[]byte("metadata-nonce-01"), metadataBody)
	metadataResponse, err := client.GetTaskDataMetadata(ctx, connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{
		ObjectRef: objectRefPB(key), RequestAuth: metadataAuth,
	}))
	if err != nil {
		t.Fatal(err)
	}
	metadata := metadataResponse.Msg.GetMetadata()
	wantHash := sha256.Sum256(payload)
	if metadata.GetSizeBytes() != uint64(len(payload)) ||
		metadata.GetObjectRef().GetContentHash() != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("metadata response = %#v", metadataResponse.Msg)
	}

	var downloaded []byte
	for index, span := range []struct{ offset, length uint64 }{{0, 5}, {5, 7}} {
		byteRange := &taskdata.ByteRange{Offset: span.offset, Length: span.length}
		fetchBody, err := taskdata.TaskDataFetchBodyDigest(key, byteRange)
		if err != nil {
			t.Fatal(err)
		}
		fetchAuth := signedTaskDataRequest(t, worker, workerKeyHex, taskdata.MethodFetch, key, 110,
			[]byte{byte(index + 1)}, fetchBody)
		stream, err := client.FetchTaskData(ctx, connect.NewRequest(&nexusv1.FetchTaskDataRequest{
			ObjectRef:   objectRefPB(key),
			Range:       &nexusv1.ByteRangeV1{Offset: span.offset, Length: span.length},
			RequestAuth: fetchAuth,
		}))
		if err != nil {
			t.Fatal(err)
		}
		for stream.Receive() {
			downloaded = append(downloaded, stream.Msg().GetChunk().GetData()...)
		}
		if err := stream.Err(); err != nil {
			t.Fatal(err)
		}
	}
	downloadedHash := sha256.Sum256(downloaded)
	if !bytes.Equal(downloaded, payload) || downloadedHash != wantHash || uint64(len(downloaded)) != metadata.GetSizeBytes() {
		t.Fatalf("downloaded bytes/hash/size = %q/%x/%d", downloaded, downloadedHash, len(downloaded))
	}
}

type integrationTaskAuthority struct {
	mu         sync.RWMutex
	height     uint64
	task       chaincli.OnChainTask
	builderKey chaincli.ServiceKeyState
	profile    chaincli.ProfileState
}

func (a *integrationTaskAuthority) LatestHeight(context.Context) (uint64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.height, nil
}

func (a *integrationTaskAuthority) QueryTask(_ context.Context, key chaincli.TaskKey) (chaincli.OnChainTask, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.task.SessionID != key.SessionID || a.task.TaskID != key.TaskID {
		return chaincli.OnChainTask{}, chaincli.ErrNotFound
	}
	return a.task, nil
}

func (a *integrationTaskAuthority) QueryProfile(_ context.Context, modelID string, profileVersion uint32) (chaincli.ProfileState, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.profile.ModelID != modelID || a.profile.ProfileVersion != profileVersion {
		return chaincli.ProfileState{}, chaincli.ErrNotFound
	}
	return a.profile, nil
}

func (a *integrationTaskAuthority) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if participantType != "BUILDER" || operator != integrationBuilderAddress {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return a.builderKey, nil
}

func (a *integrationTaskAuthority) setTask(task chaincli.OnChainTask) {
	a.mu.Lock()
	a.task = task
	a.mu.Unlock()
}

func signedTaskDataRequest(
	t *testing.T,
	requester signer.Signer,
	requesterKeyHex string,
	method taskdata.RequestMethod,
	key taskdata.ObjectKey,
	expires uint64,
	nonce []byte,
	bodyDigest [32]byte,
) *nexusv1.TaskDataRequestAuthV1 {
	t.Helper()
	// The nonce must be 32 raw CSPRNG random bytes; the fixture pads to a fixed length to guarantee the size.
	requestNonce := make([]byte, 32)
	copy(requestNonce, nonce)
	request := taskdata.RequestAuth{
		SchemaVersion: 1, ChainID: "trueopen-localnet", BuilderOperatorAddress: integrationBuilderAddress,
		RPCMethod:     "/nexus.v1.IngressAPI/" + string(method),
		BodyDigest:    hex.EncodeToString(bodyDigest[:]),
		RequesterKind: taskdata.RequesterKindCortexService, RequesterAddress: requester.Address(),
		ServiceAuthorizationNonce: 1, RequestNonce: requestNonce, ExpiryHeight: expires,
		Key: key,
	}
	digest, err := taskdata.CortexTaskDataRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return &nexusv1.TaskDataRequestAuthV1{
		SchemaVersion: request.SchemaVersion, ChainId: request.ChainID,
		BuilderOperatorAddress: request.BuilderOperatorAddress, RpcMethod: request.RPCMethod,
		BodyDigest:                request.BodyDigest,
		RequesterKind:             nexusv1.TaskDataRequesterKindV1_TASK_DATA_REQUESTER_KIND_V1_CORTEX_SERVICE,
		RequesterAddress:          request.RequesterAddress,
		ServiceAuthorizationNonce: request.ServiceAuthorizationNonce,
		RequestNonce:              request.RequestNonce,
		ExpiryHeight:              request.ExpiryHeight,
		Signature:                 mustSignDigest(t, requesterKeyHex, digest[:]),
	}
}

// objectRefPB converts an internal ref into the wire shape for integration cases to build requests with.
func objectRefPB(key taskdata.ObjectKey) *nexusv1.TaskDataObjectRefV1 {
	return objectRefToPB(key)
}
