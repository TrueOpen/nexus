package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// captureChain implements only the two methods the signed submission path uses; the rest go through
// the embedded nil and would panic (they are never reached in these tests).
type captureChain struct {
	chaincli.Client
	acc           chaincli.AccountInfo
	broadcast     [][]byte
	broadcastErr  error
	accountCalls  int
	latestHeight  uint64
	task          chaincli.OnChainTask
	profile       chaincli.ProfileState
	timeoutBucket chaincli.TimeoutBucketState
	taskCalls     int
	profileCalls  int
	selectionErr  error
	builder       chaincli.BuilderState
	builderSet    chaincli.BuilderSet
}

func (c *captureChain) AccountInfo(_ context.Context, _ string) (chaincli.AccountInfo, error) {
	c.accountCalls++
	return c.acc, nil
}

func (c *captureChain) LatestHeight(context.Context) (uint64, error) { return c.latestHeight, nil }
func (c *captureChain) QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error) {
	c.taskCalls++
	return c.task, nil
}
func (c *captureChain) QueryProfile(context.Context, string, uint32) (chaincli.ProfileState, error) {
	c.profileCalls++
	return c.profile, nil
}
func (c *captureChain) QueryTimeoutBucket(context.Context, string, uint64, uint64) (chaincli.TimeoutBucketState, error) {
	return c.timeoutBucket, nil
}
func (c *captureChain) QueryTaskBuilders(context.Context, chaincli.TaskKey) (chaincli.TaskBuilderSelectionState, error) {
	return chaincli.TaskBuilderSelectionState{}, c.selectionErr
}
func (c *captureChain) QueryEVMChainID(context.Context) (uint64, error) { return 31337, nil }

func (c *captureChain) QuerySettlementBuilderGraceBlocks(context.Context) (uint64, error) {
	return 0, c.selectionErr
}
func (c *captureChain) QueryBuilder(context.Context, string) (chaincli.BuilderState, error) {
	return c.builder, nil
}
func (c *captureChain) QueryBuilderSet(context.Context, uint64) (chaincli.BuilderSet, error) {
	return c.builderSet, nil
}

func (c *captureChain) BroadcastTx(_ context.Context, tx []byte) (chaincli.TxResult, error) {
	c.broadcast = append(c.broadcast, tx)
	if c.broadcastErr != nil {
		return chaincli.TxResult{}, c.broadcastErr
	}
	return chaincli.TxResult{Code: 0}, nil
}

func TestSignedSubmitterBuildsWorkerHandraiseProposalTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
		ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})

	res, err := sub.SubmitAssign(context.Background(), chaincli.AssignTx{
		SignedOrder:      testSignedOrder(sg.Address()),
		WorkerHandraises: testWorkerHandraises(sg.Address()),
		Submitter:        sg.Address(),
	})
	if err != nil {
		t.Fatalf("SubmitAssign: %v", err)
	}
	if res.Code != 0 || len(chain.broadcast) != 1 {
		t.Fatalf("broadcast: code=%d n=%d", res.Code, len(chain.broadcast))
	}

	body, auth := decodeBuilderTx(t, chain.broadcast[0])
	if len(body.Messages) != 1 || body.Messages[0].TypeUrl != chaincli.TypeURLMsgSubmitWorkerHandraises {
		t.Fatalf("messages: %+v", body.Messages)
	}
	var msg taskv1.MsgSubmitWorkerHandraises
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal msg: %v", err)
	}
	// §4.2.1: the request carries only the scope oneof, the signed handraises and
	// the Cosmos signer. Builder rank, selection proof, candidate set hash,
	// min-handraise threshold, reserved fee and infer deadline are Keeper-derived
	// and have no wire field left to carry them.
	if msg.GetScope().GetSignedOrder() == nil || msg.GetScope().GetExistingTask() != nil ||
		len(msg.GetHandraises()) != 2 || msg.GetSubmitterAddress() != sg.Address() {
		t.Fatalf("msg: %+v", &msg)
	}
	if got := msg.GetHandraises()[0].GetMember().GetSlot(); got != 3 {
		t.Fatalf("first handraise slot = %d, want 3", got)
	}
	if msg.GetScope().GetSignedOrder().GetSignatureScheme() != "eip712" {
		t.Fatalf("signature scheme = %q", msg.GetScope().GetSignedOrder().GetSignatureScheme())
	}
	if got := auth.SignerInfos[0].Sequence; got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}
}

func TestSignedSubmitterRejectsNonCanonicalWorkerProposal(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})

	descending := testWorkerHandraises(sg.Address())
	descending[0].Member.Slot, descending[1].Member.Slot = descending[1].GetMember().GetSlot(), descending[0].GetMember().GetSlot()

	cases := map[string]chaincli.AssignTx{
		"no scope": {WorkerHandraises: testWorkerHandraises(sg.Address()), Submitter: sg.Address()},
		"both scopes": {
			SignedOrder:      testSignedOrder(sg.Address()),
			ExistingTask:     &taskv1.ExistingTaskRefV1{TaskId: make([]byte, 32), TaskHash: make([]byte, 32)},
			WorkerHandraises: testWorkerHandraises(sg.Address()),
			Submitter:        sg.Address(),
		},
		"empty handraises": {SignedOrder: testSignedOrder(sg.Address()), Submitter: sg.Address()},
		"slots not ascending": {
			SignedOrder: testSignedOrder(sg.Address()), WorkerHandraises: descending, Submitter: sg.Address(),
		},
	}
	for name, tx := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := sub.SubmitAssign(context.Background(), tx); err == nil {
				t.Fatal("want prepare error")
			}
			if len(chain.broadcast) != 0 || chain.accountCalls != 0 {
				t.Fatalf("broadcast=%d account_calls=%d", len(chain.broadcast), chain.accountCalls)
			}
		})
	}
}

// MsgRegisterBuilder is now really sent: the descriptor is the on-chain endpoints list, and
// service_pubkey / service_key_proof are raw bytes rather than hex text.
func TestBuilderSubmitterBuildsRegisterBuilderTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{
		ChainID: "trueopen-hub", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})

	if _, err := sub.SubmitRegisterBuilder(context.Background(), chaincli.RegisterBuilderTx{
		Builder:            sg.Address(),
		ServicePubKey:      testServicePubKeyHex,
		ServiceKeyProof:    testServiceProofHex,
		AuthorizationNonce: 1,
		Endpoints:          testBuilderEndpoints(),
	}); err != nil {
		t.Fatalf("SubmitRegisterBuilder: %v", err)
	}
	if len(chain.broadcast) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(chain.broadcast))
	}
	body, auth := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgRegisterBuilder {
		t.Fatalf("type URL = %q", body.Messages[0].TypeUrl)
	}
	if got := auth.SignerInfos[0].Sequence; got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}
	var register hubv1.MsgRegisterBuilder
	if err := proto.Unmarshal(body.Messages[0].Value, &register); err != nil {
		t.Fatalf("unmarshal register: %v", err)
	}
	if register.GetBuilderOperatorAddress() != sg.Address() {
		t.Fatalf("builder = %q", register.GetBuilderOperatorAddress())
	}
	if hex.EncodeToString(register.GetServicePubkey()) != testServicePubKeyHex ||
		hex.EncodeToString(register.GetServiceKeyProof()) != testServiceProofHex {
		t.Fatalf("service key material = %x / %x", register.GetServicePubkey(), register.GetServiceKeyProof())
	}
	assertCanonicalDescriptor(t, register.GetDescriptor_())
}

// The submission point must canonicalize too: even when the input arrives out of order, what is
// sent must still be a list in ascending kind order.
func TestBuilderSubmitterSortsDescriptorEndpoints(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 1}}
	sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000})

	ordered := testBuilderEndpoints()
	shuffled := []chaincli.ServiceEndpoint{ordered[2], ordered[0], ordered[1]}
	if _, err := sub.SubmitUpdateServiceDescriptor(context.Background(), chaincli.UpdateServiceDescriptorTx{
		OperatorAddress: sg.Address(), ParticipantType: "BUILDER",
		ExpectedDescriptorVersion: 3, Endpoints: shuffled,
	}); err != nil {
		t.Fatalf("SubmitUpdateServiceDescriptor: %v", err)
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	var update hubv1.MsgUpdateServiceDescriptor
	if err := proto.Unmarshal(body.Messages[0].Value, &update); err != nil {
		t.Fatalf("unmarshal update: %v", err)
	}
	assertCanonicalDescriptor(t, update.GetDescriptor_())
}

// MsgUpdateServiceDescriptor carries expected_descriptor_version (the current version) and no
// hash / schema / effective and expiry heights / controller signature -- those fields are no longer
// on the wire.
func TestBuilderSubmitterBuildsUpdateServiceDescriptorTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 9}}
	sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000})

	if _, err := sub.SubmitUpdateServiceDescriptor(context.Background(), chaincli.UpdateServiceDescriptorTx{
		OperatorAddress:           sg.Address(),
		ParticipantType:           "BUILDER",
		ExpectedDescriptorVersion: 2,
		Endpoints:                 testBuilderEndpoints(),
	}); err != nil {
		t.Fatalf("SubmitUpdateServiceDescriptor: %v", err)
	}
	if len(chain.broadcast) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(chain.broadcast))
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgUpdateServiceDescriptor {
		t.Fatalf("type URL = %q", body.Messages[0].TypeUrl)
	}
	var update hubv1.MsgUpdateServiceDescriptor
	if err := proto.Unmarshal(body.Messages[0].Value, &update); err != nil {
		t.Fatalf("unmarshal update: %v", err)
	}
	if update.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
		t.Fatalf("participant type = %v", update.GetParticipantType())
	}
	if update.GetExpectedDescriptorVersion() != 2 || update.GetOperatorAddress() != sg.Address() {
		t.Fatalf("update = %+v", &update)
	}
	assertCanonicalDescriptor(t, update.GetDescriptor_())
}

// A non-compliant descriptor must fail definitively and locally, consuming no sequence and
// broadcasting nothing: an empty list, a duplicate kind, a scheme rejected by the closed set, and a
// domain name that is not a ParticipantType.
func TestBuilderSubmitterFailsClosedOnInvalidDescriptor(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	grpcKind := hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC
	cases := map[string]chaincli.UpdateServiceDescriptorTx{
		"empty endpoints": {
			OperatorAddress: sg.Address(), ParticipantType: "BUILDER", ExpectedDescriptorVersion: 1,
		},
		"duplicate kind": {
			OperatorAddress: sg.Address(), ParticipantType: "BUILDER", ExpectedDescriptorVersion: 1,
			Endpoints: []chaincli.ServiceEndpoint{
				{Kind: grpcKind, URI: "http://a:1", ProtocolVersion: "v1"},
				{Kind: grpcKind, URI: "http://b:2", ProtocolVersion: "v1"},
			},
		},
		"scheme outside the closed set": {
			OperatorAddress: sg.Address(), ParticipantType: "BUILDER", ExpectedDescriptorVersion: 1,
			Endpoints: []chaincli.ServiceEndpoint{{Kind: grpcKind, URI: "ftp://a:1", ProtocolVersion: "v1"}},
		},
		"unknown participant type": {
			OperatorAddress: sg.Address(), ParticipantType: "WORKER", ExpectedDescriptorVersion: 1,
			Endpoints: testBuilderEndpoints(),
		},
	}
	for name, tx := range cases {
		t.Run(name, func(t *testing.T) {
			chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
			sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000})
			_, err := sub.SubmitUpdateServiceDescriptor(context.Background(), tx)
			var submissionErr *SubmissionError
			if !errors.As(err, &submissionErr) || submissionErr.Phase != SubmissionPrepare || !submissionErr.Definitive {
				t.Fatalf("error = %v, want definitive prepare failure", err)
			}
			if len(chain.broadcast) != 0 {
				t.Fatalf("broadcasts = %d, want 0", len(chain.broadcast))
			}
		})
	}
}

// service_pubkey / service_key_proof that are not canonical hex fail closed just the same.
func TestBuilderSubmitterFailsClosedOnNonCanonicalServiceKeyMaterial(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	for name, tx := range map[string]chaincli.RegisterBuilderTx{
		"short pubkey": {
			Builder: sg.Address(), ServicePubKey: "02abcdef", ServiceKeyProof: testServiceProofHex,
			AuthorizationNonce: 1, Endpoints: testBuilderEndpoints(),
		},
		"non-hex proof": {
			Builder: sg.Address(), ServicePubKey: testServicePubKeyHex, ServiceKeyProof: "service-proof",
			AuthorizationNonce: 1, Endpoints: testBuilderEndpoints(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
			sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000})
			_, err := sub.SubmitRegisterBuilder(context.Background(), tx)
			var submissionErr *SubmissionError
			if !errors.As(err, &submissionErr) || submissionErr.Phase != SubmissionPrepare || !submissionErr.Definitive {
				t.Fatalf("error = %v, want definitive prepare failure", err)
			}
			if len(chain.broadcast) != 0 {
				t.Fatalf("broadcasts = %d, want 0", len(chain.broadcast))
			}
		})
	}
}

const (
	testServicePubKeyHex = "0211223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
	testServiceProofHex  = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testTLSPubKeyHashHex = "aabb112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

func testBuilderEndpoints() []chaincli.ServiceEndpoint {
	return []chaincli.ServiceEndpoint{
		{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
			URI:  "http://10.0.0.1:8080", ProtocolVersion: "v1",
		},
		{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
			URI:  "http://10.0.0.1:8080", ProtocolVersion: "v1",
		},
		{
			Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
			URI:  "http://10.0.0.1:8080/healthz", ProtocolVersion: "v1",
			TLSPubKeyHash: testTLSPubKeyHashHex,
		},
	}
}

// assertCanonicalDescriptor asserts that the endpoints on the wire have exactly the shape §9.6b
// requires: ascending by kind, unique kinds, and the optional tls_pubkey_hash set only when the
// configuration supplied a fingerprint.
func assertCanonicalDescriptor(t *testing.T, descriptor *hubv1.ServiceDescriptorV1) {
	t.Helper()
	endpoints := descriptor.GetEndpoints()
	if len(endpoints) != 3 {
		t.Fatalf("endpoints = %+v", endpoints)
	}
	wantKinds := []hubv1.ServiceEndpointKind{
		hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
		hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS,
	}
	for i, want := range wantKinds {
		if endpoints[i].GetEndpointKind() != want || endpoints[i].GetProtocolVersion() != "v1" {
			t.Fatalf("endpoint %d = %+v", i, endpoints[i])
		}
	}
	if endpoints[0].GetUri() != "http://10.0.0.1:8080" || endpoints[2].GetUri() != "http://10.0.0.1:8080/healthz" {
		t.Fatalf("uris = %q / %q", endpoints[0].GetUri(), endpoints[2].GetUri())
	}
	if endpoints[0].TlsPubkeyHash != nil || endpoints[1].TlsPubkeyHash != nil {
		t.Fatal("absent tls_pubkey_hash must stay absent on the wire")
	}
	if hex.EncodeToString(endpoints[2].GetTlsPubkeyHash()) != testTLSPubKeyHashHex {
		t.Fatalf("tls_pubkey_hash = %x", endpoints[2].GetTlsPubkeyHash())
	}
}

func TestBuilderSubmitterClassifiesUnknownBroadcastOutcome(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{
		acc:          chaincli.AccountInfo{AccountNumber: 7, Sequence: 42},
		broadcastErr: errors.New("connection reset"),
	}
	sub := NewBuilderSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub", GasLimit: 200000})

	_, err = sub.SubmitUpdateServiceDescriptor(context.Background(), chaincli.UpdateServiceDescriptorTx{
		OperatorAddress: sg.Address(), ParticipantType: "BUILDER",
		ExpectedDescriptorVersion: 2, Endpoints: testBuilderEndpoints(),
	})
	var submitErr *SubmissionError
	if !errors.As(err, &submitErr) || submitErr.Phase != SubmissionBroadcast || submitErr.Definitive {
		t.Fatalf("submission error = %#v", err)
	}
}

func decodeBuilderTx(t *testing.T, rawBytes []byte) (*txv1beta1.TxBody, *txv1beta1.AuthInfo) {
	t.Helper()
	var raw txv1beta1.TxRaw
	if err := proto.Unmarshal(rawBytes, &raw); err != nil {
		t.Fatalf("unmarshal TxRaw: %v", err)
	}
	var body txv1beta1.TxBody
	if err := proto.Unmarshal(raw.BodyBytes, &body); err != nil {
		t.Fatalf("unmarshal TxBody: %v", err)
	}
	var auth txv1beta1.AuthInfo
	if err := proto.Unmarshal(raw.AuthInfoBytes, &auth); err != nil {
		t.Fatalf("unmarshal AuthInfo: %v", err)
	}
	return &body, &auth
}

func TestSignedSubmitterBuildsInferReceiptTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
		ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})

	res, err := sub.SubmitOpenVerify(context.Background(), chaincli.OpenVerifyTx{
		InferReceipt: testInferReceiptV1("trueopen1worker"),
		Submitter:    sg.Address(),
	})
	if err != nil {
		t.Fatalf("SubmitOpenVerify: %v", err)
	}
	if res.Code != 0 || len(chain.broadcast) != 1 {
		t.Fatalf("broadcast: code=%d n=%d", res.Code, len(chain.broadcast))
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgSubmitInferReceipt {
		t.Fatalf("type_url=%q", body.Messages[0].TypeUrl)
	}
	var msg taskv1.MsgSubmitInferReceipt
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal MsgSubmitInferReceipt: %v", err)
	}
	// §10.3/§5.14: the request is the Worker-signed receipt plus the submitter.
	// Selected verifiers, window proof, builder rank/proof, token count and work
	// unit are gone; the receipt commits to the ordered evidence commitments.
	receipt := msg.GetReceipt()
	if msg.GetSubmitterAddress() != sg.Address() || receipt == nil ||
		receipt.GetWorkerOperatorAddress() != "trueopen1worker" || receipt.GetOutputSizeBytes() != 4096 ||
		len(receipt.GetRequiredEvidenceCommitments()) != 2 ||
		len(receipt.GetGenerationParamsDigest()) != 32 || len(receipt.GetServiceSignature()) != 64 {
		t.Fatalf("MsgSubmitInferReceipt mismatch: %+v", &msg)
	}
}

func TestSignedSubmitterBuildsVerifierHandraiseProposalTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})

	taskID := strings.Repeat("1a", 32)
	if _, err := sub.SubmitVerifierHandraises(context.Background(), chaincli.OpenVerifyTx{
		TaskID:             taskID,
		VerifierHandraises: testVerifierHandraises(taskID, t),
		Submitter:          sg.Address(),
	}); err != nil {
		t.Fatalf("SubmitVerifierHandraises: %v", err)
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgSubmitVerifierHandraises {
		t.Fatalf("type_url=%q", body.Messages[0].TypeUrl)
	}
	var msg taskv1.MsgSubmitVerifierHandraises
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.GetTaskId()) != 32 || len(msg.GetHandraises()) != 1 || msg.GetSubmitterAddress() != sg.Address() {
		t.Fatalf("MsgSubmitVerifierHandraises mismatch: %+v", &msg)
	}
}

func TestSignedSubmitterBuildsMinimalSettleTaskTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
		ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})
	taskID := strings.Repeat("ab", 32)

	res, err := sub.SubmitSettle(context.Background(), chaincli.SettleTx{
		Submitter: sg.Address(), SessionID: "sess-1", TaskID: taskID,
	})
	if err != nil {
		t.Fatalf("SubmitSettle: %v", err)
	}
	if res.Code != 0 || len(chain.broadcast) != 1 {
		t.Fatalf("broadcast: code=%d n=%d", res.Code, len(chain.broadcast))
	}
	// §10.10a: the Keeper derives every settlement fact, so nexus must not query
	// the task or the profile to build the request any more.
	if chain.taskCalls != 0 || chain.profileCalls != 0 {
		t.Fatalf("settlement must not require task/profile queries: task=%d profile=%d", chain.taskCalls, chain.profileCalls)
	}

	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if len(body.Messages) != 1 || body.Messages[0].TypeUrl != chaincli.TypeURLMsgSettleTask {
		t.Fatalf("messages: %+v", body.Messages)
	}
	var msg taskv1.MsgSettleTask
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal MsgSettleTask: %v", err)
	}
	wantTaskID, err := nodecontract.Hash32Bytes("task_id", taskID)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.GetTaskId()) != string(wantTaskID) || msg.GetSubmitterAddress() != sg.Address() {
		t.Fatalf("MsgSettleTask mismatch: %+v", &msg)
	}
	// The whole legacy settlement fact set must be absent from the wire.
	if fields := msg.ProtoReflect().Descriptor().Fields(); fields.Len() != 2 {
		t.Fatalf("MsgSettleTask has %d fields, want exactly task_id and submitter_address", fields.Len())
	}
}

func TestSignedSubmitterRejectsNonCanonicalSettleTaskID(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})

	for _, taskID := range []string{"task-1", strings.ToUpper(strings.Repeat("ab", 32)), "0x" + strings.Repeat("ab", 32)} {
		if _, err := sub.SubmitSettle(context.Background(), chaincli.SettleTx{Submitter: sg.Address(), TaskID: taskID}); err == nil {
			t.Fatalf("task_id %q must be rejected as a non-canonical Hash32", taskID)
		}
	}
	if len(chain.broadcast) != 0 {
		t.Fatalf("broadcast n=%d, want 0", len(chain.broadcast))
	}
}

func TestUnsignedFallbackFailsClosedWithoutBroadcast(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := &captureChain{}
	sub := newDefaultSubmitter(log, chain) // no signer -> JSON skeleton mode

	if _, err := sub.SubmitAssign(context.Background(), chaincli.AssignTx{SessionID: "s", TaskID: "t"}); err == nil {
		t.Fatal("unsigned submit must fail")
	}
	if len(chain.broadcast) != 0 || chain.accountCalls != 0 {
		t.Fatalf("broadcast=%d account_calls=%d", len(chain.broadcast), chain.accountCalls)
	}
}

func TestTaskPrepareFailureDoesNotConsumeAccountSequence(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})

	_, err = sub.SubmitAssign(context.Background(), chaincli.AssignTx{BuilderOperatorAddress: sg.Address(), SessionID: "sess-1", TaskID: "task-1"})
	var submissionErr *SubmissionError
	if !errors.As(err, &submissionErr) || submissionErr.Phase != SubmissionPrepare || !submissionErr.Definitive {
		t.Fatalf("err=%#v", err)
	}
	if chain.accountCalls != 0 || len(chain.broadcast) != 0 {
		t.Fatalf("account_calls=%d broadcasts=%d", chain.accountCalls, len(chain.broadcast))
	}
}

// MsgSweepDeadline is the public deadline runner of §9.6a: the signer is nexus's own Cosmos account
// and the locator takes the task branch of §5.9.
func TestSignedSubmitterBuildsSweepDeadlineTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})

	taskID := strings.Repeat("3c", 32)
	if _, err := sub.SubmitSweepDeadline(context.Background(), chaincli.SweepDeadlineTx{
		Submitter:    sg.Address(),
		SessionID:    "session-1",
		TaskID:       taskID,
		DeadlineKind: taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT,
	}); err != nil {
		t.Fatalf("SubmitSweepDeadline: %v", err)
	}
	body, _ := decodeBuilderTx(t, chain.broadcast[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgSweepDeadline {
		t.Fatalf("type_url=%q", body.Messages[0].TypeUrl)
	}
	var msg taskv1.MsgSweepDeadline
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatal(err)
	}
	task := msg.GetLocator().GetTask()
	if task == nil {
		t.Fatalf("locator must use the task branch: %+v", msg.GetLocator())
	}
	if len(task.GetTaskId()) != 32 {
		t.Fatalf("task_id must be raw Hash32, got %d bytes", len(task.GetTaskId()))
	}
	if task.GetDeadlineKind() != taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_COMMIT {
		t.Fatalf("deadline_kind=%v", task.GetDeadlineKind())
	}
	if msg.GetSubmitterAddress() != sg.Address() {
		t.Fatalf("submitter_address=%q, want the Cosmos signer", msg.GetSubmitterAddress())
	}
}

// The challenge/evidence kinds a Builder does not sweep in Phase 0 (VERIFY_ROUND_CLOSE /
// CHALLENGE_WINDOW_CLOSE / EVIDENCE_CLEANUP) and the session_lifecycle kind must fail closed before
// broadcast: the sweep executor is certain to reject them, so broadcasting only burns gas.
func TestSubmitSweepDeadlineRejectsNonTaskKindsBeforeBroadcast(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	rejected := []taskv1.DeadlineKindV1{
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_UNSPECIFIED,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_VERIFY_ROUND_CLOSE,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_CHALLENGE_WINDOW_CLOSE,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_EVIDENCE_CLEANUP,
		taskv1.DeadlineKindV1_DEADLINE_KIND_V1_SESSION_LIFECYCLE,
	}
	for _, kind := range rejected {
		t.Run(kind.String(), func(t *testing.T) {
			chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
			sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000})
			_, err := sub.SubmitSweepDeadline(context.Background(), chaincli.SweepDeadlineTx{
				Submitter: sg.Address(), SessionID: "session-1", TaskID: strings.Repeat("3c", 32), DeadlineKind: kind,
			})
			var submissionErr *SubmissionError
			if !errors.As(err, &submissionErr) || submissionErr.Phase != SubmissionPrepare || !submissionErr.Definitive {
				t.Fatalf("err=%#v, want a definitive prepare-phase rejection", err)
			}
			if chain.accountCalls != 0 || len(chain.broadcast) != 0 {
				t.Fatalf("account_calls=%d broadcasts=%d, want no chain traffic", chain.accountCalls, len(chain.broadcast))
			}
		})
	}
}

func TestUnsignedFallbackRejectsMismatchedTypeURLBeforeBroadcast(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := &captureChain{}
	sub := newDefaultSubmitter(log, chain).(*defaultSubmitter)

	_, err := sub.submitMsg(context.Background(), "RegisterBuilderTx", "/task.v1.MsgSettleTask", &hubv1.MsgRegisterBuilder{})
	if err == nil {
		t.Fatal("want error for mismatched type URL")
	}
	if len(chain.broadcast) != 0 {
		t.Fatalf("broadcast n=%d, want 0", len(chain.broadcast))
	}
}

// testSignedOrder builds a minimal but structurally canonical SignedOrderV2
// (Keeper Interface Contract §5.13). The signature bytes are fixture data: the Keeper
// verifies them against the order-domain EIP-712 digest using the on-chain
// account key.
//
// nexus **does** derive the task_hash itself (nodecontract.TaskOrderHashV2) and uses it
// to bind the proposal scope to every hand-raise, so this order really has to be canonical --
// user_address must be valid bech32 and amounts must be decimal with no leading zeros. Deriving a
// digest is not verifying a signature: the user signature is still verified only by the keeper.
func testSignedOrder(user string) *taskv1.SignedOrderV2 {
	return &taskv1.SignedOrderV2{
		Order: &taskv1.TaskOrderV2{
			SchemaVersion: 2, ChainId: "trueopen-localnet", UserAddress: user,
			SessionId: bytes.Repeat([]byte{0x11}, 32), OrderSequence: 7,
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
		// 65 bytes of R||S||V with V=27 and S < N/2: a structurally valid placeholder signature.
		UserSignature: append(bytes.Repeat([]byte{0x55}, 64), 27),
	}
}

// testWorkerHandraises returns two slot-ascending WorkerHandraiseV1 facts
// (Keeper Interface Contract §4.1/§4.2.2).
func testWorkerHandraises(user string) []*taskv1.WorkerHandraiseV1 {
	// task_hash is the canonical digest of the testSignedOrder(user) order: the proposal scope and
	// every hand-raise must be bound to the same value, or validateScopeTaskHash rejects outright.
	taskHash, err := nodecontract.TaskOrderHashV2(testSignedOrder(user).GetOrder())
	if err != nil {
		panic(err)
	}
	handraise := func(slot uint32, operator string) *taskv1.WorkerHandraiseV1 {
		return &taskv1.WorkerHandraiseV1{
			SchemaVersion: 1, ChainId: "trueopen-localnet",
			TaskId: bytes.Repeat([]byte{0x66}, 32), TaskHash: append([]byte(nil), taskHash[:]...),
			ModelId: "model-1", ProfileVersion: 2,
			Member: &taskv1.CandidateMemberRefV1{
				CandidatePoolSnapshotId: bytes.Repeat([]byte{0x88}, 32),
				Slot:                    slot, SlotVersion: 1, OperatorAddress: operator,
			},
			Duty: sharedv1.Duty_DUTY_WORKER, ServiceAuthorizationNonce: 1, ExpiryHeight: 500,
			ServiceSignature: bytes.Repeat([]byte{0x99}, 64),
		}
	}
	return []*taskv1.WorkerHandraiseV1{handraise(3, "trueopen1worker3"), handraise(9, "trueopen1worker9")}
}

func testVerifierHandraises(taskIDHex string, t *testing.T) []*taskv1.VerifierHandraiseV1 {
	t.Helper()
	taskID, err := nodecontract.Hash32Bytes("task_id", taskIDHex)
	if err != nil {
		t.Fatal(err)
	}
	return []*taskv1.VerifierHandraiseV1{{
		SchemaVersion: 1, ChainId: "trueopen-localnet", TaskId: taskID, VerifyRound: 1,
		InferReceiptHash: bytes.Repeat([]byte{0xaa}, 32), OutputHash: bytes.Repeat([]byte{0xbb}, 32),
		ModelId: "model-1", ProfileVersion: 2,
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: bytes.Repeat([]byte{0x88}, 32),
			Slot:                    5, SlotVersion: 1, OperatorAddress: "trueopen1verifier5",
		},
		Duty: sharedv1.Duty_DUTY_VERIFIER, ServiceAuthorizationNonce: 1, ExpiryHeight: 700,
		ServiceSignature: bytes.Repeat([]byte{0xcc}, 64),
	}}
}

// testInferReceipt returns a structurally canonical InferReceiptV2
// (Keeper Interface Contract §5.14) with kind-ascending evidence commitments.
func testInferReceiptV1(worker string) *taskv1.InferReceiptV2 {
	return &taskv1.InferReceiptV2{
		SchemaVersion: 1, ChainId: "trueopen-localnet",
		TaskId: bytes.Repeat([]byte{0x66}, 32), TaskHash: bytes.Repeat([]byte{0x77}, 32),
		WorkerOperatorAddress: worker, ServiceAuthorizationNonce: 1,
		GenerationParamsDigest: bytes.Repeat([]byte{0xdd}, 32),
		OutputHash:             bytes.Repeat([]byte{0xee}, 32), OutputSizeBytes: 4096,
		RequiredEvidenceCommitments: []*taskv1.EvidenceCommitmentV1{
			{
				EvidenceKind:       sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING,
				EvidenceHashOrRoot: bytes.Repeat([]byte{0x01}, 32), EncodedSizeBytes: 128,
			},
			{
				EvidenceKind:       sharedv1.EvidenceKind_EVIDENCE_KIND_VERIFIER_VALUE_OPENING,
				EvidenceHashOrRoot: bytes.Repeat([]byte{0x02}, 32), EncodedSizeBytes: 256,
			},
		},
		ExpiryHeight: 900, ServiceSignature: bytes.Repeat([]byte{0x0f}, 64),
	}
}
