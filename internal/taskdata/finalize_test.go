package taskdata

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

const finalizeSchemaHash = "7777777777777777777777777777777777777777777777777777777777777777"

// finalizeFixture puts every object a Finalize needs into STORED: the OUTPUT, the Worker
// manifest and the artifact it references.
type finalizeFixture struct {
	*authorizerFixture
	service *Service
	store   *Store

	taskHash string
	scope    ObjectKey
	output   Metadata
	manifest Metadata
	receipt  SignedInferReceipt
}

func newFinalizeFixture(t *testing.T) *finalizeFixture {
	t.Helper()
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}

	taskHash := strings.Repeat("a", 64)
	fx.authority.task.Assignment.AcceptedTaskHash = taskHash
	fx.authority.task.Assignment.ModelID = "model-1"
	fx.authority.task.Assignment.ProfileVersion = 3
	fx.authority.profile = chaincli.ProfileState{
		ModelID: "model-1", ProfileVersion: 3, Status: "ACTIVE",
		EvidenceSchemaHash: finalizeSchemaHash,
	}
	scope := ObjectKey{SessionID: testSessionID, TaskID: testTaskID}

	// Persist the artifact first: the manifest references it.
	artifactBody := []byte("worker aggregate proof bytes")
	artifactRef := ObjectKey{
		TaskHash: taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceArtifact, ContentHash: hex.EncodeToString(sha256Sum(artifactBody)),
		EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: fx.worker.Address(),
	}
	storeObject(t, store, artifactRef, artifactBody, fx.worker.Address(), "")

	manifestRef := ObjectKey{
		TaskHash: taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind:                 ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: fx.worker.Address(),
	}
	manifestBody := buildManifest(t, manifestRef, finalizeSchemaHash, []EvidenceArtifact{{
		ArtifactID: "aggregate_proof", ContentHash: artifactRef.ContentHash, SizeBytes: uint64(len(artifactBody)),
	}})
	// The Worker manifest's ref content_hash is the receipt's evidence_hash_or_root
	// (TRUEOPEN_WORKER_VALUE_COMMITMENT_V2 digest), not the H_V1 of the manifest bytes;
	// a byte-independent value is used here, Finalize only uses it for addressing.
	manifestRef.ContentHash = strings.Repeat("c", 64)
	manifest := storeObject(t, store, manifestRef, manifestBody, fx.worker.Address(), "application/json")
	if want := EvidenceBundleHash(manifestBody); manifest.EvidenceBundleHash != hex.EncodeToString(want[:]) {
		t.Fatalf("worker manifest evidence_bundle_hash = %s, want H_V1(bytes)", manifest.EvidenceBundleHash)
	}

	outputBody := []byte("the model output")
	outputRef := ObjectKey{
		TaskHash: taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindOutput, ContentHash: hex.EncodeToString(sha256Sum(outputBody)),
	}
	output := storeObject(t, store, outputRef, outputBody, fx.worker.Address(), "")

	receipt := SignedInferReceipt{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainID: testChainID,
		TaskID: testTaskID, TaskHash: taskHash,
		WorkerOperatorAddress: fx.worker.Address(), ServiceAuthorizationNonce: 1,
		GenerationParamsDigest: strings.Repeat("b", 64),
		OutputHash:             outputRef.ContentHash, OutputSizeBytes: output.SizeBytes,
		EvidenceCommitments: []EvidenceCommitment{{
			Kind:       uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING),
			HashOrRoot: manifestRef.ContentHash,
			// wire v0.4.1: encoded_size_bytes is the total artifact size, not the manifest byte count.
			EncodedSizeBytes: manifest.ArtifactTotalSizeBytes,
		}},
		ExpiryHeight: 1200, ServiceSignature: strings.Repeat("0", 128),
	}
	digest, err := receiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature = hex.EncodeToString(signDigestForTest(t, fx.workerService, digest[:]))

	return &finalizeFixture{
		authorizerFixture: fx, service: service, store: store,
		taskHash: taskHash, scope: scope, output: output, manifest: manifest, receipt: receipt,
	}
}

// request builds a signed FinalizeTaskResult request.
func (f *finalizeFixture) request(t *testing.T, nonce byte) FinalizeResultRequest {
	t.Helper()
	digest, err := receiptDigest(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	signatureDigest, err := serviceSignatureDigest(f.receipt.ServiceSignature)
	if err != nil {
		t.Fatal(err)
	}
	body, err := TaskDataFinalizeResultBodyDigest(
		f.taskHash, f.scope.SessionID, f.scope.TaskID, hex.EncodeToString(digest[:]), signatureDigest)
	if err != nil {
		t.Fatal(err)
	}
	auth := signedRequestAs(t, f.worker.Address(), f.workerService,
		MethodFinalizeResult, f.scope, body[:], nonce, 110)
	return FinalizeResultRequest{Auth: auth, TaskHash: f.taskHash, Receipt: f.receipt}
}

// storeObject puts an object into STORED through the real upload path. EVIDENCE_ARTIFACT
// media_type must be empty (§6.2); other objects default to octet-stream.
func storeObject(t *testing.T, store *Store, ref ObjectKey, body []byte, uploader, mediaType string) Metadata {
	t.Helper()
	if mediaType == "" && ref.Kind != ObjectKindEvidenceArtifact {
		mediaType = "application/octet-stream"
	}
	header := UploadHeader{
		Key: ref, Uploader: uploader, SizeBytes: uint64(len(body)),
		SemanticHash: ref.ContentHash, MediaType: mediaType, RetainUntilHeight: 180,
	}
	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	metadata, err := store.MarkStored(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

// Happy path: OUTPUT and bundle switch to READY together, one confirmation each for the
// OUTPUT and every bundle, artifacts are not confirmed separately.
func TestFinalizeTaskResultCommitsReadyAndSignsConfirmations(t *testing.T) {
	f := newFinalizeFixture(t)
	outcome, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9))
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if outcome.Idempotent {
		t.Fatal("first submission is not idempotent")
	}
	// evidence_bundle_confirmations count equals required_evidence_commitments exactly.
	if len(outcome.EvidenceConfirmations) != len(f.receipt.EvidenceCommitments) {
		t.Fatalf("confirmations = %d, commitments = %d",
			len(outcome.EvidenceConfirmations), len(f.receipt.EvidenceCommitments))
	}
	if outcome.OutputConfirmation.Ref != f.output.Key || outcome.OutputConfirmation.ArtifactTotalSizeBytes != 0 {
		t.Fatalf("output confirmation = %#v", outcome.OutputConfirmation)
	}
	bundle := outcome.EvidenceConfirmations[0]
	if bundle.Ref != f.manifest.Key || bundle.ArtifactTotalSizeBytes != f.manifest.ArtifactTotalSizeBytes {
		t.Fatalf("bundle confirmation = %#v", bundle)
	}
	// Both confirmations must verify under the current Builder service key.
	for _, confirmation := range append([]StorageConfirmation{outcome.OutputConfirmation}, outcome.EvidenceConfirmations...) {
		digest, err := BuilderStorageConfirmationDigest(confirmation)
		if err != nil {
			t.Fatal(err)
		}
		if !signer.VerifyDigestSig(f.service_pub(), digest[:], confirmation.Signature) {
			t.Fatalf("confirmation signature does not verify: %#v", confirmation)
		}
	}

	// OUTPUT, manifest and artifact are all READY; the artifact has no confirmation of its own.
	for _, ref := range []ObjectKey{f.output.Key, f.manifest.Key} {
		metadata, err := f.store.Metadata(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.State != StateReady {
			t.Fatalf("%s state = %s, want READY", ref.Kind, metadata.State)
		}
	}
	artifactRef := f.manifest.Key
	artifactRef.Kind = ObjectKindEvidenceArtifact
	artifactRef.ContentHash = f.manifest.Artifacts[0].ContentHash
	artifact, err := f.store.Metadata(context.Background(), artifactRef)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.State != StateReady {
		t.Fatalf("artifact state = %s, want READY", artifact.State)
	}
}

// An exact replay returns the originally issued bytes and signature without re-signing.
func TestFinalizeTaskResultReplayReturnsTheOriginalConfirmations(t *testing.T) {
	f := newFinalizeFixture(t)
	first, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	// Different request nonce: a replay of the same body must still get the same confirmation.
	second, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 10))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Idempotent {
		t.Fatal("replay must be marked idempotent")
	}
	if hex.EncodeToString(second.OutputConfirmation.Signature) != hex.EncodeToString(first.OutputConfirmation.Signature) {
		t.Fatal("replay re-signed a confirmation")
	}
	if second.OutputConfirmation.RetentionUntilHeight != first.OutputConfirmation.RetentionUntilHeight {
		t.Fatal("replay changed the retention commitment")
	}
}

// One missing object means no commit: READY is atomic; never switch OUTPUT first and then discover the manifest is absent.
func TestFinalizeTaskResultRejectsIncompleteBundle(t *testing.T) {
	f := newFinalizeFixture(t)
	// Add a commitment pointing at a manifest that does not exist.
	f.receipt.EvidenceCommitments = append(f.receipt.EvidenceCommitments, EvidenceCommitment{
		Kind:             uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING) + 1,
		HashOrRoot:       strings.Repeat("d", 64),
		EncodedSizeBytes: 128,
	})
	digest, err := receiptDigest(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receipt.ServiceSignature = hex.EncodeToString(signDigestForTest(t, f.workerService, digest[:]))

	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	// After the failure OUTPUT must not already be READY.
	output, err := f.store.Metadata(context.Background(), f.output.Key)
	if err != nil {
		t.Fatal(err)
	}
	if output.State != StateStored {
		t.Fatalf("output state = %s, want STORED", output.State)
	}
}

// Reject when the manifest's evidence_schema_hash does not match the locked Verification Profile.
func TestFinalizeTaskResultRejectsSchemaHashMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.authority.profile.EvidenceSchemaHash = strings.Repeat("8", 64)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

// If the receipt accepted on-chain differs from the local one, the result must not be switched.
func TestFinalizeTaskResultRejectsDifferentAcceptedReceipt(t *testing.T) {
	f := newFinalizeFixture(t)
	f.authority.task.InferReceipt = chaincli.InferReceiptState{InferReceiptHash: strings.Repeat("e", 64)}
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

// A caller that is not the current selected Worker cannot submit the result, even with a valid signature.
func TestFinalizeTaskResultRejectsNonSelectedWorker(t *testing.T) {
	f := newFinalizeFixture(t)
	request := f.request(t, 9)
	request.Auth = signedRequestAs(t, f.other.Address(), f.other,
		MethodFinalizeResult, f.scope, mustDecodeHex(t, request.Auth.BodyDigest), 9, 110)
	if _, err := f.service.FinalizeTaskResult(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

// The body digest must be recomputed server-side from the receipt: an arbitrary caller-supplied body gets no authorization.
func TestFinalizeTaskResultRejectsForeignBodyDigest(t *testing.T) {
	f := newFinalizeFixture(t)
	request := f.request(t, 9)
	request.Auth = signedRequestAs(t, f.worker.Address(), f.workerService,
		MethodFinalizeResult, f.scope, []byte("some other body"), 9, 110)
	if _, err := f.service.FinalizeTaskResult(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

// Reject when the actual OUTPUT size differs from what the receipt declares; the receipt commits to that object.
func TestFinalizeTaskResultRejectsOutputSizeMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.OutputSizeBytes = f.output.SizeBytes + 1
	digest, err := receiptDigest(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receipt.ServiceSignature = hex.EncodeToString(signDigestForTest(t, f.workerService, digest[:]))
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// FinalizeVerifierEvidence switches only its own bundle: the readiness of the Worker's
// OUTPUT and evidence is untouched.
func TestFinalizeVerifierEvidenceOnlyCommitsItsOwnBundle(t *testing.T) {
	f := newFinalizeFixture(t)
	verifier := f.verifier.Address()

	artifactBody := []byte("verifier aggregate proof bytes")
	artifactRef := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceArtifact, ContentHash: hex.EncodeToString(sha256Sum(artifactBody)),
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: verifier,
	}
	storeObject(t, f.store, artifactRef, artifactBody, verifier, "")

	manifestRef := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind:                 ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: verifier,
	}
	manifestBody := buildManifest(t, manifestRef, finalizeSchemaHash, []EvidenceArtifact{{
		ArtifactID: "aggregate_proof", ContentHash: artifactRef.ContentHash, SizeBytes: uint64(len(artifactBody)),
	}})
	bundle := EvidenceBundleHash(manifestBody)
	manifestRef.ContentHash = hex.EncodeToString(bundle[:])
	manifest := storeObject(t, f.store, manifestRef, manifestBody, verifier, "application/json")

	signingDigest := strings.Repeat("1", 64)
	signatureDigest := strings.Repeat("2", 64)
	body, err := TaskDataFinalizeVerifierBodyDigest(
		f.taskHash, testSessionID, testTaskID, 1, verifier, signingDigest, signatureDigest)
	if err != nil {
		t.Fatal(err)
	}
	auth := signedRequestAs(t, verifier, f.verifierService, MethodFinalizeVerifier, f.scope, body[:], 11, 110)
	outcome, err := f.service.FinalizeVerifierEvidence(context.Background(), FinalizeVerifierRequest{
		Auth: auth, TaskHash: f.taskHash, VerifyRound: 1, VerifierOperator: verifier,
		SigningDigest: signingDigest, SignatureDigest: signatureDigest,
		BundleHash: manifestRef.ContentHash, ManifestSizeBytes: manifest.SizeBytes,
	})
	if err != nil {
		t.Fatalf("finalize verifier: %v", err)
	}
	if outcome.Confirmation.Ref != manifestRef ||
		outcome.Confirmation.ArtifactTotalSizeBytes != uint64(len(artifactBody)) {
		t.Fatalf("confirmation = %#v", outcome.Confirmation)
	}
	// The Worker's OUTPUT and manifest are unaffected.
	for _, ref := range []ObjectKey{f.output.Key, f.manifest.Key} {
		metadata, err := f.store.Metadata(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.State != StateStored {
			t.Fatalf("worker %s state = %s, the Verifier's Finalize must not touch it", ref.Kind, metadata.State)
		}
	}
}

// producer is not the requester itself: nobody may publish evidence on another's behalf.
func TestFinalizeVerifierEvidenceRejectsProxyProducer(t *testing.T) {
	f := newFinalizeFixture(t)
	signingDigest := strings.Repeat("1", 64)
	signatureDigest := strings.Repeat("2", 64)
	body, err := TaskDataFinalizeVerifierBodyDigest(
		f.taskHash, testSessionID, testTaskID, 1, f.candidate.Address(), signingDigest, signatureDigest)
	if err != nil {
		t.Fatal(err)
	}
	auth := signedRequestAs(t, f.verifier.Address(), f.verifierService,
		MethodFinalizeVerifier, f.scope, body[:], 11, 110)
	_, err = f.service.FinalizeVerifierEvidence(context.Background(), FinalizeVerifierRequest{
		Auth: auth, TaskHash: f.taskHash, VerifyRound: 1, VerifierOperator: f.candidate.Address(),
		SigningDigest: signingDigest, SignatureDigest: signatureDigest,
		BundleHash: strings.Repeat("3", 64), ManifestSizeBytes: 100,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

func (f *finalizeFixture) service_pub() []byte { return f.authorizerFixture.service.PubKeyCompressed() }

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// streamOutput replaces the fixture's whole-object OUTPUT via the streaming path
// (OpenOutputStream -> Append x n -> Finish) and points the receipt at the MMR root.
// Returns the finalized metadata.
func (f *finalizeFixture) streamOutput(t *testing.T, texts []string) Metadata {
	t.Helper()
	key := ObjectKey{TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID, Kind: ObjectKindOutput}
	stream, _, err := f.store.OpenOutputStream(context.Background(), key, f.worker.Address(),
		OutputStreamConfig{MaxLeaves: 8, MinFrameBytes: 2, MaxFrameBytes: 64, MaxAttachmentBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i, text := range texts {
		if _, err := stream.Append(context.Background(), chunkFor(acc, uint64(i), text)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	root := acc.Root()
	meta, err := stream.Finish(context.Background(), OutputFin{FinalSeq: uint64(len(texts) - 1), OutputMMRRoot: root[:]})
	if err != nil {
		t.Fatal(err)
	}
	f.output = meta
	f.receipt.OutputHash = hex.EncodeToString(root[:])
	f.receipt.OutputSizeBytes = meta.SizeBytes
	f.receipt.OutputLeafCount = meta.OutputLeafCount
	f.resignReceipt(t)
	return meta
}

func (f *finalizeFixture) resignReceipt(t *testing.T) {
	t.Helper()
	digest, err := receiptDigest(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receipt.ServiceSignature = hex.EncodeToString(signDigestForTest(t, f.workerService, digest[:]))
}

// Streamed upload -> Fin (STORED) -> FinalizeTaskResult: receipt.output_hash is the MMR
// root, and Finalize must find the object by that root, switch it to READY and sign the
// confirmation. This path was untested before, which let the bug of using
// sha256(concatenated text) as the object identity at finalization slip through.
func TestFinalizeTaskResultAcceptsStreamedOutputByMMRRoot(t *testing.T) {
	f := newFinalizeFixture(t)
	meta := f.streamOutput(t, []string{"hello, ", "world", "!!"})
	if meta.State != StateStored || meta.OutputLeafCount != 3 || meta.Key.ContentHash != f.receipt.OutputHash {
		t.Fatalf("streamed output metadata = %+v", meta)
	}
	outcome, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9))
	if err != nil {
		t.Fatalf("finalize streamed output: %v", err)
	}
	if outcome.OutputConfirmation.Ref != meta.Key || outcome.OutputConfirmation.Ref.ContentHash != f.receipt.OutputHash {
		t.Fatalf("output confirmation = %#v", outcome.OutputConfirmation)
	}
	ready, err := f.store.Metadata(context.Background(), meta.Key)
	if err != nil || ready.State != StateReady || ready.OutputLeafCount != 3 || len(ready.ChunkLengths) != 3 {
		t.Fatalf("output after finalize = %+v / %v", ready, err)
	}
	// The receipt verified by Finalize is persisted with the OUTPUT: it is the only source
	// of the infer_receipt convenience copy in GetTaskDataMetadata, which the Cortex
	// Verifier requires when confirming the OUTPUT.
	if ready.Receipt == nil || ready.Receipt.OutputHash != f.receipt.OutputHash || ready.Receipt.ServiceSignature != f.receipt.ServiceSignature {
		t.Fatalf("output receipt after finalize = %+v", ready.Receipt)
	}
	// User/Verifier retrieval uses the same ref: fetch the whole concatenated text by output_hash (the root).
	reader, err := f.store.OpenRange(context.Background(), meta.Key, 0, meta.SizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(body) != "hello, world!!" {
		t.Fatalf("fetched output = %q", body)
	}
}

// receipt output_leaf_count differs from the leaf count recorded at finalization -> reject:
// the root a Verifier recomputes from chunk_lengths would not match the on-chain commitment.
func TestFinalizeTaskResultRejectsStreamedOutputLeafCountMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.streamOutput(t, []string{"hello, ", "world", "!!"})
	f.receipt.OutputLeafCount = 2
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// receipt points at a different root (the Worker signed a different output than the Builder received) -> object not found, reject.
func TestFinalizeTaskResultRejectsStreamedOutputRootMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.streamOutput(t, []string{"hello, ", "world", "!!"})
	f.receipt.OutputHash = strings.Repeat("c", 64)
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// receipt encoded_size_bytes differs from the total artifact size in the manifest -> reject.
// The old implementation compared it with the manifest byte count while cortex fills the
// total artifact size per wire, so they never matched.
func TestFinalizeTaskResultRejectsEncodedSizeMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.EvidenceCommitments[0].EncodedSizeBytes++
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// A Verifier manifest is not addressed via a commitment: content_hash must be the H_V1 of
// the bytes, and a wrong hash is rejected at upload.
func TestVerifierManifestContentHashMustBeBundleHash(t *testing.T) {
	f := newFinalizeFixture(t)
	verifier := f.verifier.Address()
	ref := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: strings.Repeat("e", 64),
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: verifier,
	}
	body := buildManifest(t, ref, finalizeSchemaHash, []EvidenceArtifact{{
		ArtifactID: "aggregate_proof", ContentHash: strings.Repeat("a", 64), SizeBytes: 4,
	}})
	header := UploadHeader{Key: ref, Uploader: verifier, SizeBytes: uint64(len(body)), SemanticHash: ref.ContentHash, MediaType: "application/json", RetainUntilHeight: 180}
	upload, err := f.store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("prepare = %v, want ErrHashMismatch", err)
	}
}
