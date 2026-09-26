package taskdata

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sort"
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
	return newWorkerBundleFixture(t, workerBundleSpec{})
}

// newFinalizeFixtureOn sets up the task, the profile and the streamed OUTPUT, but no Worker bundle.
func newFinalizeFixtureOn(t *testing.T, fx *authorizerFixture, store *Store, service *Service) *finalizeFixture {
	t.Helper()
	taskHash := strings.Repeat("a", 64)
	fx.authority.task.Assignment.AcceptedTaskHash = taskHash
	fx.authority.task.Assignment.ModelID = "model-1"
	fx.authority.task.Assignment.ProfileVersion = 3
	fx.authority.profile = chaincli.ProfileState{
		ModelID: "model-1", ProfileVersion: 3, Status: "ACTIVE",
		EvidenceSchemaHash: finalizeSchemaHash,
	}
	f := &finalizeFixture{
		authorizerFixture: fx, service: service, store: store,
		taskHash: taskHash, scope: ObjectKey{SessionID: testSessionID, TaskID: testTaskID},
		receipt: SignedInferReceipt{
			SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainID: testChainID,
			TaskID: testTaskID, TaskHash: taskHash,
			WorkerOperatorAddress: fx.worker.Address(), ServiceAuthorizationNonce: 1,
			GenerationParamsDigest: strings.Repeat("b", 64),
			ExpiryHeight:           1200, GeneratedTokenCount: 3, ServiceSignature: strings.Repeat("0", 128),
		},
	}
	f.streamOutput(t, []string{"hello, ", "world", "!!"})
	return f
}

// workerBundleSpec describes the Phase 0 WORKER_VALUE_OPENING bundle storeWorkerBundle writes; the
// zero value is a valid bundle.
type workerBundleSpec struct {
	evidenceKind   string // default WORKER_VALUE_OPENING; "-" omits it
	schemaMetadata string
	artifacts      map[string][]byte
	// commit overrides the bytes the receipt commitment is computed from, so the stored bundle
	// no longer matches what the Worker signed.
	commit map[string][]byte
	// commitFinishReason overrides the finish_reason in the commitment.
	commitFinishReason uint32
}

func (spec workerBundleSpec) withDefaults(t *testing.T) workerBundleSpec {
	if spec.evidenceKind == "" {
		spec.evidenceKind = workerValueOpeningManifestKind
	}
	if spec.artifacts == nil {
		spec.artifacts = map[string][]byte{
			"checkpoint":          []byte("checkpoint json"),
			"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000ffff"),
			"input_token_ids":     mustDecodeHex(t, "000000020000000100000100"),
			"trace":               []byte("trace json"),
		}
	}
	if spec.commitFinishReason == 0 {
		spec.commitFinishReason = 1
	}
	return spec
}

// storeWorkerBundle stores the artifacts and the manifest through the real upload path under the
// content_hash of the recomputed commitment, and points the receipt's single commitment at it.
func (f *finalizeFixture) storeWorkerBundle(t *testing.T, spec workerBundleSpec) {
	t.Helper()
	spec = spec.withDefaults(t)
	manifestRef := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind:                 ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: f.worker.Address(),
	}
	ids := make([]string, 0, len(spec.artifacts))
	for id := range spec.artifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	artifacts := make([]EvidenceArtifact, 0, len(ids))
	for _, id := range ids {
		body := spec.artifacts[id]
		ref := manifestRef
		ref.Kind, ref.ContentHash = ObjectKindEvidenceArtifact, hex.EncodeToString(sha256Sum(body))
		storeObject(t, f.store, ref, body, f.worker.Address(), "")
		artifacts = append(artifacts, EvidenceArtifact{ArtifactID: id, ContentHash: ref.ContentHash, SizeBytes: uint64(len(body))})
	}
	manifest := EvidenceBundleManifest{
		ManifestVersion: EvidenceBundleManifestVersionV1, ChainID: testChainID,
		TaskID: testTaskID, TaskHash: f.taskHash, EvidenceSchemaHash: finalizeSchemaHash,
		ProducerKind: EvidenceProducerWorker, ProducerOperator: f.worker.Address(), VerifyRound: 1,
		Artifacts: artifacts,
	}
	if spec.evidenceKind != "-" {
		manifest.EvidenceKind = spec.evidenceKind
	}
	manifest.SchemaMetadata = spec.schemaMetadata
	raw, err := manifest.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	committed := func(id string) []byte {
		if body, ok := spec.commit[id]; ok {
			return body
		}
		return spec.artifacts[id]
	}
	h := func(value string) []byte { return mustDecodeHex(t, value) }
	inputHash, err := nodecontract.TokenIDsHash(nodecontract.DomainInputTokenIDsV1, committed("input_token_ids"))
	if err != nil {
		t.Fatal(err)
	}
	generatedHash, err := nodecontract.TokenIDsHash(nodecontract.DomainGeneratedTokenIDsV1, committed("generated_token_ids"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodecontract.WorkerValueCommitmentV2{
		ChainID: f.receipt.ChainID, TaskID: h(f.receipt.TaskID), AcceptedTaskHash: h(f.taskHash),
		WorkerOperatorAddress: f.receipt.WorkerOperatorAddress, GenerationParamsDigest: h(f.receipt.GenerationParamsDigest),
		EvidenceSchemaHash: h(finalizeSchemaHash), OutputHash: h(f.receipt.OutputHash),
		OutputSizeBytes: f.receipt.OutputSizeBytes, FinishReason: spec.commitFinishReason,
		TraceRoot: sha256Sum(committed("trace")), TraceEncodedSizeBytes: uint64(len(committed("trace"))),
		CheckpointRoot: sha256Sum(committed("checkpoint")), CheckpointEncodedSizeBytes: uint64(len(committed("checkpoint"))),
		GeneratedTokenCount: f.receipt.GeneratedTokenCount, OutputLeafCount: f.receipt.OutputLeafCount,
		InputTokenIDsHash: inputHash[:], GeneratedTokenIDsHash: generatedHash[:],
		InputTokenIDsSizeBytes:     uint64(len(committed("input_token_ids"))),
		GeneratedTokenIDsSizeBytes: uint64(len(committed("generated_token_ids"))),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// The Worker manifest's ref content_hash is the receipt's evidence_hash_or_root, not the H_V1
	// of the manifest bytes.
	manifestRef.ContentHash = hex.EncodeToString(digest[:])
	f.manifest = storeObject(t, f.store, manifestRef, []byte(raw), f.worker.Address(), "application/json")
	if want := EvidenceBundleHash([]byte(raw)); f.manifest.EvidenceBundleHash != hex.EncodeToString(want[:]) {
		t.Fatalf("worker manifest evidence_bundle_hash = %s, want H_V1(bytes)", f.manifest.EvidenceBundleHash)
	}
	f.receipt.EvidenceCommitments = []EvidenceCommitment{{
		Kind:       uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING),
		HashOrRoot: manifestRef.ContentHash,
		// wire v0.4.1: encoded_size_bytes is the total artifact size, not the manifest byte count.
		EncodedSizeBytes: f.manifest.ArtifactTotalSizeBytes,
	}}
	f.resignReceipt(t)
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
	for rest := body; len(rest) > 0; {
		n := min(uint64(len(rest)), store.ChunkSize())
		if err := upload.WriteChunk(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
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
	for _, entry := range f.manifest.Artifacts {
		artifactRef := f.manifest.Key
		artifactRef.Kind, artifactRef.ContentHash = ObjectKindEvidenceArtifact, entry.ContentHash
		artifact, err := f.store.Metadata(context.Background(), artifactRef)
		if err != nil {
			t.Fatal(err)
		}
		if artifact.State != StateReady {
			t.Fatalf("artifact %s state = %s, want READY", entry.ArtifactID, artifact.State)
		}
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

// A Verifier finalizes a bundle only under a round it was selected in: a round-1 seat does not
// finalize a round-2 bundle.
func TestFinalizeVerifierEvidenceRejectsForeignRound(t *testing.T) {
	f := newFinalizeFixture(t)
	signingDigest := strings.Repeat("1", 64)
	signatureDigest := strings.Repeat("2", 64)
	body, err := TaskDataFinalizeVerifierBodyDigest(
		f.taskHash, testSessionID, testTaskID, 2, f.verifier.Address(), signingDigest, signatureDigest)
	if err != nil {
		t.Fatal(err)
	}
	auth := signedRequestAs(t, f.verifier.Address(), f.verifierService,
		MethodFinalizeVerifier, f.scope, body[:], 12, 110)
	_, err = f.service.FinalizeVerifierEvidence(context.Background(), FinalizeVerifierRequest{
		Auth: auth, TaskHash: f.taskHash, VerifyRound: 2, VerifierOperator: f.verifier.Address(),
		SigningDigest: signingDigest, SignatureDigest: signatureDigest,
		BundleHash: strings.Repeat("3", 64), ManifestSizeBytes: 100,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

func TestIsSelectedVerifierMatchesRound(t *testing.T) {
	task := chaincli.OnChainTask{
		Verifiers: []string{"verifier-1"},
		VerifierRounds: []chaincli.VerifierRound{
			{VerifyRound: 1, Verifiers: []string{"verifier-1"}, CommitDeadlineHeight: 10},
			{VerifyRound: 2, Verifiers: []string{"challenger-1"}, CommitDeadlineHeight: 20},
		},
	}
	for _, tt := range []struct {
		operator string
		round    uint32
		want     bool
	}{
		{"verifier-1", 1, true}, {"verifier-1", 2, false},
		{"challenger-1", 2, true}, {"challenger-1", 1, false},
		{"verifier-1", 0, false},
	} {
		if got := isSelectedVerifier(task, tt.operator, tt.round); got != tt.want {
			t.Fatalf("isSelectedVerifier(%s, %d) = %t, want %t", tt.operator, tt.round, got, tt.want)
		}
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

// streamOutput stores the OUTPUT via the streaming path (OpenOutputStream -> Append x n -> Finish
// with finish_reason EOS_TOKEN) and points the receipt at the MMR root. Returns the sealed metadata.
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
	meta, err := stream.Finish(context.Background(), OutputFin{FinalSeq: uint64(len(texts) - 1), OutputMMRRoot: root[:], FinishReason: 1})
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
	meta := f.output
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
	f.receipt.OutputLeafCount = 2
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// receipt points at a different root (the Worker signed a different output than the Builder received) -> object not found, reject.
func TestFinalizeTaskResultRejectsStreamedOutputRootMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
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

// newWorkerBundleFixture is a finalize fixture whose Worker bundle is built from spec instead of
// the default valid one.
func newWorkerBundleFixture(t *testing.T, spec workerBundleSpec) *finalizeFixture {
	t.Helper()
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	base := newFinalizeFixtureOn(t, fx, store, service)
	base.storeWorkerBundle(t, spec)
	return base
}

// requireFinalizeRejected runs Finalize, requires the given error and checks nothing became READY
// and no confirmation was recorded.
func (f *finalizeFixture) requireFinalizeRejected(t *testing.T, want error, contains string) {
	t.Helper()
	_, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9))
	if !errors.Is(err, want) || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %v, want %v containing %q", err, want, contains)
	}
	for _, ref := range []ObjectKey{f.output.Key, f.manifest.Key} {
		metadata, err := f.store.Metadata(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.State != StateStored {
			t.Fatalf("%s state = %s after a rejected Finalize, want STORED", ref.Kind, metadata.State)
		}
	}
}

// The Worker commitment is recomputed from the stored bundle (02 §2): a bundle that is not the one
// the receipt commits to is rejected even though every object hash and size checks out.
func TestFinalizeTaskResultRejectsBundleNotMatchingCommitment(t *testing.T) {
	for name, spec := range map[string]workerBundleSpec{
		"generated token changed": {commit: map[string][]byte{"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000fffe")}},
		"input token changed":     {commit: map[string][]byte{"input_token_ids": mustDecodeHex(t, "000000020000000100000101")}},
		"trace swapped":           {commit: map[string][]byte{"trace": []byte("other trace")}},
		"checkpoint swapped":      {commit: map[string][]byte{"checkpoint": []byte("other checkpoint json")}},
		"finish_reason differs":   {commitFinishReason: 2},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWorkerBundleFixture(t, spec)
			f.requireFinalizeRejected(t, ErrHashMismatch, "worker evidence commitment recomputed")
		})
	}
}

// The Phase 0 WORKER_VALUE_OPENING manifest shape (02 §2.1) is enforced before recomputing.
func TestFinalizeTaskResultRejectsWorkerManifestShape(t *testing.T) {
	artifacts := func(drop string, extra string) map[string][]byte {
		out := map[string][]byte{
			"checkpoint":          []byte("checkpoint json"),
			"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000ffff"),
			"input_token_ids":     mustDecodeHex(t, "000000020000000100000100"),
			"trace":               []byte("trace json"),
		}
		delete(out, drop)
		if extra != "" {
			out[extra] = []byte("extra artifact")
		}
		return out
	}
	for name, c := range map[string]struct {
		spec     workerBundleSpec
		contains string
	}{
		"wrong evidence_kind":   {workerBundleSpec{evidenceKind: "OTHER"}, "evidence_kind"},
		"missing evidence_kind": {workerBundleSpec{evidenceKind: "-"}, "evidence_kind"},
		"schema_metadata":       {workerBundleSpec{schemaMetadata: `{"a":1}`}, "schema_metadata"},
		"missing artifact":      {workerBundleSpec{artifacts: artifacts("trace", ""), commit: map[string][]byte{"trace": []byte("trace json")}}, "3 artifacts"},
		"extra artifact":        {workerBundleSpec{artifacts: artifacts("", "zzz")}, "5 artifacts"},
		"renamed artifact":      {workerBundleSpec{artifacts: artifacts("trace", "trace2"), commit: map[string][]byte{"trace": []byte("trace json")}}, "artifact 3"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWorkerBundleFixture(t, c.spec)
			f.requireFinalizeRejected(t, ErrMalformed, c.contains)
		})
	}
}

// A token id artifact whose count prefix does not match its length cannot be hashed (05 §7).
func TestFinalizeTaskResultRejectsTokenIDsFraming(t *testing.T) {
	f := newWorkerBundleFixture(t, workerBundleSpec{
		artifacts: map[string][]byte{
			"checkpoint":          []byte("checkpoint json"),
			"generated_token_ids": mustDecodeHex(t, "0000000400000002000001010000ffff"),
			"input_token_ids":     mustDecodeHex(t, "000000020000000100000100"),
			"trace":               []byte("trace json"),
		},
		commit: map[string][]byte{"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000ffff")},
	})
	f.requireFinalizeRejected(t, ErrMalformed, "count 4 needs")
}

// Only WORKER_VALUE_OPENING is a Phase 0 Worker evidence kind.
func TestFinalizeTaskResultRejectsUnsupportedWorkerEvidenceKind(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.EvidenceCommitments[0].Kind = uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING)
	f.resignReceipt(t)
	f.requireFinalizeRejected(t, ErrConflict, "unsupported worker evidence kind")
}

// A whole-object OUTPUT has no Fin and so no finish_reason: it cannot be finalized, and the error
// says so rather than reporting a commitment mismatch.
func TestFinalizeTaskResultRejectsWholeObjectOutput(t *testing.T) {
	f := newFinalizeFixture(t)
	body := []byte("the model output")
	ref := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindOutput, ContentHash: hex.EncodeToString(sha256Sum(body)),
	}
	f.output = storeObject(t, f.store, ref, body, f.worker.Address(), "")
	f.receipt.OutputHash, f.receipt.OutputSizeBytes = ref.ContentHash, f.output.SizeBytes
	f.resignReceipt(t)
	f.requireFinalizeRejected(t, ErrConflict, "output was not streamed")
}
