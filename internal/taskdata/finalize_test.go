package taskdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	finalizeSchemaHash = "7777777777777777777777777777777777777777777777777777777777777777"
	finalizeModelID    = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	zeroHash32Hex      = "0000000000000000000000000000000000000000000000000000000000000000"
)

// finalizeFixture puts every object a Finalize needs into STORED: the OUTPUT and the Worker's two
// bundles (token and value) with their artifacts.
type finalizeFixture struct {
	*authorizerFixture
	service *Service
	store   *Store

	taskHash string
	scope    ObjectKey
	output   Metadata
	bundles  map[EvidenceKind]Metadata
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
	paramsDigest := hashV1(DomainTaskGenerationParamsV1, []byte(finalizeGenerationParams))
	fx.authority.task.Assignment.AcceptedTaskHash = taskHash
	fx.authority.task.Assignment.GenerationParamsDigest = hex.EncodeToString(paramsDigest[:])
	fx.authority.task.Assignment.ModelID = finalizeModelID
	fx.authority.task.Assignment.ProfileVersion = 3
	fx.authority.profile = chaincli.ProfileState{
		ModelID: finalizeModelID, ProfileVersion: 3, Status: "ACTIVE",
		EvidenceSchemaHash: finalizeSchemaHash,
	}
	f := &finalizeFixture{
		authorizerFixture: fx, service: service, store: store, bundles: map[EvidenceKind]Metadata{},
		taskHash: taskHash, scope: ObjectKey{SessionID: testSessionID, TaskID: testTaskID},
		receipt: SignedInferReceipt{
			SchemaVersion: nodecontract.InferReceiptSchemaVersionV3, ChainID: testChainID,
			TaskID: testTaskID, TaskHash: taskHash,
			WorkerOperatorAddress: fx.worker.Address(), ServiceAuthorizationNonce: 1,
			GenerationParamsDigest: hex.EncodeToString(paramsDigest[:]),
			ExpiryHeight:           1200, GeneratedTokenCount: 3, ServiceSignature: strings.Repeat("0", 128),
			OutputKeyCommitment: zeroHash32Hex, WorkerTokenKeyCommitment: zeroHash32Hex,
			WorkerValueKeyCommitment: zeroHash32Hex, CiphertextOutputRoot: zeroHash32Hex,
		},
	}
	f.streamOutput(t, []string{"hello, ", "world", "!!"})
	return f
}

// workerBundleSpec describes the two Worker bundles storeWorkerBundles writes; the zero value is a
// valid pair.
type workerBundleSpec struct {
	schemaMetadata string
	// tokenArtifacts / valueArtifacts replace the default artifacts of a bundle.
	tokenArtifacts map[string][]byte
	valueArtifacts map[string][]byte
	// commit overrides the bytes a commitment is computed from, so the stored bundle no longer
	// matches what the Worker signed.
	commit map[string][]byte
	// commitFinishReason overrides the finish_reason in the token commitment.
	commitFinishReason uint32
}

func (f *finalizeFixture) defaultTokenArtifacts(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000ffff"),
		"generation_params":   []byte(finalizeGenerationParams),
		"input_token_ids":     mustDecodeHex(t, "000000020000000100000100"),
	}
}

// finalizeGenerationParams stands in for the order's canonical generation-parameter JSON; the
// task's generation_params_digest is its H_V1.
const finalizeGenerationParams = `{"generation_params_schema_version":1,"max_output_tokens":256}`

func (f *finalizeFixture) defaultValueArtifacts(t *testing.T) map[string][]byte {
	return map[string][]byte{"worker_values": f.workerValues(t, 3, nil)}
}

// workerValues builds a worker_values artifact of n leaves for this task and Worker: the leaf count
// followed by each leaf's fields. edit may change a leaf's fields before they are encoded.
func (f *finalizeFixture) workerValues(t *testing.T, n int, edit func(position int, fields [][]byte)) []byte {
	t.Helper()
	worker, err := nodecontract.CanonicalOperatorAddressBytes("worker", f.worker.Address())
	if err != nil {
		t.Fatal(err)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(n))
	for position := 0; position < n; position++ {
		entry := nodecontract.CanonicalFrameBytes(nodecontract.Uint32BE(uint32(position+7)), nodecontract.Uint64BE(uint64(1_000_000)))
		fields := [][]byte{
			[]byte(testChainID), mustDecodeHex(t, testTaskID), mustDecodeHex(t, f.taskHash), worker,
			nodecontract.Uint32BE(uint32(position)), nodecontract.Uint32BE(uint32(position + 7)),
			nodecontract.Uint64BE(uint64(1_000_000)), nodecontract.Uint32BE(1),
			nodecontract.CanonicalFrameBytes(nodecontract.Uint32BE(1), entry),
			{0}, {1},
		}
		if edit != nil {
			edit(position, fields)
		}
		out = append(out, nodecontract.CanonicalFrameBytes(fields...)...)
	}
	return out
}

func (spec workerBundleSpec) withDefaults(t *testing.T, f *finalizeFixture) workerBundleSpec {
	if spec.tokenArtifacts == nil {
		spec.tokenArtifacts = f.defaultTokenArtifacts(t)
	}
	if spec.valueArtifacts == nil {
		spec.valueArtifacts = f.defaultValueArtifacts(t)
	}
	if spec.commitFinishReason == 0 {
		spec.commitFinishReason = 1
	}
	return spec
}

// storeWorkerBundles stores both bundles through the real upload path, each under the content_hash
// of its recomputed commitment, and points the receipt's two commitments at them.
func (f *finalizeFixture) storeWorkerBundles(t *testing.T, spec workerBundleSpec) {
	t.Helper()
	spec = spec.withDefaults(t, f)
	committed := func(artifacts map[string][]byte, id string) []byte {
		if body, ok := spec.commit[id]; ok {
			return body
		}
		return artifacts[id]
	}
	h := func(value string) []byte { return mustDecodeHex(t, value) }

	inputHash, err := nodecontract.TokenIDsHash(nodecontract.DomainInputTokenIDsV1, committed(spec.tokenArtifacts, "input_token_ids"))
	if err != nil {
		t.Fatal(err)
	}
	generated := committed(spec.tokenArtifacts, "generated_token_ids")
	generatedHash, err := nodecontract.TokenIDsHash(nodecontract.DomainGeneratedTokenIDsV1, generated)
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest, err := nodecontract.WorkerTokenCommitmentV1{
		ChainID: f.receipt.ChainID, TaskID: h(f.receipt.TaskID), AcceptedTaskHash: h(f.taskHash),
		WorkerOperatorAddress: f.receipt.WorkerOperatorAddress, GenerationParamsDigest: h(f.receipt.GenerationParamsDigest),
		EvidenceSchemaHash: h(finalizeSchemaHash), OutputHash: h(f.receipt.OutputHash),
		OutputSizeBytes: f.receipt.OutputSizeBytes, OutputLeafCount: f.receipt.OutputLeafCount,
		FinishReason: spec.commitFinishReason, GeneratedTokenCount: f.receipt.GeneratedTokenCount,
		InputTokenIDsHash: inputHash[:], GeneratedTokenIDsHash: generatedHash[:],
		InputTokenIDsSizeBytes:     uint64(len(committed(spec.tokenArtifacts, "input_token_ids"))),
		GeneratedTokenIDsSizeBytes: uint64(len(generated)),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}

	values := committed(spec.valueArtifacts, "worker_values")
	root, err := nodecontract.WorkerValuesRootReader(bytes.NewReader(values), uint64(len(values)), nodecontract.WorkerValueScope{
		ChainID: f.receipt.ChainID, TaskID: h(f.receipt.TaskID), AcceptedTaskHash: h(f.taskHash),
		WorkerOperatorAddress: f.receipt.WorkerOperatorAddress,
	}, f.receipt.GeneratedTokenCount)
	if err != nil {
		t.Fatalf("committed worker_values: %v", err)
	}
	valueDigest, err := nodecontract.WorkerValueCommitmentV3{
		ChainID: f.receipt.ChainID, TaskID: h(f.receipt.TaskID), AcceptedTaskHash: h(f.taskHash),
		WorkerOperatorAddress: f.receipt.WorkerOperatorAddress, EvidenceSchemaHash: h(finalizeSchemaHash),
		WorkerValueRoot: root[:], WorkerValuesEncodedSizeBytes: uint64(len(values)),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}

	value := f.storeBundle(t, EvidenceKindWorkerValueOpening, spec.valueArtifacts, spec.schemaMetadata, hex.EncodeToString(valueDigest[:]))
	token := f.storeBundle(t, EvidenceKindWorkerTokenOpening, spec.tokenArtifacts, spec.schemaMetadata, hex.EncodeToString(tokenDigest[:]))
	// Ordered by EvidenceKind value: value (1) before token (4). encoded_size_bytes is the artifact
	// size without generation_params, not the manifest byte count.
	f.receipt.EvidenceCommitments = []EvidenceCommitment{
		{Kind: uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING), HashOrRoot: value.Key.ContentHash, EncodedSizeBytes: value.ArtifactTotalSizeBytes},
		{Kind: uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_TOKEN_OPENING), HashOrRoot: token.Key.ContentHash, EncodedSizeBytes: commitmentSizeBytes(token)},
	}
	f.resignReceipt(t)
}

// storeBundle stores one Worker bundle's artifacts and manifest under contentHash.
func (f *finalizeFixture) storeBundle(t *testing.T, kind EvidenceKind, artifactBodies map[string][]byte, schemaMetadata, contentHash string) Metadata {
	t.Helper()
	manifestRef := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind:                 ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: f.worker.Address(),
		EvidenceKind: kind,
	}
	ids := make([]string, 0, len(artifactBodies))
	for id := range artifactBodies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	artifacts := make([]EvidenceArtifact, 0, len(ids))
	for _, id := range ids {
		body := artifactBodies[id]
		ref := manifestRef
		ref.Kind, ref.ContentHash = ObjectKindEvidenceArtifact, hex.EncodeToString(sha256Sum(body))
		storeObject(t, f.store, ref, body, f.worker.Address(), "")
		artifacts = append(artifacts, EvidenceArtifact{ArtifactID: id, ContentHash: ref.ContentHash, SizeBytes: uint64(len(body))})
	}
	manifest := EvidenceBundleManifest{
		ManifestVersion: EvidenceBundleManifestVersionV1, ChainID: testChainID,
		TaskID: testTaskID, TaskHash: f.taskHash, EvidenceSchemaHash: finalizeSchemaHash,
		ProducerKind: EvidenceProducerWorker, ProducerOperator: f.worker.Address(), VerifyRound: 1,
		EvidenceKind: kind.String(), SchemaMetadata: schemaMetadata, Artifacts: artifacts,
	}
	raw, err := manifest.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The Worker manifest's ref content_hash is the receipt's evidence_hash_or_root, not the H_V1
	// of the manifest bytes.
	manifestRef.ContentHash = contentHash
	stored := storeObject(t, f.store, manifestRef, []byte(raw), f.worker.Address(), "application/json")
	if want := EvidenceBundleHash([]byte(raw)); stored.EvidenceBundleHash != hex.EncodeToString(want[:]) {
		t.Fatalf("worker manifest evidence_bundle_hash = %s, want H_V1(bytes)", stored.EvidenceBundleHash)
	}
	f.bundles[kind] = stored
	return stored
}

// request builds a signed FinalizeTaskResult request for one bundle.
func (f *finalizeFixture) request(t *testing.T, nonce byte, kind EvidenceKind) FinalizeResultRequest {
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
		f.taskHash, f.scope.SessionID, f.scope.TaskID, hex.EncodeToString(digest[:]), signatureDigest, kind)
	if err != nil {
		t.Fatal(err)
	}
	auth := signedRequestAs(t, f.worker.Address(), f.workerService,
		MethodFinalizeResult, f.scope, body[:], nonce, 110)
	return FinalizeResultRequest{Auth: auth, TaskHash: f.taskHash, Receipt: f.receipt, EvidenceKind: kind}
}

// finalizeBoth finalizes the token bundle and then the value bundle.
func (f *finalizeFixture) finalizeBoth(t *testing.T) (FinalizeResultOutcome, FinalizeResultOutcome) {
	t.Helper()
	token, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening))
	if err != nil {
		t.Fatalf("finalize token bundle: %v", err)
	}
	value, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 10, EvidenceKindWorkerValueOpening))
	if err != nil {
		t.Fatalf("finalize value bundle: %v", err)
	}
	return token, value
}

// storeObject puts an object into STORED through the real upload path. EVIDENCE_ARTIFACT
// media_type must be empty; other objects default to octet-stream.
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

func (f *finalizeFixture) state(t *testing.T, ref ObjectKey) State {
	t.Helper()
	metadata, err := f.store.Metadata(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.State
}

// Happy path: each call commits one bundle and gets the one OUTPUT confirmation plus that bundle's;
// the first call freezes the OUTPUT, both calls return the same OUTPUT confirmation, and artifacts are
// not confirmed separately.
func TestFinalizeTaskResultCommitsEachBundleAndOneOutputConfirmation(t *testing.T) {
	f := newFinalizeFixture(t)
	token, value := f.finalizeBoth(t)
	if token.Idempotent || value.Idempotent {
		t.Fatal("first submissions are not idempotent")
	}
	if token.OutputConfirmation.Ref != f.output.Key || token.OutputConfirmation.ArtifactTotalSizeBytes != 0 {
		t.Fatalf("output confirmation = %#v", token.OutputConfirmation)
	}
	if !bytes.Equal(token.OutputConfirmation.Signature, value.OutputConfirmation.Signature) ||
		token.OutputConfirmation.RetentionUntilHeight != value.OutputConfirmation.RetentionUntilHeight {
		t.Fatal("the two calls must return the same OUTPUT confirmation")
	}
	for kind, outcome := range map[EvidenceKind]FinalizeResultOutcome{EvidenceKindWorkerTokenOpening: token, EvidenceKindWorkerValueOpening: value} {
		bundle := f.bundles[kind]
		if len(outcome.EvidenceConfirmations) != 1 || outcome.EvidenceConfirmations[0].Ref != bundle.Key ||
			outcome.EvidenceConfirmations[0].ArtifactTotalSizeBytes != bundle.ArtifactTotalSizeBytes {
			t.Fatalf("%s bundle confirmations = %#v", kind, outcome.EvidenceConfirmations)
		}
	}
	// Every confirmation verifies under the current Builder service key.
	for _, confirmation := range []StorageConfirmation{token.OutputConfirmation, token.EvidenceConfirmations[0], value.EvidenceConfirmations[0]} {
		digest, err := BuilderStorageConfirmationDigest(confirmation)
		if err != nil {
			t.Fatal(err)
		}
		if !signer.VerifyDigestSig(f.service_pub(), digest[:], confirmation.Signature) {
			t.Fatalf("confirmation signature does not verify: %#v", confirmation)
		}
	}
	// OUTPUT, manifests and artifacts are all READY.
	for _, bundle := range f.bundles {
		if f.state(t, bundle.Key) != StateReady {
			t.Fatalf("%s manifest is not READY", bundle.Key.EvidenceKind)
		}
		for _, entry := range bundle.Artifacts {
			artifactRef := bundle.Key
			artifactRef.Kind, artifactRef.ContentHash = ObjectKindEvidenceArtifact, entry.ContentHash
			if f.state(t, artifactRef) != StateReady {
				t.Fatalf("artifact %s is not READY", entry.ArtifactID)
			}
		}
	}
	if f.state(t, f.output.Key) != StateReady {
		t.Fatal("OUTPUT is not READY")
	}
}

// The first Finalize freezes the OUTPUT with its receipt; a second one with any other receipt is
// refused, even though that receipt is validly signed and its own bundle checks out.
func TestFinalizeTaskResultSecondCallMustCarryTheSameReceipt(t *testing.T) {
	f := newFinalizeFixture(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); err != nil {
		t.Fatal(err)
	}
	f.receipt.ExpiryHeight++
	f.resignReceipt(t)
	_, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 10, EvidenceKindWorkerValueOpening))
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "output was finalized with receipt") {
		t.Fatalf("error = %v, want ErrConflict for a different receipt", err)
	}
	if f.state(t, f.bundles[EvidenceKindWorkerValueOpening].Key) != StateStored {
		t.Fatal("the refused bundle must stay STORED")
	}
}

// An exact replay returns the originally issued bytes and signature without re-signing.
func TestFinalizeTaskResultReplayReturnsTheOriginalConfirmations(t *testing.T) {
	f := newFinalizeFixture(t)
	first, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening))
	if err != nil {
		t.Fatal(err)
	}
	// Different request nonce: a replay of the same body must still get the same confirmation.
	second, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 10, EvidenceKindWorkerTokenOpening))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Idempotent {
		t.Fatal("replay must be marked idempotent")
	}
	if !bytes.Equal(second.OutputConfirmation.Signature, first.OutputConfirmation.Signature) ||
		!bytes.Equal(second.EvidenceConfirmations[0].Signature, first.EvidenceConfirmations[0].Signature) {
		t.Fatal("replay re-signed a confirmation")
	}
}

// One missing object means no commit: never switch OUTPUT first and then discover the manifest is absent.
func TestFinalizeTaskResultRejectsIncompleteBundle(t *testing.T) {
	f := newFinalizeFixture(t)
	// Point the token commitment at a manifest that does not exist.
	f.receipt.EvidenceCommitments[1].HashOrRoot = strings.Repeat("d", 64)
	f.resignReceipt(t)
	f.requireFinalizeRejected(t, EvidenceKindWorkerTokenOpening, ErrNotFound, "not stored")
}

// A plaintext receipt carries exactly the two Worker commitments: one alone is refused, even for the
// bundle it names.
func TestFinalizeTaskResultRejectsSingleCommitment(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.EvidenceCommitments = f.receipt.EvidenceCommitments[:1]
	f.resignReceipt(t)
	f.requireFinalizeRejected(t, EvidenceKindWorkerValueOpening, ErrMalformed, "exactly WORKER_VALUE_OPENING then WORKER_TOKEN_OPENING")
}

// Encryption is not active: a receipt with a nonzero or empty key commitment is refused.
func TestFinalizeTaskResultRejectsEncryptionMaterial(t *testing.T) {
	for name, edit := range map[string]func(*SignedInferReceipt){
		"nonzero output_key_commitment": func(r *SignedInferReceipt) { r.OutputKeyCommitment = strings.Repeat("1", 64) },
		"empty ciphertext_output_root":  func(r *SignedInferReceipt) { r.CiphertextOutputRoot = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFinalizeFixture(t)
			edit(&f.receipt)
			f.resignReceipt(t)
			f.requireFinalizeRejected(t, EvidenceKindWorkerTokenOpening, ErrMalformed, "for a plaintext task")
		})
	}
}

// Only the two Worker bundle kinds can be finalized here.
func TestFinalizeTaskResultRejectsNonWorkerKind(t *testing.T) {
	f := newFinalizeFixture(t)
	request := f.request(t, 9, EvidenceKindWorkerTokenOpening)
	request.EvidenceKind = EvidenceKindVerifierValueOpening
	if _, err := f.service.FinalizeTaskResult(context.Background(), request); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

// Reject when the manifest's evidence_schema_hash does not match the locked Verification Profile.
func TestFinalizeTaskResultRejectsSchemaHashMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.authority.profile.EvidenceSchemaHash = strings.Repeat("8", 64)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

// If the receipt accepted on-chain differs from the local one, the result must not be switched.
func TestFinalizeTaskResultRejectsDifferentAcceptedReceipt(t *testing.T) {
	f := newFinalizeFixture(t)
	f.authority.task.InferReceipt = chaincli.InferReceiptState{InferReceiptHash: strings.Repeat("e", 64)}
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

// A caller that is not the current selected Worker cannot submit the result, even with a valid signature.
func TestFinalizeTaskResultRejectsNonSelectedWorker(t *testing.T) {
	f := newFinalizeFixture(t)
	request := f.request(t, 9, EvidenceKindWorkerTokenOpening)
	request.Auth = signedRequestAs(t, f.other.Address(), f.other,
		MethodFinalizeResult, f.scope, mustDecodeHex(t, request.Auth.BodyDigest), 9, 110)
	if _, err := f.service.FinalizeTaskResult(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

// The body digest is recomputed server-side from the receipt and the bundle kind: a body for the
// other bundle, or an arbitrary one, gets no authorization.
func TestFinalizeTaskResultRejectsForeignBodyDigest(t *testing.T) {
	f := newFinalizeFixture(t)
	request := f.request(t, 9, EvidenceKindWorkerTokenOpening)
	request.Auth = signedRequestAs(t, f.worker.Address(), f.workerService,
		MethodFinalizeResult, f.scope, []byte("some other body"), 9, 110)
	if _, err := f.service.FinalizeTaskResult(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
	swapped := f.request(t, 9, EvidenceKindWorkerTokenOpening)
	swapped.EvidenceKind = EvidenceKindWorkerValueOpening
	if _, err := f.service.FinalizeTaskResult(context.Background(), swapped); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized for a body signed for the other bundle", err)
	}
}

// Reject when the actual OUTPUT size differs from what the receipt declares.
func TestFinalizeTaskResultRejectsOutputSizeMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.OutputSizeBytes = f.output.SizeBytes + 1
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); !errors.Is(err, ErrHashMismatch) {
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
		EvidenceKind: EvidenceKindVerifierValueOpening,
	}
	storeObject(t, f.store, artifactRef, artifactBody, verifier, "")

	manifestRef := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind:                 ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: verifier,
		EvidenceKind: EvidenceKindVerifierValueOpening,
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
	// The Worker's OUTPUT and manifests are unaffected.
	for _, ref := range []ObjectKey{f.output.Key, f.bundles[EvidenceKindWorkerTokenOpening].Key, f.bundles[EvidenceKindWorkerValueOpening].Key} {
		if f.state(t, ref) != StateStored {
			t.Fatalf("worker %s: the Verifier's Finalize must not touch it", ref.Kind)
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

// Streamed upload -> Fin (STORED) -> FinalizeTaskResult: receipt.output_hash is the MMR root, and
// Finalize finds the object by that root, switches it to READY with the receipt and signs the
// confirmation.
func TestFinalizeTaskResultAcceptsStreamedOutputByMMRRoot(t *testing.T) {
	f := newFinalizeFixture(t)
	meta := f.output
	if meta.State != StateStored || meta.OutputLeafCount != 3 || meta.Key.ContentHash != f.receipt.OutputHash {
		t.Fatalf("streamed output metadata = %+v", meta)
	}
	outcome, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening))
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
	// The receipt verified by Finalize is persisted with the OUTPUT: it is the only source of the
	// infer_receipt convenience copy in GetTaskDataMetadata.
	if ready.Receipt == nil || ready.Receipt.OutputHash != f.receipt.OutputHash || ready.Receipt.ServiceSignature != f.receipt.ServiceSignature {
		t.Fatalf("output receipt after finalize = %+v", ready.Receipt)
	}
	reader, err := f.store.OpenRange(context.Background(), meta.Key, 0, meta.SizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(body) != "hello, world!!" {
		t.Fatalf("fetched output = %q", body)
	}
	fin, found, err := f.service.OutputFin(context.Background(), meta.Key)
	if err != nil || !found || fin.FinishReason != 1 || fin.FinalSeq != 2 || hex.EncodeToString(fin.OutputMMRRoot) != f.receipt.OutputHash {
		t.Fatalf("stored fin = %+v found=%t err=%v", fin, found, err)
	}
}

// receipt output_leaf_count differs from the leaf count recorded at finalization -> reject.
func TestFinalizeTaskResultRejectsStreamedOutputLeafCountMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.OutputLeafCount = 2
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// receipt points at a different root -> object not found, reject.
func TestFinalizeTaskResultRejectsStreamedOutputRootMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.OutputHash = strings.Repeat("c", 64)
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// receipt encoded_size_bytes differs from the total artifact size in the manifest -> reject.
func TestFinalizeTaskResultRejectsEncodedSizeMismatch(t *testing.T) {
	f := newFinalizeFixture(t)
	f.receipt.EvidenceCommitments[0].EncodedSizeBytes++
	f.resignReceipt(t)
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerValueOpening)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// The token bundle carries the order's generation parameters: they must be the bytes the receipt
// binds, bounded before they are read, and outside the commitment's encoded_size_bytes.
func TestFinalizeTaskResultChecksGenerationParams(t *testing.T) {
	withParams := func(body []byte) func(*finalizeFixture) workerBundleSpec {
		return func(f *finalizeFixture) workerBundleSpec {
			artifacts := f.defaultTokenArtifacts(t)
			artifacts["generation_params"] = body
			return workerBundleSpec{tokenArtifacts: artifacts}
		}
	}
	for name, c := range map[string]struct {
		spec     func(*finalizeFixture) workerBundleSpec
		edit     func(*finalizeFixture)
		want     error
		contains string
	}{
		"other parameters": {
			spec: withParams([]byte(`{"generation_params_schema_version":1,"max_output_tokens":257}`)),
			want: ErrHashMismatch, contains: "generation_params artifact hashes to",
		},
		"over the size limit": {
			spec: withParams(bytes.Repeat([]byte(" "), MaxGenerationParamsBytes+1)),
			want: ErrMalformed, contains: "limit 65536",
		},
		"encoded_size_bytes counts the parameters": {
			edit: func(f *finalizeFixture) {
				f.receipt.EvidenceCommitments[1].EncodedSizeBytes = f.bundles[EvidenceKindWorkerTokenOpening].ArtifactTotalSizeBytes
				f.resignReceipt(t)
			},
			want: ErrHashMismatch, contains: "receipt encoded_size_bytes",
		},
		"receipt differs from the accepted order": {
			edit: func(f *finalizeFixture) { f.authority.task.Assignment.GenerationParamsDigest = strings.Repeat("b", 64) },
			want: ErrUnauthorized, contains: "generation_params_digest does not match the accepted order",
		},
		"task without a parameter digest": {
			edit: func(f *finalizeFixture) { f.authority.task.Assignment.GenerationParamsDigest = "" },
			want: ErrAuthorityUnavailable, contains: "no generation_params_digest",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newAuthorizerFixture(t)
			config := manifestStoreConfig()
			config.MaxBlobBytes, config.SpoolReservationBytes = 128<<10, 256<<10
			store, _, _ := newTestStore(t, config)
			service, err := NewService(store, fx.authorizer)
			if err != nil {
				t.Fatal(err)
			}
			f := newFinalizeFixtureOn(t, fx, store, service)
			spec := workerBundleSpec{}
			if c.spec != nil {
				spec = c.spec(f)
			}
			f.storeWorkerBundles(t, spec)
			if c.edit != nil {
				c.edit(f)
			}
			f.requireFinalizeRejected(t, EvidenceKindWorkerTokenOpening, c.want, c.contains)
		})
	}
}

// A Verifier manifest is not addressed via a commitment: content_hash must be the H_V1 of the
// bytes, and a wrong hash is rejected at upload.
func TestVerifierManifestContentHashMustBeBundleHash(t *testing.T) {
	f := newFinalizeFixture(t)
	verifier := f.verifier.Address()
	ref := ObjectKey{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: strings.Repeat("e", 64),
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: verifier,
		EvidenceKind: EvidenceKindVerifierValueOpening,
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

// newWorkerBundleFixture is a finalize fixture whose Worker bundles are built from spec instead of
// the default valid ones.
func newWorkerBundleFixture(t *testing.T, spec workerBundleSpec) *finalizeFixture {
	t.Helper()
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	base := newFinalizeFixtureOn(t, fx, store, service)
	base.storeWorkerBundles(t, spec)
	return base
}

// requireFinalizeRejected runs Finalize for kind, requires the given error and checks nothing
// became READY.
func (f *finalizeFixture) requireFinalizeRejected(t *testing.T, kind EvidenceKind, want error, contains string) {
	t.Helper()
	_, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, kind))
	if !errors.Is(err, want) || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %v, want %v containing %q", err, want, contains)
	}
	refs := []ObjectKey{f.output.Key}
	for _, bundle := range f.bundles {
		refs = append(refs, bundle.Key)
	}
	for _, ref := range refs {
		if state := f.state(t, ref); state != StateStored {
			t.Fatalf("%s state = %s after a rejected Finalize, want STORED", ref.Kind, state)
		}
	}
}

// Each commitment is recomputed from its stored bundle: a bundle that is not the one the receipt
// commits to is rejected even though every object hash and size checks out.
func TestFinalizeTaskResultRejectsBundleNotMatchingCommitment(t *testing.T) {
	for name, c := range map[string]struct {
		kind     EvidenceKind
		spec     func(*finalizeFixture) workerBundleSpec
		contains string
	}{
		"generated token changed": {EvidenceKindWorkerTokenOpening, func(*finalizeFixture) workerBundleSpec {
			return workerBundleSpec{commit: map[string][]byte{"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000fffe")}}
		}, "worker WORKER_TOKEN_OPENING commitment recomputed"},
		"input token changed": {EvidenceKindWorkerTokenOpening, func(*finalizeFixture) workerBundleSpec {
			return workerBundleSpec{commit: map[string][]byte{"input_token_ids": mustDecodeHex(t, "000000020000000100000101")}}
		}, "worker WORKER_TOKEN_OPENING commitment recomputed"},
		"finish_reason differs": {EvidenceKindWorkerTokenOpening, func(*finalizeFixture) workerBundleSpec {
			return workerBundleSpec{commitFinishReason: 2}
		}, "worker WORKER_TOKEN_OPENING commitment recomputed"},
		"worker value changed": {EvidenceKindWorkerValueOpening, func(f *finalizeFixture) workerBundleSpec {
			return workerBundleSpec{commit: map[string][]byte{"worker_values": f.workerValues(t, 3, func(position int, fields [][]byte) {
				if position == 1 {
					fields[6] = nodecontract.Uint64BE(2_000_000)
				}
			})}}
		}, "worker WORKER_VALUE_OPENING commitment recomputed"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newAuthorizerFixture(t)
			store, _, _ := newTestStore(t, manifestStoreConfig())
			service, err := NewService(store, fx.authorizer)
			if err != nil {
				t.Fatal(err)
			}
			f := newFinalizeFixtureOn(t, fx, store, service)
			f.storeWorkerBundles(t, c.spec(f))
			f.requireFinalizeRejected(t, c.kind, ErrHashMismatch, c.contains)
		})
	}
}

// worker_values is strictly decoded: a leaf of another task, positions out of order, or a leaf count
// that is not the receipt's generated_token_count are rejected before any commitment is compared.
func TestFinalizeTaskResultRejectsMalformedWorkerValues(t *testing.T) {
	for name, build := range map[string]func(*finalizeFixture) []byte{
		"leaf of another task": func(f *finalizeFixture) []byte {
			return f.workerValues(t, 3, func(position int, fields [][]byte) {
				if position == 2 {
					fields[1] = bytes.Repeat([]byte{9}, 32)
				}
			})
		},
		"positions out of order": func(f *finalizeFixture) []byte {
			return f.workerValues(t, 3, func(position int, fields [][]byte) {
				fields[4] = nodecontract.Uint32BE(uint32(2 - position))
			})
		},
		"one leaf short": func(f *finalizeFixture) []byte { return f.workerValues(t, 2, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newAuthorizerFixture(t)
			store, _, _ := newTestStore(t, manifestStoreConfig())
			service, err := NewService(store, fx.authorizer)
			if err != nil {
				t.Fatal(err)
			}
			f := newFinalizeFixtureOn(t, fx, store, service)
			// Commit to a valid artifact but store the malformed one under the value bundle.
			f.storeWorkerBundles(t, workerBundleSpec{
				valueArtifacts: map[string][]byte{"worker_values": build(f)},
				commit:         map[string][]byte{"worker_values": f.workerValues(t, 3, nil)},
			})
			f.requireFinalizeRejected(t, EvidenceKindWorkerValueOpening, ErrHashMismatch, "worker_values artifact")
		})
	}
}

// The shape of each Worker bundle is enforced before recomputing.
func TestFinalizeTaskResultRejectsWorkerManifestShape(t *testing.T) {
	for name, c := range map[string]struct {
		kind     EvidenceKind
		spec     func(*finalizeFixture) workerBundleSpec
		contains string
	}{
		"schema_metadata": {EvidenceKindWorkerTokenOpening, func(*finalizeFixture) workerBundleSpec {
			return workerBundleSpec{schemaMetadata: `{"a":1}`}
		}, "schema_metadata"},
		"missing token artifact": {EvidenceKindWorkerTokenOpening, func(f *finalizeFixture) workerBundleSpec {
			artifacts := f.defaultTokenArtifacts(t)
			delete(artifacts, "input_token_ids")
			return workerBundleSpec{tokenArtifacts: artifacts, commit: map[string][]byte{"input_token_ids": mustDecodeHex(t, "000000020000000100000100")}}
		}, "2 artifacts, want 3"},
		"missing generation_params": {EvidenceKindWorkerTokenOpening, func(f *finalizeFixture) workerBundleSpec {
			artifacts := f.defaultTokenArtifacts(t)
			delete(artifacts, "generation_params")
			return workerBundleSpec{tokenArtifacts: artifacts}
		}, "2 artifacts, want 3"},
		"extra token artifact": {EvidenceKindWorkerTokenOpening, func(f *finalizeFixture) workerBundleSpec {
			artifacts := f.defaultTokenArtifacts(t)
			artifacts["zzz"] = []byte("extra artifact")
			return workerBundleSpec{tokenArtifacts: artifacts}
		}, "4 artifacts, want 3"},
		"extra value artifact": {EvidenceKindWorkerValueOpening, func(f *finalizeFixture) workerBundleSpec {
			artifacts := f.defaultValueArtifacts(t)
			artifacts["zzz"] = []byte("extra artifact")
			return workerBundleSpec{valueArtifacts: artifacts}
		}, "2 artifacts"},
		"renamed value artifact": {EvidenceKindWorkerValueOpening, func(f *finalizeFixture) workerBundleSpec {
			return workerBundleSpec{
				valueArtifacts: map[string][]byte{"trace": f.workerValues(t, 3, nil)},
				commit:         map[string][]byte{"worker_values": f.workerValues(t, 3, nil)},
			}
		}, "artifact 0"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newAuthorizerFixture(t)
			store, _, _ := newTestStore(t, manifestStoreConfig())
			service, err := NewService(store, fx.authorizer)
			if err != nil {
				t.Fatal(err)
			}
			f := newFinalizeFixtureOn(t, fx, store, service)
			f.storeWorkerBundles(t, c.spec(f))
			f.requireFinalizeRejected(t, c.kind, ErrMalformed, c.contains)
		})
	}
}

// A token id artifact whose count prefix does not match its length cannot be hashed.
func TestFinalizeTaskResultRejectsTokenIDsFraming(t *testing.T) {
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	f := newFinalizeFixtureOn(t, fx, store, service)
	f.storeWorkerBundles(t, workerBundleSpec{
		tokenArtifacts: map[string][]byte{
			"generated_token_ids": mustDecodeHex(t, "0000000400000002000001010000ffff"),
			"generation_params":   []byte(finalizeGenerationParams),
			"input_token_ids":     mustDecodeHex(t, "000000020000000100000100"),
		},
		commit: map[string][]byte{"generated_token_ids": mustDecodeHex(t, "0000000300000002000001010000ffff")},
	})
	f.requireFinalizeRejected(t, EvidenceKindWorkerTokenOpening, ErrMalformed, "count 4 needs")
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
	f.requireFinalizeRejected(t, EvidenceKindWorkerTokenOpening, ErrConflict, "output was not streamed")
}

func (f *finalizeFixture) readyQuery(t *testing.T) ResultReadyQuery {
	t.Helper()
	digest, err := receiptDigest(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	return ResultReadyQuery{
		TaskHash: f.taskHash, SessionID: testSessionID, TaskID: testTaskID,
		OutputHash: f.receipt.OutputHash, InferReceiptHash: hex.EncodeToString(digest[:]),
	}
}

func (f *finalizeFixture) resultReady(t *testing.T, q ResultReadyQuery) bool {
	t.Helper()
	ready, err := f.service.ResultReady(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return ready
}

// ResultReady is local data-ready: only once the OUTPUT and both bundles are READY, and only for the
// same receipt. The observer hears the Finalize that completes the result: not the first bundle, not a
// failed one, not a replay.
func TestResultReadyFollowsFinalize(t *testing.T) {
	f := newFinalizeFixture(t)
	var notified []string
	f.service.SetResultFinalizedObserver(func(sessionID, taskID string) {
		notified = append(notified, sessionID+"|"+taskID)
	})
	q := f.readyQuery(t)
	if f.resultReady(t, q) {
		t.Fatal("ready before Finalize")
	}

	bad := f.request(t, 8, EvidenceKindWorkerTokenOpening)
	bad.Auth.BodyDigest = strings.Repeat("0", 64)
	if _, err := f.service.FinalizeTaskResult(context.Background(), bad); err == nil {
		t.Fatal("tampered Finalize succeeded")
	}
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 9, EvidenceKindWorkerTokenOpening)); err != nil {
		t.Fatal(err)
	}
	if f.resultReady(t, q) || len(notified) != 0 {
		t.Fatalf("ready after one bundle (notified %v)", notified)
	}
	if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 10, EvidenceKindWorkerValueOpening)); err != nil {
		t.Fatal(err)
	}
	if !f.resultReady(t, q) {
		t.Fatal("not ready after both bundles")
	}
	other := q
	other.InferReceiptHash = strings.Repeat("e", 64)
	if f.resultReady(t, other) {
		t.Fatal("ready for a different receipt")
	}
	missing := q
	missing.OutputHash = strings.Repeat("f", 64)
	if f.resultReady(t, missing) {
		t.Fatal("ready for an OUTPUT that does not exist")
	}

	for i, kind := range []EvidenceKind{EvidenceKindWorkerTokenOpening, EvidenceKindWorkerValueOpening} {
		if _, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, byte(20+i), kind)); err != nil {
			t.Fatalf("replay: %v", err)
		}
	}
	// Only the completing commit notifies: a replay must not let anyone re-trigger the proposal.
	if want := testSessionID + "|" + testTaskID; len(notified) != 1 || notified[0] != want {
		t.Fatalf("observer calls = %v, want exactly one for %s", notified, want)
	}
}

// The two bundle calls may arrive in parallel: they still sign the OUTPUT confirmation once and both
// return it.
func TestFinalizeTaskResultParallelBundlesShareOneOutputConfirmation(t *testing.T) {
	f := newFinalizeFixture(t)
	requests := []FinalizeResultRequest{
		f.request(t, 9, EvidenceKindWorkerTokenOpening), f.request(t, 10, EvidenceKindWorkerValueOpening),
	}
	outcomes := make([]FinalizeResultOutcome, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcomes[i], errs[i] = f.service.FinalizeTaskResult(context.Background(), requests[i])
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("finalize %d: %v", i, err)
		}
	}
	if !bytes.Equal(outcomes[0].OutputConfirmation.Signature, outcomes[1].OutputConfirmation.Signature) {
		t.Fatal("parallel calls signed two OUTPUT confirmations")
	}
	if !f.resultReady(t, f.readyQuery(t)) {
		t.Fatal("not ready after both bundles")
	}
}

// A manifest switched to READY while one of its artifacts is not (a crash between the two) does not
// make the result ready: a Verifier invited then would fetch an artifact that is not served.
func TestResultReadyRequiresEveryArtifact(t *testing.T) {
	f := newFinalizeFixture(t)
	if _, err := f.store.MarkOutputReady(context.Background(), f.output.Key, f.receipt); err != nil {
		t.Fatal(err)
	}
	for kind, bundle := range f.bundles {
		for i, entry := range bundle.Artifacts {
			if kind == EvidenceKindWorkerTokenOpening && i == 0 {
				continue
			}
			ref := bundle.Key
			ref.Kind, ref.ContentHash = ObjectKindEvidenceArtifact, entry.ContentHash
			if _, err := f.store.MarkReady(context.Background(), ref); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.store.MarkReady(context.Background(), bundle.Key); err != nil {
			t.Fatal(err)
		}
	}
	if f.resultReady(t, f.readyQuery(t)) {
		t.Fatal("ready with an artifact that is not READY")
	}
}
