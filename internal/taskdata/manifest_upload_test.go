package taskdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The content_hash of EVIDENCE_MANIFEST is evidence_bundle_hash (H_V1), not SHA256(bytes).
// The upload path must compute the right one per object kind, otherwise every valid
// manifest is rejected as a hash mismatch.
func TestUploadManifestVerifiesBundleHashNotSHA256(t *testing.T) {
	body := []byte(goldenManifest)
	store, _, _ := newTestStore(t, manifestStoreConfig())

	header := manifestUploadHeader(body)
	if header.Key.ContentHash == hex.EncodeToString(sha256Sum(body)) {
		t.Fatal("fixture broken: bundle hash should not equal SHA256")
	}

	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	metadata, err := upload.Prepare(context.Background())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if metadata.Key.ContentHash != goldenManifestDigest {
		t.Fatalf("content_hash = %q", metadata.Key.ContentHash)
	}
	// The parse result is persisted with the object: Finalize checks the artifact details
	// and schema hash and should not have to read the bytes back and re-parse them then.
	if metadata.ArtifactTotalSizeBytes != 487 {
		t.Fatalf("artifact_total_size_bytes = %d", metadata.ArtifactTotalSizeBytes)
	}
	if metadata.EvidenceSchemaHash != "7777777777777777777777777777777777777777777777777777777777777777" {
		t.Fatalf("evidence_schema_hash = %q", metadata.EvidenceSchemaHash)
	}
}

// A mismatched content_hash means a different manifest: reject, do not rewrite it to the computed one.
func TestUploadManifestRejectsWrongBundleHash(t *testing.T) {
	body := []byte(goldenManifest)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	header := manifestUploadHeader(body)
	header.Key.ContentHash = "00" + header.Key.ContentHash[2:]
	header.SemanticHash = header.Key.ContentHash

	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error = %v, want ErrHashMismatch", err)
	}
}

// A non-canonical manifest must not enter STORED: the contract requires the manifest to be
// strictly parsed by Finalize time; blocking at upload is easier to locate than failing at
// Finalize and keeps bad bytes from occupying the ref.
func TestUploadManifestRejectsNonCanonicalJSON(t *testing.T) {
	body := []byte(goldenManifest + "\n")
	store, _, _ := newTestStore(t, manifestStoreConfig())
	header := manifestUploadHeader(body)

	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

// content_hash of INPUT / OUTPUT / EVIDENCE_ARTIFACT is still SHA256(bytes).
func TestUploadNonManifestStillVerifiesSHA256(t *testing.T) {
	body := []byte("plain object bytes")
	store, _, _ := newTestStore(t, manifestStoreConfig())
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

	upload, err := store.Begin(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body); err != nil {
		t.Fatal(err)
	}
	metadata, err := upload.Prepare(context.Background())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if metadata.Key.ContentHash != hex.EncodeToString(sha256Sum(body)) {
		t.Fatalf("content_hash = %q", metadata.Key.ContentHash)
	}
}

func manifestUploadHeader(body []byte) UploadHeader {
	digest := EvidenceBundleHash(body)
	contentHash := hex.EncodeToString(digest[:])
	return UploadHeader{
		Key: ObjectKey{
			// Identity taken from the golden manifest itself: a ref inconsistent with what the
			// manifest claims is rejected, see TestUploadManifestRejectsRefMismatch.
			TaskHash: strings.Repeat("2", 64), SessionID: testSessionID, TaskID: strings.Repeat("1", 64),
			Kind: ObjectKindEvidenceManifest, ContentHash: contentHash,
			EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1,
			ProducerOperator: "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		},
		Uploader:  "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		SizeBytes: uint64(len(body)), SemanticHash: contentHash,
		MediaType: "application/json", RetainUntilHeight: 100,
	}
}

// The Task identity and producer the manifest claims must match the ref it is placed in:
// the two are signed and transported separately, and not comparing them would allow the
// same manifest to be attached to another Task or another producer.
func TestUploadManifestRejectsRefMismatch(t *testing.T) {
	body := []byte(goldenManifest)
	mismatches := map[string]func(*UploadHeader){
		"task_hash": func(h *UploadHeader) { h.Key.TaskHash = testTaskHash },
		"task_id":   func(h *UploadHeader) { h.Key.TaskID = testTaskID },
		"producer_kind": func(h *UploadHeader) {
			h.Key.EvidenceProducerKind = EvidenceProducerWorker
		},
		"verify_round":      func(h *UploadHeader) { h.Key.VerifyRound = 2 },
		"producer_operator": func(h *UploadHeader) { h.Key.ProducerOperator = testBuilder },
	}
	for name, mutate := range mismatches {
		t.Run(name, func(t *testing.T) {
			store, _, _ := newTestStore(t, manifestStoreConfig())
			header := manifestUploadHeader(body)
			mutate(&header)
			upload, err := store.Begin(context.Background(), header)
			if err != nil {
				t.Fatal(err)
			}
			if err := upload.WriteChunk(body); err != nil {
				t.Fatal(err)
			}
			if _, err := upload.Prepare(context.Background()); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

func sha256Sum(body []byte) []byte {
	digest := sha256.Sum256(body)
	return digest[:]
}

// A manifest is a few hundred bytes; the default fixture's 16-byte limit cannot hold it.
func manifestStoreConfig() Config {
	return Config{
		InlineMaxBytes: 1024, ChunkSizeBytes: 1024, MaxRangeBytes: 2048,
		MaxBlobBytes: 4096, SpoolReservationBytes: 8192, DiskAcceptWatermarkPercent: 85,
	}
}

// buildManifest assembles a canonical manifest per §2.1 as a fixture for cases that need
// "this manifest belongs to this producer". Nexus production code never generates a
// manifest, so this builder exists only in tests.
func buildManifest(t *testing.T, ref ObjectKey, schemaHash string, artifacts []EvidenceArtifact) []byte {
	t.Helper()
	manifest := EvidenceBundleManifest{
		ManifestVersion: EvidenceBundleManifestVersionV1, ChainID: testChainID,
		TaskID: ref.TaskID, TaskHash: ref.TaskHash, EvidenceSchemaHash: schemaHash,
		ProducerKind: ref.EvidenceProducerKind, ProducerOperator: ref.ProducerOperator,
		VerifyRound: ref.VerifyRound, Artifacts: artifacts,
	}
	raw, err := manifest.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The built bytes must pass strict parsing themselves: a broken fixture should fail here, not in the path under test.
	if _, err := ParseEvidenceBundleManifest([]byte(raw)); err != nil {
		t.Fatalf("fixture manifest is not canonical: %v", err)
	}
	return []byte(raw)
}
