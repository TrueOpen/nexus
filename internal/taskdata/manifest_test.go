package taskdata

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The minimal Verifier manifest published in Data Plane and Evidence Transport §2.1
// (single-line UTF-8, no newline, 556 bytes), also the evidence_bundle_manifest_v1 of wire
// v0.4.1 testdata/v1/task/canonical_json_v1.json.
const goldenManifest = `{"artifacts":[{"artifact_id":"aggregate_proof","content_hash":"6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2","size_bytes":"487"}],"chain_id":"trueopen-golden-1","evidence_schema_hash":"7777777777777777777777777777777777777777777777777777777777777777","manifest_version":1,"producer_kind":"VERIFIER","producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz","task_hash":"2222222222222222222222222222222222222222222222222222222222222222","task_id":"1111111111111111111111111111111111111111111111111111111111111111","verify_round":1}`

const goldenManifestDigest = "9b568692f6d7f01cbc7d6d8fa79d37c73c5e24e6e1f533fe7620be6ea2c9d341"

func TestEvidenceBundleHashMatchesPublishedVector(t *testing.T) {
	if len(goldenManifest) != 562 {
		t.Fatalf("vector length = %d, contract says 562", len(goldenManifest))
	}
	digest := EvidenceBundleHash([]byte(goldenManifest))
	if got := hex.EncodeToString(digest[:]); got != goldenManifestDigest {
		t.Fatalf("bundle hash\n got %s\nwant %s", got, goldenManifestDigest)
	}
}

// The digest covers the exact bytes: changing any byte yields a different bundle.
func TestEvidenceBundleHashCoversExactBytes(t *testing.T) {
	base := EvidenceBundleHash([]byte(goldenManifest))
	mutations := map[string][]byte{
		"last_byte_flipped": func() []byte {
			b := []byte(goldenManifest)
			b[len(b)-1] ^= 1
			return b
		}(),
		"first_byte_flipped": func() []byte {
			b := []byte(goldenManifest)
			b[0] ^= 1
			return b
		}(),
		"truncated_by_one": []byte(goldenManifest[:len(goldenManifest)-1]),
	}
	for name, payload := range mutations {
		t.Run(name, func(t *testing.T) {
			if EvidenceBundleHash(payload) == base {
				t.Fatal("digest did not change with the payload")
			}
		})
	}
}

func TestParseEvidenceBundleManifestGolden(t *testing.T) {
	manifest, err := ParseEvidenceBundleManifest([]byte(goldenManifest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if manifest.ManifestVersion != 1 || manifest.ChainID != "trueopen-golden-1" ||
		manifest.ProducerKind != EvidenceProducerVerifier || manifest.VerifyRound != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if manifest.TaskHash != strings.Repeat("2", 64) || manifest.TaskID != strings.Repeat("1", 64) ||
		manifest.EvidenceSchemaHash != strings.Repeat("7", 64) {
		t.Fatalf("unexpected identity: %#v", manifest)
	}
	if manifest.ProducerOperator != "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz" {
		t.Fatalf("producer_operator = %q", manifest.ProducerOperator)
	}
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("artifacts = %d", len(manifest.Artifacts))
	}
	a := manifest.Artifacts[0]
	if a.ArtifactID != "aggregate_proof" || a.SizeBytes != 487 ||
		a.ContentHash != "6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2" {
		t.Fatalf("unexpected artifact: %#v", a)
	}
	// The checked sum of artifact sizes goes into the storage confirmation; it is computed during parsing so callers need not do another pass.
	if manifest.ArtifactTotalSizeBytes != 487 {
		t.Fatalf("artifact_total_size_bytes = %d", manifest.ArtifactTotalSizeBytes)
	}
	// The parsed structure must round-trip to the exact received bytes: canonical is not "approximately equal".
	if manifest.Raw != goldenManifest {
		t.Fatal("Raw must be the exact bytes received")
	}
}

// Anything non-canonical is rejected: reordered keys, added whitespace, changed escapes,
// uint64 written as a JSON number, Hash32 in uppercase or with 0x, an extra key, a missing
// key, a duplicate key, a trailing document.
func TestParseEvidenceBundleManifestRejectsNonCanonical(t *testing.T) {
	cases := map[string]string{
		"key reordered": `{"chain_id":"trueopen-golden-1","artifacts":[{"artifact_id":"aggregate_proof","content_hash":"6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2","size_bytes":"487"}],"evidence_schema_hash":"7777777777777777777777777777777777777777777777777777777777777777","manifest_version":1,"producer_kind":"VERIFIER","producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz","task_hash":"2222222222222222222222222222222222222222222222222222222222222222","task_id":"1111111111111111111111111111111111111111111111111111111111111111","verify_round":1}`,

		"whitespace":       strings.Replace(goldenManifest, `{"artifacts"`, `{ "artifacts"`, 1),
		"trailing newline": goldenManifest + "\n",
		"leading bom":      "\ufeff" + goldenManifest,
		"trailing document": goldenManifest + `{"artifacts":[],"chain_id":"x","evidence_schema_hash":"` +
			strings.Repeat("7", 64) + `","manifest_version":1,"producer_kind":"WORKER","producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz","task_hash":"` +
			strings.Repeat("2", 64) + `","task_id":"` + strings.Repeat("1", 64) + `","verify_round":1}`,

		"unknown key": strings.Replace(goldenManifest, `"chain_id"`, `"extra":1,"chain_id"`, 1),
		"duplicate key": strings.Replace(goldenManifest,
			`"chain_id":"trueopen-golden-1"`, `"chain_id":"trueopen-golden-1","chain_id":"trueopen-golden-1"`, 1),
		"missing manifest_version": strings.Replace(goldenManifest, `"manifest_version":1,`, ``, 1),

		"size_bytes as number":      strings.Replace(goldenManifest, `"size_bytes":"487"`, `"size_bytes":487`, 1),
		"size_bytes leading zero":   strings.Replace(goldenManifest, `"size_bytes":"487"`, `"size_bytes":"0487"`, 1),
		"manifest_version as float": strings.Replace(goldenManifest, `"manifest_version":1`, `"manifest_version":1.0`, 1),

		"hash uppercase": strings.Replace(goldenManifest,
			`"task_hash":"2222222222222222222222222222222222222222222222222222222222222222"`,
			`"task_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, 1),
		"hash with 0x prefix": strings.Replace(goldenManifest,
			`"task_hash":"2222222222222222222222222222222222222222222222222222222222222222"`,
			`"task_hash":"0x22222222222222222222222222222222222222222222222222222222222222"`, 1),
		"hash too short": strings.Replace(goldenManifest,
			`"task_hash":"2222222222222222222222222222222222222222222222222222222222222222"`,
			`"task_hash":"2222"`, 1),

		"unknown producer kind": strings.Replace(goldenManifest, `"producer_kind":"VERIFIER"`, `"producer_kind":"BUILDER"`, 1),
		"producer_kind lowercase": strings.Replace(goldenManifest,
			`"producer_kind":"VERIFIER"`, `"producer_kind":"verifier"`, 1),
		"producer_operator not bech32": strings.Replace(goldenManifest,
			`"producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"`,
			`"producer_operator":"trueopen1notanaddress"`, 1),
		"verify_round zero": strings.Replace(goldenManifest, `"verify_round":1`, `"verify_round":0`, 1),

		"empty artifact id": strings.Replace(goldenManifest, `"artifact_id":"aggregate_proof"`, `"artifact_id":""`, 1),
		"artifact size zero": strings.Replace(goldenManifest,
			`"size_bytes":"487"`, `"size_bytes":"0"`, 1),
		"no artifacts": strings.Replace(goldenManifest,
			`"artifacts":[{"artifact_id":"aggregate_proof","content_hash":"6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2","size_bytes":"487"}]`,
			`"artifacts":[]`, 1),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEvidenceBundleManifest([]byte(payload)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// artifact_id must be unique and in ascending UTF-8 byte order: the order is part of the manifest and the parser does not reorder it.
func TestParseEvidenceBundleManifestRejectsUnorderedArtifacts(t *testing.T) {
	const h1 = "6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2"
	const h2 = "5a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2"
	tail := `,"chain_id":"trueopen-golden-1","evidence_schema_hash":"` + strings.Repeat("7", 64) +
		`","manifest_version":1,"producer_kind":"WORKER","producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz","task_hash":"` +
		strings.Repeat("2", 64) + `","task_id":"` + strings.Repeat("1", 64) + `","verify_round":1}`

	descending := `{"artifacts":[{"artifact_id":"b","content_hash":"` + h1 + `","size_bytes":"1"},` +
		`{"artifact_id":"a","content_hash":"` + h2 + `","size_bytes":"1"}]` + tail
	duplicate := `{"artifacts":[{"artifact_id":"a","content_hash":"` + h1 + `","size_bytes":"1"},` +
		`{"artifact_id":"a","content_hash":"` + h2 + `","size_bytes":"1"}]` + tail

	for name, payload := range map[string]string{"descending": descending, "duplicate": duplicate} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEvidenceBundleManifest([]byte(payload)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// Optional fields, when present, must also be canonical and must not change how present fields are interpreted.
func TestParseEvidenceBundleManifestOptionalFields(t *testing.T) {
	withOptional := strings.Replace(goldenManifest,
		`"chain_id":"trueopen-golden-1"`,
		`"chain_id":"trueopen-golden-1","evidence_kind":"PREFILL_METRIC"`, 1)
	// schema_metadata sorts after producer_operator and before task_hash (ascending UTF-8 byte order).
	withOptional = strings.Replace(withOptional,
		`,"task_hash"`, `,"schema_metadata":{"codec":"cbor"},"task_hash"`, 1)

	manifest, err := ParseEvidenceBundleManifest([]byte(withOptional))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if manifest.EvidenceKind != "PREFILL_METRIC" {
		t.Fatalf("evidence_kind = %q", manifest.EvidenceKind)
	}
	if manifest.SchemaMetadata != `{"codec":"cbor"}` {
		t.Fatalf("schema_metadata = %q", manifest.SchemaMetadata)
	}
	// An optional field in the payload is in the bundle hash.
	if EvidenceBundleHash([]byte(withOptional)) == EvidenceBundleHash([]byte(goldenManifest)) {
		t.Fatal("a manifest with optional fields added must be a different bundle")
	}
	// schema_metadata must be canonical internally too.
	nonCanonical := strings.Replace(withOptional, `{"codec":"cbor"}`, `{ "codec":"cbor"}`, 1)
	if _, err := ParseEvidenceBundleManifest([]byte(nonCanonical)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-canonical schema_metadata error = %v, want ErrMalformed", err)
	}
}

// The artifact size sum must use checked addition: overflow is an error, not a wraparound.
func TestParseEvidenceBundleManifestRejectsArtifactSizeOverflow(t *testing.T) {
	const h1 = "6a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2"
	const h2 = "5a54c75efb90d4fb60f16fa685633e634e3ce8a3c1d3ab68f5ff600eb1952db2"
	payload := `{"artifacts":[{"artifact_id":"a","content_hash":"` + h1 + `","size_bytes":"18446744073709551615"},` +
		`{"artifact_id":"b","content_hash":"` + h2 + `","size_bytes":"1"}],"chain_id":"trueopen-golden-1","evidence_schema_hash":"` +
		strings.Repeat("7", 64) + `","manifest_version":1,"producer_kind":"WORKER","producer_operator":"trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz","task_hash":"` +
		strings.Repeat("2", 64) + `","task_id":"` + strings.Repeat("1", 64) + `","verify_round":1}`
	if _, err := ParseEvidenceBundleManifest([]byte(payload)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}
