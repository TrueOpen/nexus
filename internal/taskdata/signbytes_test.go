package taskdata

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const testPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"

// Per-vector positive cases live in confirmation_golden_test.go; this only covers the idempotency key and rejection surface.
func TestConfirmationMaterialDigest(t *testing.T) {
	output := StorageConfirmation{
		SchemaVersion: StorageConfirmationSchemaVersionV1, ChainID: "trueopen-task-1",
		BuilderOperator: testBuilder, ServiceAuthorizationNonce: 3,
		Ref: ObjectRef{
			TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID,
			Kind: ObjectKindOutput, ContentHash: strings.Repeat("a", 64),
		},
		SizeBytes: 4096, RetentionUntilHeight: 200,
	}
	digest, err := ConfirmationMaterialDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := BuilderStorageConfirmationDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	if digest != hex.EncodeToString(signed[:]) {
		t.Fatal("material digest must be the signing digest itself")
	}
	// material digest must depend only on protocol fields: recomputing the same confirmation is stable.
	repeat, err := ConfirmationMaterialDigest(output)
	if err != nil || repeat != digest {
		t.Fatalf("material digest is not stable: %q vs %q (%v)", repeat, digest, err)
	}

	evidenceRef := ObjectRef{
		TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: strings.Repeat("b", 64),
		EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1, ProducerOperator: testBuilder,
	}
	malformed := map[string]StorageConfirmation{
		"output carries artifact total": func() StorageConfirmation { v := output; v.ArtifactTotalSizeBytes = 1; return v }(),
		"missing retention":             func() StorageConfirmation { v := output; v.RetentionUntilHeight = 0; return v }(),
		"missing size":                  func() StorageConfirmation { v := output; v.SizeBytes = 0; return v }(),
		"zero nonce":                    func() StorageConfirmation { v := output; v.ServiceAuthorizationNonce = 0; return v }(),
		"wrong schema version":          func() StorageConfirmation { v := output; v.SchemaVersion = 2; return v }(),
		"artifact kind": func() StorageConfirmation {
			v := output
			v.Ref = evidenceRef
			v.Ref.Kind = ObjectKindEvidenceArtifact
			return v
		}(),
	}
	for name, confirmation := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := BuilderStorageConfirmationDigest(confirmation); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// The UploadTaskOutputStream Header body reuses TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1 with the
// fixed-value projection of Interface & Topic Catalogue §4.2.1: canonical
// TaskDataObjectRefV1 (kind=OUTPUT, content_hash=0x00*32, producer defaulted) +
// size_bytes=0 + media_type="". It must equal the whole-object upload body function
// applied to the same fixed values; that is how Cortex computes it, and hashing only the
// three bare fields would never match the Worker.
func TestOutputStreamBodyDigestUsesUploadBodyProjection(t *testing.T) {
	key := ObjectKey{
		TaskHash: strings.Repeat("22", 32), SessionID: strings.Repeat("33", 32), TaskID: strings.Repeat("11", 32),
		Kind: ObjectKindOutput,
	}
	got, err := OutputStreamBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	projected := key
	projected.ContentHash = strings.Repeat("00", 32)
	want, err := TaskDataUploadBodyDigest(projected, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("stream header digest = %x, want the fixed-value upload body projection %x", got, want)
	}
	// content_hash is fixed to all zeros by the projection: a different caller-supplied value must not change the digest.
	other := key
	other.ContentHash = strings.Repeat("44", 32)
	if again, err := OutputStreamBodyDigest(other); err != nil || again != want {
		t.Fatalf("digest must ignore caller content_hash: %x / %v", again, err)
	}
}
