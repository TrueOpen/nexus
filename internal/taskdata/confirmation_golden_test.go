package taskdata

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// TestBuilderStorageConfirmationDigestMatchesWireVectors checks every
// TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V2 vector of the pinned wire release: one confirmation
// covers INPUT / OUTPUT / a whole evidence bundle, with every per-object difference carried by the
// canonical nine-field TaskDataObjectRefV1.
func TestBuilderStorageConfirmationDigestMatchesWireVectors(t *testing.T) {
	file := wirefixture.Load(t, "task/builder_confirmation_v1.json")
	if len(file.Vectors) != 5 {
		t.Fatalf("expected 5 confirmation vectors, found %d", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			v.CheckPreimage(t)
			f := func(name string) wirefixture.Field { return v.Field(t, name) }
			confirmation := StorageConfirmation{
				SchemaVersion:             uint32(f("schema_version").Uint64(t)),
				ChainID:                   f("chain_id").UTF8,
				BuilderOperator:           bech32Of(t, f("builder_operator_address").Bytes(t)),
				ServiceAuthorizationNonce: f("service_authorization_nonce").Uint64(t),
				Ref:                       wireObjectRef(t, f("object_ref")),
				SizeBytes:                 f("size_bytes").Uint64(t),
				ArtifactTotalSizeBytes:    f("artifact_total_size_bytes").Uint64(t),
				RetentionUntilHeight:      f("retention_until_height").Uint64(t),
			}
			digest, err := BuilderStorageConfirmationDigest(confirmation)
			if err != nil {
				t.Fatal(err)
			}
			if digest != v.Digest(t) {
				t.Fatalf("digest = %x, want %s", digest, v.DigestHex)
			}
		})
	}
}

// service_signature is not part of its own digest: filling in the signature must not change it.
func TestBuilderStorageConfirmationDigestExcludesOwnSignature(t *testing.T) {
	base := StorageConfirmation{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperator: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man", ServiceAuthorizationNonce: 7,
		Ref: ObjectRef{
			TaskHash:    "2222222222222222222222222222222222222222222222222222222222222222",
			SessionID:   "3333333333333333333333333333333333333333333333333333333333333333",
			TaskID:      "1111111111111111111111111111111111111111111111111111111111111111",
			Kind:        ObjectKindOutput,
			ContentHash: "4444444444444444444444444444444444444444444444444444444444444444",
		},
		SizeBytes: 1024, RetentionUntilHeight: 5000,
	}
	withSig := base
	withSig.Signature = make([]byte, 64)

	a, err := BuilderStorageConfirmationDigest(base)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	b, err := BuilderStorageConfirmationDigest(withSig)
	if err != nil {
		t.Fatalf("digest with signature: %v", err)
	}
	if a != b {
		t.Fatal("service_signature entered its own digest")
	}
}

// nonce must be non-zero: it must equal the signer's currently ACTIVE service binding.
func TestBuilderStorageConfirmationRejectsZeroNonce(t *testing.T) {
	c := StorageConfirmation{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperator: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
		Ref: ObjectRef{
			TaskHash:    "2222222222222222222222222222222222222222222222222222222222222222",
			SessionID:   "3333333333333333333333333333333333333333333333333333333333333333",
			TaskID:      "1111111111111111111111111111111111111111111111111111111111111111",
			Kind:        ObjectKindOutput,
			ContentHash: "4444444444444444444444444444444444444444444444444444444444444444",
		},
		SizeBytes: 1024, RetentionUntilHeight: 5000,
	}
	if _, err := BuilderStorageConfirmationDigest(c); err == nil {
		t.Fatal("nonce=0 must be rejected")
	}
}

// EVIDENCE_ARTIFACT is not confirmed on its own: it is covered by the owning manifest's hash and that bundle's confirmation.
func TestBuilderStorageConfirmationRejectsArtifact(t *testing.T) {
	c := StorageConfirmation{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperator: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man", ServiceAuthorizationNonce: 7,
		Ref: ObjectRef{
			TaskHash:             "2222222222222222222222222222222222222222222222222222222222222222",
			SessionID:            "3333333333333333333333333333333333333333333333333333333333333333",
			TaskID:               "1111111111111111111111111111111111111111111111111111111111111111",
			Kind:                 ObjectKindEvidenceArtifact,
			ContentHash:          "6666666666666666666666666666666666666666666666666666666666666666",
			EvidenceProducerKind: EvidenceProducerVerifier, EvidenceKind: EvidenceKindVerifierValueOpening,
			VerifyRound:      2,
			ProducerOperator: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		},
		SizeBytes: 100, RetentionUntilHeight: 5000,
	}
	if _, err := BuilderStorageConfirmationDigest(c); err == nil {
		t.Fatal("EVIDENCE_ARTIFACT must not be confirmable on its own")
	}
}
