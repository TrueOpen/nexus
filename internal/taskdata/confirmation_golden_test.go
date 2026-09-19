package taskdata

import (
	"encoding/hex"
	"testing"
)

// Aligned vector by vector with wire v0.4.1 testdata/v1/task/builder_confirmation_v1.json.
// The vectors come from Task Data Interface Design §6.3a and are the published values of
// TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V1: one confirmation covers INPUT / OUTPUT / the full
// evidence bundle, with all per-object differences carried by the canonical TaskDataObjectRefV1.
func TestBuilderStorageConfirmationDigestMatchesPublishedVectors(t *testing.T) {
	const (
		chainID  = "trueopen-golden-1"
		builder  = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
		taskHash = "2222222222222222222222222222222222222222222222222222222222222222"
		session  = "3333333333333333333333333333333333333333333333333333333333333333"
		taskID   = "1111111111111111111111111111111111111111111111111111111111111111"
		// The verifier's bech32 sibling field in the vector is wrong (a known class of
		// vector defect; v0.4.1's builder_confirmation_v1.json was not scanned). The preimage uses
		// the hex field c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3, so the published digest is
		// still correct; here we use an address that decodes to the same 20 bytes.
		verifier = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
		worker   = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	)

	cases := []struct {
		name   string
		input  StorageConfirmation
		digest string
	}{
		{
			name: "builder_confirmation_output",
			input: StorageConfirmation{
				SchemaVersion: 1, ChainID: chainID, BuilderOperator: builder, ServiceAuthorizationNonce: 7,
				Ref: ObjectRef{
					TaskHash: taskHash, SessionID: session, TaskID: taskID,
					Kind:        ObjectKindOutput,
					ContentHash: "4444444444444444444444444444444444444444444444444444444444444444",
				},
				SizeBytes: 1024, RetentionUntilHeight: 5000,
			},
			digest: "4614aa75559105c1f59a16e8139618a5db84c391f9f30ef5d609c4238f3614e7",
		},
		{
			name: "builder_confirmation_input",
			input: StorageConfirmation{
				SchemaVersion: 1, ChainID: chainID, BuilderOperator: builder, ServiceAuthorizationNonce: 7,
				Ref: ObjectRef{
					TaskHash: taskHash, SessionID: session, TaskID: taskID,
					Kind:        ObjectKindInput,
					ContentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
				SizeBytes: 256, RetentionUntilHeight: 5000,
			},
			digest: "444e59e09f10e1c269941d7106cd59208ee54a8994e8a3337ec304f0f10b4c6e",
		},
		{
			name: "builder_confirmation_verifier_evidence",
			input: StorageConfirmation{
				SchemaVersion: 1, ChainID: chainID, BuilderOperator: builder, ServiceAuthorizationNonce: 7,
				Ref: ObjectRef{
					TaskHash: taskHash, SessionID: session, TaskID: taskID,
					Kind:                 ObjectKindEvidenceManifest,
					ContentHash:          "6666666666666666666666666666666666666666666666666666666666666666",
					EvidenceProducerKind: EvidenceProducerVerifier,
					VerifyRound:          2,
					ProducerOperator:     verifier,
				},
				SizeBytes: 556, ArtifactTotalSizeBytes: 4096, RetentionUntilHeight: 5000,
			},
			digest: "4252e764e47f071920df42e0f71df91e2cc5beff98e22b532a64fecfbb83fa92",
		},
		{
			name: "builder_confirmation_worker_evidence",
			input: StorageConfirmation{
				SchemaVersion: 1, ChainID: chainID, BuilderOperator: builder, ServiceAuthorizationNonce: 7,
				Ref: ObjectRef{
					TaskHash: taskHash, SessionID: session, TaskID: taskID,
					Kind:                 ObjectKindEvidenceManifest,
					ContentHash:          "7777777777777777777777777777777777777777777777777777777777777777",
					EvidenceProducerKind: EvidenceProducerWorker,
					VerifyRound:          1,
					ProducerOperator:     worker,
				},
				SizeBytes: 700, ArtifactTotalSizeBytes: 2048, RetentionUntilHeight: 5000,
			},
			digest: "e006c3fe30cce2d1478a07afd23222afb8f5dcc6ed1777577fb6a4d1d1410f41",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := BuilderStorageConfirmationDigest(tc.input)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != tc.digest {
				t.Fatalf("digest mismatch\n got %s\nwant %s", got, tc.digest)
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
			EvidenceProducerKind: EvidenceProducerVerifier,
			VerifyRound:          2,
			ProducerOperator:     "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		},
		SizeBytes: 100, RetentionUntilHeight: 5000,
	}
	if _, err := BuilderStorageConfirmationDigest(c); err == nil {
		t.Fatal("EVIDENCE_ARTIFACT must not be confirmable on its own")
	}
}
